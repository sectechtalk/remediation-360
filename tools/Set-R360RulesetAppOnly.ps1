<#
.SYNOPSIS
  S7: only the r360 GitHub App may merge to main in your-org/remediations.
.DESCRIPTION
  Creates or updates a separate ruleset "r360-app-only-merge" on the default branch with a single
  "update" rule and the r360 App as the only bypass actor (bypass_mode pull_request).
  The existing "main-protection" ruleset (PR required, PSScriptAnalyzer strict, no force push, no delete)
  is read and verified but never written, so the App still has to pass every CI check.
  Idempotent. Use -WhatIf to see the change. Use -Remove for break-glass (owner only).
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Repo = 'your-org/remediations',
    [long]$AppId = 1234567,
    [string]$Name = 'r360-app-only-merge',
    [switch]$Remove
)
$ErrorActionPreference = 'Stop'

# Prerequisites
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { throw 'GitHub CLI (gh) is not installed. Run: winget install GitHub.cli' }
gh auth status 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'gh is not signed in. Run: gh auth login -h github.com' }
$perm = gh api "repos/$Repo" --jq '.permissions.admin'
if ($perm -ne 'true') { throw "The signed-in gh account is not an admin of $Repo." }
$base = @(gh api "repos/$Repo/rulesets" | ConvertFrom-Json | ForEach-Object { $_ })
$prot = $base | Where-Object name -eq 'main-protection'
if (-not $prot) { throw "Ruleset main-protection not found on $Repo. It must exist so CI stays required." }
$protFull = gh api "repos/$Repo/rulesets/$($prot.id)" | ConvertFrom-Json
$checks = ($protFull.rules | Where-Object type -eq 'required_status_checks').parameters.required_status_checks.context
if (-not $checks) { throw 'main-protection has no required status checks. Refusing: the App must stay bound by CI.' }
if ($protFull.bypass_actors.Count -gt 0) { throw 'main-protection has bypass actors. Expected none; review it first.' }
Write-Host "OK main-protection $($prot.id) requires: $($checks -join ', ')"

$existing = $base | Where-Object name -eq $Name
if ($Remove) {
    if (-not $existing) { Write-Host "No $Name ruleset. Nothing to remove."; return }
    if ($PSCmdlet.ShouldProcess("$Repo ruleset $($existing.id)", 'Delete (break-glass)')) {
        gh api -X DELETE "repos/$Repo/rulesets/$($existing.id)" | Out-Null
        Write-Host "Removed $Name ($($existing.id)). Humans can merge again. Re-run without -Remove to restore."
    }
    return
}

$body = @{
    name = $Name; target = 'branch'; enforcement = 'active'
    conditions = @{ ref_name = @{ include = @('~DEFAULT_BRANCH'); exclude = @() } }
    rules = @(@{ type = 'update'; parameters = @{ update_allows_fetch_and_merge = $false } })
    bypass_actors = @(@{ actor_id = $AppId; actor_type = 'Integration'; bypass_mode = 'pull_request' })
} | ConvertTo-Json -Depth 10
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("r360-ruleset-" + [guid]::NewGuid() + ".json")
[IO.File]::WriteAllText($tmp, $body)

if ($existing) {
    $cur = gh api "repos/$Repo/rulesets/$($existing.id)" | ConvertFrom-Json
    $ok = $cur.enforcement -eq 'active' -and ($cur.rules.type -join ',') -eq 'update' -and $cur.bypass_actors.Count -eq 1 -and
          $cur.bypass_actors[0].actor_id -eq $AppId -and $cur.bypass_actors[0].bypass_mode -eq 'pull_request'
    if ($ok) { Write-Host "OK $Name ($($existing.id)) already current."; $id = $existing.id }
    elseif ($PSCmdlet.ShouldProcess("$Repo ruleset $($existing.id)", 'Update to App-only merge')) {
        $id = (gh api -X PUT "repos/$Repo/rulesets/$($existing.id)" --input $tmp | ConvertFrom-Json).id
    }
} elseif ($PSCmdlet.ShouldProcess($Repo, "Create ruleset $Name (only App $AppId may merge to main)")) {
    $id = (gh api -X POST "repos/$Repo/rulesets" --input $tmp | ConvertFrom-Json).id
} else { Write-Host "WhatIf body:`n$body" }
Remove-Item $tmp -ErrorAction SilentlyContinue

if ($id) {
    $v = gh api "repos/$Repo/rulesets/$id" | ConvertFrom-Json
    if ($v.enforcement -ne 'active' -or $v.bypass_actors[0].actor_id -ne $AppId) { throw "Verify failed on ruleset $id." }
    $after = gh api "repos/$Repo/rulesets/$($prot.id)" | ConvertFrom-Json
    if ($after.updated_at -ne $protFull.updated_at) { throw 'main-protection changed unexpectedly.' }
    Write-Host "OK ruleset $id active. Only App $AppId may merge to main; main-protection $($prot.id) unchanged."
}
