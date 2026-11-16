<#
.SYNOPSIS
  Deployments lane: sets the deployment targets r360 shows (R360_DEPLOY_TARGETS on app-r360) and prints the
  OIDC subjects each target's deploy identities must trust.
.DESCRIPTION
  Reads a targets file (see docs/deployments.md), checks it, and stores it base64-encoded in the Container App
  setting R360_DEPLOY_TARGETS. r360 validates it again at startup and refuses to start if it is invalid, so run
  tools/Publish-R360Image.ps1 or check /healthz afterwards.
  For every target it reads the repository's OIDC subject settings and prints the federated credential subjects:
    plan identity  : <prefix>:pull_request and <prefix>:ref:refs/heads/<branch>   (read-only Graph permissions)
    apply identity : <prefix>:environment:<environment>                          (the permissions Terraform needs)
  Repositories created after 2026-07-15 use the immutable prefix repo:OWNER@OWNER_ID/REPO@REPO_ID, which is why
  the prefix is read from GitHub rather than guessed.
  Idempotent. Use -WhatIf to see the change without writing it.
.EXAMPLE
  pwsh -File tools/Set-R360DeployTargets.ps1 -Path ./deploy-targets.json -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$Path
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'R360.Common.psm1') -Force
$cfg = Get-R360Config

if (-not (Test-Path -LiteralPath $Path)) { throw "Targets file not found: $Path" }
$doc = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json -Depth 10
if ($doc.version -ne 1 -or $null -eq $doc.targets) { throw 'Expected { "version": 1, "targets": [ ... ] }' }
$targets = @($doc.targets)
if ($targets.Count -gt 20) { throw 'At most 20 targets.' }

$ids = @{}
foreach ($t in $targets) {
    if ("$($t.id)" -notmatch '^[a-z0-9][a-z0-9-]{1,39}$') { throw "Target id '$($t.id)' must be lowercase letters, digits and dashes." }
    if ($ids.ContainsKey($t.id)) { throw "Duplicate target id $($t.id)." }
    $ids[$t.id] = $true
    if ("$($t.repo)" -notmatch "^$([regex]::Escape($cfg.GitHubOrg))/[A-Za-z0-9._-]+$") { throw "Target $($t.id): repo must be $($cfg.GitHubOrg)/<name>." }
    if ("$($t.workflow)" -notmatch '^[A-Za-z0-9._-]+\.ya?ml$') { throw "Target $($t.id): workflow must be a file name such as deploy.yml." }
    if (-not "$($t.environment)") { throw "Target $($t.id): environment is required." }
    $branch = if ($t.PSObject.Properties['branch'] -and $t.branch) { $t.branch } else { 'main' }

    $sub = Invoke-R360Gh -Arguments @('api', "repos/$($t.repo)/actions/oidc/customization/sub") -AllowFailure
    if (-not $sub -or $sub -is [string]) {
        Write-Warning "Could not read the OIDC subject settings of $($t.repo) (gh needs repo admin). Subjects below assume the name form."
        $prefix = "repo:$($t.repo)"
    }
    elseif (-not $sub.use_default) { throw "$($t.repo) uses a custom OIDC subject template; the Deployments lane supports the default template only." }
    else { $prefix = if ($sub.PSObject.Properties['sub_claim_prefix'] -and $sub.sub_claim_prefix) { $sub.sub_claim_prefix } else { "repo:$($t.repo)" } }

    $wf = Invoke-R360Gh -Arguments @('api', "repos/$($t.repo)/actions/workflows/$($t.workflow)") -AllowFailure
    if (-not $wf -or $wf -is [string]) { Write-Warning "Workflow $($t.workflow) was not found in $($t.repo) yet. r360 will show an empty run list until it exists." }

    Write-R360Step "Target $($t.id) -> $($t.repo) $($t.workflow) (branch $branch, environment $($t.environment))"
    Write-Host "  Plan identity federated credentials:  ${prefix}:pull_request"
    Write-Host "                                        ${prefix}:ref:refs/heads/$branch"
    Write-Host "  Apply identity federated credential:  ${prefix}:environment:$($t.environment)"
}

$compact = $doc | ConvertTo-Json -Depth 10 -Compress
$b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($compact))
Set-R360ContainerAppEnv -Values ([ordered]@{ R360_DEPLOY_TARGETS = $b64 })
if (-not $WhatIfPreference) { Write-R360Step "R360_DEPLOY_TARGETS set ($($targets.Count) target(s)). Open the Deployments page to check them." }
