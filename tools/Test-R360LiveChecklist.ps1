#Requires -Version 7.4
<#
.SYNOPSIS
    Read-only end-to-end live checklist for r360 Phase 2. Changes nothing, never signs in.
.DESCRIPTION
    Checks the deployed app, the GitHub side (rulesets, CI and signing on remediations main, open r360 PRs)
    and the Azure side (container app, audit storage). Graph/Intune checks run only if a Graph context
    already exists in this session (delegated); otherwise they report WARN.
.EXAMPLE
    ./Test-R360LiveChecklist.ps1
#>
[CmdletBinding()]
param(
    [string]$RemediationsRepo = 'your-org/remediations',
    [string]$R360Repo = 'sectechtalk/remediation-360'
)
$ErrorActionPreference = 'Stop'
$remRepo = $RemediationsRepo
$r360Repo = $R360Repo
$WhatIfPreference = $false
Import-Module (Join-Path $PSScriptRoot 'R360.Common.psm1') -Force
$results = [System.Collections.Generic.List[object]]::new()
function Add-Check { param($St, $Ck, $Status, $Detail = '') $results.Add((Format-R360Check -Stage $St -Check $Ck -Status $Status -Detail $Detail)) }
function Invoke-Check { param($St, $Ck, [scriptblock]$Body) try { & $Body } catch { Add-Check $St $Ck 'FAIL' $_.Exception.Message } }

# Prerequisites
foreach ($c in 'az', 'gh') { if (-not (Get-Command $c -ErrorAction SilentlyContinue)) { throw "$c is not installed." } }
gh auth status 2>&1 | Out-Null; if ($LASTEXITCODE -ne 0) { throw 'gh is not signed in. Run: gh auth login -h github.com' }
az account show -o none 2>$null; if ($LASTEXITCODE -ne 0) { throw 'az is not signed in. Run: az login' }

# ---------- App ----------
$appId = $null
Invoke-Check App 'Container App' {
    $app = az containerapp show -n app-r360 -g rg-r360 -o json | ConvertFrom-Json
    $t = $app.properties.template
    $s = "$($t.scale.minReplicas)-$($t.scale.maxReplicas)"
    Add-Check App 'Container App scale' $(if ($s -eq '0-1') { 'PASS' } else { 'FAIL' }) $s
    $script:image = $t.containers[0].image
    Add-Check App 'Image' 'INFO' $script:image
    $env = @{}; foreach ($e in $t.containers[0].env) { $env[$e.name] = $e.value }
    $script:appId = $env['R360_GITHUB_APP_ID']
    Add-Check App 'Demo mode off' $(if ($env.Keys -match 'DEMO') { 'FAIL' } else { 'PASS' }) ''
    $fqdn = $app.properties.configuration.ingress.fqdn
    $h = Invoke-RestMethod "https://$fqdn/healthz" -TimeoutSec 90
    $tag = ($script:image -split ':')[-1]
    Add-Check App '/healthz' $(if ($h.ok -and "$($h.image)" -match [regex]::Escape($tag)) { 'PASS' } else { 'FAIL' }) "ok=$($h.ok) image=$($h.image)"
}

# ---------- GitHub ----------
Invoke-Check GitHub 'Rulesets' {
    $rs = @(gh api "repos/$remRepo/rulesets" | ConvertFrom-Json | ForEach-Object { $_ })
    $prot = $rs | Where-Object name -eq 'main-protection'
    $only = $rs | Where-Object name -eq 'r360-app-only-merge'
    if ($prot) {
        $p = gh api "repos/$remRepo/rulesets/$($prot.id)" | ConvertFrom-Json
        $chk = ($p.rules | Where-Object type -eq 'required_status_checks').parameters.required_status_checks.context
        Add-Check GitHub 'main-protection' $(if ($p.enforcement -eq 'active' -and $chk -and $p.bypass_actors.Count -eq 0) { 'PASS' } else { 'FAIL' }) "id=$($p.id) checks=$($chk -join ',') bypass=$($p.bypass_actors.Count)"
    } else { Add-Check GitHub 'main-protection' 'FAIL' 'missing' }
    if ($only) {
        $o = gh api "repos/$remRepo/rulesets/$($only.id)" | ConvertFrom-Json
        $b = $o.bypass_actors
        $ok = $o.enforcement -eq 'active' -and ($o.rules.type -join ',') -eq 'update' -and $b.Count -eq 1 -and $b[0].actor_type -eq 'Integration' -and
              "$($b[0].actor_id)" -eq "$script:appId" -and $b[0].bypass_mode -eq 'pull_request'
        Add-Check GitHub 'App-only merge rule' $(if ($ok) { 'PASS' } else { 'FAIL' }) "id=$($o.id) bypass=$($b[0].actor_type)/$($b[0].actor_id)/$($b[0].bypass_mode) you=$($o.current_user_can_bypass)"
    } else { Add-Check GitHub 'App-only merge rule' 'FAIL' 'ruleset r360-app-only-merge missing. Run tools/Set-R360RulesetAppOnly.ps1' }
}
Invoke-Check GitHub 'remediations main CI' {
    $sha = gh api "repos/$remRepo/commits/main" --jq .sha
    foreach ($wf in 'psscriptanalyzer.yml', 'sign-and-verify.yml') {
        $r = gh run list -R $remRepo -w $wf -b main -L 1 --json conclusion,headSha,url | ConvertFrom-Json | Select-Object -First 1
        $st = if ($r.conclusion -eq 'success' -and $r.headSha -eq $sha) { 'PASS' } elseif ($r.conclusion -eq 'success') { 'WARN' } else { 'FAIL' }
        Add-Check GitHub "main $wf" $st "$($r.conclusion) $($r.headSha.Substring(0,7)) (main $($sha.Substring(0,7))) $($r.url)"
    }
}
Invoke-Check GitHub 'Open PRs' {
    $open = @(gh pr list -R $remRepo --state open --json number,author,title | ConvertFrom-Json | ForEach-Object { $_ })
    Add-Check GitHub 'Open remediations PRs' 'INFO' "$($open.Count): $(($open | ForEach-Object { "#$($_.number) $($_.author.login)" }) -join '; ')"
    $r = @(gh pr list -R $r360Repo --state open --json number | ConvertFrom-Json | ForEach-Object { $_ })
    Add-Check GitHub 'Open r360 PRs' 'INFO' "$($r.Count)"
}

# ---------- Azure audit ----------
Invoke-Check Audit 'Audit storage' {
    $sa = az storage account list -g rg-r360 -o json | ConvertFrom-Json | Select-Object -First 1
    Add-Check Audit 'Storage account' $(if ($sa -and -not $sa.allowSharedKeyAccess) { 'PASS' } else { 'FAIL' }) "$($sa.name) sharedKey=$($sa.allowSharedKeyAccess)"
}

# ---------- Intune (only with an existing delegated Graph context) ----------
$ctx = if (Get-Command Get-MgContext -ErrorAction SilentlyContinue) { Get-MgContext } else { $null }
if (-not $ctx) { Add-Check Intune 'Graph context' 'WARN' 'Not connected; Intune checks skipped. Connect-MgGraph -Scopes DeviceManagementConfiguration.Read.All first to include them.' }
else {
    Invoke-Check Intune 'Remediations' {
        $r = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts?`$select=id,displayName,enforceSignatureCheck"
        $bad = @($r.value | Where-Object { $_.displayName -like 'Stt-*' -and -not $_.enforceSignatureCheck })
        Add-Check Intune 'deviceHealthScripts' $(if ($bad) { 'FAIL' } else { 'PASS' }) "$(@($r.value).Count) scripts; unsigned Stt-*: $($bad.Count)"
    }
}

$results | Format-Table -AutoSize -Wrap
$f = @($results | Where-Object Status -eq 'FAIL')
"Summary: " + (($results | Group-Object Status | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join '  ')
if ($f) { throw "$($f.Count) live check(s) failed: $(($f.Check) -join '; ')" }
