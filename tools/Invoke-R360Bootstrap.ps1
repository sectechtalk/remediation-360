#Requires -Version 7.4
<#
.SYNOPSIS
    Runs the r360 Phase 0 bootstrap end to end, in order, stopping on the first failure.
.DESCRIPTION
    Steps: Repo (gh repo create sectechtalk/remediation-360, private, push) -> Infrastructure -> AppRegistration -> GitHubApp -> CodeSigning.
    Prereqs run before the first step and again after each step (-RequireDeployed, so anything missing fails).
    Under -WhatIf nothing is changed, Graph is not signed in, and post-step deployment checks are skipped.
    Re-running is safe: every step checks before it creates.
    Not part of Phase 0 (deferred, gated): the App-only merge ruleset on remediations main.
.EXAMPLE
    ./Invoke-R360Bootstrap.ps1 -WhatIf
.EXAMPLE
    ./Invoke-R360Bootstrap.ps1
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateSet('Repo', 'Infrastructure', 'AppRegistration', 'GitHubApp', 'CodeSigning')][string[]]$Steps = @('Repo', 'Infrastructure', 'AppRegistration', 'GitHubApp', 'CodeSigning'),
    [switch]$SkipMainRuleset
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'R360.Common.psm1') -Force
$cfg = Get-R360Config
$log = Enable-R360Log -Name 'Invoke-R360Bootstrap'
$prereq = Join-Path $PSScriptRoot 'Test-R360Prereqs.ps1'
$addRuleset = -not $SkipMainRuleset.IsPresent
try {
    Write-R360Step "Log: $log  WhatIf=$([bool]$WhatIfPreference)  Steps=$($Steps -join ', ')"
    & $prereq -Stage Tools

    # One delegated Graph sign-in for the whole run (skipped under -WhatIf).
    if (($Steps | Where-Object { $_ -in 'AppRegistration', 'CodeSigning' }) -and -not $WhatIfPreference) {
        Connect-R360Graph -Scopes $cfg.BootstrapGraphScopes | Out-Null
    }

    $repoFull = "$($cfg.GitHubOrg)/$($cfg.ProductRepo)"
    $plan = [ordered]@{
        Repo            = {
            $exists = Invoke-R360Gh -Arguments @('repo', 'view', $repoFull, '--json', 'name') -AllowFailure
            if ($exists) { Write-R360Step "$repoFull exists" }
            elseif ($PSCmdlet.ShouldProcess($repoFull, "gh repo create --private --source $($cfg.RepoRoot) --push")) {
                $dirty = git -C $cfg.RepoRoot status --porcelain
                if ($dirty) { throw "Uncommitted changes in $($cfg.RepoRoot); commit them first." }
                Invoke-R360Gh -Arguments @('repo', 'create', $repoFull, '--private', '--source', $cfg.RepoRoot, '--remote', 'origin', '--push',
                    '--description', 'r360 - Remediation 360 (standalone)') | Out-Null
                Wait-R360Condition -Activity "$repoFull visible" -TimeoutSeconds 120 -IntervalSeconds 5 -Condition {
                    Invoke-R360Gh -Arguments @('repo', 'view', $repoFull, '--json', 'name') -AllowFailure } | Out-Null
            }
            if ($addRuleset) {
                $rs = if (-not $WhatIfPreference -or $exists) { @(Invoke-R360Gh -Arguments @('api', "repos/$repoFull/rulesets") -AllowFailure) } else { @() }
                if (-not ($rs | Where-Object { $_.name -eq 'main-protection' }) -and $PSCmdlet.ShouldProcess($repoFull, 'Add ruleset main-protection (PR + CODEOWNERS review, no force-push/delete)')) {
                    $body = @{ name = 'main-protection'; target = 'branch'; enforcement = 'active'
                        conditions = @{ ref_name = @{ include = @('~DEFAULT_BRANCH'); exclude = @() } }
                        rules = @(@{ type = 'deletion' }, @{ type = 'non_fast_forward' },
                            @{ type = 'pull_request'; parameters = @{ required_approving_review_count = 0; require_code_owner_review = $true; dismiss_stale_reviews_on_push = $true; require_last_push_approval = $false; required_review_thread_resolution = $false } }) }
                    $f = New-TemporaryFile -WhatIf:$false
                    try { $body | ConvertTo-Json -Depth 8 | Set-Content $f -Encoding utf8 -WhatIf:$false; Invoke-R360Gh -Arguments @('api', '-X', 'POST', "repos/$repoFull/rulesets", '--input', $f.FullName) | Out-Null }
                    finally { Remove-Item $f -Force -WhatIf:$false }
                }
            }
        }
        Infrastructure  = { & (Join-Path $PSScriptRoot 'New-R360Infrastructure.ps1') -WhatIf:$WhatIfPreference -Confirm:$false }
        AppRegistration = { & (Join-Path $PSScriptRoot 'New-R360AppRegistration.ps1') -WhatIf:$WhatIfPreference -Confirm:$false }
        GitHubApp       = { & (Join-Path $PSScriptRoot 'New-R360GitHubApp.ps1') -WhatIf:$WhatIfPreference -Confirm:$false }
        CodeSigning     = { & (Join-Path $PSScriptRoot 'New-R360CodeSigningCert.ps1') -WhatIf:$WhatIfPreference -Confirm:$false }
    }
    $i = 0
    foreach ($name in $plan.Keys | Where-Object { $_ -in $Steps }) {
        $i++
        Write-R360Step "===== Step $i/$($Steps.Count): $name ====="
        try { & $plan[$name] } catch { throw "Step '$name' failed: $($_.Exception.Message)" }
        if ($WhatIfPreference) { Write-R360Step "WhatIf: skipping post-step prereq check for $name (resources are not created under -WhatIf)." }
        else { & $prereq -Stage $name -RequireDeployed }
    }
    if (-not $WhatIfPreference) { & $prereq -Stage All -RequireDeployed }
    Write-R360Step 'Manual, not scripted: Defender live response settings + role (portal), CA auth context c1, PIM. Deferred: App-only merge rule on remediations main.'
    Write-R360Step "Bootstrap finished. Log: $log"
} finally { Disable-R360Log }
