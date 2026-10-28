#Requires -Version 7.4
<#
.SYNOPSIS
    Configures everything outside the repo that the remediations "Sign and Verify" workflow needs (idempotent, -WhatIf safe).
.DESCRIPTION
    For the Entra app r360-ci-signer (GitHub Actions OIDC, no secret):
      1. Prereq checks (read-only): PowerShell 7.4+, az and gh signed in to the right tenant/account, app + service principal,
         Key Vault in RBAC mode, key and certificate r360-codesign present (and the thumbprint, if -ExpectedThumbprint is given).
      2. Federated credential `github-remediations-main`: issuer GitHub, audience api://AzureADTokenExchange, subject = the
         `sub` GitHub really issues for refs/heads/main of your-org/remediations (immutable form for repos created after
         2026-07-15: repo:OWNER@OWNER_ID/REPO@REPO_ID:ref:refs/heads/main). Created or corrected; extra credentials are
         reported, never deleted.
      3. Key Vault RBAC, least privilege, scoped to the single key and the single certificate (not the vault):
         Key Vault Crypto User on keys/r360-codesign and Key Vault Certificate User on certificates/r360-codesign.
         Other role assignments of the service principal are reported, never removed.
      4. The three non-secret repo variables in your-org/remediations: R360_CI_CLIENT_ID, R360_TENANT_ID, R360_KEYVAULT.
         Existing repo secrets are listed and flagged (the workflow needs none).
      5. Read-back of every item with PASS/FAIL.
    Nothing here creates a secret, certificate or password. az is used for Entra/RBAC so no extra Graph consent is needed.
.EXAMPLE
    ./Set-R360CiSigningConfig.ps1 -WhatIf
.EXAMPLE
    ./Set-R360CiSigningConfig.ps1 -ExpectedThumbprint 00000000000000000000000000000000000000F1
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [ValidatePattern('^[0-9A-Fa-f]{40}$')][string]$ExpectedThumbprint,
    [string]$Branch = 'main'
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'R360.Common.psm1') -Force
$cfg = Get-R360Config
$log = Enable-R360Log -Name 'Set-R360CiSigningConfig'
$results = [System.Collections.Generic.List[object]]::new()
function Add-Check { param($Check, $Status, $Detail = '') $results.Add((Format-R360Check -Stage 'CiSigning' -Check $Check -Status $Status -Detail $Detail)) }
$repo = "$($cfg.GitHubOrg)/$($cfg.RemediationsRepo)"
$ficName = 'github-remediations-main'
try {
    Write-R360Step "Log: $log"

    # ---------- 1. Prereqs (read-only) ----------
    Add-Check 'PowerShell 7.4+' $(if ($PSVersionTable.PSVersion -ge [version]'7.4') { 'PASS' } else { 'FAIL' }) "$($PSVersionTable.PSVersion)"
    foreach ($t in 'az', 'gh') { Add-Check "CLI $t" $(if (Get-Command $t -ErrorAction SilentlyContinue) { 'PASS' } else { 'FAIL' }) }
    if ($results.Status -contains 'FAIL') { throw 'Missing tools; install them and re-run.' }
    $acct = Invoke-R360Az -Arguments @('account', 'show') -AllowFailure
    if (-not $acct) { throw 'az is not signed in: run az login.' }
    if ($acct.tenantId -ne $cfg.TenantId) { throw "az is signed in to tenant $($acct.tenantId), expected $($cfg.TenantId)." }
    Add-Check 'az tenant' 'PASS' "$($acct.user.name) @ $($acct.tenantId)"
    $ghUser = Invoke-R360Gh -Arguments @('api', 'user', '--jq', '.login') -AllowFailure
    if (-not $ghUser) { throw 'gh is not signed in: run gh auth login.' }
    $perm = Invoke-R360Gh -Arguments @('api', "repos/$repo", '--jq', '.permissions.admin') -AllowFailure
    Add-Check 'gh admin on repo' $(if ("$perm" -eq 'True' -or $perm -eq $true) { 'PASS' } else { 'FAIL' }) "$ghUser on $repo (repo variables need admin)"

    $app = @(Invoke-R360Az -Arguments @('ad', 'app', 'list', '--display-name', $cfg.AppCiSigner))
    if ($app.Count -ne 1) { throw "Expected exactly one app named $($cfg.AppCiSigner), found $($app.Count). Run New-R360AppRegistration.ps1." }
    $app = $app[0]
    $sp = Invoke-R360Az -Arguments @('ad', 'sp', 'show', '--id', $app.appId)
    Add-Check 'r360-ci-signer app + service principal' 'PASS' "appId $($app.appId), SP $($sp.id)"
    $kv = Invoke-R360Az -Arguments @('keyvault', 'show', '-n', $cfg.KeyVault)
    Add-Check 'Key Vault uses RBAC' $(if ($kv.properties.enableRbacAuthorization) { 'PASS' } else { 'FAIL' }) $cfg.KeyVault
    $key = Invoke-R360Az -Arguments @('keyvault', 'key', 'show', '--vault-name', $cfg.KeyVault, '--name', $cfg.CodeSigningCert)
    $ops = (@($key.key.keyOps) | Sort-Object) -join ','
    Add-Check 'Key is HSM, non-exportable, sign/verify only' $(if ($key.key.kty -eq 'RSA-HSM' -and $ops -eq 'sign,verify') { 'PASS' } else { 'FAIL' }) "$($key.key.kty), ops=$ops"
    $crt = Invoke-R360Az -Arguments @('keyvault', 'certificate', 'show', '--vault-name', $cfg.KeyVault, '--name', $cfg.CodeSigningCert)
    $thumb = "$($crt.x509ThumbprintHex)".ToUpperInvariant()
    $thumbOk = (-not $ExpectedThumbprint) -or ($thumb -eq $ExpectedThumbprint.ToUpperInvariant())
    Add-Check 'Certificate thumbprint' $(if ($thumbOk) { 'PASS' } else { 'FAIL' }) "$thumb (workflow pins CODESIGN_THUMBPRINT; they must match)"
    if ($results.Status -contains 'FAIL') { throw 'Prerequisite checks failed (see table); nothing was changed.' }

    # ---------- 2. Federated credential ----------
    $subject = Get-R360GitHubOidcSubject -Branch $Branch
    $issuer = 'https://token.actions.githubusercontent.com'
    Write-R360Step "Token subject GitHub issues for $repo@$Branch : $subject"
    $fics = @(Invoke-R360Az -Arguments @('ad', 'app', 'federated-credential', 'list', '--id', $app.id))
    $fic = $fics | Where-Object name -EQ $ficName | Select-Object -First 1
    $want = [ordered]@{ name = $ficName; issuer = $issuer; subject = $subject; audiences = @($cfg.FicAudience); description = "GitHub Actions $repo $Branch (r360 CI signing, OIDC)" }
    $tmp = Get-Item -LiteralPath ([IO.Path]::GetTempFileName())
    try {
        Set-Content -Path $tmp.FullName -Value ($want | ConvertTo-Json -Compress) -Encoding utf8NoBOM -WhatIf:$false
        if (-not $fic) {
            if ($PSCmdlet.ShouldProcess($cfg.AppCiSigner, "Create federated credential $subject")) {
                Invoke-R360Az -Arguments @('ad', 'app', 'federated-credential', 'create', '--id', $app.id, '--parameters', $tmp.FullName) | Out-Null
            }
        } elseif ($fic.issuer -ne $issuer -or $fic.subject -ne $subject -or (@($fic.audiences) -join ',') -ne $cfg.FicAudience) {
            if ($PSCmdlet.ShouldProcess($cfg.AppCiSigner, "Update federated credential '$ficName' subject '$($fic.subject)' -> '$subject'")) {
                Invoke-R360Az -Arguments @('ad', 'app', 'federated-credential', 'update', '--id', $app.id, '--federated-credential-id', $fic.id, '--parameters', $tmp.FullName) | Out-Null
            }
        } else { Write-R360Step "Federated credential '$ficName' already current" }
    } finally { Remove-Item $tmp.FullName -Force -ErrorAction SilentlyContinue -WhatIf:$false }

    # ---------- 3. Key Vault RBAC: one key, one certificate ----------
    Set-R360RoleAssignment -PrincipalId $sp.id -PrincipalType ServicePrincipal -Role 'Key Vault Crypto User' -Scope "$($kv.id)/keys/$($cfg.CodeSigningCert)" -WhatIf:$WhatIfPreference
    Set-R360RoleAssignment -PrincipalId $sp.id -PrincipalType ServicePrincipal -Role 'Key Vault Certificate User' -Scope "$($kv.id)/certificates/$($cfg.CodeSigningCert)" -WhatIf:$WhatIfPreference

    # ---------- 4. Repo variables (non-secret) ----------
    $vars = [ordered]@{ R360_CI_CLIENT_ID = $app.appId; R360_TENANT_ID = $cfg.TenantId; R360_KEYVAULT = $cfg.KeyVault }
    $have = @{}
    foreach ($v in @(Invoke-R360Gh -Arguments @('api', "repos/$repo/actions/variables", '--jq', '.variables')) | Where-Object { $_ -and $_ -isnot [string] }) { $have[$v.name] = $v.value }
    foreach ($name in $vars.Keys) {
        if ($have[$name] -eq $vars[$name]) { Write-R360Step "Repo variable $name already current"; continue }
        if ($PSCmdlet.ShouldProcess($repo, "Set repo variable $name = $($vars[$name])")) {
            Invoke-R360Gh -Arguments @('variable', 'set', $name, '--repo', $repo, '--body', $vars[$name]) | Out-Null
        }
    }

    # ---------- 5. Read-back ----------
    if ($WhatIfPreference) { Write-R360Step 'WhatIf: nothing was changed; the table below is the CURRENT state.' }
    $fics = @(Invoke-R360Az -Arguments @('ad', 'app', 'federated-credential', 'list', '--id', $app.id))
    $f = $fics | Where-Object name -EQ $ficName | Select-Object -First 1
    Add-Check "Federated credential $ficName" $(if ($f -and $f.subject -eq $subject -and $f.issuer -eq $issuer) { 'PASS' } elseif ($WhatIfPreference) { 'WARN' } else { 'FAIL' }) $(if ($f) { $f.subject } else { 'absent' })
    foreach ($x in $fics | Where-Object name -NE $ficName) { Add-Check "Extra federated credential $($x.name)" 'WARN' "$($x.subject) (not removed; review)" }
    $ras = @(Invoke-R360Az -Arguments @('role', 'assignment', 'list', '--assignee', $sp.id, '--all'))
    $expected = @{ "Key Vault Crypto User|$($kv.id)/keys/$($cfg.CodeSigningCert)".ToLowerInvariant() = $true; "Key Vault Certificate User|$($kv.id)/certificates/$($cfg.CodeSigningCert)".ToLowerInvariant() = $true }
    foreach ($e in $expected.Keys) {
        $role, $scope = $e -split '\|', 2
        $ok = @($ras | Where-Object { $_.roleDefinitionName.ToLowerInvariant() -eq $role -and $_.scope.ToLowerInvariant() -eq $scope }).Count -gt 0
        Add-Check "RBAC $role" $(if ($ok) { 'PASS' } else { $(if ($WhatIfPreference) { 'MISSING' } else { 'FAIL' }) }) $scope
    }
    foreach ($r in $ras | Where-Object { -not $expected.ContainsKey("$($_.roleDefinitionName)|$($_.scope)".ToLowerInvariant()) }) { Add-Check "Extra RBAC $($r.roleDefinitionName)" 'WARN' "$($r.scope) (not removed; r360-ci-signer should only sign)" }
    $now = @{}
    foreach ($v in @(Invoke-R360Gh -Arguments @('api', "repos/$repo/actions/variables", '--jq', '.variables')) | Where-Object { $_ -and $_ -isnot [string] }) { $now[$v.name] = $v.value }
    foreach ($name in $vars.Keys) { Add-Check "Repo variable $name" $(if ($now[$name] -eq $vars[$name]) { 'PASS' } else { $(if ($WhatIfPreference) { 'MISSING' } else { 'FAIL' }) }) $vars[$name] }
    $secrets = @(Invoke-R360Gh -Arguments @('api', "repos/$repo/actions/secrets", '--jq', '.secrets') -AllowFailure | Where-Object { $_ -and $_ -isnot [string] })
    Add-Check 'Repo secrets (workflow needs none)' $(if ($secrets.Count) { 'WARN' } else { 'PASS' }) $(if ($secrets.Count) { ($secrets.name -join ', ') } else { 'none' })

    $results | Format-Table -AutoSize -Wrap | Out-String -Width 250 | Write-Host
    if (-not $WhatIfPreference -and ($results.Status -contains 'FAIL')) { throw 'One or more read-back checks FAILED.' }
} finally { Disable-R360Log }
