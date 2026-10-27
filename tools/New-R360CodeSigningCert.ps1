#Requires -Version 7.4
<#
.SYNOPSIS
    Creates the r360 code-signing certificate in Key Vault (RSA-HSM 3072, non-exportable) and trusts it on the canary
    device through Intune: Trusted Root profile + custom OMA-URI TrustedPublisher profile, assigned to sg-remediation-canary.
.DESCRIPTION
    - Self-signed cert, CN=SecTechTalk r360 Code Signing, EKU Code Signing (1.3.6.1.5.5.7.3.3), 36 months. The key cannot be
      exported; signing happens in Key Vault only. r360-ci-signer (GitHub OIDC) gets Crypto User on the key and Certificate
      User on the certificate (public part).
    - Intune profiles are created/updated via Graph beta deviceConfigurations (Invoke-MgGraphRequest), assigned to the canary
      group (existing assignments kept), then DEVICE01 is synced and deviceStatuses is polled until both profiles succeed.
    Idempotent (profile displayName + thumbprint in description). Supports -WhatIf. Logs to C:\path\to\logs.
.EXAMPLE
    ./New-R360CodeSigningCert.ps1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [int]$CertTimeoutMinutes = 10,
    [int]$DeviceTimeoutMinutes = 90,
    [int]$PollSeconds = 60,
    [int]$ResyncMinutes = 15
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'R360.Common.psm1') -Force
$cfg = Get-R360Config
$log = Enable-R360Log -Name 'New-R360CodeSigningCert'
try {
    Write-R360Step "Log: $log"
    & (Join-Path $PSScriptRoot 'Test-R360Prereqs.ps1') -Stage Tools | Out-Null
    $kv = Invoke-R360Az -Arguments @('keyvault', 'show', '-n', $cfg.KeyVault, '-g', $cfg.ResourceGroup) -AllowFailure
    if (-not $kv) {
        if ($WhatIfPreference) { Write-R360Step "WhatIf: Key Vault not created yet; would create cert '$($cfg.CodeSigningCert)' (RSA-HSM 3072, non-exportable), Intune '$($cfg.IntuneRootProfile)' + '$($cfg.IntunePubProfile)', assign to the canary group and wait for $($cfg.CanaryDevice)."; return }
        throw 'Run New-R360Infrastructure.ps1 first.'
    }

    # 1. Certificate
    $cert = Invoke-R360Az -Arguments @('keyvault', 'certificate', 'show', '--vault-name', $cfg.KeyVault, '-n', $cfg.CodeSigningCert) -AllowFailure
    if (-not $cert) {
        $policy = @{
            issuerParameters = @{ name = 'Self' }
            keyProperties = @{ exportable = $false; keyType = 'RSA-HSM'; keySize = 3072; reuseKey = $false }
            secretProperties = @{ contentType = 'application/x-pkcs12' }
            x509CertificateProperties = @{ subject = $cfg.CodeSigningSubject; ekus = @('1.3.6.1.5.5.7.3.3'); keyUsage = @('digitalSignature'); validityInMonths = 36 }
            lifetimeActions = @(@{ trigger = @{ daysBeforeExpiry = 60 }; action = @{ actionType = 'EmailContacts' } })
        }
        if (-not $PSCmdlet.ShouldProcess($cfg.CodeSigningCert, 'Create self-signed code-signing certificate (RSA-HSM 3072, non-exportable)')) {
            Write-R360Step 'WhatIf: Intune profiles depend on the new certificate thumbprint; would create, assign and wait for them next.'
            return
        }
        $pf = Join-Path ([IO.Path]::GetTempPath()) "r360-certpolicy-$PID.json"
        $policy | ConvertTo-Json -Depth 6 | Set-Content $pf -Encoding utf8 -WhatIf:$false
        try { Invoke-R360Az -Arguments @('keyvault', 'certificate', 'create', '--vault-name', $cfg.KeyVault, '-n', $cfg.CodeSigningCert, '--policy', "@$pf", '--tags', 'product=r360') | Out-Null }
        finally { Remove-Item $pf -Force -WhatIf:$false }
        Wait-R360Condition -Activity 'certificate issuance' -TimeoutSeconds ($CertTimeoutMinutes * 60) -IntervalSeconds 10 -Condition {
            $p = Invoke-R360Az -Arguments @('keyvault', 'certificate', 'pending', 'show', '--vault-name', $cfg.KeyVault, '-n', $cfg.CodeSigningCert) -AllowFailure
            if ($p -and $p.status -eq 'failed') { throw "Certificate request failed: $($p.statusDetails)" }
            (-not $p) -or $p.status -eq 'completed' } | Out-Null
        $cert = Invoke-R360Az -Arguments @('keyvault', 'certificate', 'show', '--vault-name', $cfg.KeyVault, '-n', $cfg.CodeSigningCert)
    } else {
        $kp = $cert.policy.keyProperties
        if ($kp.exportable -or $kp.keyType -ne 'RSA-HSM') { throw "Certificate $($cfg.CodeSigningCert) is exportable or not HSM-backed. r360 requires a non-exportable RSA-HSM key." }
        Write-R360Step "Certificate $($cfg.CodeSigningCert) exists"
    }
    $der = [Convert]::FromBase64String($cert.cer)
    $x509 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($der)
    $thumb = $x509.Thumbprint
    $b64 = [Convert]::ToBase64String($der)
    Write-R360Step "Thumbprint $thumb, valid to $($x509.NotAfter.ToString('yyyy-MM-dd'))"

    # 2. CI signer access (key sign, certificate read). No secrets.
    $ci = Invoke-R360Az -Arguments @('ad', 'sp', 'list', '--display-name', $cfg.AppCiSigner, '--query', '[0].id') -AllowFailure
    if ($ci) {
        Set-R360RoleAssignment -PrincipalId $ci -PrincipalType ServicePrincipal -Role 'Key Vault Crypto User' -Scope "$($kv.id)/keys/$($cfg.CodeSigningCert)" -WhatIf:$WhatIfPreference
        Set-R360RoleAssignment -PrincipalId $ci -PrincipalType ServicePrincipal -Role 'Key Vault Certificate User' -Scope "$($kv.id)/certificates/$($cfg.CodeSigningCert)" -WhatIf:$WhatIfPreference
    } else { Write-Warning "$($cfg.AppCiSigner) not found; run New-R360AppRegistration.ps1, then re-run to grant signing access." }

    # 3. Intune profiles (Graph beta, delegated)
    $scopes = @('DeviceManagementConfiguration.ReadWrite.All', 'DeviceManagementManagedDevices.Read.All', 'DeviceManagementManagedDevices.PrivilegedOperations.All')
    if (-not (Connect-R360Graph -Scopes $scopes -NoInteractive:$WhatIfPreference)) {
        Write-R360Step "WhatIf: Graph not connected; would create/assign '$($cfg.IntuneRootProfile)' and '$($cfg.IntunePubProfile)' for thumbprint $thumb."
        return
    }
    $desc = "r360 code signing. thumbprint=$thumb"
    $profiles = @(
        @{ Name = $cfg.IntuneRootProfile; Body = @{ '@odata.type' = '#microsoft.graph.windows81TrustedRootCertificate'; displayName = $cfg.IntuneRootProfile; description = $desc
                certFileName = 'r360-codesign.cer'; trustedRootCertificate = $b64; destinationStore = 'computerCertStoreRoot' } }
        @{ Name = $cfg.IntunePubProfile; Body = @{ '@odata.type' = '#microsoft.graph.windows10CustomConfiguration'; displayName = $cfg.IntunePubProfile; description = $desc
                omaSettings = @(@{ '@odata.type' = '#microsoft.graph.omaSettingBase64'; displayName = 'r360 TrustedPublisher'; fileName = 'r360-codesign.cer'
                        omaUri = "./Device/Vendor/MSFT/RootCATrustedCertificates/TrustedPublisher/$thumb/EncodedCertificate"; value = $b64 }) } }
    )
    $ids = @()
    foreach ($p in $profiles) {
        $existing = @(Invoke-R360Graph -Uri "/beta/deviceManagement/deviceConfigurations?`$filter=displayName eq '$($p.Name)'" -All | ForEach-Object { $_ } | Where-Object { $_ })
        if ($existing.Count -gt 1) { throw "$($existing.Count) Intune profiles are named '$($p.Name)'; remove the duplicate first." }
        if (-not $existing) {
            if (-not $PSCmdlet.ShouldProcess($p.Name, 'Create Intune device configuration')) { continue }
            $id = (Invoke-R360Graph -Method POST -Uri '/beta/deviceManagement/deviceConfigurations' -Body $p.Body).id
        } else {
            $id = $existing[0].id
            if ($existing[0].description -ne $desc) {
                if ($PSCmdlet.ShouldProcess($p.Name, "Update to thumbprint $thumb")) {
                    Invoke-R360Graph -Method PATCH -Uri "/beta/deviceManagement/deviceConfigurations/$id" -Body $p.Body | Out-Null
                }
            } else { Write-R360Step "$($p.Name) is current" }
        }
        $assigned = @(Invoke-R360Graph -Uri "/beta/deviceManagement/deviceConfigurations/$id/assignments" -All | ForEach-Object { $_ } | Where-Object { $_ })
        $targets = @($assigned | ForEach-Object { $_.target } | Where-Object { $_ })
        if (-not ($targets | Where-Object { $_ -and $_.groupId -eq $cfg.CanaryGroupId })) {
            if ($PSCmdlet.ShouldProcess($p.Name, "Assign to canary group $($cfg.CanaryGroupId) (keeping $($targets.Count) existing)")) {
                $all = @($targets) + @(@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $cfg.CanaryGroupId })
                Invoke-R360Graph -Method POST -Uri "/beta/deviceManagement/deviceConfigurations/$id/assign" -Body @{ assignments = @($all | ForEach-Object { @{ target = $_ } }) } | Out-Null
            }
        }
        $ids += $id
    }
    if ($WhatIfPreference -or $ids.Count -ne 2) { Write-R360Step "WhatIf: would sync $($cfg.CanaryDevice) and poll deviceStatuses (timeout $DeviceTimeoutMinutes min)."; return }

    # 4. Sync canary and wait for both profiles to report success
    $dev = @(Invoke-R360Graph -Uri "/v1.0/deviceManagement/managedDevices?`$filter=deviceName eq '$($cfg.CanaryDevice)'&`$select=id,deviceName" -All | ForEach-Object { $_ } | Where-Object { $_ }) | Select-Object -First 1
    if (-not $dev) { throw "$($cfg.CanaryDevice) is not an Intune managed device." }
    $sync = { if ($PSCmdlet.ShouldProcess($cfg.CanaryDevice, 'Intune sync')) { Invoke-R360Graph -Method POST -Uri "/v1.0/deviceManagement/managedDevices/$($dev.id)/syncDevice" | Out-Null } }
    & $sync
    $syncState = @{ Last = Get-Date; EveryMinutes = $ResyncMinutes }
    Wait-R360Condition -Activity "$($cfg.CanaryDevice) to apply both profiles" -TimeoutSeconds ($DeviceTimeoutMinutes * 60) -IntervalSeconds $PollSeconds -Condition {
        if (((Get-Date) - $syncState.Last).TotalMinutes -ge $syncState.EveryMinutes) { & $sync; $syncState.Last = Get-Date }
        $ok = 0
        foreach ($id in $ids) {
            $s = @(Invoke-R360Graph -Uri "/beta/deviceManagement/deviceConfigurations/$id/deviceStatuses" -All | ForEach-Object { $_ } | Where-Object { $_ }) | Where-Object { $_.deviceDisplayName -eq $cfg.CanaryDevice } | Select-Object -First 1
            $state = if ($s) { $s.status } else { 'notReported' }
            if ($state -in 'error', 'conflict') { throw "Profile $id reports '$state' on $($cfg.CanaryDevice)." }
            Write-R360Step "  $id -> $state"
            if ($state -in 'succeeded', 'compliant') { $ok++ }
        }
        $ok -eq $ids.Count
    } | Out-Null
    Write-R360Step "$($cfg.CanaryDevice) trusts $thumb (Root + TrustedPublisher)."
    Write-R360Step 'New-R360CodeSigningCert finished.'
} finally { Disable-R360Log }
