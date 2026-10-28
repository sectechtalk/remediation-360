#Requires -Version 7.4
<#
.SYNOPSIS
    Creates the r360 Azure footprint (idempotent): rg-r360, id-r360, Premium Key Vault (RBAC, purge protection),
    audit storage (append-only table + immutable export container), cae-r360 / app-r360 (scale 0-1).
.DESCRIPTION
    Check-then-create for every resource. Supports -WhatIf. Uses az CLI with your delegated sign-in; no secrets.
    All waits are polling loops with timeouts. Logs to C:\path\to\logs.
    Note: Key Vault purge protection cannot be turned off later (intended).
.EXAMPLE
    ./New-R360Infrastructure.ps1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param([int]$TimeoutMinutes = 20)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'R360.Common.psm1') -Force
$cfg = Get-R360Config
$log = Enable-R360Log -Name 'New-R360Infrastructure'
try {
    Write-R360Step "Log: $log"
    & (Join-Path $PSScriptRoot 'Test-R360Prereqs.ps1') -Stage Tools | Out-Null
    $timeout = $TimeoutMinutes * 60
    $sub = Invoke-R360Az -Arguments @('account', 'show')
    $me = Invoke-R360Az -Arguments @('ad', 'signed-in-user', 'show', '--query', '{id:id,upn:userPrincipalName}')
    Write-R360Step "Subscription '$($sub.name)' ($($sub.id)) as $($me.upn)"
    $rgScope = "/subscriptions/$($sub.id)/resourceGroups/$($cfg.ResourceGroup)"

    # Resource providers
    foreach ($ns in 'Microsoft.App', 'Microsoft.KeyVault', 'Microsoft.Storage', 'Microsoft.ManagedIdentity') {
        $st = Invoke-R360Az -Arguments @('provider', 'show', '-n', $ns, '--query', 'registrationState')
        if ($st -eq 'Registered') { continue }
        if ($PSCmdlet.ShouldProcess($ns, 'Register resource provider')) {
            Invoke-R360Az -Arguments @('provider', 'register', '-n', $ns) | Out-Null
            Wait-R360Condition -Activity "$ns registration" -TimeoutSeconds $timeout -IntervalSeconds 15 -Condition {
                (Invoke-R360Az -Arguments @('provider', 'show', '-n', $ns, '--query', 'registrationState')) -eq 'Registered' } | Out-Null
        }
    }

    # Resource group
    if (-not (Invoke-R360Az -Arguments @('group', 'exists', '-n', $cfg.ResourceGroup))) {
        if ($PSCmdlet.ShouldProcess($cfg.ResourceGroup, "Create resource group in $($cfg.Location)")) {
            Invoke-R360Az -Arguments @('group', 'create', '-n', $cfg.ResourceGroup, '-l', $cfg.Location, '--tags', 'product=r360') | Out-Null
        }
    } else { Write-R360Step "Resource group $($cfg.ResourceGroup) exists" }
    $rgReady = [bool](Invoke-R360Az -Arguments @('group', 'exists', '-n', $cfg.ResourceGroup))
    if (-not $rgReady) { Write-R360Step 'WhatIf: everything below would be created in the new resource group.' ; return }

    # User-assigned managed identity
    $mi = Invoke-R360Az -Arguments @('identity', 'show', '-n', $cfg.Identity, '-g', $cfg.ResourceGroup) -AllowFailure
    if (-not $mi -and $PSCmdlet.ShouldProcess($cfg.Identity, 'Create user-assigned managed identity')) {
        $mi = Invoke-R360Az -Arguments @('identity', 'create', '-n', $cfg.Identity, '-g', $cfg.ResourceGroup, '-l', $cfg.Location, '--tags', 'product=r360')
        Wait-R360Condition -Activity 'managed identity in Entra' -TimeoutSeconds $timeout -Condition {
            Invoke-R360Az -Arguments @('ad', 'sp', 'show', '--id', $mi.clientId) -AllowFailure } | Out-Null
    } elseif ($mi) { Write-R360Step "Managed identity $($cfg.Identity) exists (principalId $($mi.principalId))" }

    # Key Vault (Premium for HSM keys, RBAC, purge protection)
    $kv = Invoke-R360Az -Arguments @('keyvault', 'show', '-n', $cfg.KeyVault, '-g', $cfg.ResourceGroup) -AllowFailure
    if (-not $kv) {
        $deleted = Invoke-R360Az -Arguments @('keyvault', 'show-deleted', '-n', $cfg.KeyVault) -AllowFailure
        if ($deleted) { throw "Key Vault $($cfg.KeyVault) is soft-deleted. Recover it (az keyvault recover -n $($cfg.KeyVault)) and re-run." }
        if ($PSCmdlet.ShouldProcess($cfg.KeyVault, 'Create Premium Key Vault (RBAC, purge protection)')) {
            $kv = Invoke-R360Az -Arguments @('keyvault', 'create', '-n', $cfg.KeyVault, '-g', $cfg.ResourceGroup, '-l', $cfg.Location, '--sku', 'premium',
                '--enable-rbac-authorization', 'true', '--enable-purge-protection', 'true', '--retention-days', '90', '--tags', 'product=r360')
        }
    } else {
        Write-R360Step "Key Vault $($cfg.KeyVault) exists"
        $p = $kv.properties
        if ($p.sku.name -ne 'premium' -or -not $p.enableRbacAuthorization -or -not $p.enablePurgeProtection) { throw "Key Vault $($cfg.KeyVault) is not Premium+RBAC+purge protection; fix before continuing." }
    }
    if ($kv) {
        foreach ($role in 'Key Vault Crypto Officer', 'Key Vault Certificates Officer') {
            Set-R360RoleAssignment -PrincipalId $me.id -PrincipalType User -Role $role -Scope $kv.id -WhatIf:$WhatIfPreference
        }
        if (-not $WhatIfPreference) {
            Wait-R360Condition -Activity 'Key Vault data-plane RBAC propagation' -TimeoutSeconds $timeout -IntervalSeconds 15 -Condition {
                Test-R360KvDataPlane -VaultName $cfg.KeyVault } | Out-Null
        }
    }

    # Audit storage: no shared keys, no public blobs, TLS 1.2
    $st = Invoke-R360Az -Arguments @('storage', 'account', 'show', '-n', $cfg.Storage, '-g', $cfg.ResourceGroup) -AllowFailure
    if (-not $st -and $PSCmdlet.ShouldProcess($cfg.Storage, 'Create storage account (Standard_LRS, shared key off)')) {
        $st = Invoke-R360Az -Arguments @('storage', 'account', 'create', '-n', $cfg.Storage, '-g', $cfg.ResourceGroup, '-l', $cfg.Location, '--sku', 'Standard_LRS',
            '--kind', 'StorageV2', '--min-tls-version', 'TLS1_2', '--allow-blob-public-access', 'false', '--allow-shared-key-access', 'false', '--https-only', 'true', '--tags', 'product=r360')
    } elseif ($st) { Write-R360Step "Storage $($cfg.Storage) exists" }
    if ($st) {
        $tblUrl = "https://management.azure.com$($st.id)/tableServices/default/tables/$($cfg.AuditTable)?api-version=2023-05-01"
        if (-not (Invoke-R360Az -Arguments @('rest', '--method', 'get', '--url', $tblUrl) -AllowFailure) -and $PSCmdlet.ShouldProcess($cfg.AuditTable, 'Create audit table')) {
            Invoke-R360Az -Arguments @('rest', '--method', 'put', '--url', $tblUrl, '--body', '{}') | Out-Null
        }
        if (-not (Invoke-R360Az -Arguments @('storage', 'container-rm', 'show', '--storage-account', $cfg.Storage, '-g', $cfg.ResourceGroup, '-n', $cfg.AuditExportContainer) -AllowFailure) -and
            $PSCmdlet.ShouldProcess($cfg.AuditExportContainer, 'Create private export container')) {
            Invoke-R360Az -Arguments @('storage', 'container-rm', 'create', '--storage-account', $cfg.Storage, '-g', $cfg.ResourceGroup, '-n', $cfg.AuditExportContainer, '--public-access', 'off') | Out-Null
        }
        $imm = Invoke-R360Az -Arguments @('storage', 'container', 'immutability-policy', 'show', '--account-name', $cfg.Storage, '-g', $cfg.ResourceGroup, '--container-name', $cfg.AuditExportContainer) -AllowFailure
        $hasImm = $imm -and $imm.PSObject.Properties['immutabilityPeriodSinceCreationInDays'] -and $imm.immutabilityPeriodSinceCreationInDays -ge 365
        # Unlocked time-based retention (365 days). Locking is irreversible and is left as a separate decision.
        if (-not $hasImm -and $PSCmdlet.ShouldProcess($cfg.AuditExportContainer, 'Set 365-day immutability policy (unlocked)')) {
            Invoke-R360Az -Arguments @('storage', 'container', 'immutability-policy', 'create', '--account-name', $cfg.Storage, '-g', $cfg.ResourceGroup, '--container-name', $cfg.AuditExportContainer, '--period', '365') | Out-Null
        }
    }

    # Custom role: audit read + append only
    $roleExists = @(Invoke-R360Az -Arguments @('role', 'definition', 'list', '--custom-role-only', 'true', '--name', $cfg.AuditRoleName)).Count -gt 0
    if (-not $roleExists -and $PSCmdlet.ShouldProcess($cfg.AuditRoleName, 'Create custom role (table entities read + add; no update/delete)')) {
        $def = @{
            Name = $cfg.AuditRoleName; IsCustom = $true; Description = 'r360 audit: read and append table entities only. No update or delete.'
            Actions = @(); NotActions = @()
            DataActions = @('Microsoft.Storage/storageAccounts/tableServices/tables/entities/read', 'Microsoft.Storage/storageAccounts/tableServices/tables/entities/add/action')
            NotDataActions = @(); AssignableScopes = @($rgScope)
        }
        $f = Join-Path ([IO.Path]::GetTempPath()) "r360-role-$PID.json"
        $def | ConvertTo-Json -Depth 5 | Set-Content $f -Encoding utf8 -WhatIf:$false
        try { Invoke-R360Az -Arguments @('role', 'definition', 'create', '--role-definition', "@$f") | Out-Null } finally { Remove-Item $f -Force -WhatIf:$false }
        Wait-R360Condition -Activity 'custom role propagation' -TimeoutSeconds $timeout -IntervalSeconds 15 -Condition {
            @(Invoke-R360Az -Arguments @('role', 'definition', 'list', '--custom-role-only', 'true', '--name', $cfg.AuditRoleName)).Count -gt 0 } | Out-Null
        $roleExists = $true
    }
    if ($mi -and $st -and $roleExists) {
        Set-R360RoleAssignment -PrincipalId $mi.principalId -PrincipalType ServicePrincipal -Role $cfg.AuditRoleName -Scope "$($st.id)/tableServices/default/tables/$($cfg.AuditTable)" -WhatIf:$WhatIfPreference
    }
    # Phase 2: one immutable blob per audit event. Scoped to the export container only. The container's 365-day retention policy
    # (not this role) is what stops an existing blob being overwritten or deleted.
    if ($mi -and $st) {
        Set-R360RoleAssignment -PrincipalId $mi.principalId -PrincipalType ServicePrincipal -Role 'Storage Blob Data Contributor' -Scope "$($st.id)/blobServices/default/containers/$($cfg.AuditExportContainer)" -WhatIf:$WhatIfPreference
    }

    # Container Apps environment + app (scale 0-1, user-assigned identity, placeholder image until Phase 1)
    $cae = Invoke-R360Az -Arguments @('containerapp', 'env', 'show', '-n', $cfg.ContainerEnv, '-g', $cfg.ResourceGroup) -AllowFailure
    if (-not $cae -and $PSCmdlet.ShouldProcess($cfg.ContainerEnv, 'Create Container Apps environment (no Log Analytics)')) {
        Invoke-R360Az -Arguments @('containerapp', 'env', 'create', '-n', $cfg.ContainerEnv, '-g', $cfg.ResourceGroup, '-l', $cfg.Location, '--logs-destination', 'none', '--tags', 'product=r360') | Out-Null
        $cae = Wait-R360Condition -Activity "$($cfg.ContainerEnv) provisioning" -TimeoutSeconds $timeout -IntervalSeconds 15 -Condition {
            $e = Invoke-R360Az -Arguments @('containerapp', 'env', 'show', '-n', $cfg.ContainerEnv, '-g', $cfg.ResourceGroup) -AllowFailure
            if ($e -and $e.properties.provisioningState -eq 'Failed') { throw "$($cfg.ContainerEnv) provisioning failed" }
            if ($e -and $e.properties.provisioningState -eq 'Succeeded') { $e } }
    }
    $settings = [ordered]@{}
    foreach ($k in $cfg.AppSettings.Keys) { $settings[$k] = $cfg.AppSettings[$k] }
    if ($mi) { $settings['AZURE_CLIENT_ID'] = $mi.clientId }
    $app = Invoke-R360Az -Arguments @('containerapp', 'show', '-n', $cfg.ContainerApp, '-g', $cfg.ResourceGroup) -AllowFailure
    if (-not $app -and $cae -and $mi -and $PSCmdlet.ShouldProcess($cfg.ContainerApp, 'Create Container App (scale 0-1, external ingress, placeholder image)')) {
        $envArgs = @($settings.Keys | ForEach-Object { "$_=$($settings[$_])" })
        Invoke-R360Az -Arguments (@('containerapp', 'create', '-n', $cfg.ContainerApp, '-g', $cfg.ResourceGroup, '--environment', $cfg.ContainerEnv,
                '--image', $cfg.PlaceholderImage, '--target-port', '80', '--ingress', 'external', '--min-replicas', '0', '--max-replicas', '1',
                '--user-assigned', $mi.id, '--tags', 'product=r360', '--env-vars') + $envArgs) | Out-Null
    } elseif ($app) {
        Write-R360Step "Container App $($cfg.ContainerApp) exists"
        $sc = $app.properties.template.scale
        if (($sc.minReplicas -ne 0 -or $sc.maxReplicas -ne 1) -and $PSCmdlet.ShouldProcess($cfg.ContainerApp, 'Set scale 0-1')) {
            Invoke-R360Az -Arguments @('containerapp', 'update', '-n', $cfg.ContainerApp, '-g', $cfg.ResourceGroup, '--min-replicas', '0', '--max-replicas', '1') | Out-Null
        }
        $ids = if ($app.identity -and $app.identity.PSObject.Properties['userAssignedIdentities'] -and $app.identity.userAssignedIdentities) { @($app.identity.userAssignedIdentities.PSObject.Properties.Name) } else { @() }
        if ($mi -and $ids -notcontains $mi.id -and $PSCmdlet.ShouldProcess($cfg.ContainerApp, "Attach $($cfg.Identity)")) {
            Invoke-R360Az -Arguments @('containerapp', 'identity', 'assign', '-n', $cfg.ContainerApp, '-g', $cfg.ResourceGroup, '--user-assigned', $mi.id) | Out-Null
        }
        Set-R360ContainerAppEnv -Values $settings -WhatIf:$WhatIfPreference
    }
    if (-not $WhatIfPreference -and (Invoke-R360Az -Arguments @('containerapp', 'show', '-n', $cfg.ContainerApp, '-g', $cfg.ResourceGroup) -AllowFailure)) {
        $app = Wait-R360Condition -Activity "$($cfg.ContainerApp) provisioning" -TimeoutSeconds $timeout -IntervalSeconds 15 -Condition {
            $a = Invoke-R360Az -Arguments @('containerapp', 'show', '-n', $cfg.ContainerApp, '-g', $cfg.ResourceGroup)
            if ($a.properties.provisioningState -eq 'Failed') { throw "$($cfg.ContainerApp) provisioning failed" }
            if ($a.properties.provisioningState -eq 'Succeeded') { $a } }
        Write-R360Step "Container App URL: https://$($app.properties.configuration.ingress.fqdn)"
    }
    Write-R360Step 'New-R360Infrastructure finished.'
} finally { Disable-R360Log }
