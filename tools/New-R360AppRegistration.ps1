#Requires -Version 7.4
<#
.SYNOPSIS
    Creates the r360 Entra app registrations (idempotent): r360-web (sign-in, read), r360-write (step-up writes),
    r360-ci-signer (GitHub Actions OIDC, signing only). Delegated permissions only, no stored credentials.
.DESCRIPTION
    - r360-web and r360-write get a federated identity credential that trusts the user-assigned managed identity id-r360
      (no secret, no certificate). r360-ci-signer trusts GitHub OIDC for your-org/remediations main only, using the subject GitHub really issues (immutable form for newer repos; see Get-R360GitHubOidcSubject).
    - Scopes are resolved from the resource service principals' delegated (oauth2PermissionScopes) list only; an app role
      (application permission) can never be added.
    - Tenant-wide admin consent is granted in code (oauth2PermissionGrants, consentType AllPrincipals) as you, so there is
      no browser consent step. Any existing secret or certificate on these apps fails the script (nothing is deleted).
    - Assignment is required on r360-web / r360-write; you (and sg-r360-operators if it exists) are assigned.
    Graph via Invoke-MgGraphRequest only. Logs to C:\path\to\logs. Supports -WhatIf.
.EXAMPLE
    ./New-R360AppRegistration.ps1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param([int]$TimeoutMinutes = 10)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'R360.Common.psm1') -Force
$cfg = Get-R360Config
$log = Enable-R360Log -Name 'New-R360AppRegistration'
try {
    Write-R360Step "Log: $log"
    & (Join-Path $PSScriptRoot 'Test-R360Prereqs.ps1') -Stage Tools | Out-Null
    $timeout = $TimeoutMinutes * 60
    $scopes = @('Application.ReadWrite.All', 'DelegatedPermissionGrant.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All', 'Group.Read.All')
    if (-not (Connect-R360Graph -Scopes $scopes -NoInteractive:$WhatIfPreference)) {
        Write-R360Step "WhatIf: Graph is not connected; would sign in (delegated) with: $($scopes -join ', '), then create $($cfg.AppWeb), $($cfg.AppWrite), $($cfg.AppCiSigner)."
        return
    }
    $me = Invoke-R360Graph -Uri '/v1.0/me?$select=id,userPrincipalName'

    # Inputs from the infrastructure step
    $mi = Invoke-R360Az -Arguments @('identity', 'show', '-n', $cfg.Identity, '-g', $cfg.ResourceGroup) -AllowFailure
    $app = Invoke-R360Az -Arguments @('containerapp', 'show', '-n', $cfg.ContainerApp, '-g', $cfg.ResourceGroup) -AllowFailure
    if (-not $mi -or -not $app) {
        if ($WhatIfPreference) { Write-R360Step 'WhatIf: id-r360 / app-r360 not created yet; would create the three app registrations with MI + GitHub OIDC federated credentials and admin consent.'; return }
        throw 'Run New-R360Infrastructure.ps1 first (id-r360 and app-r360 are required).'
    }
    $fqdn = $app.properties.configuration.ingress.fqdn

    # Delegated scope catalogs
    $resources = @{}
    foreach ($r in @(@{ Key = 'Graph'; AppId = $cfg.GraphAppId }, @{ Key = 'Defender'; AppId = $cfg.DefenderAppId })) {
        $sp = @(Invoke-R360Graph -Uri "/v1.0/servicePrincipals?`$filter=appId eq '$($r.AppId)'&`$select=id,appId,displayName,oauth2PermissionScopes" -All)
        if (-not $sp) { throw "Service principal for $($r.Key) ($($r.AppId)) not found in the tenant." }
        $resources[$r.Key] = $sp[0]
    }
    function Resolve-Scope {
        param($Key, [string[]]$Names)
        $sp = $resources[$Key]
        $out = foreach ($n in $Names) {
            $s = $sp.oauth2PermissionScopes | Where-Object value -EQ $n
            if (-not $s) { throw "Delegated scope '$n' not found on $($sp.displayName). Fix the scope list." }
            @{ id = $s.id; type = 'Scope' }
        }
        @{ resourceAppId = $sp.appId; resourceAccess = @($out) }
    }
    $oidc = @('openid', 'profile', 'offline_access', 'User.Read')
    $defs = @(
        @{ Name = $cfg.AppWeb; Redirect = @("https://$fqdn/auth/callback"); AssignRequired = $true
            Fic = @{ name = 'r360-managed-identity'; issuer = "https://login.microsoftonline.com/$($cfg.TenantId)/v2.0"; subject = $mi.principalId }
            Access = @{ Graph = $oidc + @('DeviceManagementConfiguration.Read.All', 'DeviceManagementManagedDevices.Read.All', 'DeviceManagementScripts.Read.All', 'RoleManagement.Read.Directory', 'GroupMember.Read.All') } }
        @{ Name = $cfg.AppWrite; Redirect = @("https://$fqdn/auth/write/callback"); AssignRequired = $true
            Fic = @{ name = 'r360-managed-identity'; issuer = "https://login.microsoftonline.com/$($cfg.TenantId)/v2.0"; subject = $mi.principalId }
            Access = @{
                Graph    = $oidc + @('DeviceManagementScripts.ReadWrite.All', 'DeviceManagementConfiguration.ReadWrite.All', 'DeviceManagementManagedDevices.PrivilegedOperations.All',
                    'DeviceManagementManagedDevices.Read.All', 'RoleManagement.Read.Directory', 'GroupMember.Read.All')
                Defender = @('Machine.Read', 'Machine.ReadWrite', 'Machine.LiveResponse', 'Machine.Isolate', 'Machine.Scan', 'Machine.RestrictExecution',
                    'Machine.CollectForensics', 'Machine.StopAndQuarantine', 'Library.Manage', 'Ti.ReadWrite') } }
        @{ Name = $cfg.AppCiSigner; Redirect = @(); AssignRequired = $false
            Fic = @{ name = 'github-remediations-main'; issuer = 'https://token.actions.githubusercontent.com'; subject = (Get-R360GitHubOidcSubject -Branch main) }
            Access = @{} }
    )

    $clientIds = @{}
    foreach ($d in $defs) {
        Write-R360Step "== $($d.Name)"
        $rra = @(foreach ($k in $d.Access.Keys) { Resolve-Scope -Key $k -Names $d.Access[$k] })
        $body = @{ displayName = $d.Name; signInAudience = 'AzureADMyOrg'; tags = @('r360')
            requiredResourceAccess = $rra
            web = @{ redirectUris = $d.Redirect; implicitGrantSettings = @{ enableIdTokenIssuance = $false; enableAccessTokenIssuance = $false } } }
        $found = @(Invoke-R360Graph -Uri "/v1.0/applications?`$filter=displayName eq '$($d.Name)'" -All | ForEach-Object { $_ })
        if ($found.Count -gt 1) { throw "$($found.Count) applications are named $($d.Name); resolve the duplicate first." }
        $a = if ($found) { $found[0] } else { $null }
        if (-not $a) {
            if (-not $PSCmdlet.ShouldProcess($d.Name, 'Create app registration (delegated scopes only)')) { continue }
            $a = Invoke-R360Graph -Method POST -Uri '/v1.0/applications' -Body $body
            $aid = $a.id
            Wait-R360Condition -Activity "$($d.Name) replication" -TimeoutSeconds $timeout -Condition {
                try { Invoke-R360Graph -Uri "/v1.0/applications/$($aid)?`$select=id" } catch { $null } } | Out-Null
        } else {
            $credCount = @($a.passwordCredentials | Where-Object { $_ }).Count + @($a.keyCredentials | Where-Object { $_ }).Count
            if ($credCount) { throw "$($d.Name) has $credCount stored credential(s) (secret/certificate). r360 forbids them; remove them in Entra and re-run." }
            $curR = ($a.requiredResourceAccess | ConvertTo-Json -Depth 10 -Compress)
            $newR = ($rra | ConvertTo-Json -Depth 10 -Compress)
            $curU = (@($a.web.redirectUris) | Sort-Object) -join ' '
            $newU = (@($d.Redirect) | Sort-Object) -join ' '
            if (($curR -ne $newR -or $curU -ne $newU) -and $PSCmdlet.ShouldProcess($d.Name, 'Update scopes / redirect URIs')) {
                Invoke-R360Graph -Method PATCH -Uri "/v1.0/applications/$($a.id)" -Body @{ requiredResourceAccess = $rra; web = $body.web } | Out-Null
            } else { Write-R360Step "$($d.Name) exists and is current (appId $($a.appId))" }
        }
        $clientIds[$d.Name] = $a.appId

        # Federated identity credential (no stored secret)
        $fics = @(Invoke-R360Graph -Uri "/v1.0/applications/$($a.id)/federatedIdentityCredentials" -All | ForEach-Object { $_ })
        $fic = $fics | Where-Object name -EQ $d.Fic.name | Select-Object -First 1
        $ficBody = @{ name = $d.Fic.name; issuer = $d.Fic.issuer; subject = $d.Fic.subject; audiences = @($cfg.FicAudience); description = 'r360 bootstrap' }
        if (-not $fic) {
            if ($PSCmdlet.ShouldProcess($d.Name, "Add federated credential $($d.Fic.subject)")) {
                Invoke-R360Graph -Method POST -Uri "/v1.0/applications/$($a.id)/federatedIdentityCredentials" -Body $ficBody | Out-Null
            }
        } elseif ($fic.issuer -ne $d.Fic.issuer -or $fic.subject -ne $d.Fic.subject) {
            if ($PSCmdlet.ShouldProcess($d.Name, "Update federated credential to $($d.Fic.subject)")) {
                Invoke-R360Graph -Method PATCH -Uri "/v1.0/applications/$($a.id)/federatedIdentityCredentials/$($fic.id)" -Body @{ issuer = $d.Fic.issuer; subject = $d.Fic.subject; audiences = @($cfg.FicAudience) } | Out-Null
            }
        }

        # Service principal
        $sp = @(Invoke-R360Graph -Uri "/v1.0/servicePrincipals?`$filter=appId eq '$($a.appId)'" -All | ForEach-Object { $_ }) | Select-Object -First 1
        if (-not $sp) {
            if (-not $PSCmdlet.ShouldProcess($d.Name, 'Create service principal')) { continue }
            $sp = Invoke-R360Graph -Method POST -Uri '/v1.0/servicePrincipals' -Body @{ appId = $a.appId; appRoleAssignmentRequired = $d.AssignRequired; tags = @('r360', 'HideApp') }
            $spid = $sp.id
            Wait-R360Condition -Activity "$($d.Name) service principal replication" -TimeoutSeconds $timeout -Condition {
                try { Invoke-R360Graph -Uri "/v1.0/servicePrincipals/$($spid)?`$select=id" } catch { $null } } | Out-Null
        } elseif ($sp.appRoleAssignmentRequired -ne $d.AssignRequired -and $PSCmdlet.ShouldProcess($d.Name, "Set assignment required = $($d.AssignRequired)")) {
            Invoke-R360Graph -Method PATCH -Uri "/v1.0/servicePrincipals/$($sp.id)" -Body @{ appRoleAssignmentRequired = $d.AssignRequired } | Out-Null
        }

        # Admin consent (delegated grants for all users) - in code, no browser step
        foreach ($k in $d.Access.Keys) {
            $res = $resources[$k]
            $want = ($d.Access[$k] | Sort-Object) -join ' '
            $grant = @(Invoke-R360Graph -Uri "/v1.0/oauth2PermissionGrants?`$filter=clientId eq '$($sp.id)'" -All | ForEach-Object { $_ } | Where-Object { $_.resourceId -eq $res.id -and $_.consentType -eq 'AllPrincipals' }) | Select-Object -First 1
            if (-not $grant) {
                if ($PSCmdlet.ShouldProcess("$($d.Name) -> $($res.displayName)", "Admin consent: $want")) {
                    Invoke-R360Graph -Method POST -Uri '/v1.0/oauth2PermissionGrants' -Body @{ clientId = $sp.id; consentType = 'AllPrincipals'; resourceId = $res.id; scope = $want } | Out-Null
                }
            } elseif ((($grant.scope -split ' ' | Where-Object { $_ } | Sort-Object) -join ' ') -ne $want) {
                if ($PSCmdlet.ShouldProcess("$($d.Name) -> $($res.displayName)", "Update admin consent to: $want")) {
                    Invoke-R360Graph -Method PATCH -Uri "/v1.0/oauth2PermissionGrants/$($grant.id)" -Body @{ scope = $want } | Out-Null
                }
            } else { Write-R360Step "Consent for $($res.displayName) is current" }
        }

        # Assignment (default access) for you and, if present, sg-r360-operators. Group membership stays in Entra.
        if ($d.AssignRequired) {
            $principals = @(@{ id = $me.id; label = $me.userPrincipalName })
            $op = @(Invoke-R360Graph -Uri "/v1.0/groups?`$filter=displayName eq '$($cfg.OperatorsGroup)'&`$select=id" -All | ForEach-Object { $_ }) | Select-Object -First 1
            if ($op) { $principals += @{ id = $op.id; label = $cfg.OperatorsGroup } } else { Write-R360Step "$($cfg.OperatorsGroup) not found in Entra; assigning you only (create the group in Entra and re-run to add it)." }
            $have = @(Invoke-R360Graph -Uri "/v1.0/servicePrincipals/$($sp.id)/appRoleAssignedTo" -All | ForEach-Object { $_ } | ForEach-Object principalId)
            foreach ($p in $principals | Where-Object { $_.id -notin $have }) {
                if ($PSCmdlet.ShouldProcess($d.Name, "Assign $($p.label)")) {
                    Invoke-R360Graph -Method POST -Uri "/v1.0/servicePrincipals/$($sp.id)/appRoleAssignedTo" -Body @{ principalId = $p.id; resourceId = $sp.id; appRoleId = '00000000-0000-0000-0000-000000000000' } | Out-Null
                }
            }
        }
    }

    # Publish non-secret ids to the Container App
    if ($clientIds[$cfg.AppWeb] -and $clientIds[$cfg.AppWrite]) {
        Set-R360ContainerAppEnv -Values ([ordered]@{ R360_WEB_CLIENT_ID = $clientIds[$cfg.AppWeb]; R360_WRITE_CLIENT_ID = $clientIds[$cfg.AppWrite]; AZURE_CLIENT_ID = $mi.clientId; ENTRA_TENANT_ID = $cfg.TenantId }) -WhatIf:$WhatIfPreference
    }
    Write-R360Step 'New-R360AppRegistration finished.'
} finally { Disable-R360Log }
