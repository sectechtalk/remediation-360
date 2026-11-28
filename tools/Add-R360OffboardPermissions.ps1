#Requires -Version 7.4
<#
.SYNOPSIS
    Adds the Offboard page's delegated Microsoft Graph permissions to r360-write and grants admin consent for them.
    Additive only: nothing else on r360-write changes (redirect URIs, credentials, other scopes stay as they are).
.DESCRIPTION
    Use this on a local install (http://localhost:3660) instead of re-running New-R360AppRegistration.ps1, which also
    resets r360-write's redirect URIs to the Azure Container App and would drop the localhost one.

    Adds to r360-write, delegated only:
      User.Read.All, User.EnableDisableAccount.All, User.RevokeSessions.All, Synchronization.ReadWrite.All,
      AppRoleAssignment.ReadWrite.All
    and adds the same five to r360-write's existing tenant-wide consent for Microsoft Graph (consentType AllPrincipals).
    Entra still checks the signed-in operator's own role on every call (User Administrator, Privileged Authentication
    Administrator for admins, Application Administrator for Provision on demand), so r360 can never do more than you can.

    Run it as a Global Administrator or Privileged Role Administrator. Supports -WhatIf. Logs to C:\path\to\logs.
.EXAMPLE
    ./Add-R360OffboardPermissions.ps1 -WhatIf
    ./Add-R360OffboardPermissions.ps1
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param()
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'R360.Common.psm1') -Force
$cfg = Get-R360Config
$log = Enable-R360Log -Name 'Add-R360OffboardPermissions'
$wanted = @('User.Read.All', 'User.EnableDisableAccount.All', 'User.RevokeSessions.All', 'Synchronization.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All')
try {
    Write-R360Step "Log: $log"
    if (-not (Connect-R360Graph -Scopes @('Application.ReadWrite.All', 'DelegatedPermissionGrant.ReadWrite.All'))) { throw 'Graph sign-in failed.' }

    $graph = @(Invoke-R360Graph -Uri "/v1.0/servicePrincipals?`$filter=appId eq '$($cfg.GraphAppId)'&`$select=id,appId,displayName,oauth2PermissionScopes" -All)[0]
    if (-not $graph) { throw 'Microsoft Graph service principal not found.' }
    $ids = @{}
    foreach ($n in $wanted) {
        $s = $graph.oauth2PermissionScopes | Where-Object value -EQ $n
        if (-not $s) { throw "Delegated scope $n not found on Microsoft Graph." }
        $ids[$n] = $s.id
    }

    $apps = @(Invoke-R360Graph -Uri "/v1.0/applications?`$filter=displayName eq '$($cfg.AppWrite)'&`$select=id,appId,displayName,requiredResourceAccess" -All)
    if ($apps.Count -ne 1) { throw "Expected exactly one app registration named $($cfg.AppWrite); found $($apps.Count)." }
    $app = $apps[0]

    # 1. requiredResourceAccess: add the missing scopes to the Microsoft Graph entry, keep everything else.
    $rra = @($app.requiredResourceAccess | ForEach-Object { @{ resourceAppId = $_.resourceAppId; resourceAccess = @($_.resourceAccess | ForEach-Object { @{ id = $_.id; type = $_.type } }) } })
    $g = $rra | Where-Object resourceAppId -EQ $cfg.GraphAppId | Select-Object -First 1
    if (-not $g) { $g = @{ resourceAppId = $cfg.GraphAppId; resourceAccess = @() }; $rra += $g }
    $missing = @($wanted | Where-Object { $ids[$_] -notin @($g.resourceAccess | ForEach-Object id) })
    if ($missing) {
        $g.resourceAccess = @($g.resourceAccess) + @($missing | ForEach-Object { @{ id = $ids[$_]; type = 'Scope' } })
        if ($PSCmdlet.ShouldProcess($cfg.AppWrite, "Add delegated Graph permissions: $($missing -join ', ')")) {
            Invoke-R360Graph -Method PATCH -Uri "/v1.0/applications/$($app.id)" -Body @{ requiredResourceAccess = $rra } | Out-Null
            Write-R360Step "Added to $($cfg.AppWrite): $($missing -join ', ')"
        }
    } else { Write-R360Step "$($cfg.AppWrite) already lists all five permissions." }

    # 2. Tenant-wide consent: add the scopes to the existing AllPrincipals grant for Microsoft Graph.
    $sp = @(Invoke-R360Graph -Uri "/v1.0/servicePrincipals?`$filter=appId eq '$($app.appId)'&`$select=id" -All)[0]
    if (-not $sp) { throw "$($cfg.AppWrite) has no enterprise application (service principal) in this tenant." }
    $grant = @(Invoke-R360Graph -Uri "/v1.0/oauth2PermissionGrants?`$filter=clientId eq '$($sp.id)'" -All | ForEach-Object { $_ } | Where-Object { $_.resourceId -eq $graph.id -and $_.consentType -eq 'AllPrincipals' }) | Select-Object -First 1
    if (-not $grant) {
        if ($PSCmdlet.ShouldProcess("$($cfg.AppWrite) -> Microsoft Graph", "Admin consent: $($wanted -join ' ')")) {
            Invoke-R360Graph -Method POST -Uri '/v1.0/oauth2PermissionGrants' -Body @{ clientId = $sp.id; consentType = 'AllPrincipals'; resourceId = $graph.id; scope = ($wanted -join ' ') } | Out-Null
        }
    } else {
        $have = @($grant.scope -split ' ' | Where-Object { $_ })
        $add = @($wanted | Where-Object { $_ -notin $have })
        if ($add -and $PSCmdlet.ShouldProcess("$($cfg.AppWrite) -> Microsoft Graph", "Add to admin consent: $($add -join ' ')")) {
            Invoke-R360Graph -Method PATCH -Uri "/v1.0/oauth2PermissionGrants/$($grant.id)" -Body @{ scope = (($have + $add) -join ' ') } | Out-Null
            Write-R360Step "Consent now includes: $($add -join ', ')"
        } elseif (-not $add) { Write-R360Step 'Consent already covers all five permissions.' }
    }
    Write-R360Step 'Done. In r360: End write session, then Elevate to write again, then open Offboard.'
} finally { Disable-R360Log }
