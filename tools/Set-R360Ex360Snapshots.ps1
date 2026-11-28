#Requires -Version 7.4
<#
.SYNOPSIS
    Turns on Exchange 360 config snapshots stored in r360: the private snapshots repository, the r360 API scope, the
    Exchange 360 permission with admin consent, and the app-r360 setting.
.DESCRIPTION
    Dry run by default: every step reports what exists and what it would change. Nothing is written without -Apply.
    Steps:
      1. GitHub: creates the private repository (default your-org/ex360-snapshots) if it is missing, and checks that
         the r360 GitHub App is installed on it. If not, it opens the GitHub page and waits until you have added it.
      2. Entra, r360-web: adds the Application ID URI api://<r360-web app id> if missing, and the delegated scope
         Snapshots.ReadWrite (admins only consent) under Expose an API.
      3. Entra, Exchange 360 app registration (-Ex360ClientId, the ENTRA_CLIENT_ID in Exchange 360's .env): adds the
         delegated permission r360-web / Snapshots.ReadWrite and grants admin consent for the tenant.
      4. Sets R360_EX360_SNAPSHOT_REPO on app-r360, which starts a new revision.
    Free: a private GitHub repository and app registration settings cost nothing. Rerunning is safe.
.EXAMPLE
    pwsh -File .\tools\Set-R360Ex360Snapshots.ps1 -Ex360ClientId 00000000-0000-0000-0000-000000000000
.EXAMPLE
    pwsh -File .\tools\Set-R360Ex360Snapshots.ps1 -Ex360ClientId 00000000-0000-0000-0000-000000000000 -Apply
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$Ex360ClientId,
    [string]$Repo = 'your-org/ex360-snapshots',
    [switch]$Apply,
    [int]$TimeoutSeconds = 900
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'R360.Common.psm1') -Force
$cfg = Get-R360Config
$log = Enable-R360Log -Name 'Set-R360Ex360Snapshots'
$scopeName = 'Snapshots.ReadWrite'
$report = [System.Collections.Generic.List[object]]::new()
$note = { param($stage, $check, $status, $detail) $report.Add([pscustomobject]@{ Stage = $stage; Check = $check; Status = $status; Detail = $detail }) }
# Invoke-MgGraphRequest -OutputType PSObject leaves out empty arrays and nulls (identifierUris = [] has no property at
# all), and StrictMode throws on a missing property. Read Graph properties through this.
$prop = { param($obj, $name) if ($null -ne $obj -and $obj.PSObject.Properties[$name]) { $obj.$name } }
try {
    Write-R360Step "Log: $log"
    Write-R360Step ($Apply ? 'APPLY: changes will be made' : 'DRY RUN: nothing will be changed (add -Apply)')

    # --- Prerequisites (read-only) ---
    foreach ($c in 'az', 'gh') { if (-not (Get-Command $c -ErrorAction SilentlyContinue)) { throw "$c is not installed or not on PATH." } }
    if ($Repo -notmatch "^$([regex]::Escape($cfg.GitHubOrg))/[A-Za-z0-9._-]+$") { throw "Repo must be $($cfg.GitHubOrg)/<name>." }
    if (-not (Invoke-R360Az -Arguments @('account', 'show') -AllowFailure)) { throw 'az is not signed in. Run: az login' }
    $appEnv = Get-R360ContainerAppEnv
    if (-not $appEnv.Count) { throw "$($cfg.ContainerApp) was not found in $($cfg.ResourceGroup)." }

    # --- 1. GitHub: private repository and the r360 GitHub App on it ---
    Write-R360Step "GitHub: $Repo"
    & gh api "repos/$Repo" --silent 2>$null
    $exists = $LASTEXITCODE -eq 0
    if (-not $exists) {
        if ($Apply) {
            & gh repo create $Repo --private --add-readme --description 'Exchange 360 config snapshots, stored by r360. Read-only reads; secrets removed.'
            if ($LASTEXITCODE -ne 0) { throw "gh repo create $Repo failed." }
            & $note 'GitHub' 'Repository' 'CREATED' "$Repo (private)"
            $exists = $true
        } else { & $note 'GitHub' 'Repository' 'WOULD CREATE' "$Repo (private, with a README so main exists)" }
    } else {
        $vis = (& gh api "repos/$Repo" --jq '.visibility')
        if ($vis -ne 'private') { throw "$Repo is $vis. Snapshots hold tenant details; the repository must be private." }
        & $note 'GitHub' 'Repository' 'OK' "$Repo exists (private)"
    }
    $appId = $appEnv['R360_GITHUB_APP_ID']
    if (-not $appId) { throw 'R360_GITHUB_APP_ID is not set on app-r360.' }
    $installed = { try { [bool](Invoke-R360GitHubAsApp -AppId $appId -Path "/repos/$Repo/installation") } catch { $false } }
    if ($exists -and -not (& $installed)) {
        if ($Apply) {
            Write-R360Step "Add $Repo to the $($cfg.GitHubAppName) installation: Only select repositories > $Repo > Save"
            Start-Process "https://github.com/apps/$($cfg.GitHubAppName)/installations/new"
            Wait-R360Condition -Activity "$($cfg.GitHubAppName) installed on $Repo" -TimeoutSeconds $TimeoutSeconds -IntervalSeconds 10 -Condition $installed | Out-Null
            & $note 'GitHub' 'r360 GitHub App' 'ADDED' "installed on $Repo"
        } else { & $note 'GitHub' 'r360 GitHub App' 'WOULD ADD' "opens the installation page so you add $Repo" }
    } elseif ($exists) { & $note 'GitHub' 'r360 GitHub App' 'OK' "installed on $Repo" }

    # --- 2. Entra: r360-web exposes Snapshots.ReadWrite ---
    if (-not (Connect-R360Graph -Scopes @('Application.ReadWrite.All', 'DelegatedPermissionGrant.ReadWrite.All'))) { throw 'Graph sign-in failed.' }
    $web = @(Invoke-R360Graph -Uri "/v1.0/applications?`$filter=displayName eq '$($cfg.AppWeb)'&`$select=id,appId,identifierUris,api" -All) | Select-Object -First 1
    if (-not $web) { throw "$($cfg.AppWeb) was not found in Entra." }
    $uri = "api://$($web.appId)"
    $uris = @(& $prop $web 'identifierUris')
    if ($uris -notcontains $uri) {
        if ($Apply) { Invoke-R360Graph -Method PATCH -Uri "/v1.0/applications/$($web.id)" -Body @{ identifierUris = @($uris + $uri) } | Out-Null; & $note 'Entra' "$($cfg.AppWeb) Application ID URI" 'ADDED' $uri }
        else { & $note 'Entra' "$($cfg.AppWeb) Application ID URI" 'WOULD ADD' $uri }
    } else { & $note 'Entra' "$($cfg.AppWeb) Application ID URI" 'OK' $uri }
    $scopes = @(& $prop (& $prop $web 'api') 'oauth2PermissionScopes')
    $scope = $scopes | Where-Object value -EQ $scopeName | Select-Object -First 1
    if (-not $scope) {
        $scope = [pscustomobject]@{
            id = [guid]::NewGuid().ToString(); value = $scopeName; type = 'Admin'; isEnabled = $true
            adminConsentDisplayName = 'Save and read Exchange 360 config snapshots'
            adminConsentDescription = 'Lets Exchange 360 send read-only configuration snapshots to r360 and read them back, as the signed-in user.'
            userConsentDisplayName = $null; userConsentDescription = $null
        }
        if ($Apply) {
            $api = @{ oauth2PermissionScopes = @($scopes + $scope) }
            Invoke-R360Graph -Method PATCH -Uri "/v1.0/applications/$($web.id)" -Body @{ api = $api } | Out-Null
            & $note 'Entra' "$($cfg.AppWeb) scope $scopeName" 'ADDED' 'delegated, admins only'
        } else { & $note 'Entra' "$($cfg.AppWeb) scope $scopeName" 'WOULD ADD' 'delegated, admins only' }
    } else { & $note 'Entra' "$($cfg.AppWeb) scope $scopeName" 'OK' "id $($scope.id)" }

    # --- 3. Entra: Exchange 360 has the permission, with admin consent ---
    $ex = @(Invoke-R360Graph -Uri "/v1.0/applications?`$filter=appId eq '$Ex360ClientId'&`$select=id,appId,displayName,requiredResourceAccess" -All) | Select-Object -First 1
    if (-not $ex) { throw "No app registration has the client ID $Ex360ClientId (ENTRA_CLIENT_ID in Exchange 360's .env)." }
    Write-R360Step "Exchange 360 app registration: $($ex.displayName)"
    $rra = @(& $prop $ex 'requiredResourceAccess')
    $forWeb = $rra | Where-Object resourceAppId -EQ $web.appId | Select-Object -First 1
    $hasPerm = $forWeb -and @(& $prop $forWeb 'resourceAccess' | Where-Object { $_.id -eq $scope.id }).Count
    if (-not $hasPerm) {
        if ($Apply) {
            $others = @($rra | Where-Object resourceAppId -NE $web.appId)
            $access = @(& $prop $forWeb 'resourceAccess') + @{ id = $scope.id; type = 'Scope' }
            Invoke-R360Graph -Method PATCH -Uri "/v1.0/applications/$($ex.id)" -Body @{ requiredResourceAccess = @($others + @{ resourceAppId = $web.appId; resourceAccess = $access }) } | Out-Null
            & $note 'Entra' "$($ex.displayName) permission" 'ADDED' "$($cfg.AppWeb) / $scopeName"
        } else { & $note 'Entra' "$($ex.displayName) permission" 'WOULD ADD' "$($cfg.AppWeb) / $scopeName" }
    } else { & $note 'Entra' "$($ex.displayName) permission" 'OK' "$($cfg.AppWeb) / $scopeName" }
    $exSp = @(Invoke-R360Graph -Uri "/v1.0/servicePrincipals?`$filter=appId eq '$Ex360ClientId'&`$select=id" -All) | Select-Object -First 1
    $webSp = @(Invoke-R360Graph -Uri "/v1.0/servicePrincipals?`$filter=appId eq '$($web.appId)'&`$select=id" -All) | Select-Object -First 1
    if (-not $exSp -or -not $webSp) { throw 'A service principal is missing (sign in to each app once, or create it in Enterprise applications).' }
    $grant = @(Invoke-R360Graph -Uri "/v1.0/oauth2PermissionGrants?`$filter=clientId eq '$($exSp.id)'" -All | ForEach-Object { $_ } | Where-Object { $_.resourceId -eq $webSp.id -and $_.consentType -eq 'AllPrincipals' }) | Select-Object -First 1
    $have = @("$(& $prop $grant 'scope')" -split ' ' | Where-Object { $_ })
    if ($have -notcontains $scopeName) {
        if ($Apply) {
            if ($grant) { Invoke-R360Graph -Method PATCH -Uri "/v1.0/oauth2PermissionGrants/$($grant.id)" -Body @{ scope = (@($have + $scopeName) -join ' ') } | Out-Null }
            else { Invoke-R360Graph -Method POST -Uri '/v1.0/oauth2PermissionGrants' -Body @{ clientId = $exSp.id; consentType = 'AllPrincipals'; resourceId = $webSp.id; scope = $scopeName } | Out-Null }
            & $note 'Entra' 'Admin consent' 'GRANTED' "$($ex.displayName) -> $($cfg.AppWeb) $scopeName"
        } else { & $note 'Entra' 'Admin consent' 'WOULD GRANT' "$($ex.displayName) -> $($cfg.AppWeb) $scopeName (tenant-wide)" }
    } else { & $note 'Entra' 'Admin consent' 'OK' 'already granted' }

    # --- 4. app-r360 setting ---
    if ($appEnv['R360_EX360_SNAPSHOT_REPO'] -eq $Repo) { & $note 'Azure' 'R360_EX360_SNAPSHOT_REPO' 'OK' $Repo }
    elseif ($Apply) { Set-R360ContainerAppEnv -Values ([ordered]@{ R360_EX360_SNAPSHOT_REPO = $Repo }) -TimeoutSeconds $TimeoutSeconds; & $note 'Azure' 'R360_EX360_SNAPSHOT_REPO' 'SET' "$Repo (new revision)" }
    else { & $note 'Azure' 'R360_EX360_SNAPSHOT_REPO' 'WOULD SET' $Repo }

    $fqdn = Invoke-R360Az -Arguments @('containerapp', 'show', '-n', $cfg.ContainerApp, '-g', $cfg.ResourceGroup, '--query', 'properties.configuration.ingress.fqdn')
    Write-R360Step "Exchange 360 .env needs: R360_URL=https://$fqdn and R360_API_SCOPE=$uri/$scopeName"
}
finally {
    $report | Format-Table -AutoSize | Out-String -Width 220 | Write-Host
    Disable-R360Log
}
