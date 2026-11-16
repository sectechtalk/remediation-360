#Requires -Version 7.4
<#
.SYNOPSIS
    Turns on r360 change requests: the shared change mailbox, operator access to it, the GitHub issue tracker,
    the summary provider key and the app-r360 settings.
.DESCRIPTION
    Dry run by default: every step reports what exists and what it would change. Nothing is written without -Apply.
    Steps:
      1. Exchange Online: creates the shared mailbox if it is missing (free: no license while it stays under 50 GB with no
         archive or hold; nobody signs in to it) and gives every user in sg-r360-operators Full Access, without Outlook
         auto-mapping. r360 reads it with each operator's own delegated token (Mail.Read.Shared). No application permission.
      2. Entra: makes sure r360-web has the delegated scope Mail.Read.Shared with admin consent (runs
         New-R360AppRegistration.ps1, which owns r360-web's scope list).
      3. GitHub: checks that the r360 GitHub App has Issues: read and write and is installed on the tracker repo. If not,
         it opens the two GitHub pages and waits until you have saved and accepted the change. Creates the r360-change and r360-summary-requested labels.
      4. -SetApiKey: asks for the summary provider's API key in a masked prompt, stores it as the Key Vault secret
         r360-llm-api-key, lets id-r360 read that one secret, and makes the Container App secret llm-api-key a Key Vault
         reference. The key is never printed, logged or put on a command line (az reads it from a private temp file that is
         overwritten and deleted).
      5. Sets R360_CHANGE_MAILBOX, R360_CHANGE_REPO, R360_LLM_PROVIDER, R360_LLM_MODEL (and R360_LLM_API_KEY=secretref:llm-api-key
         once the secret exists) on app-r360, which starts a new revision, then waits for the startup self-check line.
    Rerunning is safe: each step changes only what differs.
.EXAMPLE
    pwsh -File .\tools\Set-R360ChangeRequests.ps1
.EXAMPLE
    pwsh -File .\tools\Set-R360ChangeRequests.ps1 -Apply -SetApiKey
.EXAMPLE
    pwsh -File .\tools\Set-R360ChangeRequests.ps1 -Apply -Provider openai -Model gpt-5 -SetApiKey
#>
[CmdletBinding()]
param(
    [string]$Mailbox = 'changes@contoso.com',
    [string]$DisplayName = 'r360 Changes',
    [string]$Repo = 'your-org/r360',
    [ValidateSet('anthropic', 'openai', 'azure-openai')][string]$Provider = 'anthropic',
    [string]$Model = '',
    [string]$Endpoint = '',
    [string]$Label = 'r360-change',
    [switch]$SetApiKey,
    [switch]$SkipExchange,
    [switch]$Apply,
    [int]$TimeoutSeconds = 900
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'R360.Common.psm1') -Force
$cfg = Get-R360Config
$log = Enable-R360Log -Name 'Set-R360ChangeRequests'
$secretName = 'r360-llm-api-key'
$appSecretName = 'llm-api-key'
if (-not $Model) { $Model = @{ anthropic = 'claude-opus-5-5'; openai = 'gpt-5'; 'azure-openai' = '' }[$Provider] }
$report = [System.Collections.Generic.List[object]]::new()
$note = { param($stage, $check, $status, $detail) $report.Add([pscustomobject]@{ Stage = $stage; Check = $check; Status = $status; Detail = $detail }) }
try {
    Write-R360Step "Log: $log"
    Write-R360Step ($Apply ? 'APPLY: changes will be made' : 'DRY RUN: nothing will be changed (add -Apply)')

    # --- Prerequisites (read-only) ---
    Write-R360Step 'Checking prerequisites'
    if ($env:COMPUTERNAME -ne 'DEVICE02') { throw "Run this on DEVICE02 (this is $env:COMPUTERNAME)." }
    foreach ($c in 'az', 'gh') { if (-not (Get-Command $c -ErrorAction SilentlyContinue)) { throw "$c is not installed or not on PATH." } }
    if ($Mailbox -notmatch '^[^@\s]+@[^@\s]+\.[a-z]{2,}$') { throw "Mailbox '$Mailbox' is not an email address." }
    if ($Repo -notmatch "^$([regex]::Escape($cfg.GitHubOrg))/[A-Za-z0-9._-]+$") { throw "Repo must be $($cfg.GitHubOrg)/<name>." }
    if ($Provider -eq 'azure-openai' -and (-not $Endpoint -or -not $Model)) { throw 'azure-openai needs -Endpoint https://<name>.openai.azure.com and -Model <deployment name>.' }
    if (-not (Invoke-R360Az -Arguments @('account', 'show') -AllowFailure)) { throw 'az is not signed in. Run: az login' }
    $appEnv = Get-R360ContainerAppEnv
    if (-not $appEnv.Count) { throw "$($cfg.ContainerApp) was not found in $($cfg.ResourceGroup)." }
    if (-not $SkipExchange -and -not (Get-Module -ListAvailable ExchangeOnlineManagement)) {
        throw 'The ExchangeOnlineManagement module is missing. Run: Install-Module ExchangeOnlineManagement -Scope CurrentUser'
    }

    # --- 1. Exchange Online: shared mailbox and operator Full Access ---
    if ($SkipExchange) { & $note 'Exchange' 'Shared mailbox' 'SKIP' '-SkipExchange' }
    else {
        Write-R360Step "Exchange Online: $Mailbox"
        if (-not (Connect-R360Graph -Scopes @('GroupMember.Read.All', 'User.Read.All'))) { throw 'Graph sign-in failed.' }
        $grp = @(Invoke-R360Graph -Uri "/v1.0/groups?`$filter=displayName eq '$($cfg.OperatorsGroup)'&`$select=id" -All | ForEach-Object { $_ }) | Select-Object -First 1
        if (-not $grp) { throw "$($cfg.OperatorsGroup) was not found in Entra." }
        $operators = @(Invoke-R360Graph -Uri "/v1.0/groups/$($grp.id)/transitiveMembers/microsoft.graph.user?`$select=userPrincipalName,accountEnabled" -All | ForEach-Object { $_ } | Where-Object { $_.accountEnabled } | ForEach-Object userPrincipalName)
        Write-R360Step "Operators: $($operators -join ', ')"
        $signedIn = [string](Get-MgContext).Account
        if ($signedIn -and $operators -notcontains $signedIn) { & $note 'Exchange' "Full Access $signedIn" 'WARN' "you are not in $($cfg.OperatorsGroup), so you get no Full Access and Watch-R360Summaries.ps1 cannot read the mailbox" }
        Import-Module ExchangeOnlineManagement
        if (-not (Get-ConnectionInformation -ErrorAction SilentlyContinue | Where-Object State -EQ 'Connected')) { Connect-ExchangeOnline -ShowBanner:$false }
        $mbx = Get-EXOMailbox -Identity $Mailbox -ErrorAction SilentlyContinue
        if ($mbx -and $mbx.RecipientTypeDetails -ne 'SharedMailbox') { throw "$Mailbox exists but is a $($mbx.RecipientTypeDetails), not a shared mailbox." }
        if (-not $mbx) {
            if ($Apply) {
                $alias = ($Mailbox -split '@')[0]
                New-Mailbox -Shared -Name $DisplayName -DisplayName $DisplayName -Alias $alias -PrimarySmtpAddress $Mailbox | Out-Null
                $mbx = Wait-R360Condition -Activity "$Mailbox provisioning" -TimeoutSeconds $TimeoutSeconds -IntervalSeconds 15 -Condition { Get-EXOMailbox -Identity $Mailbox -ErrorAction SilentlyContinue }
                & $note 'Exchange' 'Shared mailbox' 'CREATED' $Mailbox
            } else { & $note 'Exchange' 'Shared mailbox' 'WOULD CREATE' "$Mailbox ($DisplayName), no license needed" }
        } else { & $note 'Exchange' 'Shared mailbox' 'OK' "$Mailbox exists ($($mbx.RecipientTypeDetails))" }
        foreach ($upn in $operators) {
            $has = $mbx -and @(Get-EXOMailboxPermission -Identity $Mailbox -User $upn -ErrorAction SilentlyContinue | Where-Object { $_.AccessRights -contains 'FullAccess' -and -not $_.Deny }).Count
            if ($has) { & $note 'Exchange' "Full Access $upn" 'OK' 'already granted'; continue }
            if ($Apply) {
                Add-MailboxPermission -Identity $Mailbox -User $upn -AccessRights FullAccess -InheritanceType All -AutoMapping $false | Out-Null
                & $note 'Exchange' "Full Access $upn" 'GRANTED' 'AutoMapping off'
            } else { & $note 'Exchange' "Full Access $upn" 'WOULD GRANT' 'AutoMapping off' }
        }
    }

    # --- 2. Entra: Mail.Read.Shared on r360-web ---
    Write-R360Step 'Entra: r360-web delegated scope Mail.Read.Shared'
    if (-not (Connect-R360Graph -Scopes $cfg.BootstrapGraphScopes)) { throw 'Graph sign-in failed.' }
    $web = @(Invoke-R360Graph -Uri "/v1.0/servicePrincipals?`$filter=displayName eq '$($cfg.AppWeb)'&`$select=id" -All | ForEach-Object { $_ }) | Select-Object -First 1
    $graphSp = @(Invoke-R360Graph -Uri "/v1.0/servicePrincipals?`$filter=appId eq '$($cfg.GraphAppId)'&`$select=id" -All | ForEach-Object { $_ }) | Select-Object -First 1
    $grant = if ($web) { @(Invoke-R360Graph -Uri "/v1.0/oauth2PermissionGrants?`$filter=clientId eq '$($web.id)'" -All | ForEach-Object { $_ } | Where-Object { $_.resourceId -eq $graphSp.id -and $_.consentType -eq 'AllPrincipals' }) | Select-Object -First 1 } else { $null }
    if ($grant -and ($grant.scope -split ' ') -contains 'Mail.Read.Shared') { & $note 'Entra' 'r360-web Mail.Read.Shared' 'OK' 'scope and admin consent present' }
    elseif ($Apply) {
        & (Join-Path $PSScriptRoot 'New-R360AppRegistration.ps1') | Out-Null
        & $note 'Entra' 'r360-web Mail.Read.Shared' 'ADDED' 'via New-R360AppRegistration.ps1'
    } else { & $note 'Entra' 'r360-web Mail.Read.Shared' 'WOULD ADD' 'runs New-R360AppRegistration.ps1 (delegated scope + admin consent)' }

    # --- 3. GitHub App: Issues permission and installation on the tracker repo ---
    Write-R360Step "GitHub: r360 GitHub App on $Repo"
    $appId = $appEnv['R360_GITHUB_APP_ID']; $instId = $appEnv['R360_GITHUB_INSTALLATION_ID']
    if (-not $appId -or -not $instId) { throw 'R360_GITHUB_APP_ID / R360_GITHUB_INSTALLATION_ID are not set on app-r360.' }
    $repoName = ($Repo -split '/')[1]
    $ghState = {
        $inst = Invoke-R360GitHubAsApp -AppId $appId -Path "/app/installations/$instId"
        $perm = if ($inst.permissions.PSObject.Properties['issues']) { $inst.permissions.issues } else { $null }
        $tok = Invoke-R360GitHubAsApp -AppId $appId -Path "/app/installations/$instId/access_tokens" -Method POST -Body @{ permissions = @{ metadata = 'read' } }
        $repos = @((Invoke-R360GitHubAsApp -AppId $appId -Path '/installation/repositories?per_page=100' -Token $tok.token).repositories | ForEach-Object name)
        [pscustomobject]@{ Issues = $perm; Selection = $inst.repository_selection; HasRepo = ($inst.repository_selection -eq 'all' -or $repos -contains $repoName) }
    }
    $s = & $ghState
    $ok = { param($x) $x.Issues -eq 'write' -and $x.HasRepo }
    if (& $ok $s) { & $note 'GitHub' 'App Issues permission + repo' 'OK' "issues:$($s.Issues), $Repo included" }
    elseif ($Apply) {
        Write-Host ''
        Write-Host 'The r360 GitHub App needs a change only you can make in the browser. Opening the pages now:' -ForegroundColor Yellow
        if ($s.Issues -ne 'write') {
            Write-Host '  1. App permissions page: Repository permissions > Issues > Read and write > Save changes.'
            Start-Process "https://github.com/settings/apps/$($cfg.GitHubAppName)/permissions"
        }
        Write-Host "  2. Installation page: accept the new permissions (Review request > Accept) and under Repository access add $Repo > Save."
        Start-Process "https://github.com/settings/installations/$instId"
        Write-Host 'This script waits and continues by itself when GitHub shows the change.' -ForegroundColor Yellow
        $s = Wait-R360Condition -Activity 'GitHub App Issues permission and repo access' -TimeoutSeconds $TimeoutSeconds -IntervalSeconds 15 -Condition { $x = & $ghState; if (& $ok $x) { $x } }
        & $note 'GitHub' 'App Issues permission + repo' 'FIXED' "issues:$($s.Issues), $Repo included"
    } else { & $note 'GitHub' 'App Issues permission + repo' 'WOULD FIX' "now issues:$($s.Issues ?? 'none'), repo included: $($s.HasRepo). -Apply opens the two GitHub pages and waits" }
    $labels = [ordered]@{ $Label = @('0E8A16', 'Change request tracked by email in r360'); 'r360-summary-requested' = @('FBCA04', 'r360 Summarize now is waiting for the summary watcher') }
    foreach ($name in $labels.Keys) {
        $lbl = Invoke-R360Gh -Arguments @('api', "repos/$Repo/labels/$name") -AllowFailure
        if ($lbl) { & $note 'GitHub' "Label $name" 'OK' 'exists' }
        elseif ($Apply) {
            Invoke-R360Gh -Arguments @('api', '-X', 'POST', "repos/$Repo/labels", '-f', "name=$name", '-f', "color=$($labels[$name][0])", '-f', "description=$($labels[$name][1])") | Out-Null
            & $note 'GitHub' "Label $name" 'CREATED' $Repo
        } else { & $note 'GitHub' "Label $name" 'WOULD CREATE' $Repo }
    }

    # --- 4. API key in Key Vault, referenced by the Container App ---
    $secretUri = "https://$($cfg.KeyVault).vault.azure.net/secrets/$secretName"
    $kvId = (Invoke-R360Az -Arguments @('keyvault', 'show', '-n', $cfg.KeyVault, '-g', $cfg.ResourceGroup)).id
    $mi = Invoke-R360Az -Arguments @('identity', 'show', '-n', $cfg.Identity, '-g', $cfg.ResourceGroup)
    $haveSecret = [bool](Invoke-R360Az -Arguments @('keyvault', 'secret', 'show', '--id', $secretUri) -AllowFailure)
    if ($SetApiKey) {
        if (-not $Apply) { & $note 'Key Vault' $secretName 'WOULD SET' 'masked prompt, stored as a Key Vault secret' }
        else {
            $me = Invoke-R360Az -Arguments @('ad', 'signed-in-user', 'show')
            Set-R360RoleAssignment -PrincipalId $me.id -PrincipalType User -Role 'Key Vault Secrets Officer' -Scope $kvId
            Wait-R360Condition -Activity 'Key Vault secrets data plane' -TimeoutSeconds $TimeoutSeconds -Condition {
                $null = Invoke-R360Az -Arguments @('keyvault', 'secret', 'list', '--vault-name', $cfg.KeyVault) -AllowFailure; $LASTEXITCODE -eq 0 } | Out-Null
            $sec = Read-Host -AsSecureString "Paste the $Provider API key (input is hidden), then press Enter"
            $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
            if ($plain.Length -lt 20) { throw 'That does not look like an API key (too short). Nothing was stored.' }
            $tmp = New-TemporaryFile
            try {
                Set-R360PrivateFileAcl -Path $tmp.FullName
                [IO.File]::WriteAllText($tmp.FullName, $plain)
                $plain = $null
                Invoke-R360Az -Arguments @('keyvault', 'secret', 'set', '--vault-name', $cfg.KeyVault, '--name', $secretName, '--file', $tmp.FullName, '--content-type', "$Provider api key") | Out-Null
            } finally { Remove-R360FileSecurely -Path $tmp.FullName }
            $haveSecret = $true
            & $note 'Key Vault' $secretName 'SET' 'stored; never printed'
        }
    } else { & $note 'Key Vault' $secretName ($haveSecret ? 'OK' : 'MISSING') ($haveSecret ? 'exists (add -SetApiKey to replace it)' : 'add -SetApiKey to store it') }
    if ($haveSecret) {
        if ($Apply) {
            Set-R360RoleAssignment -PrincipalId $mi.principalId -PrincipalType ServicePrincipal -Role 'Key Vault Secrets User' -Scope "$kvId/secrets/$secretName"
            Invoke-R360Az -Arguments @('containerapp', 'secret', 'set', '-n', $cfg.ContainerApp, '-g', $cfg.ResourceGroup, '--secrets', "$appSecretName=keyvaultref:$secretUri,identityref:$($mi.id)") | Out-Null
            & $note 'Container App' "secret $appSecretName" 'SET' "Key Vault reference via $($cfg.Identity)"
        } else { & $note 'Container App' "secret $appSecretName" 'WOULD SET' "Key Vault reference to $secretName via $($cfg.Identity)" }
    }

    # --- 5. App settings ---
    $values = [ordered]@{ R360_CHANGE_MAILBOX = $Mailbox.ToLowerInvariant(); R360_CHANGE_REPO = $Repo; R360_LLM_PROVIDER = $Provider; R360_LLM_MODEL = $Model }
    if ($Endpoint) { $values.R360_LLM_ENDPOINT = $Endpoint }
    if ($haveSecret) { $values.R360_LLM_API_KEY = "secretref:$appSecretName" }
    if ($Apply) {
        Set-R360ContainerAppEnv -Values $values -TimeoutSeconds $TimeoutSeconds
        & $note 'Container App' 'settings' 'SET' (($values.Keys | ForEach-Object { "$_=$($values[$_])" }) -join '; ')
        $fqdn = (Invoke-R360Az -Arguments @('containerapp', 'show', '-n', $cfg.ContainerApp, '-g', $cfg.ResourceGroup)).properties.configuration.ingress.fqdn
        Wait-R360Condition -Activity "https://$fqdn/healthz" -TimeoutSeconds $TimeoutSeconds -IntervalSeconds 10 -Condition {
            try { (Invoke-RestMethod "https://$fqdn/healthz" -TimeoutSec 20).ok } catch { $false } } | Out-Null
        & $note 'Container App' 'health' 'OK' "https://$fqdn/healthz"
    } else { & $note 'Container App' 'settings' 'WOULD SET' (($values.Keys | ForEach-Object { "$_=$($values[$_])" }) -join '; ') }

    # Local r360 (DEVICE02) has no Container Apps secret reference: Install-R360Local.ps1 grants this PC's Arc identity
    # read on the secret and points the container at it (R360_LLM_API_KEY_SECRET), so the key reaches local r360 too.
    if (Test-Path -LiteralPath 'C:\ProgramData\r360-local\r360.env') {
        & $note 'Local r360' 'settings and API key' 'NEXT' 'run in elevated PowerShell 7: pwsh -File .\tools\Install-R360Local.ps1 -RefreshEnv -Update -Apply'
    }
    $report | Format-Table -AutoSize -Wrap | Out-String -Width 220 | Write-Host
    if ($Apply) { Write-R360Step 'Done. Sign out of r360 and sign in again so your session picks up the mailbox scope, then open Change requests.' }
    else { Write-R360Step 'Dry run finished. Re-run with -Apply to make these changes (add -SetApiKey only when you have an API key).' }
}
finally { Disable-R360Log }
