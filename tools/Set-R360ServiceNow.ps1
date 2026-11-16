#Requires -Version 7.4
<#
.SYNOPSIS
    Sets up the ServiceNow page for the local r360 on DEVICE02. Dry run by default.
.DESCRIPTION
    The ServiceNow page searches ServiceNow read-only with the svc.r360 service account and shows which items already have
    an r360 change request (GitHub issue). Preconfigured queries live in config/servicenow-queries.json in the repo; queries
    that operators save from the page live in the Azure Table r360snqueries.

    Nothing is written without -Apply. With -Apply (elevated PowerShell 7):
      1. If the Key Vault secret servicenow-r360-password does not exist (or -ResetSecret is given), asks for the svc.r360
         password in a masked prompt and stores it. It is never printed, logged or put on a command line (az reads it from
         a private temp file that is overwritten and deleted). Gives you 'Key Vault Secrets Officer' first if you lack it.
      2. Gives this PC's Azure Arc managed identity 'Key Vault Secrets User' on that one secret, so r360 reads the password
         from Key Vault at run time. The container itself holds no password.
      3. Creates the table r360snqueries in the r360 storage account and gives the Arc identity
         'Storage Table Data Contributor' on that one table (read, add and delete saved queries; nothing else).
      4. Writes SERVICENOW_INSTANCE, SERVICENOW_USER, SERVICENOW_PASSWORD_SECRET and R360_SERVICENOW_QUERY_TABLE into
         C:\ProgramData\r360-local\r360.env (Install-R360Local.ps1 -RefreshEnv keeps them).
    Then run .\Install-R360Local.ps1 -Update -Apply to restart r360 with the new settings.
.EXAMPLE
    .\Set-R360ServiceNow.ps1
.EXAMPLE
    .\Set-R360ServiceNow.ps1 -Apply
.EXAMPLE
    .\Set-R360ServiceNow.ps1 -Apply -ResetSecret
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive operator console script')]
[CmdletBinding()]
param(
    [string]$Instance = 'https://your-instance.service-now.com',
    [string]$ServiceNowUser = 'svc.r360',
    [string]$SecretName = 'servicenow-r360-password',
    [string]$QueryTable = 'r360snqueries',
    [string]$SubscriptionId = '00000000-0000-4000-8000-0000000000b5',
    [string]$EnvFile = 'C:\ProgramData\r360-local\r360.env',
    [switch]$ResetSecret,
    [switch]$Apply
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'R360.Common.psm1') -Force
$cfg = Get-R360Config
function Step([string]$Text) { Write-Host "  $Text" -ForegroundColor Yellow }

# ---------- Prerequisites (read-only) ----------
Write-R360Step 'Checking prerequisites'
if ($env:COMPUTERNAME -ne 'DEVICE02') { throw "Run this on DEVICE02 (this is $env:COMPUTERNAME)." }
if ($Instance -notmatch '^https://[a-z0-9-]+\.service-now\.com$') { throw 'Instance must be https://<name>.service-now.com' }
if ($SecretName -notmatch '^[A-Za-z0-9-]{1,127}$') { throw "Invalid secret name $SecretName" }
if ($QueryTable -notmatch '^[A-Za-z][A-Za-z0-9]{2,62}$') { throw "Invalid table name $QueryTable" }
foreach ($exe in 'az', 'azcmagent') { if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) { throw "$exe is not installed or not on PATH." } }
if ($Apply -and -not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run -Apply from an elevated PowerShell 7 (it writes the r360 settings file under C:\ProgramData).'
}
if (-not (Test-Path -LiteralPath $EnvFile)) { throw "$EnvFile not found. Install local r360 first: .\Install-R360Local.ps1 -Apply" }
$acct = Invoke-R360Az -Arguments @('account', 'show') -AllowFailure
if (-not $acct) { throw "az is not signed in. Run: az login --tenant $($cfg.TenantId)" }
if ($acct.tenantId -ne $cfg.TenantId) { throw "az is signed in to tenant $($acct.tenantId), expected $($cfg.TenantId). Run: az login --tenant $($cfg.TenantId)" }
$null = Invoke-R360Az -Arguments @('account', 'set', '--subscription', $SubscriptionId)
$arc = & azcmagent show -j 2>$null | ConvertFrom-Json
if (-not $arc -or $arc.status -ne 'Connected') { throw 'Azure Arc agent is not connected on this PC (azcmagent show).' }
$arcId = (& az resource show --ids $arc.resourceId --query identity.principalId -o tsv 2>$null)
if (-not $arcId) { throw "Could not read the Arc machine identity of $($arc.resourceId)." }
$arcId = $arcId.Trim()
$kv = Invoke-R360Az -Arguments @('keyvault', 'show', '-n', $cfg.KeyVault, '-g', $cfg.ResourceGroup)
$st = Invoke-R360Az -Arguments @('storage', 'account', 'show', '-n', $cfg.Storage, '-g', $cfg.ResourceGroup)
$me = Invoke-R360Az -Arguments @('ad', 'signed-in-user', 'show')
$secretScope = "$($kv.id)/secrets/$SecretName"
$tableScope = "$($st.id)/tableServices/default/tables/$QueryTable"
Write-Host "  Arc managed identity of this PC: $arcId"
Write-Host "  Key Vault $($cfg.KeyVault), storage account $($cfg.Storage), ServiceNow $Instance as $ServiceNowUser"

$canReadSecrets = { $null = Invoke-R360Az -Arguments @('keyvault', 'secret', 'list', '--vault-name', $cfg.KeyVault) -AllowFailure; $LASTEXITCODE -eq 0 }
$secretExists = { [bool](Invoke-R360Az -Arguments @('keyvault', 'secret', 'show', '--vault-name', $cfg.KeyVault, '--name', $SecretName, '--query', 'id') -AllowFailure) }

# ---------- 1. Password in Key Vault ----------
Write-R360Step "1. Key Vault secret $SecretName (the svc.r360 password)"
if (-not (& $canReadSecrets)) {
    Step "Give $($me.userPrincipalName) 'Key Vault Secrets Officer' on $($cfg.KeyVault)"
    if ($Apply) {
        Set-R360RoleAssignment -PrincipalId $me.id -PrincipalType User -Role 'Key Vault Secrets Officer' -Scope $kv.id
        Wait-R360Condition -Activity 'Key Vault secret permission' -Condition $canReadSecrets -TimeoutSeconds 600 | Out-Null
    }
}
$have = if ($Apply -or (& $canReadSecrets)) { & $secretExists } else { $false }
if ($have -and -not $ResetSecret) { Write-Host '  Secret exists; the password is not changed (use -ResetSecret to replace it).' }
else {
    Step 'Ask for the svc.r360 password (masked) and store it in Key Vault'
    if ($Apply) {
        $secure = Read-Host -AsSecureString -Prompt "Password for $ServiceNowUser on $Instance"
        $plain = [Net.NetworkCredential]::new('', $secure).Password
        if ([string]::IsNullOrEmpty($plain)) { throw 'No password entered. Nothing was stored.' }
        $tmp = New-TemporaryFile
        try {
            Set-R360PrivateFileAcl -Path $tmp.FullName
            [IO.File]::WriteAllText($tmp.FullName, $plain)
            $null = Invoke-R360Az -Arguments @('keyvault', 'secret', 'set', '--vault-name', $cfg.KeyVault, '--name', $SecretName, '--file', $tmp.FullName, '--query', 'id')
        } finally { Remove-R360FileSecurely -Path $tmp.FullName; $plain = $null }
        Write-Host '  Stored (not shown).'
    }
}

# ---------- 2. Arc identity may read that one secret ----------
Write-R360Step "2. Arc identity: 'Key Vault Secrets User' on secret $SecretName"
if ($Apply) { Set-R360RoleAssignment -PrincipalId $arcId -PrincipalType ServicePrincipal -Role 'Key Vault Secrets User' -Scope $secretScope }
else { Step "Would assign 'Key Vault Secrets User' at $secretScope" }

# ---------- 3. Saved-query table ----------
Write-R360Step "3. Table $QueryTable and 'Storage Table Data Contributor' on it for the Arc identity"
$tableArm = "https://management.azure.com$($tableScope)?api-version=2023-05-01"
$tableThere = [bool](Invoke-R360Az -Arguments @('rest', '--method', 'get', '--url', $tableArm) -AllowFailure)
if ($tableThere) { Write-Host "  Table $QueryTable exists" }
else {
    Step "Create table $QueryTable"
    if ($Apply) { $null = Invoke-R360Az -Arguments @('rest', '--method', 'put', '--url', $tableArm, '--body', '{}') }
}
if ($Apply) { Set-R360RoleAssignment -PrincipalId $arcId -PrincipalType ServicePrincipal -Role 'Storage Table Data Contributor' -Scope $tableScope }
else { Step "Would assign 'Storage Table Data Contributor' at $tableScope" }

# ---------- 4. Settings file ----------
Write-R360Step "4. ServiceNow settings in $EnvFile"
$want = [ordered]@{ SERVICENOW_INSTANCE = $Instance; SERVICENOW_USER = $ServiceNowUser; SERVICENOW_PASSWORD_SECRET = $SecretName; R360_SERVICENOW_QUERY_TABLE = $QueryTable }
$lines = @(Get-Content -LiteralPath $EnvFile | Where-Object { $_ -notmatch '^(SERVICENOW_[A-Z_]+|R360_SERVICENOW_[A-Z_]+)=' })
foreach ($k in $want.Keys) { $lines += "$k=$($want[$k])"; Write-Host "  $k=$($want[$k])" }
if ($Apply) { Set-Content -LiteralPath $EnvFile -Value $lines -Encoding utf8NoBOM }

Write-Host ''
if ($Apply) {
    Write-Host 'Done. Restart r360 with the new settings:' -ForegroundColor Green
    Write-Host "  & '$PSScriptRoot\Install-R360Local.ps1' -Update -Apply"
} else {
    Write-Host 'Dry run: nothing was changed. Run again with -Apply from an elevated PowerShell 7.' -ForegroundColor Cyan
}
