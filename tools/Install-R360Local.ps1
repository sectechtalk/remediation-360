#Requires -Version 7.4
<#
.SYNOPSIS
  Run r360 always-on and private on this PC (DEVICE02) as a local Docker container. Dry run by default.
.DESCRIPTION
  Free, local-only hosting in place of Azure Container Apps.
  - Runs from its own clean copy, C:\path\to\remediation-360-local (a git worktree of origin/main from C:\path\to\remediation-360), so unfinished
    edits in your working checkout never reach the running app.
  - Container "r360" (image r360:local, built here, nothing pulled from ghcr.io), --restart always, published on
    http://localhost:3660 bound to 127.0.0.1 only. Docker Desktop starts at logon, and the container with it.
  - Identity: the container has no secret, certificate or key. It gets short-lived tokens from this PC's Azure Arc
    managed identity through tools/r360-identity-helper.mjs, which runs as SYSTEM from the scheduled task
    "r360 identity helper (local)" (at startup, 127.0.0.1:3661, shared header, allow list of 3 resources).
    That identity is trusted by r360-web and r360-write through a federated credential, exactly like id-r360 in Azure,
    and holds the same narrow roles: sign with the GitHub App key, append to the audit table, write the audit export.
  - Settings are copied once from the Azure Container App's environment variables (ids only, no secrets) into
    C:\ProgramData\r360-local\r360.env, with the public URL changed to http://localhost:3660.
  Azure changes made by -Apply are additive only (redirect URIs, federated credentials, role assignments). This script
  never stops, scales or deletes the Azure Container App.
.EXAMPLE
  .\Install-R360Local.ps1                       # dry run: checks and shows what it would do
.EXAMPLE
  .\Install-R360Local.ps1 -Apply                # install and start (elevated PowerShell)
.EXAMPLE
  .\Install-R360Local.ps1 -Update -Apply        # pull latest main into the run copy, rebuild, restart
.EXAMPLE
  .\Install-R360Local.ps1 -Status               # helper task, container, health
.EXAMPLE
  .\Install-R360Local.ps1 -Remove -Apply        # stop and remove container + helper task (data folder kept)
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive operator console script')]
[CmdletBinding()]
param(
  [switch]$Apply,
  [switch]$Update,
  [switch]$Remove,
  [switch]$Status,
  [switch]$SkipAzure,
  [switch]$RefreshEnv,
  [string]$Ref = 'origin/main',
  [string]$Source = 'C:\path\to\remediation-360',
  [string]$RunDir = 'C:\path\to\remediation-360-local',
  [string]$DataDir = 'C:\ProgramData\r360-local',
  [int]$Port = 3660,
  [int]$IdentityPort = 3661,
  [string]$ContainerName = 'r360',
  [string]$ImageName = 'r360:local',
  [string]$HelperTask = 'r360 identity helper (local)',
  [string]$SubscriptionId = '00000000-0000-4000-8000-0000000000b5',
  [string]$TenantId = '00000000-0000-4000-8000-0000000000b1',
  [string]$ResourceGroup = 'rg-r360',
  [string]$ContainerApp = 'app-r360',
  [string]$WebAppId = '00000000-0000-4000-8000-0000000000b6',
  [string]$WriteAppId = '00000000-0000-4000-8000-0000000000b7',
  [string]$KeyVault = 'kv-r360-abc123',
  [string]$GitHubKeyName = 'github-app-r360',
  [string]$StorageAccount = 'str360abc123',
  [string]$AuditTable = 'r360audit',
  [string]$AuditContainer = 'r360audit-export',
  [string]$FicName = 'r360-local-DEVICE02-arc',
  [string]$LlmSecretName = 'r360-llm-api-key'
)
$ErrorActionPreference = 'Stop'
$mode = if ($Apply) { 'APPLY' } else { 'DRY RUN' }
$what = if ($Remove) { 'REMOVE' } elseif ($Update) { 'UPDATE' } elseif ($Status) { 'STATUS' } else { 'INSTALL' }
Write-Host "r360 local hosting - $what - $mode" -ForegroundColor Cyan

$url = "http://localhost:$Port"
$envFile = Join-Path $DataDir 'r360.env'
$headerFile = Join-Path $DataDir 'identity-header'
$helperFile = Join-Path $DataDir 'r360-identity-helper.mjs'
$helperRunner = Join-Path $DataDir 'Run-IdentityHelper.ps1'
$logDir = Join-Path $DataDir 'logs'
$rgId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
$scopes = [ordered]@{
  'Key Vault Crypto User'         = "$rgId/providers/Microsoft.KeyVault/vaults/$KeyVault/keys/$GitHubKeyName"
  'r360 Audit Table Append'       = "$rgId/providers/Microsoft.Storage/storageAccounts/$StorageAccount/tableServices/default/tables/$AuditTable"
  'Storage Blob Data Contributor' = "$rgId/providers/Microsoft.Storage/storageAccounts/$StorageAccount/blobServices/default/containers/$AuditContainer"
}

function Step([string]$Text) { Write-Host "  $Text" -ForegroundColor Yellow }
function Invoke-Native([string]$Exe, [string[]]$ArgList, [switch]$Quiet) {
  Step ("$Exe " + ($ArgList -join ' '))
  if (-not $Apply) { return }
  if ($Quiet) { $out = & $Exe @ArgList 2>&1 } else { & $Exe @ArgList | Out-Host }
  if ($LASTEXITCODE -ne 0) { if ($Quiet) { $out | Out-Host }; throw "$Exe failed with exit code $LASTEXITCODE" }
}
# Reads through az with retries: Graph and ARM sometimes time out once (seen 2026-11-15 on az ad app show). A read that
# still fails stops the script, because acting on a missing answer could overwrite a setting (redirect URIs are replaced
# as a whole list).
function Get-AzJson([string[]]$ArgList, [string]$What, [int]$Tries = 4) {
  for ($i = 1; ; $i++) {
    $out = & az @ArgList -o json 2>$null
    if ($LASTEXITCODE -eq 0 -and $out) { return ($out | ConvertFrom-Json) }
    if ($i -ge $Tries) { throw "Could not read $What after $Tries tries (az exit code $LASTEXITCODE). Nothing was changed for it; run the script again." }
    Write-Host "  [retry] reading $What failed (try $i of $Tries); waiting $(5 * $i) s" -ForegroundColor DarkYellow
    Start-Sleep -Seconds (5 * $i)
  }
}
function Get-ArcPrincipalId {
  $show = & azcmagent show -j 2>$null | ConvertFrom-Json
  if (-not $show -or $show.status -ne 'Connected') { throw 'Azure Arc agent is not connected on this PC (azcmagent show).' }
  $id = & az resource show --ids $show.resourceId --query identity.principalId -o tsv 2>$null
  if (-not $id) { throw "Could not read the Arc machine identity of $($show.resourceId)." }
  return $id.Trim()
}
function Test-Helper {
  if (-not (Test-Path -LiteralPath $headerFile)) { return 'no header file' }
  try {
    $h = (Get-Content -LiteralPath $headerFile -Raw).Trim()
    $r = Invoke-RestMethod "http://127.0.0.1:$IdentityPort/token?resource=https%3A%2F%2Fvault.azure.net" -Headers @{ 'X-IDENTITY-HEADER' = $h } -TimeoutSec 20
    if ($r.access_token) { return 'PASS' } else { return 'no token' }
  } catch { return "FAIL $($_.Exception.Message)" }
}
function Test-Health {
  $ok = $false
  for ($i = 0; $i -lt 45 -and -not $ok; $i++) {
    try { $r = Invoke-WebRequest -Uri "$url/" -UseBasicParsing -TimeoutSec 3; $ok = $r.StatusCode -eq 200 } catch { Start-Sleep -Seconds 1 }
  }
  $login = (& curl.exe -s -o NUL -w '%{http_code} %{redirect_url}' --max-time 15 "$url/auth/signin") -join ''
  $selfcheck = @()
  for ($i = 0; $i -lt 30 -and $selfcheck.Count -lt 3; $i++) {
    $selfcheck = @(& docker logs $ContainerName 2>&1 | Where-Object { $_ -match '^selfcheck ' } | Select-Object -Last 3)
    if ($selfcheck.Count -lt 3) { Start-Sleep -Seconds 2 }
  }
  $listen = @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LocalAddress -Unique)
  $restart = (& docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' $ContainerName 2>$null) -join ''
  $rows = @(
    [pscustomobject]@{ Check = 'Identity helper (vault token)'; Result = $(if ((Test-Helper) -eq 'PASS') { 'PASS' } else { 'FAIL' }); Detail = "127.0.0.1:$IdentityPort" }
    [pscustomobject]@{ Check = "Home page $url"; Result = $(if ($ok) { 'PASS' } else { 'FAIL' }); Detail = $(if ($ok) { 'HTTP 200' } else { "no answer; docker logs $ContainerName" }) }
    [pscustomobject]@{ Check = '/auth/signin redirect'; Result = $(if ($login -match '^302 https://login\.microsoftonline\.com/' -and $login -match [regex]::Escape([uri]::EscapeDataString("$url/auth/callback"))) { 'PASS' } else { 'FAIL' }); Detail = $(if ($login.Length -gt 90) { $login.Substring(0, 90) + '...' } else { $login }) }
    [pscustomobject]@{ Check = 'Listening on 127.0.0.1 only'; Result = $(if ($listen.Count -and -not ($listen | Where-Object { $_ -ne '127.0.0.1' })) { 'PASS' } else { 'FAIL' }); Detail = ($listen -join ', ') }
    [pscustomobject]@{ Check = 'Container restart policy'; Result = $(if ($restart -eq 'always') { 'PASS' } else { 'FAIL' }); Detail = $restart }
  )
  foreach ($line in $selfcheck) {
    $name = ($line -split ' ')[1].TrimEnd(':')
    $rows += [pscustomobject]@{ Check = "selfcheck $name"; Result = $(if ($line -match ': PASS') { 'PASS' } else { 'FAIL' }); Detail = $(if ($line.Length -gt 100) { $line.Substring(0, 100) + '...' } else { $line }) }
  }
  if ($selfcheck.Count -lt 3) { $rows += [pscustomobject]@{ Check = 'selfcheck'; Result = 'FAIL'; Detail = "only $($selfcheck.Count) of 3 lines in docker logs" } }
  $rows | Format-Table -AutoSize | Out-Host
  return -not ($rows | Where-Object Result -ne 'PASS')
}

# ---------- Status ----------
if ($Status) {
  $t = Get-ScheduledTask -TaskName $HelperTask -ErrorAction SilentlyContinue
  Write-Host "  Task '$HelperTask': $(if ($t) { $t.State } else { 'not installed' })"
  Write-Host ("  Container: " + ((& docker ps -a --filter "name=^$ContainerName$" --format '{{.Status}}  {{.Image}}') -join ''))
  if (Test-Path -LiteralPath (Join-Path $RunDir '.git')) { Write-Host ("  Run copy: " + ((& git -C $RunDir log -1 --oneline) -join '')) }
  $null = Test-Health
  return
}

# ---------- Prerequisites ----------
$problems = @()
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { $problems += 'Run this from an elevated PowerShell (the identity helper task runs as SYSTEM).' }
$node = (Get-Command node -ErrorAction SilentlyContinue).Source
if (-not $node) { $problems += 'Node.js not found.' }
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { $problems += 'git not found.' }
& docker info --format '{{.OSType}}' 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) { $problems += 'Docker engine is not running. Start Docker Desktop.' }
$azUser = (& az account show --query user.name -o tsv 2>$null)
if ($LASTEXITCODE -ne 0 -or -not $azUser) { $problems += 'Azure CLI not signed in. Run: az login --tenant contoso.com' }
if ($problems) { $problems | ForEach-Object { Write-Host "  [FAIL] $_" -ForegroundColor Red }; throw 'Fix the items above, then re-run.' }
Write-Host "  az signed in as $azUser"

# ---------- Remove ----------
if ($Remove) {
  Invoke-Native 'docker' @('rm', '-f', $ContainerName) -Quiet
  Step "Stop and unregister scheduled task '$HelperTask'"
  if ($Apply -and (Get-ScheduledTask -TaskName $HelperTask -ErrorAction SilentlyContinue)) {
    Stop-ScheduledTask -TaskName $HelperTask -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $HelperTask -Confirm:$false
  }
  Get-CimInstance Win32_Process -Filter "Name='node.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like '*r360-identity-helper.mjs*' } | ForEach-Object {
    Step "Stop identity helper (PID $($_.ProcessId))"; if ($Apply) { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
  }
  Write-Host "  Kept: $DataDir, $RunDir and all Azure settings (redirect URIs, federated credential, roles)."
  if (-not $Apply) { Write-Host 'Dry run only. Re-run with -Apply.' -ForegroundColor Cyan }
  return
}

# ---------- Azure (additive) ----------
$llmSecretExists = $false
if (-not $SkipAzure) {
  $arcId = Get-ArcPrincipalId
  Write-Host "  Arc managed identity of this PC: $arcId"
  foreach ($app in @(@{ Id = $WebAppId; Path = '/auth/callback' }, @{ Id = $WriteAppId; Path = '/auth/write/callback' })) {
    $a = Get-AzJson @('ad', 'app', 'show', '--id', $app.Id, '--query', '{name:displayName,redirects:web.redirectUris}') "app registration $($app.Id)"
    if (-not $a.name) { throw "App registration $($app.Id) was not found." }
    $want = "$url$($app.Path)"
    if (@($a.redirects) -contains $want) { Write-Host "  $($a.name): redirect URI $want present" }
    else { Invoke-Native 'az' (@('ad', 'app', 'update', '--id', $app.Id, '--web-redirect-uris') + @($a.redirects) + $want) -Quiet }
    $fics = @(Get-AzJson @('ad', 'app', 'federated-credential', 'list', '--id', $app.Id) "federated credentials of $($a.name)")
    if ($fics | Where-Object { $_.subject -eq $arcId }) { Write-Host "  $($a.name): federated credential for $arcId present" }
    else {
      $json = @{ name = $FicName; issuer = "https://login.microsoftonline.com/$TenantId/v2.0"; subject = $arcId; audiences = @('api://AzureADTokenExchange')
        description = 'r360 local hosting on DEVICE02: trust this PC''s Azure Arc managed identity' } | ConvertTo-Json -Compress
      $tmp = New-TemporaryFile
      if ($Apply) { Set-Content -LiteralPath $tmp -Value $json -Encoding utf8NoBOM }
      try { Invoke-Native 'az' @('ad', 'app', 'federated-credential', 'create', '--id', $app.Id, '--parameters', "@$tmp") -Quiet } finally { Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue }
    }
  }
  # Summary provider key: only when the secret exists (checked through ARM, so no secret read permission is needed).
  $llmSecretId = "$rgId/providers/Microsoft.KeyVault/vaults/$KeyVault/secrets/$LlmSecretName"
  $llmSecretExists = [bool](& az rest --method get --url "https://management.azure.com$($llmSecretId)?api-version=2023-07-01" --query id -o tsv 2>$null)
  if ($llmSecretExists) { $scopes['Key Vault Secrets User'] = $llmSecretId; Write-Host "  Key Vault secret $LlmSecretName exists: local r360 will read the summary API key from it" }
  else { Write-Host "  Key Vault secret $LlmSecretName not found: summaries stay on the watcher handoff (Set-R360ChangeRequests.ps1 -Apply -SkipExchange -SetApiKey adds it)" }
  $have = @(& az role assignment list --assignee $arcId --all --subscription $SubscriptionId --query '[].{role:roleDefinitionName,scope:scope}' -o json | ConvertFrom-Json)
  foreach ($role in $scopes.Keys) {
    if ($have | Where-Object { $_.role -eq $role -and $_.scope -eq $scopes[$role] }) { Write-Host "  Role '$role' present" }
    else { Invoke-Native 'az' @('role', 'assignment', 'create', '--assignee-object-id', $arcId, '--assignee-principal-type', 'ServicePrincipal', '--role', $role, '--scope', $scopes[$role], '--subscription', $SubscriptionId) -Quiet }
  }
}

# ---------- Data folder (SYSTEM + Administrators full, you read) ----------
$user = "$env:USERDOMAIN\$env:USERNAME"
Step "Create $DataDir and $logDir (SYSTEM and Administrators full control, $user read; inheritance off)"
if ($Apply) {
  New-Item -ItemType Directory -Force -Path $DataDir, $logDir | Out-Null
  & icacls $DataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "${user}:(OI)(CI)RX" | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'icacls failed' }
}
Step "Shared header value in $headerFile (create once, 32 random bytes)"
if ($Apply -and -not (Test-Path -LiteralPath $headerFile)) {
  Set-Content -LiteralPath $headerFile -Value ([Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))) -NoNewline -Encoding ascii
}

# ---------- Run copy ----------
Invoke-Native 'git' @('-C', $Source, 'fetch', 'origin')
if (Test-Path -LiteralPath (Join-Path $RunDir '.git')) { Invoke-Native 'git' @('-C', $RunDir, 'checkout', '--detach', $Ref) -Quiet }
else { Invoke-Native 'git' @('-C', $Source, 'worktree', 'add', '--detach', $RunDir, $Ref) -Quiet }
$sha = if ($Apply) { (& git -C $RunDir rev-parse --short HEAD).Trim() } else { 'dryrun' }

# ---------- Identity helper (SYSTEM, at startup) ----------
Step "Copy $RunDir\tools\r360-identity-helper.mjs to $helperFile (admin-only folder, so the SYSTEM task never runs user-writable code)"
if ($Apply) { Copy-Item -LiteralPath (Join-Path $RunDir 'tools\r360-identity-helper.mjs') -Destination $helperFile -Force }
$runnerText = @"
# Written by Install-R360Local.ps1. Started at boot as SYSTEM by the scheduled task '$HelperTask'.
`$ErrorActionPreference = 'Continue'
`$env:R360_LOCAL_DATA = '$DataDir'
`$env:R360_IDENTITY_PORT = '$IdentityPort'
while (`$true) {
  & '$node' '$helperFile'
  Add-Content -LiteralPath '$logDir\identity-helper.log' -Value "`$(Get-Date -Format o) helper exited with code `$LASTEXITCODE; restarting in 5 seconds"
  Start-Sleep -Seconds 5
}
"@
Step "Write $helperRunner"
if ($Apply) { Set-Content -LiteralPath $helperRunner -Value $runnerText -Encoding utf8NoBOM }
# 64-bit Windows PowerShell from the real System32 (Task Scheduler is 64-bit; pwsh on this PC is the 32-bit build).
$pwsh = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
Step "Register scheduled task '$HelperTask' as SYSTEM at startup: $pwsh -File $helperRunner"
if ($Apply) {
  if (Get-ScheduledTask -TaskName $HelperTask -ErrorAction SilentlyContinue) { Stop-ScheduledTask -TaskName $HelperTask -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName $HelperTask -Confirm:$false }
  Get-CimInstance Win32_Process -Filter "Name='node.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like '*r360-identity-helper.mjs*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
  $action = New-ScheduledTaskAction -Execute $pwsh -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$helperRunner`""
  $trigger = New-ScheduledTaskTrigger -AtStartup
  $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
  $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
  Register-ScheduledTask -TaskName $HelperTask -Action $action -Trigger $trigger -Settings $settings -Principal $principal `
    -Description "Arc managed identity tokens for the local r360 container on 127.0.0.1:$IdentityPort. Managed by C:\path\to\remediation-360\tools\Install-R360Local.ps1" | Out-Null
  Start-ScheduledTask -TaskName $HelperTask
  $h = 'starting'; for ($i = 0; $i -lt 20 -and $h -ne 'PASS'; $i++) { Start-Sleep -Seconds 1; $h = Test-Helper }
  if ($h -ne 'PASS') { throw "Identity helper is not answering: $h. See $logDir\identity-helper.log" }
  Write-Host '  Identity helper answers with a Key Vault token (not shown).'
}

# ---------- Settings ----------
if ($RefreshEnv -or -not (Test-Path -LiteralPath $envFile)) {
  Step "Write $envFile from $ContainerApp's environment variables (values only; secret references and ServiceNow skipped)"
  $vars = & az containerapp show -g $ResourceGroup -n $ContainerApp --subscription $SubscriptionId --query 'properties.template.containers[0].env' -o json 2>$null | ConvertFrom-Json
  if (-not $vars) { throw "Could not read $ContainerApp settings." }
  $lines = @("# Written by Install-R360Local.ps1 from $ContainerApp on $(Get-Date -Format o). Rerun with -RefreshEnv to rebuild.")
  foreach ($v in $vars) {
    if ($v.secretRef -or $v.name -match '^(SERVICENOW_|R360_PUBLIC_URL$|R360_IMAGE_TAG$|IDENTITY_)') { continue }
    $lines += "$($v.name)=$($v.value)"
  }
  $lines += "R360_PUBLIC_URL=$url"
  $lines += "IDENTITY_ENDPOINT=http://host.docker.internal:$IdentityPort/token"
  # ServiceNow settings come from Set-R360ServiceNow.ps1, not from the Container App: keep them.
  if (Test-Path -LiteralPath $envFile) { $lines += @(Get-Content -LiteralPath $envFile | Where-Object { $_ -match '^(SERVICENOW_[A-Z_]+|R360_SERVICENOW_[A-Z_]+)=' }) }
  if ($Apply) {
    $lines += "IDENTITY_HEADER=$((Get-Content -LiteralPath $headerFile -Raw).Trim())"
    Set-Content -LiteralPath $envFile -Value $lines -Encoding utf8NoBOM
  }
} else { Write-Host "  Keeping $envFile (use -RefreshEnv to rebuild it from $ContainerApp)" }
# The summary key's secret name (never the key) goes into the settings file whenever the secret exists.
if ($llmSecretExists) {
  $current = if (Test-Path -LiteralPath $envFile) { @(Get-Content -LiteralPath $envFile) } else { @() }
  if ($current -notcontains "R360_LLM_API_KEY_SECRET=$LlmSecretName") {
    Step "Add R360_LLM_API_KEY_SECRET=$LlmSecretName to $envFile"
    if ($Apply) { Set-Content -LiteralPath $envFile -Value (@($current | Where-Object { $_ -notmatch '^R360_LLM_API_KEY_SECRET=' }) + "R360_LLM_API_KEY_SECRET=$LlmSecretName") -Encoding utf8NoBOM }
  }
}

# ---------- Container ----------
Invoke-Native 'docker' @('build', '--pull', '-t', $ImageName, $RunDir) -Quiet
Invoke-Native 'docker' @('rm', '-f', $ContainerName) -Quiet
Invoke-Native 'docker' @('run', '-d', '--name', $ContainerName, '--restart', 'always', '-p', "127.0.0.1:${Port}:8080",
  '--env-file', $envFile, '-e', "R360_IMAGE_TAG=local-$sha", '--label', 'managed-by=Install-R360Local.ps1', $ImageName) -Quiet

# ---------- Docker Desktop at logon ----------
$dd = Join-Path $env:APPDATA 'Docker\settings-store.json'
if (Test-Path -LiteralPath $dd) {
  $cfg = Get-Content -LiteralPath $dd -Raw | ConvertFrom-Json
  if ($cfg.AutoStart -eq $true) { Write-Host '  Docker Desktop already starts at logon' }
  else {
    Step "Set AutoStart=true in $dd (Docker Desktop starts at logon; takes effect at next logon)"
    if ($Apply) { Copy-Item -LiteralPath $dd -Destination "$dd.pre-r360-$(Get-Date -Format yyyyMMddHHmm)"; $cfg | Add-Member -NotePropertyName AutoStart -NotePropertyValue $true -Force; $cfg | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $dd -Encoding utf8NoBOM }
  }
} else { Write-Host "  [WARN] $dd not found; turn on Docker Desktop > Settings > General > Start Docker Desktop when you sign in." -ForegroundColor DarkYellow }

if ($Apply) {
  if (Test-Health) { Write-Host "r360 is running at $url (local-$sha) and comes back by itself after a restart." -ForegroundColor Green }
  else { Write-Host "Health check failed. Run: .\Install-R360Local.ps1 -Status   and   docker logs $ContainerName" -ForegroundColor Red; exit 1 }
} else { Write-Host 'Dry run only. Re-run with -Apply.' -ForegroundColor Cyan }
