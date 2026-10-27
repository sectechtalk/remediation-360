#Requires -Version 7.4
<#
.SYNOPSIS
    Creates the r360 GitHub App with the manifest flow and stores its private key in Key Vault as a non-exportable HSM key.
.DESCRIPTION
    1. Starts a one-shot local listener on http://127.0.0.1:<Port> (TcpListener, no admin/urlacl needed).
    2. Opens your browser to a local page that posts the manifest to GitHub. You click "Create GitHub App" once.
    3. GitHub redirects back with a one-time code; the state value is verified; the code is converted via
       POST /app-manifests/{code}/conversions.
    4. The PEM is written to a temp file readable only by you, imported into Key Vault (--protection hsm, sign only),
       then overwritten and deleted. The client secret and webhook secret in the response are discarded, never stored.
    5. Opens the installation page (only the remediations repo). The script polls with an App JWT signed by Key Vault
       until the installation exists and is limited to that repository.
    The remediations main ruleset (App-only merge) is NOT changed here; it is a later, gated step once r360 can publish.
    Idempotent: if the Key Vault key already carries an app-id tag and the App answers, nothing is recreated. Supports -WhatIf.
.EXAMPLE
    ./New-R360GitHubApp.ps1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateRange(1024, 65535)][int]$Port = 8765,
    [int]$TimeoutMinutes = 15
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'R360.Common.psm1') -Force
$cfg = Get-R360Config
$log = Enable-R360Log -Name 'New-R360GitHubApp'

function Receive-R360ManifestCode {
    # One-shot HTTP listener: GET / -> auto-submitting manifest form; GET /callback?code&state -> returns the code.
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$ManifestJson, [string]$State, [int]$ListenPort, [int]$TimeoutSeconds, [string]$NewAppUrl)
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $ListenPort)
    $listener.Start()
    try {
        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        $action = "$($NewAppUrl)?state=$State"
        $encoded = [System.Net.WebUtility]::HtmlEncode($ManifestJson)
        Start-Process "http://127.0.0.1:$ListenPort/"
        Write-R360Step "Browser opened. Review the App and click 'Create GitHub App for $($cfg.GitHubOrg)'. Waiting until $($deadline.ToString('HH:mm:ss'))."
        while ((Get-Date) -lt $deadline) {
            if (-not $listener.Pending()) { Start-Sleep -Milliseconds 250; continue }
            $client = $listener.AcceptTcpClient()
            try {
                $stream = $client.GetStream()
                $reader = [IO.StreamReader]::new($stream, [Text.Encoding]::ASCII, $false, 4096, $true)
                $line = $reader.ReadLine()
                while (($h = $reader.ReadLine())) { $null = $h }
                $target = if ($line -match '^GET (\S+) HTTP') { $Matches[1] } else { '' }
                $uri = [Uri]::new("http://127.0.0.1$target")
                $q = [System.Web.HttpUtility]::ParseQueryString($uri.Query)
                $code = $null
                if ($uri.AbsolutePath -eq '/') {
                    $html = "<!doctype html><html><body><p>Sending the r360 GitHub App manifest to GitHub...</p><form id=f method=post action=""$action""><input type=hidden name=manifest value=""$encoded""></form><script>document.getElementById('f').submit()</script></body></html>"
                } elseif ($uri.AbsolutePath -eq '/callback' -and $q['state'] -eq $State -and $q['code'] -match '^[A-Za-z0-9_-]+$') {
                    $code = $q['code']; $html = '<!doctype html><html><body><p>r360: code received. You can close this tab and return to PowerShell.</p></body></html>'
                } elseif ($uri.AbsolutePath -eq '/callback') {
                    $html = '<!doctype html><html><body><p>r360: state mismatch - ignored.</p></body></html>'
                    Write-Warning 'Callback with a wrong or missing state was ignored.'
                } else { $html = '' }
                $body = [Text.Encoding]::UTF8.GetBytes($html)
                $status = if ($html) { '200 OK' } else { '404 Not Found' }
                $hdr = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 $status`r`nContent-Type: text/html; charset=utf-8`r`nContent-Length: $($body.Length)`r`nCache-Control: no-store`r`nConnection: close`r`n`r`n")
                $stream.Write($hdr, 0, $hdr.Length); $stream.Write($body, 0, $body.Length); $stream.Flush()
                if ($code) { return $code }
            } finally { $client.Dispose() }
        }
        throw "Timed out after $TimeoutSeconds s waiting for the GitHub App approval."
    } finally { $listener.Stop() }
}

try {
    Write-R360Step "Log: $log"
    & (Join-Path $PSScriptRoot 'Test-R360Prereqs.ps1') -Stage Tools | Out-Null
    $timeout = $TimeoutMinutes * 60
    $kv = Invoke-R360Az -Arguments @('keyvault', 'show', '-n', $cfg.KeyVault, '-g', $cfg.ResourceGroup) -AllowFailure
    $mi = Invoke-R360Az -Arguments @('identity', 'show', '-n', $cfg.Identity, '-g', $cfg.ResourceGroup) -AllowFailure
    if (-not $kv -or -not $mi) {
        if ($WhatIfPreference) { Write-R360Step "WhatIf: Key Vault/identity not created yet; would run the manifest flow for $($cfg.GitHubAppName), import key '$($cfg.GitHubAppKey)' (HSM, non-exportable), and wait for the installation on $($cfg.GitHubOrg)/$($cfg.RemediationsRepo)."; return }
        throw 'Run New-R360Infrastructure.ps1 first.'
    }

    # sectechtalk may be a user account or an organization; the manifest and install URLs differ.
    $owner = Invoke-R360Gh -Arguments @('api', "users/$($cfg.GitHubOrg)")
    $newAppUrl = if ($owner.type -eq 'Organization') { "https://github.com/organizations/$($cfg.GitHubOrg)/settings/apps/new" } else { 'https://github.com/settings/apps/new' }
    $appSettingsUrl = if ($owner.type -eq 'Organization') { "https://github.com/organizations/$($cfg.GitHubOrg)/settings/apps" } else { 'https://github.com/settings/apps' }
    Write-R360Step "GitHub owner $($cfg.GitHubOrg) is a $($owner.type)"

    # Existing App?
    $key = Invoke-R360Az -Arguments @('keyvault', 'key', 'show', '--vault-name', $cfg.KeyVault, '-n', $cfg.GitHubAppKey) -AllowFailure
    $appId = if ($key -and $key.tags -and $key.tags.PSObject.Properties['app-id']) { $key.tags.'app-id' } else { $null }
    $ghApp = $null
    if ($appId) {
        try { $ghApp = Invoke-R360GitHubAsApp -AppId $appId -Path '/app' } catch { throw "Key '$($cfg.GitHubAppKey)' says App $appId but GitHub rejected its JWT: $($_.Exception.Message)" }
        Write-R360Step "GitHub App $($ghApp.slug) (id $appId) exists; key is in Key Vault."
    } elseif ($key) {
        throw "Key '$($cfg.GitHubAppKey)' exists without an app-id tag. Inspect it in Key Vault before re-running."
    } else {
        $manifest = [ordered]@{
            name = $cfg.GitHubAppName; url = "https://github.com/$($cfg.GitHubOrg)/$($cfg.ProductRepo)"; public = $false
            redirect_url = "http://127.0.0.1:$Port/callback"
            hook_attributes = @{ url = 'https://example.invalid/r360-webhooks-disabled'; active = $false }
            default_permissions = [ordered]@{ contents = 'write'; pull_requests = 'write'; metadata = 'read'; actions = 'read'; checks = 'read' }
            default_events = @()
        }
        $manifestJson = $manifest | ConvertTo-Json -Depth 5 -Compress
        Write-R360Step "Manifest: $manifestJson"
        if (-not $PSCmdlet.ShouldProcess("$($cfg.GitHubOrg)/$($cfg.GitHubAppName)", 'Create GitHub App via manifest (browser approval), import key to Key Vault HSM')) { return }
        Add-Type -AssemblyName System.Web
        $state = ConvertTo-R360Base64Url ([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(24))
        $code = Receive-R360ManifestCode -ManifestJson $manifestJson -State $state -ListenPort $Port -TimeoutSeconds $timeout -NewAppUrl $newAppUrl
        $conv = Invoke-RestMethod -Method POST -Uri "https://api.github.com/app-manifests/$code/conversions" -Headers @{ Accept = 'application/vnd.github+json'; 'X-GitHub-Api-Version' = '2022-11-28' }
        $appId = "$($conv.id)"
        $pem = Join-Path ([IO.Path]::GetTempPath()) ("r360-" + [guid]::NewGuid().ToString('n') + '.pem')
        try {
            New-Item -ItemType File -Path $pem -Force -WhatIf:$false | Out-Null
            Set-R360PrivateFileAcl -Path $pem -WhatIf:$false
            [IO.File]::WriteAllText($pem, $conv.pem)
            $conv.pem = $null; $conv.client_secret = $null; $conv.webhook_secret = $null
            Invoke-R360Az -Arguments @('keyvault', 'key', 'import', '--vault-name', $cfg.KeyVault, '-n', $cfg.GitHubAppKey, '--pem-file', $pem, '--protection', 'hsm',
                '--ops', 'sign', '--tags', "app-id=$appId", "slug=$($conv.slug)", "client-id=$($conv.client_id)") | Out-Null
        } finally { Remove-R360FileSecurely -Path $pem -WhatIf:$false -Confirm:$false }
        Write-R360Step "GitHub App $($conv.slug) created (id $appId). Private key is in Key Vault only; local PEM overwritten and deleted."
        Write-R360Step "The manifest flow also issued a client secret that r360 never uses. Optional: delete it at $appSettingsUrl/$($conv.slug)"
        $ghApp = Wait-R360Condition -Activity 'App JWT accepted' -TimeoutSeconds 120 -IntervalSeconds 5 -Condition {
            try { Invoke-R360GitHubAsApp -AppId $appId -Path '/app' } catch { $null } }
    }

    # MI may sign with the key (key scope only)
    $keyId = "$($kv.id)/keys/$($cfg.GitHubAppKey)"
    Set-R360RoleAssignment -PrincipalId $mi.principalId -PrincipalType ServicePrincipal -Role 'Key Vault Crypto User' -Scope $keyId -WhatIf:$WhatIfPreference

    # Installation on remediations only
    $repoId = (Invoke-R360Gh -Arguments @('api', "repos/$($cfg.GitHubOrg)/$($cfg.RemediationsRepo)", '--jq', '.id'))
    $inst = @(Invoke-R360GitHubAsApp -AppId $appId -Path '/app/installations') | Where-Object { $_.account.login -eq $cfg.GitHubOrg } | Select-Object -First 1
    if (-not $inst) {
        if (-not $PSCmdlet.ShouldProcess("$($cfg.GitHubOrg)/$($cfg.RemediationsRepo)", "Install $($ghApp.slug) (browser click)")) { return }
        $orgId = $owner.id
        Start-Process "https://github.com/apps/$($ghApp.slug)/installations/new/permissions?target_id=$orgId&repository_ids[]=$repoId"
        Write-R360Step "Browser opened: choose 'Only select repositories' = $($cfg.RemediationsRepo) and click Install."
        $inst = Wait-R360Condition -Activity "installation of $($ghApp.slug)" -TimeoutSeconds $timeout -IntervalSeconds 10 -Condition {
            @(Invoke-R360GitHubAsApp -AppId $appId -Path '/app/installations') | Where-Object { $_.account.login -eq $cfg.GitHubOrg } | Select-Object -First 1 }
    }
    # Verify scope as the App itself; if wrong, open the install's settings page and poll until it is fixed (no re-run needed).
    $want = "$($cfg.GitHubOrg)/$($cfg.RemediationsRepo)"
    $getScope = {
        $i = @(Invoke-R360GitHubAsApp -AppId $appId -Path '/app/installations') | ForEach-Object { $_ } | Where-Object { $_.id -eq $inst.id } | Select-Object -First 1
        if (-not $i) { return 'missing' }
        if ($i.repository_selection -ne 'selected') { return 'all' }
        $t = Invoke-R360GitHubAsApp -AppId $appId -Method POST -Path "/app/installations/$($inst.id)/access_tokens"
        $r = @((Invoke-R360GitHubAsApp -AppId $appId -Path '/installation/repositories' -Token $t.token).repositories.full_name)
        $t = $null
        return ($r -join ', ')
    }
    $scope = & $getScope
    if ($scope -ne $want) {
        Start-Process "https://github.com/settings/installations/$($inst.id)"
        Write-R360Step "Installation $($inst.id) currently covers [$scope]. Browser opened: set 'Only select repositories' = $($cfg.RemediationsRepo) only, Save. Polling every 10 s."
        Wait-R360Condition -Activity "installation scope = $want" -TimeoutSeconds $timeout -IntervalSeconds 10 -Condition { (& $getScope) -eq $want } | Out-Null
    }
    $repos = @($want)
    Write-R360Step "Installation $($inst.id) limited to $($repos[0])."

    Set-R360ContainerAppEnv -Values ([ordered]@{ R360_GITHUB_APP_ID = $appId; R360_GITHUB_INSTALLATION_ID = "$($inst.id)"; R360_GITHUB_KEY_NAME = $cfg.GitHubAppKey; R360_KEY_VAULT = $cfg.KeyVault }) -WhatIf:$WhatIfPreference
    Write-R360Step 'Deferred (not done here): App-only merge ruleset on remediations main - turn on once r360 can publish.'
    Write-R360Step 'New-R360GitHubApp finished.'
} finally { Disable-R360Log }
