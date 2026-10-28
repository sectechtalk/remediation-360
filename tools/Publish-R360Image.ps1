#Requires -Version 7.4
<#
.SYNOPSIS
    Tests, builds, pushes and deploys the r360 web image to app-r360, then verifies the live sign-in redirect.
.DESCRIPTION
    1. Prereqs: docker (Linux engine, logged in to ghcr.io), az (signed in, containerapp extension), node/npm.
    2. npm ci + npm test + PSScriptAnalyzer. Any failure stops the deploy.
    3. docker build/push ghcr.io/your-org/remediation-360:<yyyyMMdd-HHmm>.
    4. Checks the image is pullable anonymously (no registry secret is stored on the Container App).
       If it is not, it opens the package settings page and waits until it is.
    5. Sets env vars, image, target port 8080, scale 0-1. Waits for the revision.
    6. Verifies / -> /auth/signin -> login.microsoftonline.com with the r360-web client_id, and the startup self-checks.
.EXAMPLE
    pwsh -File .\tools\Publish-R360Image.ps1
.EXAMPLE
    pwsh -File .\tools\Publish-R360Image.ps1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Image = 'ghcr.io/your-org/remediation-360',
    [string]$Tag = (Get-Date -Format 'yyyyMMdd-HHmm'),
    [string]$CodeSigningThumbprint = '00000000000000000000000000000000000000F1',
    [int]$TimeoutSeconds = 900
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'R360.Common.psm1') -Force
$cfg = Get-R360Config
$root = Split-Path $PSScriptRoot -Parent
$ref = "${Image}:$Tag"

# --- 1. Prereqs ---
Write-R360Step 'Checking prerequisites'
foreach ($c in 'docker', 'az', 'node', 'npm') { if (-not (Get-Command $c -ErrorAction SilentlyContinue)) { throw "$c is not installed or not on PATH." } }
$os = docker info --format '{{.OSType}}' 2>$null
if ($LASTEXITCODE -ne 0) { throw 'Docker engine is not running. Start Docker Desktop and rerun.' }
if ($os -ne 'linux') { throw "Docker is in $os container mode. Switch Docker Desktop to Linux containers." }
$dockerCfg = Join-Path $HOME '.docker/config.json'
if (-not ((Test-Path $dockerCfg) -and ((Get-Content $dockerCfg -Raw) -match '"ghcr\.io"'))) {
    throw 'Docker is not logged in to ghcr.io. Run: gh auth token | docker login ghcr.io -u sectechtalk --password-stdin'
}
$acct = Invoke-R360Az -Arguments @('account', 'show') -AllowFailure
if (-not $acct) { throw 'az is not signed in. Run: az login' }
if (-not (Invoke-R360Az -Arguments @('extension', 'show', '--name', 'containerapp') -AllowFailure)) { throw 'az containerapp extension missing. Run: az extension add --name containerapp --upgrade' }
if (-not (Get-Module -ListAvailable PSScriptAnalyzer)) { throw 'PSScriptAnalyzer missing. Run: Install-PSResource PSScriptAnalyzer -Scope CurrentUser' }
$app = Invoke-R360Az -Arguments @('containerapp', 'show', '-n', $cfg.ContainerApp, '-g', $cfg.ResourceGroup)
$fqdn = $app.properties.configuration.ingress.fqdn
if (-not $fqdn) { throw "$($cfg.ContainerApp) has no ingress FQDN." }
$base = "https://$fqdn"
$envNow = Get-R360ContainerAppEnv
foreach ($k in 'ENTRA_TENANT_ID', 'R360_WEB_CLIENT_ID', 'R360_WRITE_CLIENT_ID', 'AZURE_CLIENT_ID', 'R360_GITHUB_APP_ID', 'R360_GITHUB_INSTALLATION_ID', 'R360_KEY_VAULT') {
    if (-not $envNow[$k]) { throw "$($cfg.ContainerApp) is missing $k. Rerun the Phase 0 tools (Initialize-R360.ps1 / New-R360GitHubApp.ps1)." }
}

# --- 2. Tests ---
Push-Location $root
try {
    Write-R360Step 'npm ci'
    npm ci --no-audit --no-fund | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'npm ci failed.' }
    Write-R360Step 'npm test'
    npm test | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Unit tests failed. Not deploying.' }
    Write-R360Step 'PSScriptAnalyzer'
    $issues = @(Invoke-ScriptAnalyzer -Path $root -Recurse -Settings (Join-Path $root 'PSScriptAnalyzerSettings.psd1') | ForEach-Object { $_ } | Where-Object { $_ })
    if ($issues) { $issues | Format-Table -AutoSize | Out-Host; throw 'PSScriptAnalyzer findings. Not deploying.' }

    # --- 3. Build and push ---
    if ($PSCmdlet.ShouldProcess($ref, 'docker build and push')) {
        Write-R360Step "Building $ref"
        docker build --pull -t $ref . | Out-Host
        if ($LASTEXITCODE -ne 0) { throw 'docker build failed.' }
        docker push $ref | Out-Host
        if ($LASTEXITCODE -ne 0) { throw 'docker push failed. If ghcr said denied, the ghcr.io login lacks write:packages. Run: gh auth refresh -h github.com -s write:packages,read:packages; gh auth token | docker login ghcr.io -u sectechtalk --password-stdin' }
    }
}
finally { Pop-Location }

# --- 4. Anonymous pull check (no registry secret on the app) ---
$repoPath = $Image -replace '^ghcr\.io/', ''
$testPull = {
    try {
        $t = Invoke-RestMethod "https://ghcr.io/token?scope=repository:${repoPath}:pull&service=ghcr.io"
        $r = Invoke-WebRequest -Method Head -Uri "https://ghcr.io/v2/$repoPath/manifests/$Tag" -SkipHttpErrorCheck -Headers @{
            Authorization = "Bearer $($t.token)"; Accept = 'application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json'
        }
        $r.StatusCode -eq 200
    }
    catch { $false }
}
if (-not $WhatIfPreference -and -not (& $testPull)) {
    $settings = "https://github.com/users/sectechtalk/packages/container/$($repoPath.Split('/')[-1])/settings"
    Write-Warning "The package is private, so $($cfg.ContainerApp) cannot pull it without a stored secret."
    Write-Warning "Open $settings > Danger Zone > Change visibility > Public. The image holds code only, no secrets."
    Start-Process $settings
    Wait-R360Condition -Activity "anonymous pull of $ref" -TimeoutSeconds $TimeoutSeconds -IntervalSeconds 15 -Condition $testPull | Out-Null
}

# --- 5. Deploy ---
$values = [ordered]@{
    R360_PUBLIC_URL          = $base
    R360_KEY_VAULT_URI       = "https://$($envNow['R360_KEY_VAULT']).vault.azure.net"
    R360_CODESIGN_THUMBPRINT = $CodeSigningThumbprint
    R360_IMAGE_TAG           = $Tag
}
# Settings the config file owns. A blank or missing value there must never wipe a value that is already live.
foreach ($k in 'R360_AUDIT_STORAGE_ACCOUNT', 'R360_AUDIT_TABLE', 'R360_AUDIT_EXPORT_CONTAINER', 'R360_ELEVATION_TTL_MINUTES', 'R360_CANARY_GROUP_ID', 'R360_MAX_OPEN_CHANGES') {
    $fromConfig = "$($cfg.AppSettings[$k])"
    if ($fromConfig) { $values[$k] = $fromConfig } elseif ($envNow[$k]) { $values[$k] = $envNow[$k] }
}
# Everything else r360 already has on the app (R360_FOUR_EYES, R360_CANARY_SOAK_DAYS, R360_PROD_GROUP_ID, R360_PIM_MODE and any other R360_* setting) is carried forward as it is.
$preserved = [ordered]@{}
foreach ($k in @($envNow.Keys | Where-Object { $_ -like 'R360_*' -and -not $values.Contains($_) } | Sort-Object)) { $values[$k] = $envNow[$k]; $preserved[$k] = $envNow[$k] }
if ($PSCmdlet.ShouldProcess($cfg.ContainerApp, "Deploy $ref (port 8080, scale 0-1)")) {
    Set-R360ContainerAppEnv -Values $values -TimeoutSeconds $TimeoutSeconds
    Write-R360Step "Updating image to $ref"
    Invoke-R360Az -Arguments @('containerapp', 'update', '-n', $cfg.ContainerApp, '-g', $cfg.ResourceGroup, '--image', $ref, '--min-replicas', '0', '--max-replicas', '1') | Out-Null
    if ($app.properties.configuration.ingress.targetPort -ne 8080) {
        Invoke-R360Az -Arguments @('containerapp', 'ingress', 'update', '-n', $cfg.ContainerApp, '-g', $cfg.ResourceGroup, '--target-port', '8080') | Out-Null
    }
    Wait-R360Condition -Activity "revision running $ref" -TimeoutSeconds $TimeoutSeconds -IntervalSeconds 15 -Condition {
        $revs = @(Invoke-R360Az -Arguments @('containerapp', 'revision', 'list', '-n', $cfg.ContainerApp, '-g', $cfg.ResourceGroup) | ForEach-Object { $_ } | Where-Object { $_ })
        $rev = $revs | Where-Object { $_.properties.template.containers[0].image -eq $ref } | Select-Object -First 1
        if ($rev -and $rev.properties.provisioningState -eq 'Failed') { throw "Revision $($rev.name) failed to provision." }
        $rev -and $rev.properties.provisioningState -eq 'Provisioned' -and $rev.properties.trafficWeight -eq 100
    } | Out-Null

    # --- 6. Live verification ---
    $health = Wait-R360Condition -Activity "$base/healthz reports $Tag" -TimeoutSeconds $TimeoutSeconds -IntervalSeconds 10 -Condition {
        try { $h = Invoke-RestMethod "$base/healthz" -TimeoutSec 30; if ($h.image -eq $Tag) { $h } } catch { $null }
    }
    $results = [System.Collections.Generic.List[object]]::new()
    $results.Add((Format-R360Check -Stage 'Live' -Check 'healthz' -Status 'PASS' -Detail "image $($health.image)"))
    $envAfter = Get-R360ContainerAppEnv
    $lost = @($preserved.Keys | Where-Object { "$($envAfter[$_])" -ne "$($preserved[$_])" })
    $results.Add((Format-R360Check -Stage 'Live' -Check 'existing env vars preserved' -Status $(if ($lost) { 'FAIL' } else { 'PASS' }) -Detail $(if ($lost) { "changed or lost: $($lost -join ', ')" } else { "$($preserved.Count) kept: $(@($preserved.Keys) -join ', ')" })))
    $r1 = Invoke-WebRequest "$base/" -MaximumRedirection 0 -SkipHttpErrorCheck -ErrorAction SilentlyContinue
    $loc1 = "$($r1.Headers.Location)"
    $results.Add((Format-R360Check -Stage 'Live' -Check '/ redirects to sign-in' -Status $(if ($r1.StatusCode -eq 302 -and $loc1 -eq '/auth/signin') { 'PASS' } else { 'FAIL' }) -Detail "$($r1.StatusCode) $loc1"))
    $r2 = Invoke-WebRequest "$base/auth/signin" -MaximumRedirection 0 -SkipHttpErrorCheck -ErrorAction SilentlyContinue
    $loc2 = "$($r2.Headers.Location)"
    $okEntra = $r2.StatusCode -eq 302 -and $loc2.StartsWith("https://login.microsoftonline.com/$($envNow['ENTRA_TENANT_ID'])/") -and $loc2 -match "client_id=$($envNow['R360_WEB_CLIENT_ID'])"
    $results.Add((Format-R360Check -Stage 'Live' -Check 'sign-in goes to Entra (r360-web)' -Status $(if ($okEntra) { 'PASS' } else { 'FAIL' }) -Detail "$($r2.StatusCode) $($loc2.Split('?')[0])"))
    $r3 = Invoke-WebRequest "$base/api/remediations" -SkipHttpErrorCheck
    $results.Add((Format-R360Check -Stage 'Live' -Check 'API needs a session' -Status $(if ($r3.StatusCode -eq 401) { 'PASS' } else { 'FAIL' }) -Detail "$($r3.StatusCode)"))
    $logs = Wait-R360Condition -Activity 'startup self-check log lines' -TimeoutSeconds 300 -IntervalSeconds 15 -Condition {
        $l = az containerapp logs show -n $cfg.ContainerApp -g $cfg.ResourceGroup --tail 200 --format text 2>$null
        $lines = @($l | Where-Object { $_ -match 'selfcheck' })
        if ($lines.Count -ge 3) { , $lines }
    }
    foreach ($name in 'mi-fic-token', 'github-app', 'audit-store') {
        $line = @($logs | Where-Object { $_ -match "selfcheck $name" }) | Select-Object -Last 1
        $results.Add((Format-R360Check -Stage 'Live' -Check "selfcheck $name" -Status $(if ($line -match 'PASS') { 'PASS' } else { 'FAIL' }) -Detail "$line".Trim()))
    }
    $results | Format-Table -AutoSize -Wrap | Out-Host
    if ($results | Where-Object Status -eq 'FAIL') { throw 'Live verification failed. See table above.' }
    Write-R360Step "Deployed $ref to $base"
}
