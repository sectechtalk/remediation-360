#Requires -Version 7.4
<#
.SYNOPSIS
    Read-only prerequisite and state checks for the r360 bootstrap. Never changes anything and never signs in.
.DESCRIPTION
    Tools checks always run. Other stages report what already exists. Before a stage is deployed its resources show
    MISSING, which is normal. With -RequireDeployed, MISSING counts as a failure (the bootstrap uses this after each step).
    Graph checks use the existing Microsoft Graph context only. Without one they report WARN, or FAIL with -RequireDeployed.
.EXAMPLE
    ./Test-R360Prereqs.ps1
.EXAMPLE
    ./Test-R360Prereqs.ps1 -Stage Infrastructure -RequireDeployed
#>
[CmdletBinding()]
param(
    [ValidateSet('Tools', 'Repo', 'Infrastructure', 'AppRegistration', 'GitHubApp', 'CodeSigning', 'All')]
    [string[]]$Stage = 'All',
    [switch]$RequireDeployed,
    [switch]$PassThru
)
$ErrorActionPreference = 'Stop'
$WhatIfPreference = $false  # read-only script; never inherit -WhatIf from a caller
Import-Module (Join-Path $PSScriptRoot 'R360.Common.psm1') -Force
$cfg = Get-R360Config
$all = 'All' -in $Stage
$want = { param($s) $all -or $s -in $Stage }
$results = [System.Collections.Generic.List[object]]::new()
function Add-Check { param($St, $Ck, $Status, $Detail = '') $results.Add((Format-R360Check -Stage $St -Check $Ck -Status $Status -Detail $Detail)) }
$missing = if ($RequireDeployed) { 'FAIL' } else { 'MISSING' }

# ---------- Tools (always) ----------
$ok = $PSVersionTable.PSVersion -ge [version]'7.4'
Add-Check Tools 'PowerShell 7.4+' $(if ($ok) { 'PASS' } else { 'FAIL' }) "$($PSVersionTable.PSVersion)"
foreach ($m in 'Microsoft.Graph.Authentication', 'PSScriptAnalyzer') {
    $mod = Get-Module -ListAvailable $m | Sort-Object Version -Descending | Select-Object -First 1
    Add-Check Tools "Module $m" $(if ($mod) { 'PASS' } else { 'FAIL' }) $(if ($mod) { "$($mod.Version)" } else { "Install-Module $m -Scope CurrentUser" })
}
foreach ($t in 'az', 'gh', 'git') {
    $c = Get-Command $t -ErrorAction SilentlyContinue
    Add-Check Tools "CLI $t" $(if ($c) { 'PASS' } else { 'FAIL' }) $(if ($c) { $c.Source } else { 'not on PATH' })
}
$azOk = $false
if (Get-Command az -ErrorAction SilentlyContinue) {
    $acct = Invoke-R360Az -Arguments @('account', 'show') -AllowFailure
    if (-not $acct) { Add-Check Tools 'az signed in' 'FAIL' "Run: az login --tenant $($cfg.TenantId)" }
    elseif ($acct.tenantId -ne $cfg.TenantId) { Add-Check Tools 'az tenant' 'FAIL' "Signed in to $($acct.tenantId), expected $($cfg.TenantId)" }
    else {
        $azOk = $true
        Add-Check Tools 'az signed in' 'PASS' "$($acct.user.name) / subscription '$($acct.name)' ($($acct.id))"
        if ($acct.user.type -ne 'user') { Add-Check Tools 'az delegated user' 'FAIL' "az is signed in as $($acct.user.type); delegated user sign-in required" }
    }
    $ext = Invoke-R360Az -Arguments @('extension', 'show', '-n', 'containerapp') -AllowFailure
    Add-Check Tools 'az extension containerapp' $(if ($ext) { 'PASS' } else { 'FAIL' }) $(if ($ext) { $ext.version } else { 'az extension add -n containerapp' })
    if ($azOk) {
        foreach ($ns in 'Microsoft.App', 'Microsoft.KeyVault', 'Microsoft.Storage', 'Microsoft.ManagedIdentity') {
            $st = Invoke-R360Az -Arguments @('provider', 'show', '-n', $ns, '--query', 'registrationState') -AllowFailure
            Add-Check Tools "Provider $ns" $(if ($st -eq 'Registered') { 'PASS' } else { 'WARN' }) "$st$(if ($st -ne 'Registered') { ' (New-R360Infrastructure registers it)' })"
        }
    }
}
$ghOk = $false
if (Get-Command gh -ErrorAction SilentlyContinue) {
    $null = & gh auth status 2>&1
    $ghOk = $LASTEXITCODE -eq 0
    $who = if ($ghOk) { Invoke-R360Gh -Arguments @('api', 'user', '--jq', '.login') -AllowFailure } else { $null }
    Add-Check Tools 'gh signed in' $(if ($ghOk) { 'PASS' } else { 'FAIL' }) $(if ($ghOk) { "$who" } else { 'Run: gh auth login' })
    if ($ghOk) {
        $ownerType = Invoke-R360Gh -Arguments @('api', "users/$($cfg.GitHubOrg)", '--jq', '.type') -AllowFailure
        if ($ownerType -eq 'User') {
            Add-Check Tools "gh owner $($cfg.GitHubOrg)" $(if ("$who" -eq $cfg.GitHubOrg) { 'PASS' } else { 'FAIL' }) "user account; signed in as $who (must be $($cfg.GitHubOrg) to create the repo and App)"
        } else {
            $role = Invoke-R360Gh -Arguments @('api', "user/memberships/orgs/$($cfg.GitHubOrg)", '--jq', '.role') -AllowFailure
            Add-Check Tools "gh org role in $($cfg.GitHubOrg)" $(if ($role -eq 'admin') { 'PASS' } else { 'WARN' }) "$(if ($role) { $role } else { 'unknown' }); creating the repo and GitHub App needs owner/admin"
        }
    }
}
$logOk = $true
try {
    if (-not (Test-Path $cfg.LogDir)) { $logOk = $false }
    else { $probe = Join-Path $cfg.LogDir ".r360-probe-$PID"; [IO.File]::WriteAllText($probe, 'x'); [IO.File]::Delete($probe) }
} catch { $logOk = $false }
Add-Check Tools "Log folder $($cfg.LogDir)" $(if ($logOk) { 'PASS' } else { 'WARN' }) $(if ($logOk) { 'writable' } else { 'missing or not writable (scripts create it)' })
$ctx = Get-MgContext
$graphOk = $ctx -and $ctx.TenantId -eq $cfg.TenantId -and $ctx.AuthType -eq 'Delegated'
if ($graphOk) {
    $miss = @($cfg.BootstrapGraphScopes | Where-Object { $_ -notin $ctx.Scopes })
    Add-Check Tools 'Graph delegated context' $(if ($miss) { 'WARN' } else { 'PASS' }) "$($ctx.Account)$(if ($miss) { "; missing scopes (bootstrap requests them): $($miss -join ', ')" })"
} else {
    Add-Check Tools 'Graph delegated context' 'WARN' 'Not connected in this session; the bootstrap signs in (delegated) when it needs Graph'
}

# ---------- Repo ----------
if (& $want 'Repo') {
    $git = Join-Path $cfg.RepoRoot '.git'
    Add-Check Repo "Local repo $($cfg.RepoRoot)" $(if (Test-Path $git) { 'PASS' } else { $missing }) ''
    foreach ($f in '.gitignore', 'README.md', '.github/CODEOWNERS', '.github/workflows/psscriptanalyzer.yml', 'PSScriptAnalyzerSettings.psd1') {
        Add-Check Repo "File $f" $(if (Test-Path (Join-Path $cfg.RepoRoot $f)) { 'PASS' } else { 'FAIL' }) ''
    }
    if ($ghOk) {
        $r = Invoke-R360Gh -Arguments @('repo', 'view', "$($cfg.GitHubOrg)/$($cfg.ProductRepo)", '--json', 'visibility,url') -AllowFailure
        if (-not $r) { Add-Check Repo "GitHub $($cfg.GitHubOrg)/$($cfg.ProductRepo)" $missing 'not created yet (bootstrap step 1)' }
        else { Add-Check Repo "GitHub $($cfg.GitHubOrg)/$($cfg.ProductRepo)" $(if ($r.visibility -eq 'PRIVATE') { 'PASS' } else { 'FAIL' }) "$($r.visibility) $($r.url)" }
        $rem = Invoke-R360Gh -Arguments @('repo', 'view', "$($cfg.GitHubOrg)/$($cfg.RemediationsRepo)", '--json', 'name') -AllowFailure
        Add-Check Repo "GitHub $($cfg.GitHubOrg)/$($cfg.RemediationsRepo)" $(if ($rem) { 'PASS' } else { 'FAIL' }) 'GitHub App target repo'
    }
}

# ---------- Infrastructure ----------
$kv = $null; $mi = $null
if ((& $want 'Infrastructure') -and $azOk) {
    $rg = Invoke-R360Az -Arguments @('group', 'exists', '-n', $cfg.ResourceGroup)
    Add-Check Infrastructure "Resource group $($cfg.ResourceGroup)" $(if ($rg) { 'PASS' } else { $missing }) $cfg.Location
    if ($rg) {
        $mi = Invoke-R360Az -Arguments @('identity', 'show', '-n', $cfg.Identity, '-g', $cfg.ResourceGroup) -AllowFailure
        Add-Check Infrastructure "Managed identity $($cfg.Identity)" $(if ($mi) { 'PASS' } else { $missing }) $(if ($mi) { "principalId $($mi.principalId)" })
        $kv = Invoke-R360Az -Arguments @('keyvault', 'show', '-n', $cfg.KeyVault, '-g', $cfg.ResourceGroup) -AllowFailure
        if ($kv) {
            $p = $kv.properties
            $good = $p.sku.name -eq 'premium' -and $p.enableRbacAuthorization -and $p.enablePurgeProtection
            Add-Check Infrastructure "Key Vault $($cfg.KeyVault)" $(if ($good) { 'PASS' } else { 'FAIL' }) "sku=$($p.sku.name) rbac=$($p.enableRbacAuthorization) purgeProtection=$($p.enablePurgeProtection)"
            $dp = $(if (Test-R360KvDataPlane -VaultName $cfg.KeyVault) { 0 } else { $null })
            Add-Check Infrastructure 'Key Vault data-plane access (you)' $(if ($null -ne $dp) { 'PASS' } else { $missing }) 'Key Vault Crypto Officer + Certificates Officer'
        } else { Add-Check Infrastructure "Key Vault $($cfg.KeyVault)" $missing '' }
        $st = Invoke-R360Az -Arguments @('storage', 'account', 'show', '-n', $cfg.Storage, '-g', $cfg.ResourceGroup) -AllowFailure
        if ($st) {
            $good = (-not $st.allowSharedKeyAccess) -and (-not $st.allowBlobPublicAccess) -and $st.minimumTlsVersion -eq 'TLS1_2'
            Add-Check Infrastructure "Storage $($cfg.Storage)" $(if ($good) { 'PASS' } else { 'FAIL' }) "sharedKey=$($st.allowSharedKeyAccess) publicBlob=$($st.allowBlobPublicAccess) tls=$($st.minimumTlsVersion)"
            $tbl = Invoke-R360Az -Arguments @('rest', '--method', 'get', '--url', "https://management.azure.com$($st.id)/tableServices/default/tables/$($cfg.AuditTable)?api-version=2023-05-01") -AllowFailure
            Add-Check Infrastructure "Audit table $($cfg.AuditTable)" $(if ($tbl) { 'PASS' } else { $missing }) ''
            $imm = Invoke-R360Az -Arguments @('storage', 'container', 'immutability-policy', 'show', '--account-name', $cfg.Storage, '-g', $cfg.ResourceGroup, '--container-name', $cfg.AuditExportContainer) -AllowFailure
            Add-Check Infrastructure "Immutable container $($cfg.AuditExportContainer)" $(if ($imm -and $imm.PSObject.Properties['immutabilityPeriodSinceCreationInDays'] -and $imm.immutabilityPeriodSinceCreationInDays -ge 365) { 'PASS' } else { $missing }) $(if ($imm) { "$($imm.immutabilityPeriodSinceCreationInDays) days, $($imm.state)" })
        } else { Add-Check Infrastructure "Storage $($cfg.Storage)" $missing '' }
        $role = @(Invoke-R360Az -Arguments @('role', 'definition', 'list', '--custom-role-only', 'true', '--name', $cfg.AuditRoleName) -AllowFailure).Count
        Add-Check Infrastructure "Custom role '$($cfg.AuditRoleName)'" $(if ($role -gt 0) { 'PASS' } else { $missing }) 'read + add only (no update/delete)'
        $blobScope = "$($st.id)/blobServices/default/containers/$($cfg.AuditExportContainer)"
        $blobRole = if ($st -and $mi) { @(Invoke-R360Az -Arguments @('role', 'assignment', 'list', '--assignee', $mi.principalId, '--scope', $blobScope) -AllowFailure | Where-Object { $_.roleDefinitionName -eq 'Storage Blob Data Contributor' }).Count } else { 0 }
        Add-Check Infrastructure "Blob role for $($cfg.Identity) on $($cfg.AuditExportContainer)" $(if ($blobRole -gt 0) { 'PASS' } else { $missing }) 'Storage Blob Data Contributor, container scope (immutability policy protects existing blobs)'
        $cae = Invoke-R360Az -Arguments @('containerapp', 'env', 'show', '-n', $cfg.ContainerEnv, '-g', $cfg.ResourceGroup) -AllowFailure
        Add-Check Infrastructure "Container Apps env $($cfg.ContainerEnv)" $(if ($cae) { 'PASS' } else { $missing }) ''
        $app = Invoke-R360Az -Arguments @('containerapp', 'show', '-n', $cfg.ContainerApp, '-g', $cfg.ResourceGroup) -AllowFailure
        if ($app) {
            $sc = $app.properties.template.scale
            $ids = if ($app.identity -and $app.identity.PSObject.Properties['userAssignedIdentities'] -and $app.identity.userAssignedIdentities) { @($app.identity.userAssignedIdentities.PSObject.Properties.Name) } else { @() }
            $good = $sc.minReplicas -eq 0 -and $sc.maxReplicas -eq 1 -and ($mi -and ($ids -contains $mi.id))
            Add-Check Infrastructure "Container App $($cfg.ContainerApp)" $(if ($good) { 'PASS' } else { 'FAIL' }) "scale $($sc.minReplicas)-$($sc.maxReplicas), id-r360 attached=$([bool]($mi -and ($ids -contains $mi.id))), https://$($app.properties.configuration.ingress.fqdn)"
            $envVars = Get-R360ContainerAppEnv
            $bad = @($cfg.AppSettings.Keys | Where-Object { $envVars[$_] -ne $cfg.AppSettings[$_] })
            Add-Check Infrastructure 'Container App settings' $(if ($bad) { 'FAIL' } else { 'PASS' }) $(if ($bad) { "differs: $($bad -join ', ')" } else { ($cfg.AppSettings.Keys | ForEach-Object { "$_=$($cfg.AppSettings[$_])" }) -join ' ' })
        } else { Add-Check Infrastructure "Container App $($cfg.ContainerApp)" $missing '' }
    }
}

# ---------- App registrations (Graph) ----------
if (& $want 'AppRegistration') {
    if (-not $graphOk) { Add-Check AppRegistration 'Graph context' $(if ($RequireDeployed) { 'FAIL' } else { 'WARN' }) 'Not connected; app registration checks skipped' }
    else {
        $defender = Invoke-R360Graph -Uri "/v1.0/servicePrincipals?`$filter=appId eq '$($cfg.DefenderAppId)'&`$select=id" -All
        Add-Check AppRegistration 'WindowsDefenderATP service principal' $(if ($defender) { 'PASS' } else { 'FAIL' }) 'needed for delegated Defender scopes'
        foreach ($n in $cfg.AppWeb, $cfg.AppWrite, $cfg.AppCiSigner) {
            $a = @(Invoke-R360Graph -Uri "/v1.0/applications?`$filter=displayName eq '$n'&`$select=id,appId,passwordCredentials,keyCredentials,requiredResourceAccess" -All)
            if (-not $a) { Add-Check AppRegistration "App $n" $missing ''; continue }
            if ($a.Count -gt 1) { Add-Check AppRegistration "App $n" 'FAIL' "$($a.Count) apps share this name"; continue }
            $a = $a[0]
            $creds = @($a.passwordCredentials | Where-Object { $_ }).Count + @($a.keyCredentials | Where-Object { $_ }).Count
            Add-Check AppRegistration "App $n has no stored credential" $(if ($creds -eq 0) { 'PASS' } else { 'FAIL' }) "appId $($a.appId); secrets+certs=$creds"
            $roles = @($a.requiredResourceAccess | ForEach-Object { $_.resourceAccess } | Where-Object { $_.type -ne 'Scope' })
            Add-Check AppRegistration "App $n delegated only" $(if ($roles) { 'FAIL' } else { 'PASS' }) $(if ($roles) { "$($roles.Count) application permission(s)" })
            $fic = @(Invoke-R360Graph -Uri "/v1.0/applications/$($a.id)/federatedIdentityCredentials" -All)
            Add-Check AppRegistration "App $n federated credential" $(if ($fic) { 'PASS' } else { $missing }) (($fic | ForEach-Object { "$($_.issuer) | $($_.subject)" }) -join '; ')
        }
        $g = Invoke-R360Graph -Uri "/v1.0/groups/$($cfg.CanaryGroupId)?`$select=displayName"
        Add-Check AppRegistration 'Canary group' 'PASS' "$($g.displayName) ($($cfg.CanaryGroupId))"
        $op = @(Invoke-R360Graph -Uri "/v1.0/groups?`$filter=displayName eq '$($cfg.OperatorsGroup)'&`$select=id" -All)
        Add-Check AppRegistration "Group $($cfg.OperatorsGroup)" $(if ($op) { 'PASS' } else { 'WARN' }) $(if (-not $op) { 'optional; create in Entra to grant r360 access by group (until then: signed-in admin only)' })
    }
}

# ---------- GitHub App ----------
if ((& $want 'GitHubApp') -and $azOk) {
    $key = Invoke-R360Az -Arguments @('keyvault', 'key', 'show', '--vault-name', $cfg.KeyVault, '--name', $cfg.GitHubAppKey) -AllowFailure
    if ($key) {
        $exp = $key.attributes.PSObject.Properties['exportable'] -and $key.attributes.exportable
        Add-Check GitHubApp "KV key $($cfg.GitHubAppKey)" $(if ($exp) { 'FAIL' } else { 'PASS' }) "kty=$($key.key.kty) exportable=$([bool]$exp) app-id=$($key.tags.'app-id')"
    } else { Add-Check GitHubApp "KV key $($cfg.GitHubAppKey)" $missing '' }
    $envVars = Get-R360ContainerAppEnv
    foreach ($v in 'R360_GITHUB_APP_ID', 'R360_GITHUB_INSTALLATION_ID') {
        Add-Check GitHubApp "Setting $v" $(if ($envVars[$v]) { 'PASS' } else { $missing }) "$($envVars[$v])"
    }
    $rs = @(Invoke-R360Gh -Arguments @('api', "repos/$($cfg.GitHubOrg)/remediations/rulesets") -AllowFailure | ForEach-Object { $_ }) | Where-Object name -eq 'r360-app-only-merge'
    $ro = if ($rs) { Invoke-R360Gh -Arguments @('api', "repos/$($cfg.GitHubOrg)/remediations/rulesets/$($rs.id)") } else { $null }
    $okRule = $ro -and $ro.enforcement -eq 'active' -and $ro.bypass_actors.Count -eq 1 -and "$($ro.bypass_actors[0].actor_id)" -eq "$($envVars['R360_GITHUB_APP_ID'])" -and $ro.bypass_actors[0].bypass_mode -eq 'pull_request'
    Add-Check GitHubApp 'remediations main: App-only merge rule' $(if ($okRule) { 'PASS' } elseif ($ro) { 'FAIL' } else { $missing }) $(if ($ro) { "ruleset $($ro.id) $($ro.enforcement), bypass $($ro.bypass_actors[0].actor_type) $($ro.bypass_actors[0].actor_id) ($($ro.bypass_actors[0].bypass_mode))" } else { 'Run tools/Set-R360RulesetAppOnly.ps1' })
}

# ---------- Code signing ----------
if ((& $want 'CodeSigning') -and $azOk) {
    $cert = Invoke-R360Az -Arguments @('keyvault', 'certificate', 'show', '--vault-name', $cfg.KeyVault, '--name', $cfg.CodeSigningCert) -AllowFailure
    if ($cert) {
        $kp = $cert.policy.keyProperties
        $good = (-not $kp.exportable) -and $kp.keyType -eq 'RSA-HSM'
        Add-Check CodeSigning "KV certificate $($cfg.CodeSigningCert)" $(if ($good) { 'PASS' } else { 'FAIL' }) "kty=$($kp.keyType) exportable=$($kp.exportable) thumbprint=$($cert.x509ThumbprintHex) expires=$($cert.attributes.expires)"
    } else { Add-Check CodeSigning "KV certificate $($cfg.CodeSigningCert)" $missing '' }
    $dmScope = $graphOk -and @(@('DeviceManagementConfiguration.ReadWrite.All', 'DeviceManagementConfiguration.Read.All') | Where-Object { $_ -in $ctx.Scopes }).Count -gt 0
    if ($dmScope) {
        $profiles = @(Invoke-R360Graph -Uri "/beta/deviceManagement/deviceConfigurations?`$select=id,displayName,description" -All | ForEach-Object { $_ } | Where-Object { $_ })
        # Intune status reporting lags; check the canary device directly over WinRM (stored credential).
        $devStores = @{}
        $credPath = Join-Path $env:LOCALAPPDATA "remediations\devices\$($cfg.CanaryDevice).xml"
        if (Test-Path $credPath) {
            try {
                $devCred = Import-Clixml $credPath
                $target = if ($devCred.PSObject.Properties['Address']) { $devCred.Address } else { '192.168.50.123' }
                $c = if ($devCred -is [pscredential]) { $devCred } else { $devCred.Credential }
                $thumb = ($cert.x509ThumbprintHex)
                $devStores = Invoke-Command -ComputerName $target -Credential $c -ErrorAction Stop -ScriptBlock {
                    @{ Root = [bool](Get-ChildItem Cert:\LocalMachine\Root | Where-Object Thumbprint -EQ $using:thumb)
                       Pub  = [bool](Get-ChildItem Cert:\LocalMachine\TrustedPublisher | Where-Object Thumbprint -EQ $using:thumb) }
                }
            } catch { $devStores = @{ Error = $_.Exception.Message } }
        }        foreach ($n in $cfg.IntuneRootProfile, $cfg.IntunePubProfile) {
            $p = $profiles | Where-Object displayName -EQ $n | Select-Object -First 1
            if (-not $p) { Add-Check CodeSigning "Intune profile '$n'" $missing ''; continue }
            $asg = @(Invoke-R360Graph -Uri "/beta/deviceManagement/deviceConfigurations/$($p.id)/assignments" -All | ForEach-Object { $_ } | Where-Object { $_ })
            $onCanary = @($asg | Where-Object { $_.target.PSObject.Properties['groupId'] -and $_.target.groupId -eq $cfg.CanaryGroupId }).Count -gt 0
            $sts = @(Invoke-R360Graph -Uri "/beta/deviceManagement/deviceConfigurations/$($p.id)/deviceStatuses" -All | ForEach-Object { $_ } | Where-Object deviceDisplayName -EQ $cfg.CanaryDevice)
            $state = if ($sts) { ($sts | ForEach-Object status) -join ',' } else { 'no status yet' }
            $storeKey = if ($n -eq $cfg.IntuneRootProfile) { 'Root' } else { 'Pub' }
            if ($devStores[$storeKey]) { $state = "cert present on device ($state in Intune)" }
            Add-Check CodeSigning "Intune profile '$n'" $(if ($onCanary -and $state -match 'succeeded|compliant|present on device') { 'PASS' } else { $missing }) "assigned to canary=$onCanary; $($cfg.CanaryDevice): $state"
        }
    } else { Add-Check CodeSigning 'Intune profiles' $(if ($RequireDeployed) { 'FAIL' } else { 'WARN' }) 'Graph not connected with DeviceManagementConfiguration scope; skipped' }
    Add-Check CodeSigning 'Defender live response settings' 'INFO' 'Manual in Defender portal: Live response on, unsigned script execution OFF, device group remediation level set (no delegated API)'
}

# ---------- Output ----------
$results | Format-Table Stage, Status, Check, Detail -AutoSize -Wrap | Out-String -Width 220 | Write-Host
$sum = $results | Group-Object Status | ForEach-Object { "$($_.Name)=$($_.Count)" }
Write-Host "Summary: $($sum -join '  ')"
if ($PassThru) { $results }
$fails = @($results | Where-Object Status -EQ 'FAIL')
if ($fails) { throw "$($fails.Count) prerequisite check(s) failed: $(($fails | ForEach-Object Check) -join '; ')" }
