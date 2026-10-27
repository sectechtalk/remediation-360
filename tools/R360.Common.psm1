#Requires -Version 7.4
# Shared helpers for the r360 bootstrap scripts. Delegated only, no secrets.
Set-StrictMode -Version Latest

$script:TenantId = '00000000-0000-4000-8000-0000000000b1'

# Load the Graph auth module once, outside any -WhatIf scope (its type-data import honours WhatIf).
& { $WhatIfPreference = $false; Import-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue }

function Get-R360Config {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()
    $sha = [System.Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes("$script:TenantId/r360"))
    $suffix = ([Convert]::ToHexString($sha)).Substring(0, 6).ToLowerInvariant()
    [pscustomobject]@{
        TenantId             = $script:TenantId
        Location             = 'westus3'
        ResourceGroup        = 'rg-r360'
        Identity             = 'id-r360'
        Suffix               = $suffix
        KeyVault             = "kv-r360-$suffix"
        Storage              = "str360$suffix"
        AuditTable           = 'r360audit'
        AuditExportContainer = 'r360audit-export'
        AuditRoleName        = 'r360 Audit Table Append'
        ContainerEnv         = 'cae-r360'
        ContainerApp         = 'app-r360'
        PlaceholderImage     = 'mcr.microsoft.com/k8se/quickstart:latest'
        RepoRoot             = (Split-Path $PSScriptRoot -Parent)
        GitHubOrg            = 'sectechtalk'
        ProductRepo          = 'r360'
        RemediationsRepo     = 'remediations'
        GitHubAppName        = 'r360-github-app'
        GitHubAppKey         = 'github-app-r360'
        CodeSigningCert      = 'r360-codesign'
        CodeSigningSubject   = 'CN=SecTechTalk r360 Code Signing'
        AppWeb               = 'r360-web'
        AppWrite             = 'r360-write'
        AppCiSigner          = 'r360-ci-signer'
        CanaryGroupId        = '00000000-0000-4000-8000-0000000000b2'
        CanaryDevice         = 'DEVICE01'
        OperatorsGroup       = 'sg-r360-operators'
        IntuneRootProfile    = 'r360 - Code Signing - Trusted Root'
        IntunePubProfile     = 'r360 - Code Signing - Trusted Publisher'
        LogDir               = 'C:\path\to\logs'
        GraphAppId           = '00000003-0000-0000-c000-000000000000'
        DefenderAppId        = 'fc780465-2017-40d4-a0c5-307022471b92'
        FicAudience          = 'api://AzureADTokenExchange'
        AppSettings          = [ordered]@{
            ENTRA_TENANT_ID               = $script:TenantId
            R360_FOUR_EYES                = 'testing'
            R360_PIM_MODE                 = 'warn'
            R360_ELEVATION_TTL_MINUTES    = '480'
            R360_EMERGENCY_WINDOW_MINUTES = '240'
            R360_EMERGENCY_MAX_DEVICES    = '1'
            R360_CANARY_DEVICE            = 'DEVICE01'
        }
        # Every Graph scope the bootstrap uses (delegated, signed-in admin).
        BootstrapGraphScopes = @('Application.ReadWrite.All', 'DelegatedPermissionGrant.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All',
            'Group.Read.All', 'GroupMember.Read.All', 'DeviceManagementConfiguration.ReadWrite.All', 'DeviceManagementManagedDevices.Read.All',
            'DeviceManagementManagedDevices.PrivilegedOperations.All')
    }
}

function Enable-R360Log {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Name)
    $dir = (Get-R360Config).LogDir
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force -WhatIf:$false | Out-Null }
    $path = Join-Path $dir ('r360-{0}-{1}.log' -f $Name, (Get-Date -Format 'yyyyMMdd-HHmmss'))
    Start-Transcript -Path $path -UseMinimalHeader -WhatIf:$false | Out-Null
    $path
}

function Disable-R360Log {
    [CmdletBinding()]
    param()
    try { Stop-Transcript -WhatIf:$false | Out-Null } catch { Write-Verbose "No transcript active: $_" }
}

function Write-R360Step {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Message)
    Write-Host ('[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $Message)
}

function Invoke-R360Az {
    # Runs az with JSON output; returns parsed JSON (or $null). Throws on failure unless -AllowFailure.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$Arguments, [switch]$AllowFailure)
    $WhatIfPreference = $false  # read/exec wrapper: temp-file redirection must not be suppressed by -WhatIf
    $err = New-TemporaryFile
    try {
        $out = & az @Arguments --only-show-errors -o json 2> $err.FullName
        if ($LASTEXITCODE -ne 0) {
            if ($AllowFailure) { return $null }
            throw "az $($Arguments -join ' ') failed: $((Get-Content $err.FullName -Raw))"
        }
        $text = ($out -join "`n").Trim()
        if ($text) { return ($text | ConvertFrom-Json -Depth 64) }
    } finally { Remove-Item $err.FullName -Force -ErrorAction SilentlyContinue -WhatIf:$false }
}

function Test-R360KvDataPlane {
    # True when the signed-in user can list keys (data-plane RBAC active). No --query: cmd.exe (az.cmd) breaks on parentheses.
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$VaultName)
    $null = Invoke-R360Az -Arguments @('keyvault', 'key', 'list', '--vault-name', $VaultName) -AllowFailure
    return ($LASTEXITCODE -eq 0)
}
function Invoke-R360Gh {
    # Runs gh; returns parsed JSON when the output is JSON. Throws on failure unless -AllowFailure.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$Arguments, [switch]$AllowFailure)
    $WhatIfPreference = $false  # read/exec wrapper: temp-file redirection must not be suppressed by -WhatIf
    $err = New-TemporaryFile
    try {
        $out = & gh @Arguments 2> $err.FullName
        if ($LASTEXITCODE -ne 0) {
            if ($AllowFailure) { return $null }
            throw "gh $($Arguments -join ' ') failed: $((Get-Content $err.FullName -Raw))"
        }
        $text = ($out -join "`n").Trim()
        if (-not $text) { return $null }
        try { return ($text | ConvertFrom-Json -Depth 64) } catch { return $text }
    } finally { Remove-Item $err.FullName -Force -ErrorAction SilentlyContinue -WhatIf:$false }
}

function Wait-R360Condition {
    # Polls $Condition until it returns a truthy value or the timeout passes. No manual waits anywhere.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Activity,
        [Parameter(Mandatory)][scriptblock]$Condition,
        [int]$TimeoutSeconds = 600,
        [int]$IntervalSeconds = 10
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ($true) {
        $result = & $Condition
        if ($result) { return $result }
        if ((Get-Date) -ge $deadline) { throw "Timed out after $TimeoutSeconds s waiting for: $Activity" }
        Write-R360Step "Waiting for $Activity (next check in $IntervalSeconds s, gives up at $($deadline.ToString('HH:mm:ss')))"
        Start-Sleep -Seconds $IntervalSeconds
    }
}

function Connect-R360Graph {
    # Delegated Graph sign-in. Returns $true when the context has the tenant and every scope.
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string[]]$Scopes, [switch]$NoInteractive)
    $cfg = Get-R360Config
    $ctx = Get-MgContext
    $missing = if ($ctx -and $ctx.TenantId -eq $cfg.TenantId) { @($Scopes | Where-Object { $_ -notin $ctx.Scopes }) } else { $Scopes }
    if (-not $missing) { return $true }
    if ($NoInteractive) { return $false }
    $want = @(@($Scopes) + @(if ($ctx) { $ctx.Scopes }) | Sort-Object -Unique)
    Connect-MgGraph -TenantId $cfg.TenantId -Scopes $want -NoWelcome -ContextScope Process | Out-Null
    $ctx = Get-MgContext
    if ($ctx.AuthType -ne 'Delegated') { throw "Graph context is $($ctx.AuthType); r360 bootstrap is delegated only." }
    $still = @($Scopes | Where-Object { $_ -notin $ctx.Scopes })
    if ($still) { throw "Graph sign-in is missing scopes: $($still -join ', ')" }
    $true
}

function Invoke-R360Graph {
    [CmdletBinding()]
    param(
        [ValidateSet('GET', 'POST', 'PATCH', 'PUT', 'DELETE')][string]$Method = 'GET',
        [Parameter(Mandatory)][string]$Uri,
        [object]$Body,
        [switch]$All
    )
    $p = @{ Method = $Method; Uri = $Uri; OutputType = 'PSObject' }
    if ($null -ne $Body) { $p.Body = ($Body | ConvertTo-Json -Depth 30 -Compress); $p.ContentType = 'application/json' }
    $r = Invoke-MgGraphRequest @p
    if (-not $All) { return $r }
    $items = [System.Collections.Generic.List[object]]::new()
    while ($r) {
        if ($r.PSObject.Properties['value']) { foreach ($v in $r.value) { $items.Add($v) } }
        $next = if ($r.PSObject.Properties['@odata.nextLink']) { $r.'@odata.nextLink' } else { $null }
        $r = if ($next) { Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject } else { $null }
    }
    , $items.ToArray()
}

function Format-R360Check {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Stage,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][ValidateSet('PASS', 'FAIL', 'WARN', 'MISSING', 'INFO')][string]$Status,
        [string]$Detail = ''
    )
    [pscustomobject]@{ Stage = $Stage; Check = $Check; Status = $Status; Detail = $Detail }
}

function Remove-R360FileSecurely {
    # Overwrites a file with random bytes three times, then deletes it.
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { return }
    if (-not $PSCmdlet.ShouldProcess($Path, 'Overwrite and delete')) { return }
    $len = (Get-Item $Path).Length
    for ($i = 0; $i -lt 3; $i++) {
        $bytes = [byte[]]::new([Math]::Max($len, 1))
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
        [IO.File]::WriteAllBytes($Path, $bytes)
    }
    Remove-Item $Path -Force
    if (Test-Path $Path) { throw "Could not delete $Path" }
}

function Set-R360PrivateFileAcl {
    # Restricts a file to the current user only (no inheritance).
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Path)
    if (-not $PSCmdlet.ShouldProcess($Path, 'Restrict ACL to current user')) { return }
    $acl = [System.Security.AccessControl.FileSecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($me, 'FullControl', 'Allow'))
    Set-Acl -Path $Path -AclObject $acl
}

function ConvertTo-R360Base64Url {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][byte[]]$Bytes)
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Get-R360GitHubAppJwt {
    # App JWT (RS256) signed by the non-exportable Key Vault key. The private key never leaves Key Vault.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$AppId)
    $cfg = Get-R360Config
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $h = ConvertTo-R360Base64Url ([Text.Encoding]::UTF8.GetBytes('{"alg":"RS256","typ":"JWT"}'))
    $p = ConvertTo-R360Base64Url ([Text.Encoding]::UTF8.GetBytes((@{ iat = $now - 60; exp = $now + 540; iss = $AppId } | ConvertTo-Json -Compress)))
    $digest = [Convert]::ToBase64String([System.Security.Cryptography.SHA256]::HashData([Text.Encoding]::ASCII.GetBytes("$h.$p")))
    $r = Invoke-R360Az -Arguments @('keyvault', 'key', 'sign', '--vault-name', $cfg.KeyVault, '--name', $cfg.GitHubAppKey, '--algorithm', 'RS256', '--digest', $digest)
    $sig = if ($r.PSObject.Properties['signature']) { $r.signature } else { $r.result }
    $sig = $sig.TrimEnd('=').Replace('+', '-').Replace('/', '_')
    "$h.$p.$sig"
}

function Invoke-R360GitHubAsApp {
    # Calls the GitHub REST API with the App JWT (no stored token).
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$AppId, [Parameter(Mandatory)][string]$Path, [string]$Method = 'GET', [object]$Body, [string]$Token)
    if (-not $Token) { $Token = Get-R360GitHubAppJwt -AppId $AppId }
    $p = @{ Method = $Method; Uri = "https://api.github.com$Path"; Headers = @{ Authorization = "Bearer $Token"; Accept = 'application/vnd.github+json'; 'X-GitHub-Api-Version' = '2022-11-28' } }
    if ($null -ne $Body) { $p.Body = ($Body | ConvertTo-Json -Depth 10 -Compress); $p.ContentType = 'application/json' }
    Invoke-RestMethod @p
}

function Get-R360ContainerAppEnv {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    $cfg = Get-R360Config
    $app = Invoke-R360Az -Arguments @('containerapp', 'show', '-n', $cfg.ContainerApp, '-g', $cfg.ResourceGroup) -AllowFailure
    $envs = @{}
    if ($app) { foreach ($e in @($app.properties.template.containers[0].env)) { if ($e -and $e.PSObject.Properties['value']) { $envs[$e.name] = $e.value } } }
    $envs
}

function Set-R360ContainerAppEnv {
    # Sets env vars on app-r360 only when they differ, then waits for provisioning to finish.
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Values, [int]$TimeoutSeconds = 900)
    $cfg = Get-R360Config
    $current = Get-R360ContainerAppEnv
    $diff = @($Values.Keys | Where-Object { "$($current[$_])" -ne "$($Values[$_])" })
    if (-not $diff) { Write-R360Step "Container App settings already current ($($Values.Keys -join ', '))"; return }
    $pairs = @($diff | ForEach-Object { "$_=$($Values[$_])" })
    if (-not $PSCmdlet.ShouldProcess($cfg.ContainerApp, "Set env vars $($diff -join ', ')")) { return }
    Invoke-R360Az -Arguments (@('containerapp', 'update', '-n', $cfg.ContainerApp, '-g', $cfg.ResourceGroup, '--set-env-vars') + $pairs) | Out-Null
    Wait-R360Condition -Activity "$($cfg.ContainerApp) provisioning" -TimeoutSeconds $TimeoutSeconds -Condition {
        $s = Invoke-R360Az -Arguments @('containerapp', 'show', '-n', $cfg.ContainerApp, '-g', $cfg.ResourceGroup, '--query', 'properties.provisioningState')
        if ($s -eq 'Failed') { throw "$($cfg.ContainerApp) provisioning failed" }
        $s -eq 'Succeeded'
    } | Out-Null
}

function Set-R360RoleAssignment {
    # Idempotent Azure RBAC assignment at a scope.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$PrincipalId,
        [Parameter(Mandatory)][ValidateSet('User', 'ServicePrincipal', 'Group')][string]$PrincipalType,
        [Parameter(Mandatory)][string]$Role,
        [Parameter(Mandatory)][string]$Scope
    )
    $have = @(Invoke-R360Az -Arguments @('role', 'assignment', 'list', '--assignee', $PrincipalId, '--scope', $Scope) | Where-Object { $_.roleDefinitionName -eq $Role }).Count
    if ($have -gt 0) { Write-R360Step "RBAC '$Role' already assigned at $(Split-Path $Scope -Leaf)"; return }
    if (-not $PSCmdlet.ShouldProcess($Scope, "Assign '$Role' to $PrincipalType $PrincipalId")) { return }
    Invoke-R360Az -Arguments @('role', 'assignment', 'create', '--assignee-object-id', $PrincipalId, '--assignee-principal-type', $PrincipalType, '--role', $Role, '--scope', $Scope) | Out-Null
}

Export-ModuleMember -Function *-R360*
