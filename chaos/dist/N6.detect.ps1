# STT - Chaos - N6 DCs refuse NTLM
# Active probe (NTLM). Proves: NTLM is blocked at the domain controllers (last reduction stage).
# Chaos Monkey test from HeatMap 360. It only reads and asks: it never changes this machine or any other.
# Exit 0 = PASS (proved hardened). Exit 1 = FAIL or COULD NOT TEST. The first line of output is the verdict.
# Built from chaos/tests/N6.ps1 and chaos/lib.ps1 in r360 by tools/build-chaos.mjs.

#region Base
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$script:Detail = New-Object -TypeName System.Collections.Generic.List[string]

# One line of detail under the verdict.
function Add-Detail {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)
    $script:Detail.Add($Text)
}

# Prints the verdict and the details (Intune keeps about 2,000 characters) and ends the script. Only PASS exits 0, so
# FAIL and COULD NOT TEST never show a machine as hardened.
function Write-Verdict {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('PASS', 'FAIL', 'COULD NOT TEST')][string]$Verdict,
        [Parameter(Mandatory = $true)][string]$Summary
    )
    $text = (@("$Verdict ${script:ChaosId}: $Summary") + @($script:Detail)) -join "`n"
    if ($text.Length -gt 2000) { $text = $text.Substring(0, 1980) + "`n... (cut)" }
    Write-Output $text
    if ($Verdict -eq 'PASS') { exit 0 }
    exit 1
}

# Probes and AD checks need a machine joined to an AD domain.
function Test-DomainJoined {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    return [bool]$cs.PartOfDomain
}
#endregion

#region Reg
# A registry value, or $null when the key or value is missing.
function Get-RegValue {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Name)
    $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $null }
    return $item.$Name
}
#endregion

#region Ad
# Naming contexts and SIDs of this machine's domain and forest, read with the computer account (SYSTEM).
function Get-AdContext {
    $rootDse = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList 'LDAP://RootDSE'
    $domainDn = [string]$rootDse.Properties['defaultNamingContext'][0]
    $forestDn = [string]$rootDse.Properties['rootDomainNamingContext'][0]
    $sidOf = {
        param($Dn)
        $e = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "LDAP://$Dn"
        (New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList ([byte[]]$e.Properties['objectSid'][0]), 0).Value
    }
    $domainSid = & $sidOf $domainDn
    $forestSid = if ($forestDn -eq $domainDn) { $domainSid } else { & $sidOf $forestDn }
    [pscustomobject]@{
        DomainDn  = $domainDn
        ConfigDn  = [string]$rootDse.Properties['configurationNamingContext'][0]
        SchemaDn  = [string]$rootDse.Properties['schemaNamingContext'][0]
        ForestDn  = $forestDn
        DnsDomain = (($domainDn -split ',') | ForEach-Object { $_ -replace '^DC=', '' }) -join '.'
        DomainSid = $domainSid
        ForestSid = $forestSid
    }
}

# LDAP search. Returns one object per entry with lower-case attribute names; single values are unwrapped.
function Find-AdObject {
    param(
        [Parameter(Mandatory = $true)][string]$SearchBase,
        [Parameter(Mandatory = $true)][string]$Filter,
        [string[]]$Property = @('distinguishedname'),
        [ValidateSet('Base', 'OneLevel', 'Subtree')][string]$Scope = 'Subtree',
        [int]$SizeLimit = 0,
        [switch]$WithAcl
    )
    $root = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "LDAP://$SearchBase"
    $props = @($Property)
    if ($WithAcl) { $props += 'ntsecuritydescriptor' }
    $searcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList $root, $Filter, $props, ([System.DirectoryServices.SearchScope]::$Scope)
    $searcher.PageSize = 500
    if ($SizeLimit -gt 0) { $searcher.SizeLimit = $SizeLimit }
    if ($WithAcl) { $searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl -bor [System.DirectoryServices.SecurityMasks]::Owner }
    $found = $searcher.FindAll()
    try {
        foreach ($r in $found) {
            $o = [ordered]@{}
            foreach ($p in $r.Properties.PropertyNames) {
                $v = $r.Properties[$p]
                if ($v.Count -eq 1) { $o[$p] = $v[0] } else { $o[$p] = @($v) }
            }
            if (-not $o.Contains('distinguishedname')) { $o['distinguishedname'] = ($r.Path -replace '^LDAP://([^/]+/)?', '') }
            [pscustomobject]$o
        }
    } finally {
        $found.Dispose()
    }
}

# Domain controllers (writable and read-only) with their DNS names.
function Get-DomainController {
    param([Parameter(Mandatory = $true)]$Context)
    Find-AdObject -SearchBase $Context.DomainDn -Filter '(&(objectCategory=computer)(|(primaryGroupID=516)(primaryGroupID=521)))' -Property 'dnshostname', 'name', 'operatingsystem', 'objectsid'
}

# A readable name for a SID, or the SID itself when it cannot be translated.
function Resolve-SidName {
    param([Parameter(Mandatory = $true)][string]$Sid)
    try {
        return (New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $Sid).Translate([System.Security.Principal.NTAccount]).Value
    } catch {
        $null = $_
        return $Sid
    }
}

# Groups any signed-in user (or anonymous) is part of. A right held by one of these is open to everyone.
function Get-LowPrivilegeSid {
    param([Parameter(Mandatory = $true)]$Context)
    @('S-1-1-0', 'S-1-5-7', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-32-546', "$($Context.DomainSid)-513", "$($Context.DomainSid)-514", "$($Context.DomainSid)-515")
}

# Admin-level principals that may hold any right on directory objects.
function Get-AdminSid {
    param([Parameter(Mandatory = $true)]$Context)
    @('S-1-5-18', 'S-1-5-9', 'S-1-5-10', 'S-1-3-0', 'S-1-5-32-544', 'S-1-5-32-548', "$($Context.DomainSid)-512", "$($Context.DomainSid)-516", "$($Context.DomainSid)-521",
        "$($Context.ForestSid)-518", "$($Context.ForestSid)-519", "$($Context.ForestSid)-498", "$($Context.DomainSid)-526", "$($Context.ForestSid)-527")
}

# The access rules of an object's nTSecurityDescriptor (read with -WithAcl), with SIDs, skipping rules that only apply
# to child objects unless -IncludeInheritOnly. Returns the descriptor too, for owner and inheritance checks.
function Get-AdAclRule {
    param([Parameter(Mandatory = $true)]$AdObject, [switch]$IncludeInheritOnly)
    $sd = New-Object -TypeName System.DirectoryServices.ActiveDirectorySecurity
    $sd.SetSecurityDescriptorBinaryForm([byte[]]$AdObject.ntsecuritydescriptor)
    $rules = foreach ($rule in $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne 'Allow') { continue }
        if (-not $IncludeInheritOnly -and ($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly)) { continue }
        $rule
    }
    [pscustomobject]@{ Descriptor = $sd; Owner = $sd.GetOwner([System.Security.Principal.SecurityIdentifier]).Value; Rules = @($rules) }
}

# True when the rule lets its holder change the object: full control, change permissions or owner, write every
# property, write one of the listed properties, or (with -CreateChild) create objects inside a container.
function Test-WriteRule {
    param([Parameter(Mandatory = $true)]$Rule, [guid[]]$PropertyGuid = @(), [switch]$CreateChild)
    $r = [System.DirectoryServices.ActiveDirectoryRights]
    $rights = $Rule.ActiveDirectoryRights
    if ($rights -band ($r::GenericAll -bor $r::WriteDacl -bor $r::WriteOwner)) { return $true }
    $anyType = $Rule.ObjectType -eq [guid]::Empty
    if (($rights -band $r::WriteProperty) -and ($anyType -or ($PropertyGuid -contains $Rule.ObjectType))) { return $true }
    if ($CreateChild -and ($rights -band $r::CreateChild)) { return $true }
    return $false
}

# schemaIDGUID of an attribute or class by its LDAP name, or $null when the schema does not have it.
function Get-SchemaGuid {
    param([Parameter(Mandatory = $true)]$Context, [Parameter(Mandatory = $true)][string]$LdapName)
    $s = @(Find-AdObject -SearchBase $Context.SchemaDn -Filter "(lDAPDisplayName=$LdapName)" -Property 'schemaidguid' -Scope OneLevel)
    if ($s.Count -eq 0) { return $null }
    return [guid][byte[]]$s[0].schemaidguid
}

# A FILETIME attribute as a UTC date, or $null when it is empty or never set.
function ConvertFrom-FileTime {
    param($Value)
    if ($null -eq $Value) { return $null }
    $n = [int64]$Value
    if ($n -le 0 -or $n -ge [int64]::MaxValue) { return $null }
    return [DateTime]::FromFileTimeUtc($n)
}

# The SID string of an object read with the objectsid attribute.
function ConvertTo-SidString {
    param([Parameter(Mandatory = $true)]$Bytes)
    (New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList ([byte[]]$Bytes), 0).Value
}
#endregion

#region Net
# The first IPv4 address of a host name, or $null.
function Resolve-HostIPv4 {
    param([Parameter(Mandatory = $true)][string]$Name)
    try {
        $a = [System.Net.Dns]::GetHostAddresses($Name) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1
        if ($a) { return $a.IPAddressToString }
    } catch {
        $null = $_
    }
    return $null
}

# True when a TCP port accepts a connection within the timeout.
function Test-TcpPort {
    param([Parameter(Mandatory = $true)][string]$Target, [Parameter(Mandatory = $true)][int]$Port, [int]$TimeoutMs = 2000)
    $c = New-Object -TypeName System.Net.Sockets.TcpClient
    try {
        $iar = $c.BeginConnect($Target, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs)) { return $false }
        $c.EndConnect($iar)
        return $true
    } catch {
        $null = $_
        return $false
    } finally {
        $c.Close()
    }
}
#endregion

#region NtlmShare
# Outgoing NTLM blocked by this machine itself (N5 / V2) makes an NTLM probe meaningless.
function Test-OutgoingNtlmBlocked {
    $restrict = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'RestrictSendingNTLMTraffic'
    $smbBlock = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' -Name 'BlockNTLM'
    return ($restrict -eq 2 -or $smbBlock -eq 1)
}

# Connects to \\<IP>\<share> as this computer (SYSTEM) through WNetAddConnection2, which never prompts. By IP address
# Windows cannot use Kerberos, so the login is NTLM. The connection is dropped again straight away.
# Returns 'accepted', 'refused (<Windows error>)' or 'unreachable (<Windows error>)'.
function Test-NtlmShare {
    param([Parameter(Mandatory = $true)][string]$Address, [string]$Share = 'IPC$')
    if (-not ('ChaosMonkey.Wnet' -as [type])) {
        Add-Type -Namespace ChaosMonkey -Name Wnet -MemberDefinition @'
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NETRESOURCE { public int dwScope; public int dwType; public int dwDisplayType; public int dwUsage; public string lpLocalName; public string lpRemoteName; public string lpComment; public string lpProvider; }
[DllImport("mpr.dll", CharSet = CharSet.Unicode)] public static extern int WNetAddConnection2(ref NETRESOURCE netResource, string secret, string account, int flags);
[DllImport("mpr.dll", CharSet = CharSet.Unicode)] public static extern int WNetCancelConnection2(string name, int flags, bool force);
'@
    }
    $unc = "\\$Address\$Share"
    $nr = New-Object -TypeName 'ChaosMonkey.Wnet+NETRESOURCE'
    $nr.lpRemoteName = $unc
    $code = [ChaosMonkey.Wnet]::WNetAddConnection2([ref]$nr, $null, $null, 0)
    if ($code -eq 0) {
        $null = [ChaosMonkey.Wnet]::WNetCancelConnection2($unc, 0, $true)
        return 'accepted'
    }
    if ($code -in 53, 64, 67, 121, 1203, 1231, 1232, 1311) { return "unreachable (Windows error $code)" }
    return "refused (Windows error $code)"
}
#endregion

$script:ChaosId = 'N6'
try {
    if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
    $ctx = Get-AdContext
    if (Test-OutgoingNtlmBlocked) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine blocks outgoing NTLM itself (N5 or V2), so it cannot tell whether the DCs refuse it.' }
    $dcs = @(Get-DomainController -Context $ctx)
    if ($dcs.Count -eq 0) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'no domain controller was found in AD.' }
    $accepted = @(); $unreachable = @()
    foreach ($dc in $dcs) {
        $ip = Resolve-HostIPv4 -Name ([string]$dc.dnshostname)
        if (-not $ip) { Add-Detail "$($dc.name): no IPv4 address"; $unreachable += $dc.name; continue }
        $r = Test-NtlmShare -Address $ip -Share 'NETLOGON'
        Add-Detail "$($dc.name) ($ip): NTLM login $r"
        if ($r -eq 'accepted') { $accepted += $dc.name } elseif ($r -like 'unreachable*') { $unreachable += $dc.name }
    }
    if ($accepted.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "$($accepted.Count) of $($dcs.Count) DCs accepted an NTLM login: $($accepted -join ', ')." }
    if ($unreachable.Count -gt 0) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary "could not reach $($unreachable -join ', ')." }
    Write-Verdict -Verdict 'PASS' -Summary "all $($dcs.Count) DCs refused an NTLM login."
} catch {
    Write-Verdict -Verdict 'COULD NOT TEST' -Summary "the test stopped: $($_.Exception.Message)"
}
