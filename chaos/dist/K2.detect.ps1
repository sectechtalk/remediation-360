# STT - Chaos - K2 AES only for Kerberos
# Configuration check: AD objects (Kerberos). Proves: RC4 tickets are not issued.
# Chaos Monkey test from HeatMap 360. It only reads and asks: it never changes this machine or any other.
# Exit 0 = PASS (proved hardened). Exit 1 = FAIL or COULD NOT TEST. The first line of output is the verdict.
# Built from chaos/tests/K2.ps1 and chaos/lib.ps1 in r360 by tools/build-chaos.mjs.

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

#region Sysvol
# GPOs linked (and enabled) on the domain root and the Domain Controllers OU, as SYSVOL folder paths. This is the
# policy as written in SYSVOL, not what a DC applied (security filtering and WMI filters are not evaluated).
function Get-DcGpoPath {
    param([Parameter(Mandatory = $true)]$Context)
    $paths = New-Object -TypeName System.Collections.Generic.List[string]
    foreach ($dn in @($Context.DomainDn, "OU=Domain Controllers,$($Context.DomainDn)")) {
        $o = @(Find-AdObject -SearchBase $dn -Filter '(objectClass=*)' -Property 'gplink' -Scope Base)
        if ($o.Count -eq 0 -or -not $o[0].gplink) { continue }
        foreach ($m in [regex]::Matches([string]$o[0].gplink, '\[LDAP://[Cc][Nn]=(\{[0-9A-Fa-f-]+\}),[^;]*;(\d+)\]')) {
            if ([int]$m.Groups[2].Value -band 1) { continue }
            $p = "\\$($Context.DnsDomain)\SYSVOL\$($Context.DnsDomain)\Policies\$($m.Groups[1].Value)"
            if (-not $paths.Contains($p)) { $paths.Add($p) }
        }
    }
    return $paths
}

# Lines of a GPO's security template (GptTmpl.inf), or an empty list.
function Get-GpoSecurityLine {
    param([Parameter(Mandatory = $true)][string]$GpoPath)
    $f = Join-Path -Path $GpoPath -ChildPath 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
    if (-not (Test-Path -LiteralPath $f)) { return @() }
    return @(Get-Content -LiteralPath $f)
}

# Entries of a GPO's Machine\Registry.pol (key, value name, type, data).
function Get-GpoRegistryPol {
    param([Parameter(Mandatory = $true)][string]$GpoPath)
    $f = Join-Path -Path $GpoPath -ChildPath 'Machine\Registry.pol'
    if (-not (Test-Path -LiteralPath $f)) { return @() }
    $b = [System.IO.File]::ReadAllBytes($f)
    if ($b.Length -lt 8 -or [System.Text.Encoding]::ASCII.GetString($b, 0, 4) -ne 'PReg') { return @() }
    $i = 8
    $readText = {
        $start = $script:polPos
        while ($script:polPos + 1 -lt $b.Length -and -not ($b[$script:polPos] -eq 0 -and $b[$script:polPos + 1] -eq 0)) { $script:polPos += 2 }
        $t = [System.Text.Encoding]::Unicode.GetString($b, $start, $script:polPos - $start)
        $script:polPos += 4  # the terminating null and the ';'
        $t
    }
    $entries = while ($i + 2 -lt $b.Length) {
        $script:polPos = $i + 2  # skip '['
        $key = & $readText
        $name = & $readText
        $type = [BitConverter]::ToUInt32($b, $script:polPos); $script:polPos += 6
        $size = [BitConverter]::ToUInt32($b, $script:polPos); $script:polPos += 6
        $data = if ($type -eq 4 -and $size -ge 4) { [BitConverter]::ToUInt32($b, $script:polPos) } elseif ($type -in 1, 2) { [System.Text.Encoding]::Unicode.GetString($b, $script:polPos, [Math]::Max(0, [int]$size - 2)) } else { $null }
        $script:polPos += [int]$size + 2  # data and ']'
        $i = $script:polPos
        [pscustomobject]@{ Key = $key; Name = $name; Type = $type; Data = $data }
    }
    return @($entries)
}

# Group Policy Preferences registry items of a GPO (Machine\Preferences\Registry\Registry.xml).
function Get-GpoPreferenceRegistry {
    param([Parameter(Mandatory = $true)][string]$GpoPath)
    $f = Join-Path -Path $GpoPath -ChildPath 'Machine\Preferences\Registry\Registry.xml'
    if (-not (Test-Path -LiteralPath $f)) { return @() }
    [xml]$x = Get-Content -LiteralPath $f -Raw
    return @($x.SelectNodes('//Properties') | ForEach-Object { [pscustomobject]@{ Key = $_.key; Name = $_.name; Value = $_.value; Action = $_.action } })
}

# A registry-backed security option set in the DC GPOs ([Registry Values] in GptTmpl.inf), as found per GPO.
function Find-DcGpoRegistryValue {
    param([Parameter(Mandatory = $true)]$Context, [Parameter(Mandatory = $true)][string]$Pattern)
    foreach ($g in Get-DcGpoPath -Context $Context) {
        foreach ($line in Get-GpoSecurityLine -GpoPath $g) {
            if ($line -match "^\s*(MACHINE\\[^=]*$Pattern[^=]*)=\s*(\d+),(.*)$") {
                [pscustomobject]@{ Gpo = Split-Path -Path $g -Leaf; Key = $Matches[1]; Value = $Matches[3].Trim('" ') }
            }
        }
    }
}
#endregion

$script:ChaosId = 'K2'
try {
    if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
    $ctx = Get-AdContext
    $problems = @()
    $aesOnly = { param($v) $n = [int64]$v -band 0x1F; (($n -band 0x7) -eq 0) -and (($n -band 0x18) -ne 0) }
    $local = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -Name 'SupportedEncryptionTypes'
    Add-Detail "This machine SupportedEncryptionTypes = $(if ($null -eq $local) { 'not set' } else { '0x{0:X}' -f [int64]$local })"
    if ($null -eq $local -or -not (& $aesOnly $local)) { $problems += 'this machine does not limit Kerberos to AES' }
    $dc = @(Find-DcGpoRegistryValue -Context $ctx -Pattern 'Kerberos\\Parameters\\SupportedEncryptionTypes')
    if ($dc.Count -eq 0) { $problems += 'no DC policy limits Kerberos to AES'; Add-Detail 'DC policy SupportedEncryptionTypes: not set' }
    foreach ($d in $dc) {
        Add-Detail "DC policy SupportedEncryptionTypes = 0x$('{0:X}' -f [int64]$d.Value) in GPO $($d.Gpo)"
        if (-not (& $aesOnly $d.Value)) { $problems += "GPO $($d.Gpo) allows more than AES" }
    }
    $noAes = @(Find-AdObject -SearchBase $ctx.DomainDn -Filter '(&(samAccountType=805306368)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(sAMAccountName=krbtgt)))' -Property 'samaccountname', 'msds-supportedencryptiontypes' | Where-Object { $null -eq $_.'msds-supportedencryptiontypes' -or -not ([int]$_.'msds-supportedencryptiontypes' -band 0x18) } | ForEach-Object { [string]$_.samaccountname })
    if ($noAes.Count -gt 0) { $problems += "$($noAes.Count) service account(s) without AES"; Add-Detail "Service accounts without AES: $((@($noAes) | Select-Object -First 25) -join ', ')" }
    if ($problems.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "$($problems -join '; ')." }
    Write-Verdict -Verdict 'PASS' -Summary 'DC policy and this machine allow AES only, and every service account has AES.'
} catch {
    Write-Verdict -Verdict 'COULD NOT TEST' -Summary "the test stopped: $($_.Exception.Message)"
}
