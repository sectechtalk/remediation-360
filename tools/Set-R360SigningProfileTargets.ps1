#Requires -Version 7.4
<#
.SYNOPSIS
    Makes the two r360 code-signing certificate profiles reach every group (or All devices) that an r360 remediation is
    assigned to in Intune. One-time catch-up for promotions made before r360 widened the profiles itself. Dry run by default.
.DESCRIPTION
    r360 publishes every remediation with enforceSignatureCheck on. A device runs it only if it has the r360 code-signing
    certificate, which reaches devices through two Intune profiles:
      'r360 - Code Signing - Trusted Root' and 'r360 - Code Signing - Trusted Publisher'.
    From this release on, each r360 publish adds its target to both profiles before assigning the remediation. This script
    does the same for what is already in Intune:
      1. Finds both profiles by name (exactly one each).
      2. Reads every Intune remediation published by r360 (description contains "via r360]") and its assignments.
      3. For each profile, adds every missing include group (or All devices). Existing assignments, including exclusions,
         are kept. A target group that a profile EXCLUDES is reported and left alone.
      4. With -Apply, posts the new assignment list and reads it back to confirm.
    Delegated Graph only (your sign-in): DeviceManagementConfiguration.ReadWrite.All, DeviceManagementScripts.Read.All,
    Group.Read.All. Nothing is removed.
.EXAMPLE
    pwsh -File .\tools\Set-R360SigningProfileTargets.ps1           # dry run: shows what is missing
.EXAMPLE
    pwsh -File .\tools\Set-R360SigningProfileTargets.ps1 -Apply    # adds the missing targets
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive operator console script')]
[CmdletBinding()]
param([switch]$Apply)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'R360.Common.psm1') -Force
$cfg = Get-R360Config
$log = Enable-R360Log -Name 'Set-R360SigningProfileTargets'
$G = '#microsoft.graph.groupAssignmentTarget'; $X = '#microsoft.graph.exclusionGroupAssignmentTarget'; $ALL = '#microsoft.graph.allDevicesAssignmentTarget'
$typeOf = { param($t) if ($t -and $t.PSObject.Properties['@odata.type']) { [string]$t.'@odata.type' } else { '' } }
$groupOf = { param($t) if ($t -and $t.PSObject.Properties['groupId'] -and $t.groupId) { ([string]$t.groupId).ToLowerInvariant() } else { '' } }
try {
    Write-R360Step "Log: $log"
    Write-R360Step ($Apply ? 'APPLY: missing targets will be added' : 'DRY RUN: nothing will be changed (add -Apply)')
    if (-not (Connect-R360Graph -Scopes @('DeviceManagementConfiguration.ReadWrite.All', 'DeviceManagementScripts.Read.All', 'Group.Read.All'))) { throw 'Graph sign-in failed.' }

    # 1. The two profiles
    $configs = @(Invoke-R360Graph -Uri '/beta/deviceManagement/deviceConfigurations?$select=id,displayName' -All | ForEach-Object { $_ } | Where-Object { $_ })
    $profiles = foreach ($name in @($cfg.IntuneRootProfile, $cfg.IntunePubProfile)) {
        $hits = @($configs | Where-Object { $_.displayName -eq $name })
        if ($hits.Count -ne 1) { throw "Expected exactly one Intune profile named '$name', found $($hits.Count). Fix that in Intune (or run New-R360CodeSigningCert.ps1) first." }
        [pscustomobject]@{ Name = $name; Id = $hits[0].id }
    }

    # 2. Every target of every r360-published remediation
    $scripts = @(Invoke-R360Graph -Uri '/beta/deviceManagement/deviceHealthScripts?$select=id,displayName,description' -All | ForEach-Object { $_ } | Where-Object { $_ -and [string]$_.description -match 'via r360\]' })
    Write-R360Step "Remediations published by r360: $($scripts.Count)"
    $wantGroups = [ordered]@{}; $wantAll = $false; $usedBy = @{}
    $use = { param($key, $name) if (-not $usedBy.ContainsKey($key)) { $usedBy[$key] = [System.Collections.Generic.List[string]]::new() }; if (-not $usedBy[$key].Contains($name)) { $usedBy[$key].Add($name) } }
    foreach ($s in $scripts) {
        $as = @(Invoke-R360Graph -Uri "/beta/deviceManagement/deviceHealthScripts/$($s.id)/assignments" -All | ForEach-Object { $_ } | Where-Object { $_ })
        foreach ($a in $as) {
            $t = $a.target
            $type = & $typeOf $t
            if ($type -eq $ALL) { $wantAll = $true; & $use 'allDevices' ([string]$s.displayName) }
            elseif ($type -eq $G) { $gid = & $groupOf $t; $wantGroups[$gid] = $true; & $use $gid ([string]$s.displayName) }
        }
    }
    $names = @{}
    foreach ($gid in $wantGroups.Keys) {
        try { $names[$gid] = (Invoke-R360Graph -Uri "/v1.0/groups/$gid`?`$select=displayName").displayName } catch { $names[$gid] = '(group not found)' }
    }

    # 3-4. Widen each profile
    $report = [System.Collections.Generic.List[object]]::new()
    foreach ($p in $profiles) {
        $cur = @(Invoke-R360Graph -Uri "/beta/deviceManagement/deviceConfigurations/$($p.Id)/assignments" -All | ForEach-Object { $_ } | Where-Object { $_ })
        $targets = @($cur | ForEach-Object { $_.target } | Where-Object { $_ })
        $hasAll = [bool]($targets | Where-Object { (& $typeOf $_) -eq $ALL })
        $inc = @($targets | Where-Object { (& $typeOf $_) -eq $G } | ForEach-Object { & $groupOf $_ })
        $exc = @($targets | Where-Object { (& $typeOf $_) -eq $X } | ForEach-Object { & $groupOf $_ })
        $add = [System.Collections.Generic.List[object]]::new()
        if ($wantAll -and -not $hasAll) { $add.Add(@{ '@odata.type' = $ALL }); $report.Add([pscustomobject]@{ Profile = $p.Name; Target = 'All devices'; Status = ($Apply ? 'ADDED' : 'WOULD ADD'); UsedBy = ($usedBy['allDevices'] -join ', ') }) }
        foreach ($gid in $wantGroups.Keys) {
            $label = "$($names[$gid]) ($gid)"
            if ($exc -contains $gid) { $report.Add([pscustomobject]@{ Profile = $p.Name; Target = $label; Status = 'EXCLUDED: left alone, remove the exclusion in Intune'; UsedBy = ($usedBy[$gid] -join ', ') }); continue }
            if ($hasAll -or $inc -contains $gid) { $report.Add([pscustomobject]@{ Profile = $p.Name; Target = $label; Status = 'OK'; UsedBy = ($usedBy[$gid] -join ', ') }); continue }
            $add.Add(@{ '@odata.type' = $G; groupId = $gid })
            $report.Add([pscustomobject]@{ Profile = $p.Name; Target = $label; Status = ($Apply ? 'ADDED' : 'WOULD ADD'); UsedBy = ($usedBy[$gid] -join ', ') })
        }
        if ($Apply -and $add.Count) {
            $all = @($targets) + @($add)
            Invoke-R360Graph -Method POST -Uri "/beta/deviceManagement/deviceConfigurations/$($p.Id)/assign" -Body @{ assignments = @($all | ForEach-Object { @{ target = $_ } }) } | Out-Null
            $after = @(Invoke-R360Graph -Uri "/beta/deviceManagement/deviceConfigurations/$($p.Id)/assignments" -All | ForEach-Object { $_.target } | Where-Object { $_ })
            foreach ($t in $add) {
                $ok = if ($t['@odata.type'] -eq $ALL) { [bool]($after | Where-Object { (& $typeOf $_) -eq $ALL }) } else { [bool]($after | Where-Object { (& $groupOf $_) -eq $t.groupId }) }
                if (-not $ok) { throw "$($p.Name): Intune does not show $($t.groupId ?? 'All devices') after the assign. Check the profile in Intune." }
            }
        }
    }
    if (-not $report.Count) { Write-R360Step 'No r360 remediation has an assignment yet; nothing to do.' }
    else { $report | Format-Table -AutoSize -Wrap | Out-String -Width 220 | Write-Host }
    Write-R360Step ($Apply ? 'Done. Devices pick up the certificate at their next Intune check-in (Certificates page shows per-device status).' : 'Dry run finished. Re-run with -Apply to add the missing targets.')
}
finally { Disable-R360Log }
