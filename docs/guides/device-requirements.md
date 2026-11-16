# How to: make a Windows device work with r360

This guide answers one question: what does a Windows PC need before r360 can manage it? It is written from what r360
actually calls today (Intune Remediations through Graph `deviceHealthScripts`), not from the roadmap.

## Short answer

r360 manages a device **through Intune Remediations**. A device works with r360 when all of these are true:

| # | Requirement | Why r360 needs it |
|---|---|---|
| 1 | **Windows 10 or 11 Pro, Enterprise or Education**, not in S mode | Remediations run in the Intune Management Extension, which does not run on Home or S mode. |
| 2 | **Microsoft Entra joined or Microsoft Entra hybrid joined** | Microsoft's prerequisite for Remediations. **Entra registered (Access work or school on a personal PC) is not enough.** |
| 3 | **Enrolled in Intune (MDM)**, or co-managed with Configuration Manager | r360 publishes and reads scripts in Intune; an unenrolled device never receives them. |
| 4 | **The device's user has a Remediations license**: Windows Enterprise E3/E5 (in Microsoft 365 F3, E3, E5), Windows Education A3/A5, or Windows VDA per user | Microsoft licensing for Remediations. An Intune license is needed for enrollment too (included in those Microsoft 365 suites). |
| 5 | **Both r360 code-signing profiles applied**: `r360 - Code Signing - Trusted Root` and `r360 - Code Signing - Trusted Publisher` | r360 always publishes with `enforceSignatureCheck: true`. Without the `CN=SecTechTalk r360 Code Signing` certificate in the machine Trusted Root and Trusted Publisher stores, every r360 script fails the signature check and never runs. |
| 6 | **In an Entra group the remediation is assigned to**: `sg-remediation-canary` for a new publish, or the groups chosen at promotion | r360 assigns only to the canary group on publish and to the promoted groups after the soak, and adds the same target to both certificate profiles. |
| 7 | Checks in with Intune (Intune Management Extension running, version 1.58.103.0 or later; it updates itself) | Results reach the **Fleet** page only after the device reports its run state. |

Nothing else is required on the device. r360 installs no agent, needs no domain join (Entra join alone is fine), and
needs no Defender for Endpoint license today.

## Defender: what comes free and what r360 uses

**Yes, Microsoft Defender Antivirus is built into every Windows 10 and 11 PC.** It runs in active mode with no license,
no domain join and no Entra join, as long as no other antivirus has registered with Windows Security Center (then it
turns itself off).

**Microsoft Defender for Endpoint (MDE) is different.** It adds EDR, the security.microsoft.com device inventory and the
remote response actions (isolate, live response, scan, collect package). It needs a license (Defender for Endpoint P1 or
P2, Defender for Business, or a suite that includes one, such as Microsoft 365 E3 for P1, E5 or Business Premium) and
the device must be **onboarded** (the `Sense` service running).

| r360 feature | Needs Defender Antivirus | Needs Defender for Endpoint (license + onboarding) |
|---|---|---|
| Remediations, Fleet, Certificates, Changes, Publish, Promote | No | No |
| Change requests, ServiceNow search, Deployments, Audit | No (no device involved) | No |
| Emergency page: isolate, AV scan, stop and quarantine (P1 or P2), investigation package and restrict app execution (P2) | Yes | **Yes**, plus a Defender role with "Active remediation actions" for the approver |
| A remediation script that calls Defender cmdlets (for example `Get-MpComputerStatus`, `Start-MpScan`) | Yes, for that script only | No |

So today a PC with only the built-in Defender Antivirus is fully supported by r360. MDE becomes a requirement only for
the Emergency page actions, and only on the devices you want to act on.

## The signing certificate follows every publish

Every r360 publish (canary or promotion) first adds its target to both certificate profiles, then assigns the
remediation. It keeps every existing assignment, refuses to publish if a profile **excludes** the target group (remove
the exclusion in Intune), and records what it added in the audit row (`signingProfiles`). A re-publish of an old
promotion repairs a profile that lost its target. Devices get the certificate at their next Intune check-in; a
remediation that runs before that fails once and succeeds on its next scheduled run.

Promotions made before this existed: run the one-time catch-up on DEVICE02 (PowerShell 7):

```powershell
cd C:\path\to\remediation-360
pwsh -File .\tools\Set-R360SigningProfileTargets.ps1          # dry run: lists every r360 target missing from the profiles
pwsh -File .\tools\Set-R360SigningProfileTargets.ps1 -Apply   # adds them (additive, exclusions left alone)
```

## Check a device (run on the device, PowerShell as administrator)

```powershell
# 1-2. Windows edition and Entra join state
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, OperatingSystemSKU
dsregcmd /status | Select-String 'AzureAdJoined|DomainJoined|WorkplaceJoined|DeviceId|TenantName'
# Pass: AzureAdJoined : YES (DomainJoined YES as well means hybrid joined). WorkplaceJoined alone is not enough.

# 3. Intune enrollment and the management extension
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments' | Get-ItemProperty | Where-Object ProviderID -eq 'MS DM Server' | Select-Object UPN, EnrollmentState
Get-Service IntuneManagementExtension | Select-Object Status, StartType
(Get-Item 'C:\Program Files (x86)\Microsoft Intune Management Extension\Microsoft.Management.Services.IntuneWindowsAgent.exe').VersionInfo.FileVersion

# 5. r360 code-signing certificate in both machine stores
'Root', 'TrustedPublisher' | ForEach-Object { [pscustomobject]@{ Store = $_; Found = [bool](Get-ChildItem "Cert:\LocalMachine\$_" | Where-Object Subject -eq 'CN=SecTechTalk r360 Code Signing') } }

# Defender Antivirus (free) and Defender for Endpoint (licensed, onboarded)
Get-MpComputerStatus | Select-Object AMRunningMode, AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated
Get-Service Sense -ErrorAction SilentlyContinue | Select-Object Status   # Running = onboarded to Defender for Endpoint
(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' -ErrorAction SilentlyContinue).OnboardingState  # 1 = onboarded

# Make the device fetch new remediations now (restarting the extension triggers a check-in)
Get-ScheduledTask | Where-Object TaskName -eq 'PushLaunch' | Start-ScheduledTask
Restart-Service IntuneManagementExtension
```

## Check the tenant side (DEVICE02, PowerShell 7)

```powershell
Import-Module Microsoft.Graph.Authentication
Connect-MgGraph -Scopes 'DeviceManagementConfiguration.Read.All','DeviceManagementManagedDevices.Read.All','Group.Read.All' -NoWelcome

# 4. Remediations is available: an Intune admin confirms the Windows license once (Devices > Scripts and remediations)
(Invoke-MgGraphRequest -Uri 'https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts?$top=1&$select=id').value.Count  # an error here means Remediations is not available to r360

# 5-6. Which groups get the r360 certificate profiles, and is DEVICE01 in the canary group
$profiles = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$filter=startswith(displayName,'r360 - Code Signing')&`$select=id,displayName").value
foreach ($p in $profiles) {
  $groups = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$($p.id)/assignments").value.target.groupId
  foreach ($g in $groups) { [pscustomobject]@{ Profile = $p.displayName; Group = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/groups/$g`?`$select=displayName").displayName } }
}
$canary = '00000000-0000-4000-8000-0000000000b2'
(Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/groups/$canary/members?`$select=displayName").value.displayName
```

## Sources

- Remediations prerequisites and licensing: https://learn.microsoft.com/intune/device-management/tools/deploy-remediations#prerequisites
- Intune Management Extension prerequisites: https://learn.microsoft.com/intune/device-management/tools/management-extension-windows#prerequisites
- Defender Antivirus without Defender for Endpoint: https://learn.microsoft.com/defender-endpoint/defender-antivirus-compatibility-without-mde
- r360: `server/intune.mjs` (publish body, `enforceSignatureCheck: true`), `server/changes.mjs` `ensureSigningProfiles` (profiles follow each publish), `tools/New-R360CodeSigningCert.ps1` (profiles and canary assignment), `docs/remediation-360-design.md` section 8 (Defender actions)
