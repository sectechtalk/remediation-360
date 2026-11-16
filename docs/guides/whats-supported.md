# What's supported: r360 by license and join state

This guide says what r360 can and cannot do on a Windows PC, depending on **the license its user has** and **how the PC
is joined**. Today r360 reaches devices through exactly one channel, **Intune Remediations**, and the
**Emergency** page (Defender for Endpoint response actions on one device). Everything else in r360 (Change requests, ServiceNow, Deployments, Audit)
does not touch devices and works regardless of what a PC has.

For the step-by-step device checklist, see [device-requirements.md](device-requirements.md).

## The two things that decide it

**1. Join state** decides whether Intune can manage the PC at all.

| Join state | How to tell (`dsregcmd /status`) | Intune enrollment | Intune Remediations (r360 today) | Defender for Endpoint |
|---|---|---|---|---|
| **Entra joined** | `AzureAdJoined : YES`, `DomainJoined : NO` | Yes (automatic enrollment) | **Yes** | Yes, if licensed and onboarded |
| **Entra hybrid joined** | `AzureAdJoined : YES`, `DomainJoined : YES` | Yes (GPO auto-enrollment or co-management) | **Yes** | Yes, if licensed and onboarded |
| **Entra registered** (Access work or school, BYOD) | `WorkplaceJoined : YES` only | Possible (BYOD MDM enrollment) | **No.** Microsoft requires joined or hybrid joined. Device-context platform scripts can run once enrolled; r360 does not use those yet. | Yes, if licensed and onboarded |
| **On-premises AD domain joined only** | `DomainJoined : YES`, `AzureAdJoined : NO` | No. Make it hybrid joined first (sync the computer object with Cloud Sync or Connect Sync). | **No** | **Yes**, if licensed: onboard with Group Policy. No Entra or Intune needed. |
| **None** (workgroup, local accounts) | All three `NO` | No | **No** | **Yes**, if licensed: onboard with the local script (up to 10 devices) |

**2. License** decides which features those channels unlock. The license is per user (Remediations) or per user/device
(Defender), not per tenant.

| License (what the user has) | Intune | Windows Enterprise E3 (Remediations right) | Defender on the PC | Defender response actions on the Emergency page |
|---|---|---|---|---|
| **None** (Windows Pro, no Microsoft 365) | No | No | Defender Antivirus only (free, local) | None |
| **Office 365 E1 / E3 / E5** | No | No | Defender Antivirus only (Office 365 E5's Defender for Office 365 protects email and files, not PCs) | None |
| **Microsoft 365 Business Basic / Standard** | No | No | Defender Antivirus only | None |
| **Microsoft 365 Business Premium** | Intune P1 | **No**: Business Premium is not on Microsoft's Remediations license list | Defender for Business | Isolate, AV scan, file indicators, **live response** |
| **Intune P1 alone** (or EMS E3) | Intune P1 | No | Defender Antivirus only | None |
| **Microsoft 365 F3** | Intune P1 | Yes | Defender Antivirus (add MDE P1 to get response actions) | None unless MDE is added |
| **Microsoft 365 E3** (or Windows E3 + Intune) | Intune P1 | **Yes** | Defender for Endpoint P1 | Isolate, AV scan, stop and quarantine file, file indicators. **No live response.** |
| **Microsoft 365 E5** (or E3 + MDE P2) | Intune P1 | **Yes** | Defender for Endpoint P2 | **All**: isolate, AV scan, live response, collect investigation package, restrict app execution |
| **Windows VDA per user / Education A3, A5** | With Intune | **Yes** | As E3 (A3) / E5 (A5) | As E3 / E5 |

**Entra ID licenses** decide enrollment and admin controls, not r360 features: Entra ID Free is enough to Entra join or
hybrid join a PC, but automatic Intune enrollment needs Entra ID P1 (in every Microsoft 365 suite, not in Office 365).
Entra ID P2 adds PIM, which r360's write gate reads (Intune Administrator active) when `R360_PIM_MODE=enforce`.

## The combined matrix: what r360 can do on that PC

"Remediations" means every device feature r360 has today: publish signed detect/remediate scripts, canary, promote,
the Fleet page run states, drift. "Defender" means the Emergency page actions.

| | Entra joined | Hybrid joined | Entra registered | AD domain joined only | None |
|---|---|---|---|---|---|
| **No license, Office 365, Business Basic/Standard** | Nothing | Nothing | Nothing | Nothing | Nothing |
| **Business Premium** | Defender (incl. live response). **No Remediations.** | Defender (incl. live response). No Remediations. | Defender, if onboarded | Defender, if onboarded by GPO | Defender, if onboarded by script |
| **E3 / F3 / A3 / VDA** | **Remediations** + Defender P1 actions (E3) | **Remediations** + Defender P1 actions (E3) | Defender P1 actions only | Defender P1 actions, if onboarded | Defender P1 actions, if onboarded |
| **E5 / A5** | **Everything** | **Everything** | Defender (all actions) only | Defender (all actions), if onboarded | Defender (all actions), if onboarded |

How to read it:

- **r360's core feature needs two things at once:** a joined or hybrid joined PC **and** a Windows E3-class license.
  Missing either one, r360 cannot run a remediation on that PC today.
- **Defender actions ignore join state.** Any PC can be onboarded to Defender for Endpoint (Group Policy, local script,
  Intune or Configuration Manager). Only the license matters.
- **Business Premium is the trap.** It has Intune and Defender for Business but not Windows Enterprise E3, so Microsoft's
  license verification blocks Remediations. To use r360's core feature, add Windows E3 (or move those users to M365 E3).
- **The built-in Defender Antivirus** is on every PC with no license, but it has no remote API. Nothing in r360 can drive
  it remotely; only a script that already runs on the PC (a remediation, or an agent) can call its cmdlets.
- **Every Remediations PC also needs** Pro, Enterprise or Education (not Home, not S mode) and the two r360 code-signing
  certificate profiles. See [device-requirements.md](device-requirements.md).

## Check a user's license and a device's join state (DEVICE02, PowerShell 7)

```powershell
Import-Module Microsoft.Graph.Authentication
Connect-MgGraph -Scopes 'User.Read.All','Device.Read.All','DeviceManagementManagedDevices.Read.All' -NoWelcome

# Licenses for one user (SKU part numbers: SPB = Business Premium, SPE_E3 = M365 E3, SPE_E5 = M365 E5, WIN_ENT_E3 / WIN10_VDA_E3 = Windows E3)
$upn = (Get-MgContext).Account   # you; set another UPN here to check someone else
(Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/users/$upn/licenseDetails?`$select=skuPartNumber").value.skuPartNumber

# Join state and Intune management for every Windows device in Entra
$devices = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/devices?`$filter=operatingSystem eq 'Windows'&`$select=displayName,trustType,isManaged,isCompliant,approximateLastSignInDateTime&`$top=999").value
$devices | ForEach-Object {
  [pscustomobject]@{
    Device   = $_.displayName
    Join     = switch ($_.trustType) { 'AzureAd' { 'Entra joined' } 'ServerAd' { 'Hybrid joined' } 'Workplace' { 'Entra registered' } default { 'Unknown' } }
    Intune   = $_.isManaged
    LastSeen = $_.approximateLastSignInDateTime
  }
} | Sort-Object Join, Device | Format-Table -AutoSize
```

AD-only and workgroup PCs do not appear in Entra at all; list AD-only ones on SYNCSERVER01 with
`Get-ADComputer -Filter 'OperatingSystem -like "Windows 1*"' | Select-Object Name, DistinguishedName`.

## Option for unlicensed and unmanaged PCs: an r360 agent

The matrix leaves a large gap: PCs with no E3-class license, and PCs that are registered, AD-only or not joined. A small
r360 agent can close most of it, because r360's remediation model (signed detect script, signed remediate script, run
state reported back) does not depend on Intune. The agent would be r360's own software, so it needs no Microsoft license.

### What the agent could cover

| Capability | Agent | Notes |
|---|---|---|
| Run r360 detect/remediate scripts on a schedule | **Yes** | Same `remediations` repo, same CI-signed artifact, same canary then promote flow. |
| Enforce the signature | **Yes** | The agent verifies Authenticode against the pinned r360 code-signing thumbprint itself, so the Intune certificate profiles are not needed. |
| Report run state to the Fleet page | **Yes** | Detection result, remediation result, output (truncated), time, device name, OS. |
| Basic inventory | **Yes** | OS version, edition, join state, Defender Antivirus status (`Get-MpComputerStatus`), last boot. |
| Drive built-in Defender Antivirus | **Yes, from scripts** | Scans, signature updates and status, through the Defender cmdlets on the PC. |
| Intune policies, compliance, Conditional Access, app deployment | **No** | Those are Intune and Entra features. |
| Defender for Endpoint EDR, isolation, live response | **No** | Those need the MDE license and sensor; the agent cannot replace them. |
| Run as a user, or show UI | Not at first | SYSTEM context only keeps it simple and safe. |

### Recommended design (keeps r360's rules: no secrets on devices, no application permissions, no new Azure spend)

1. **Install**: a signed PowerShell 5.1 script installed as a scheduled task running as SYSTEM every hour. No service
   binary to maintain. Works on Windows 10/11 Home, Pro and Enterprise.
2. **Enroll**: the installer shows a one-time code; an r360 operator approves it on a new **Agents** page (audited,
   four-eyes like everything else). Approval issues a per-device identity.
3. **Transport without exposing r360**: r360 stays on `localhost:3660`. The agent talks only to the storage account r360
   already uses (`str360abc123`): it reads signed packages from a blob container with a read-only SAS, and writes results to
   an Azure table with an add-only SAS limited to its own partition. r360 reads that table for the Fleet page. Cost is a
   fraction of a cent a month.
4. **Trust**: the agent runs a package only if every script's Authenticode signature is Valid **and** the signer
   thumbprint equals the pinned r360 thumbprint, and the package manifest hash matches. A stolen SAS can therefore not run
   code; at worst it can read packages or add junk rows to one device's partition.
5. **Assign**: targets are agent device groups kept in r360 (canary first, then promote), mirroring the Intune flow.
6. **Revoke**: r360 rotates or expires a device's SAS, and the next run fails closed.

Open questions before building it: whether Aaron wants the agent to reach PCs outside his tenant (MSP use), how long
SAS tokens should live (recommend 30 days with automatic renewal on check-in), and whether results should also be
written to the audit trail. This is a design sketch only; nothing in r360 implements it yet.

## Sources

- Remediations prerequisites and licensing: https://learn.microsoft.com/intune/device-management/tools/deploy-remediations#prerequisites
- Windows license verification (Remediations): https://learn.microsoft.com/intune/privacy/enable-windows-diagnostic-data#enable-windows-license-verification
- Intune platform scripts and registered devices: https://learn.microsoft.com/intune/device-management/tools/run-powershell-scripts-windows
- Defender response actions by plan: https://learn.microsoft.com/defender-endpoint/respond-machine-alerts
- Defender for Business vs Defender for Endpoint: https://learn.microsoft.com/defender-business/mdb-overview
- Business Premium includes Defender for Business, Intune and Entra ID P1: https://learn.microsoft.com/microsoft-365/admin/security-and-compliance/m365bp-security-faq
- Onboarding Windows clients to Defender for Endpoint: https://learn.microsoft.com/defender-endpoint/onboard-client
