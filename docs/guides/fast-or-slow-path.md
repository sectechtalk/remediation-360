# Fast path (Defender) or slow path (Intune)

r360 has two ways to act on a Windows PC. This guide says which one to use. The same content is in r360 under
**New hire > Fast or slow path**; what each PC can use is under **New hire > What works where** and in
[whats-supported.md](whats-supported.md). What each feature costs is in [licenses-by-feature.md](licenses-by-feature.md).

## Rule of thumb

**Fast path to stop the bleeding, slow path to fix it for good.** The slow path (Intune Remediations) is how almost every
change should ship. The fast path (Defender for Endpoint response actions) is for one PC that cannot wait. After a
fast-path action, follow up with a slow-path change so the problem cannot come back on that PC or any other.

## Use the fast path when

- A PC is compromised or showing an active attack and must come off the network now.
- One PC needs an antivirus scan, or a file stopped and quarantined, right away.
- You need evidence from one PC (investigation package) before it is rebooted or wiped.
- The PC is not Entra joined or hybrid joined, or its user has no Windows Enterprise E3-class license, so Intune
  Remediations cannot reach it at all.

## Use the slow path when

- The same fix belongs on many PCs, or every PC.
- The problem keeps coming back and should be fixed automatically every time.
- It is a configuration standard: certificates, registry, services, cleanup.
- Nothing is on fire. If it can wait for the canary, it goes through the slow path.

## Side by side

| | Fast path: Defender | Slow path: Intune |
|---|---|---|
| Speed | Minutes; the PC acts as soon as it is online | Hours to days. PCs fetch new scripts about every 8 hours, then r360 holds the canary for 7 days before you widen it |
| How many PCs | One per request (`R360_EMERGENCY_MAX_DEVICES=1`) | From the canary group to every PC |
| How long it lasts | Once | For good; Intune reruns the check on its schedule |
| Actions r360 offers | Isolate and release, AV scan (P1, P2, Defender for Business). Stop and quarantine a file (P1, P2; not Defender for Business). Investigation package, restrict app execution and remove it (P2 only) | Any reviewed, CI-signed detect/remediate script pair |
| Review | Second person approves within 4 hours (`R360_EMERGENCY_WINDOW_MINUTES=240`) | Pull request approval (four-eyes), CI signing, canary soak |
| PC needs | Onboarded to Defender for Endpoint or Defender for Business, with a license. Join state does not matter | Entra joined or hybrid joined, Intune enrolled, Windows Pro/Enterprise/Education, Windows Enterprise E3-class license, both r360 code-signing profiles |
| Status in r360 | **Built**: Emergency page (Roll out > Emergency) | **Built**: Remediations, Changes, Fleet, Certificates |

## How to use the fast path

1. **Elevate** (top right) to start a write session.
2. Open **Roll out > Emergency**, search the device by name, pick the action, and give a reason of at least 10
   characters. The reason goes into Defender and the audit trail.
3. A second person with the `emergencyApprover` role clicks **Approve and run now** within 4 hours. r360 runs the action
   in Defender immediately, as the approver, with the approver's own Defender sign-in.
4. Click **Check status in Defender** until it reports Succeeded. When the PC is clean, request the release action
   (Release from isolation, Remove app restriction) the same way.
5. Follow up with a slow-path remediation if the problem could return.

Every step (requested, approved, executed, result, cancelled, rejected and every refused attempt) is in the audit trail.
The approver needs a Defender role with **Active remediation actions** that covers the device's device group; Defender
enforces it. Live response is not offered: use the Defender portal at https://security.microsoft.com/machines and record
it with a Change request.

## The middle option: run one remediation now

Intune's **Run remediation** device action (preview) runs an existing remediation on one PC immediately instead of
waiting for the schedule. It needs everything the slow path needs (join state, license, enrollment, signed scripts) plus
the PC being online and reachable through Windows Push Notification Service. r360's design includes it as
Track 2 of the emergency path (`initiateOnDemandProactiveRemediation`), not built yet; until then, use the Intune admin center
(Devices > Windows > the device > ... > Run remediation).

## Sources

- Remediations prerequisites, licensing, schedule and on-demand runs: https://learn.microsoft.com/intune/device-management/tools/deploy-remediations
- Defender response actions and what Plan 1 and Defender for Business include: https://learn.microsoft.com/defender-endpoint/respond-machine-alerts
- Defender for Business remediation actions (includes live response): https://learn.microsoft.com/defender-business/mdb-review-remediation-actions
- r360 emergency path design: [remediation-360-design.md](../remediation-360-design.md) section 8
