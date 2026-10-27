# Remediation 360 (r360): product design

Status: v3.1, 2026-10-25 23:00 PT. Applies Aaron's decisions R1-R3 (accepted). Phase 0 scripts are written in `tools/` (not yet run); no infrastructure has been created.
r360 is a **standalone product** with its own code, identity and infrastructure. Design rules: delegated-only access and no secrets.

## 1. Purpose

Manage Intune Remediations (deviceHealthScripts) from `your-org/remediations` through draft → test → review → publish → canary → widen → monitor → retire. Also provide an **in-app, two-person emergency path** (Defender for Endpoint delegated actions + Intune on-demand remediation), with everything driven from r360 wherever Microsoft's delegated APIs allow.

## 2. Product footprint (all new, nothing shared)

| Item | Name (proposed) |
|---|---|
| Repo (private, not created yet; **accepted**, R1) | `sectechtalk/remediation-360` |
| Image | `ghcr.io/your-org/remediation-360:<yyyyMMdd-HHmm>` |
| Resource group | `rg-r360`, westus3 |
| Container Apps env + app | `cae-r360` / `app-r360`, scale 0-1 (maxReplicas 1), **default `*.azurecontainerapps.io` FQDN, no custom domain** (R2) |
| Managed identity | user-assigned `id-r360` (needed for the federated credential) |
| Key Vault | `kv-r360-<suffix>`, RBAC mode, **Premium** (HSM-backed keys) |
| Storage (audit) | `str360audit<suffix>`, Standard LRS, table `r360audit` + immutable blob container `r360audit-export` |
| Entra app regs | `r360-web` (sign-in, read scopes) and `r360-write` (write scopes) |
| GitHub App | `r360-github-app`, installed on `your-org/remediations` only |
| Groups (managed in Entra, not by r360) | `sg-remediation-canary` (DEVICE01), `sg-remediation-emergency`, `sg-r360-operators` |
| Signing cert | `r360-codesign` (KV, HSM, non-exportable key) |

## 3. Identity and elevation

### 3.1 Sign-in: Entra only

- Users sign in to r360 with Entra only. **They never sign in to GitHub.**
- `r360-web` holds read-only delegated scopes for the dashboard. `r360-write` holds the write scopes, requested only on step-up.
- **Credential: none stored.** Both app registrations use a **managed-identity federated identity credential (FIC)**: issuer `https://login.microsoftonline.com/<tenant>/v2.0`, subject = `id-r360` principal id, audience `api://AzureADTokenExchange`.
  - The server gets an MI token for that audience and passes it as the MSAL `clientAssertion`.
  - It uses auth code + PKCE and is a server-side confidential client.
  - It has no secret, certificate or key.
- **Local development:** the MI is not available locally. Dev uses the documented fallback.
- **Documented fallback (browser PKCE):** register the redirect as SPA. MSAL.js gets the tokens with PKCE and sends them as a bearer. The server validates aud/scp/oid/acrs and proxies.
  - No stored credential.
  - The trade-off is that tokens sit in the browser and the refresh token caps at 24 h.

### 3.2 Step-up to writes

1. **PIM gate** (server-side, `R360_PIM_MODE=warn` during testing, `enforce` later). Require an active, time-bound Entra role through `roleAssignmentScheduleInstances`:
   - Intune Administrator for Intune actions.
   - The Defender RBAC role (3.4) for Defender actions.
2. **Incremental consent** on `r360-write`. Each resource gets its own token cache entry.
   - **Microsoft Graph:**
     - `DeviceManagementScripts.ReadWrite.All`
     - `DeviceManagementConfiguration.ReadWrite.All` (trusted-cert profiles)
     - `DeviceManagementManagedDevices.PrivilegedOperations.All`
     - `DeviceManagementManagedDevices.Read.All`
     - `RoleManagement.Read.Directory`
     - `GroupMember.Read.All`
   - **Defender** (`https://api.securitycenter.microsoft.com`):
     - `Machine.Read`
     - `Machine.ReadWrite`
     - `Machine.LiveResponse`
     - `Machine.Isolate`
     - `Machine.Scan`
     - `Machine.RestrictExecution`
     - `Machine.CollectForensics`
     - `Machine.StopAndQuarantine`
     - `Library.Manage`
     - `Ti.ReadWrite`
   - **No group-write scopes.**
3. **CA authentication context `c1`** (acrs claim; MFA + compliant device). It starts report-only and is enforced in hardening.
4. **Elevation TTL:** `R360_ELEVATION_TTL_MINUTES=480` (8 h, testing), capped at the PIM end once PIM is enforced. Tokens are held in memory only.
5. **Per-write checks:** scp, oid, acrs (when enforced), and the PIM instance (when enforced).

### 3.3 Global Admin

Aaron's permanent GA bypasses PIM. In hardening: make it eligible, and create two break-glass accounts (FIDO2, permanent GA, sign-in alerting).

### 3.4 Roles

- **Testing (now):** built-in roles.
  - Entra **Intune Administrator** (PIM-eligible).
  - Defender **unified RBAC custom role** with:
    - Security operations → *Response (manage)*
    - *Live response capabilities: advanced* (upload scripts / run)
    - Security data basics (read)
  - Scope: all devices, or a device group containing DEVICE01.
  - Defender has no truly built-in "role"; this is the minimal Defender role definition.
- **Hardening:** custom least-privilege roles.
  - Intune: read devices/scripts, create/assign remediations, run remote tasks.
  - Defender: live response, isolation, scans.

## 4. GitHub: r360 acts as the GitHub App

- **GitHub App `r360-github-app`**, installed on `your-org/remediations` only.
  - Permissions: contents RW, pull_requests RW, checks R, actions R, metadata R.
  - Administration is not granted.
- **App private key:** imported into Key Vault as a **non-exportable RSA key** (accepted and required). r360 builds the app JWT (RS256) through the KV `sign` operation via the MI, then exchanges it for a **1-hour installation token** held in memory. The key never leaves KV.
- **Attribution** (users don't sign in to GitHub):
  - Every commit r360 creates has the trailer `Co-authored-by: <Display Name> <entra-oid@users.r360.invalid>` and `R360-Entra-Oid: <oid>`.
  - Every PR body has a signed-off block: submitter oid/UPN, approver oid/UPN, timestamps, audit ids.
  - Audit rows hold the Entra oid.
- **r360 is the sole four-eyes enforcer.** GitHub sees one actor (the App), so GitHub reviews can't distinguish people.
- **Ruleset changes** (`main-protection` 25825962). **Deferred (R3):** none of this is applied in Phase 0. The current `Publish-Remediation.ps1` flow (humans merge PRs) stays until r360 can publish end to end; then the App-only rule is turned on as a separate, gated step (section 13, "Gated later step").
  - Keep: PR required, required check `PSScriptAnalyzer` (strict), no deletion/force-push.
  - **Restrict updates to main** (merges) to the GitHub App only: add the App as the **only bypass actor**, `bypass_mode: pull_request`. Add an `update` restriction so humans can't merge to main.
  - `required_approving_review_count` stays 0, because the App cannot approve its own PRs.
  - Humans keep read access and may open PRs. Only r360 merges.
- **Break-glass for the repo:** an org owner can temporarily edit the ruleset. That is audited by GitHub and documented as an emergency-only procedure.
- **Future option:** GitHub Enterprise Cloud with SAML/OIDC SSO to Entra (and Enterprise Managed Users). Then user-to-server tokens map 1:1 to Entra identities and GitHub-native reviews could become the second enforcer.

## 5. Account matching: `approvers.json`

In the root of `your-org/remediations`:

```json
{ "version": 1, "approvers": [
  { "entraObjectId": "<guid>", "upn": "aaron@...", "roles": ["author","approver","emergencyApprover","admin"] } ] }
```

- **Entra-only means no GitHub ids are needed:**
  - Matching is by **Entra oid** from the validated token. The UPN is display-only.
  - `githubUserId` is optional, reserved for the future EMU/SSO option.
- **Change control:**
  - Changes go through r360 (four-eyes) and CODEOWNERS.
  - r360 reads the file only from the merged main.
  - It fails closed if the file is missing or invalid.
- **Why not an Entra custom security attribute:** it needs extra permissions and roles, and it has no review history.

## 6. Lifecycle

| Step | In r360 | Gate |
|---|---|---|
| 1 Draft | Upload/edit detect.ps1 / remediate.ps1 / remediation.json → branch + PR via App | Author ∈ approvers.json |
| 2 Direct test | `Test-RemediationOnDevice.ps1` (CLI) on DEVICE01, or Live Response RunScript on DEVICE01 from the PR artifact | 1 device, canary only |
| 3 PR | Created by r360 with attribution | `PSScriptAnalyzer` required check |
| 4 Four-eyes approve | Approver clicks Approve | See 6.1 |
| 5 Merge | r360 merges (only actor allowed) | Check green on HEAD |
| 6 Sign + build | CI signs the scripts (section 7) and builds `remediations-<sha>` with a SHA256 manifest | Signature valid, chain to `r360-codesign` |
| 7 Publish | deviceHealthScript create/update, `enforceSignatureCheck: true`, `runAs64Bit: true` | PIM, c1, CI succeeded (auto-wait), manifest match |
| 8 Canary | Assign to `sg-remediation-canary` (DEVICE01); on-demand run; poll deviceRunStates (auto-wait) | Success after remediation, 0 errors |
| 9 Widen | Assign the production group | Canary evidence ≤ 7 days |
| 10 Monitor | runSummary / deviceRunStates | Read |
| 11 Retire | Unassign → delete → PR removing the folder | PIM, four-eyes |

### 6.1 Four-eyes: testing mode now, enforced later

- `R360_FOUR_EYES=testing` (default) allows the approver = submitter. This shows a red banner, writes `selfApproved=true` in audit, puts `Self-approved: yes (testing mode)` in the PR body, and stamps the Intune description.
- In `enforced`, a different Entra oid with the `approver` role is required.
- **Switch-on steps after testing:**
  1. PR (through r360) adding the second approver to `approvers.json`.
  2. Set the Container App setting `R360_FOUR_EYES=enforced`. The script waits for the healthy revision.
  3. Confirm the ruleset bypass is the App only (requires the gated later step to be done). No change to the review count is needed, since r360 enforces four-eyes.
  4. Turn off `-AllowSelfPublish` in the CLI (honor the same flag).
  5. `Test-R360Prereqs.ps1` → PASS.

## 7. Code signing

- **Certificate:** self-signed code-signing certificate (free) `CN=SecTechTalk r360 Code Signing`, EKU 1.3.6.1.5.5.7.3.3, RSA 3072, 3-year validity. It is generated **inside Key Vault** (Premium, `RSA-HSM`, non-exportable). Only the public `.cer` is exported.
- **Where signing happens: GitHub Actions in CI**, authenticated to Azure with **GitHub OIDC → federated credential** on a dedicated Entra app `r360-ci-signer`.
  - No secret.
  - The federated credential subject is pinned to `repo:your-org/remediations:ref:refs/heads/main`.
  - The role is a custom RBAC role with only `keys/sign/action` + `certificates/read` on that one key.
  - The signing tool is `jsign` or `AzureSignTool` with a Key Vault token.
  - Rationale: the signed artifact is immutable and hashed in the manifest. Signing happens only after merge to main, so only four-eyes-approved code gets signed. r360 never holds signing rights and only **verifies**.
- **Trust distribution** (via r360, delegated Graph):
  - **Trusted Root:** Intune trusted certificate profile (`windows81TrustedRootCertificate`, `destinationStore: computerCertStoreRoot`).
  - **Trusted Publishers:** the trusted certificate profile type can't target this store. Use a **custom OMA-URI** profile: `./Device/Vendor/MSFT/RootCATrustedCertificates/TrustedPublisher/<thumbprint>/EncodedCertificate` = base64 cer.
  - Assign both to `sg-remediation-canary` first (DEVICE01), then to production.
- **Enforcement:**
  - Intune `enforceSignatureCheck: true` on every remediation.
  - Defender setting **Live response unsigned script execution = Off**.
  - Optional: execution policy `AllSigned` via Intune settings catalog (later; can break other scripts).
- **Rotation:** new cert 90 days before expiry. Both certs are deployed during overlap, and the old profile is removed after.

## 8. Emergency path (in-app, two-person)

Microsoft Learn (checked 2026-10-25) lists **delegated permissions** for all of these actions:

- run live response
- live response results
- library upload
- isolate / unisolate
- AV scan
- restrict code execution
- collect investigation package
- stop and quarantine
- indicators
- action status

Docs: https://learn.microsoft.com/en-us/defender-endpoint/api/run-live-response , upload-library, isolate-machine, unisolate-machine, run-av-scan, restrict-code-execution, collect-investigation-package, stop-and-quarantine-file, post-ti-indicator, get-machineaction-object.

**Flow** (`R360_EMERGENCY_WINDOW_MINUTES=240`, `R360_EMERGENCY_MAX_DEVICES=1`):

1. **Request:** the user has the emergencyApprover or author role and selects 1 device (DEVICE01 for testing), the track and actions, and a reason. Scripts come only from a signed main artifact.
2. **Approve:** a second person approves within 4 h. In testing mode, self-approval is allowed and logged loudly. Pending state is persisted in the audit table.
3. **Execute as the approver:**
   - **Track 1, Defender:**
     - Upload the signed script to the library (sha-suffixed name; never overwrite non-r360 files).
     - `runliveresponse` PutFile/RunScript/GetFile, and/or isolate, scan, restrict, collect, quarantine, indicator.
     - Poll `machineactions` (auto backoff, 2 h queue cap).
   - **Track 2, Intune:** `initiateOnDemandProactiveRemediation` + `syncDevice`, then poll deviceRunStates. The device must be in an assigned group (Entra-managed).
4. **Close:** results go to audit. Isolation and restriction create a "Release" task.

Verify in Phase 4: the Defender token audience (`api.securitycenter.microsoft.com`) vs the endpoint host (`api.security.microsoft.com`).

## 9. What r360 does in-app vs outside

**In r360** (delegated, as the signed-in user):

- **Intune:**
  - Create/update/assign/delete remediations.
  - On-demand runs and sync.
  - Create trusted-cert (Root) and custom OMA-URI (TrustedPublisher) profiles, and assign them.
- **Defender:**
  - All actions in section 8.
  - Live response library management.
  - Indicators.
- **GitHub (as the App):**
  - Branches, PRs, merges.
  - Read CI runs and artifacts.
  - Edits to `approvers.json` (four-eyes).
- **Reading:**
  - Read and check PIM status (with an activation deep link).
  - Read group membership.
- **Audit:** viewer and export.

**Outside r360** (by design or necessity):

- Entra group membership (decision: managed in Entra).
- PIM activation itself. Users activate in Entra; r360 only checks and links.
- **Bootstrap (Phase 0):**
  - App registrations and admin consent (granted in code via `oauth2PermissionGrants`, no consent click).
  - FICs, managed identity, RG/Container App/KV/storage.
  - GitHub App creation and installation (manifest flow; an org owner clicks Create and Install). The remediations ruleset change is deferred (R3).
  - Signing cert creation in KV.
  - Defender role definitions and the advanced feature "Live response" settings. The Defender settings API is not delegated-public; they are set once in the portal.
  - CA policy and auth context.
- **Reason for bootstrap staying outside:** it is chicken-and-egg, and it needs tenant- or org-admin rights r360 shouldn't hold.

## 10. Audit

- Azure Table `r360audit`, append-only. The MI has a custom role with `tableServiceEntity/add` only.
- Nightly export to an immutable blob container.
- Fields:
  - actor oid/UPN, approver oid, `selfApproved`
  - action, target
  - git sha, request ids
  - PIM instance, acrs
  - emergency id, result

## 11. UI

- One `.btn` style, greyed with a reason tooltip when unusable.
- Multi-select header filters, all checked by default, sortable.
- Dark mode default, Inter 9pt tables, horizontal scrolling, resizable columns.
- No demo mode.
- No duplicated data: each dataset has one home page.
- Banners: elevation (until HH:MM PT) and **TESTING MODE**.
- Nav: Remediations, Rollouts, Fleet, Emergency, Certificates, Audit, Settings (read-only view of config).

## 12. Scripts (PowerShell, idempotent, prereq checks, automated waits, `-WhatIf`)

| Script | Purpose |
|---|---|
| `Test-R360Prereqs.ps1` | Read-only verification of everything below. Modules (Az.Accounts, Az.KeyVault, Microsoft.Graph.Authentication, PSScriptAnalyzer), `gh` auth, signed-in scopes (`(Get-MgContext).Scopes`), RG/MI/KV/storage/Container App, app regs have **no passwordCredentials or keyCredentials** and the expected FICs, delegated scopes only, GitHub App installed on one repo, ruleset bypass = App only (INFO until the gated step), `approvers.json` valid, cert profiles assigned, DEVICE01 in Intune + Defender with matching `azureADDeviceId`, app settings present |
| `New-R360Infrastructure.ps1` | RG, MI, KV (Premium, RBAC), storage + table + immutable container, Container Apps env/app (scale 0-1), role assignments. Waits for provisioning |
| `New-R360AppRegistration.ps1` | `r360-web`, `r360-write`, `r360-ci-signer`: delegated scopes, redirect URIs, FICs (MI and GitHub OIDC). Grants tenant-wide admin consent in code (`oauth2PermissionGrants`, AllPrincipals) |
| `New-R360GitHubApp.ps1` | GitHub App via manifest flow (an org owner completes the one browser approval; a local listener captures the code), imports the private key into KV as non-exportable and shreds the local PEM, installs on `your-org/remediations` only. Does not touch the remediations ruleset (R3) |
| `New-R360CodeSigningCert.ps1` | Creates the KV certificate (RSA-HSM, code-signing EKU) and polls until issued. Exports the public `.cer`. Creates the Intune Root trusted-cert profile + TrustedPublisher OMA-URI profile via delegated Graph (`Invoke-MgGraphRequest`). Assigns them to `sg-remediation-canary`. Polls DEVICE01 deviceStatuses until compliant |
| `Publish-R360Image.ps1` | Build/push `ghcr.io/your-org/remediation-360`, update the Container App, wait for a healthy revision |

## 13. Phased plan

| Phase | Delivers |
|---|---|
| **P0 Bootstrap** | Checklist below |
| P1 Read-only dashboard | Remediations catalog (repo + Intune), drift, fleet run states, certificate deployment status, PIM status |
| P2 Author/approve/publish | PRs via App with attribution, four-eyes **testing mode**, CI signing, publish with signature enforcement, audit |
| P3 Rollout | Canary (DEVICE01) run and verify, widen, retire, cert profile management |
| P4 Emergency | Defender delegated actions + Live Response, Intune on-demand + sync, 4 h / 1 device |
| P5 Harden | Four-eyes enforced, PIM enforce, c1 enforce, TTL 8 h → 30-60 min, custom roles, GA → eligible + break-glass, optional AllSigned |

### Phase 0 checklist

1. [ ] Create the private repo `sectechtalk/remediation-360` (+ CODEOWNERS, PSScriptAnalyzer workflow, ruleset).
2. [ ] `Test-R360Prereqs.ps1` written first. Every following step re-runs it.
3. [ ] `New-R360Infrastructure.ps1`: rg-r360, id-r360, kv-r360 (Premium), storage/audit, cae-r360 + app-r360 (placeholder image, scale 0-1).
4. [ ] `New-R360AppRegistration.ps1`: r360-web, r360-write (MI FIC), r360-ci-signer (GitHub OIDC FIC), admin consent.
5. [ ] `New-R360GitHubApp.ps1`: App created, key in KV, installed on `your-org/remediations` only. (Ruleset is **not** changed in Phase 0; see the gated later step.)
6. [ ] `approvers.json` committed (Aaron: author, approver, emergencyApprover, admin).
7. [ ] `New-R360CodeSigningCert.ps1`: KV cert, Root + TrustedPublisher profiles assigned to the canary, DEVICE01 shows the cert.
8. [ ] Defender: role with Response + Live response advanced assigned to Aaron, Live Response enabled, unsigned script execution Off, device group remediation level set.
9. [ ] Entra: PIM-eligible Intune Administrator for Aaron, CA auth context c1 (report-only policy), groups exist (canary contains DEVICE01).
10. [ ] Container App settings: `R360_FOUR_EYES=testing`, `R360_PIM_MODE=warn`, `R360_ELEVATION_TTL_MINUTES=480`, `R360_EMERGENCY_WINDOW_MINUTES=240`, `R360_EMERGENCY_MAX_DEVICES=1`.
11. [ ] `Test-R360Prereqs.ps1` → all PASS.

### Gated later step (not Phase 0): App-only merge on remediations main (R3)

Run only when **all** are true: r360 has published at least one remediation end to end (PR → merge → sign → canary) through the App, `Test-R360Prereqs.ps1 -Stage All -RequireDeployed` passes, and Aaron approves the switch.

1. [ ] Add the GitHub App as the only bypass actor on `main-protection` (25825962), `bypass_mode: pull_request`, plus the `update` restriction.
2. [ ] Retire the human merge step of `Publish-Remediation.ps1` (it keeps working for PR creation).
3. [ ] Document and test the org-owner ruleset break-glass.
4. [ ] `Test-R360Prereqs.ps1` ruleset check changes from INFO to PASS/FAIL.

## 14. Remaining decisions

- **R1 (decided):** `sectechtalk/remediation-360`, private. Accepted.
- **R2 (decided):** default Container Apps FQDN for now; no custom domain.
- **R3 (decided):** App-only merge on `remediations` main is turned on only once r360 can publish. The current `Publish-Remediation.ps1` flow stays until then. Separate gated step, not Phase 0.
- **R4:** Execution policy AllSigned fleet-wide in hardening: yes/no.
- **R5:** Hardening timing: GA → eligible + break-glass, and the four-eyes switch-on (who is the second approver?).
- **R6:** Canary pass criteria / evidence age (7 days proposed).

## 15. Risks

- **Testing mode:** four-eyes is not enforced and an 8 h elevated session is long. Mitigated by the banner, audit, and a dated exit.
- **App-only merge** (after the gated step) makes r360 a dependency for repo changes. The documented ruleset break-glass covers this.
- **Commits authored by the GitHub App:** GitHub-side attribution relies on the trailers and the PR body, and Entra oids are not verifiable by GitHub.
- **Self-signed root in Trusted Root:** if the key leaks, anything can be signed. Mitigated by the HSM non-exportable key, OIDC pinned to main, sign-only RBAC, and monitoring of KV sign logs.
- **Delegated Defender actions are powerful.** Rely on Defender RBAC scope, the two-person rule, the 1-device cap, and signed artifact-only scripts.
- **Scale-to-zero:** in-memory sessions are lost (acceptable), and pending emergencies are persisted.
- **Graph beta APIs** (deviceHealthScripts, on-demand remediation) may change.
