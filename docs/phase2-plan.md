# r360 Phase 2 plan: author, approve, sign, publish (canary), promote

Status: DONE, 2026-10-27. S1-S7 delivered and live; see "S7 status" at the end. (Originally written 2026-10-26 as a plan.)
Grounded in: docs/remediation-360-design.md (v3.1), server/*.mjs and public/*.js at r360 main 9b1ce20, and your-org/remediations main 3dfaf50
(tools/, workflows, schema, approvers.json) plus the live main-protection ruleset (read with `gh api`, read-only).

## 1. What the design doc says Phase 2 is

- Phasing table (section 13): "P2 Author/approve/publish: PRs via App with attribution, four-eyes testing mode, CI signing, publish with signature enforcement, audit".
- Lifecycle rows in scope (section 6): 1 Draft, 3 PR, 4 Four-eyes approve, 5 Merge, 6 Sign + build, 7 Publish, and the assignment half of 8 (assign to canary).
- Out of Phase 2 per the design: canary on-demand run and verify (needs PrivilegedOperations scope), 9 Widen, 11 Retire, cert profile management (all P3); Emergency (P4); enforce flags and custom roles (P5).
- README roadmap says "Publish through r360, audit viewer and export"; app.js already stubs Audit as "phase 2".
- Discrepancy to settle: you asked for "promote to production after 7 clean days". The design puts Widen in P3. This plan includes it as the last slice (S6, "P2b") so it can be cut without affecting S1-S5.
- Deferred and still deferred (R3): App-only merge rule on remediations main. It is a gated step after S5 is proven live (S7).

## 2. Current state (what exists, what does not)

### r360 server (Phase 1, read-only)
- Routes: GET /healthz, /auth/signin, /auth/callback, POST /auth/signout, then (session required) static files, GET /api/me, /api/remediations, /api/fleet, /api/certificates, /api/pim, /api/settings. No other POST exists.
- Auth: auth.mjs, one MSAL ConfidentialClientApplication for r360-web, auth code + PKCE, clientAssertion = MI token (audience api://AzureADTokenExchange). Scopes = 6 Graph read scopes. No nonce is passed to getAuthCodeUrl / acquireTokenByCode (see risk R1).
- Session: in-memory SessionStore, cookie __Host-r360 (Secure, HttpOnly, SameSite=Lax), 8 h TTL, max 1000, lost on scale-to-zero (accepted). Session holds user {oid, upn, name}, homeAccountId, per-session response cache.
- Write session (r360-write): NOT implemented. The app registration exists with redirect /auth/write/callback, FIC, admin consent for Graph DeviceManagementScripts.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.PrivilegedOperations.All, ...Read.All, RoleManagement.Read.Directory, GroupMember.Read.All and the Defender scopes. R360_WRITE_CLIENT_ID is set on the Container App by New-R360AppRegistration.ps1 but config.mjs does not read it yet.
- Config flags exist (R360_FOUR_EYES=testing, R360_PIM_MODE=warn, R360_ELEVATION_TTL_MINUTES=480) and the UI shows the TESTING MODE banner, but nothing enforces or consumes them.
- GitHub (github.mjs): App JWT signed in Key Vault key github-app-r360 via MI, installation token narrowed to {contents: read, metadata: read}, cached in memory. Catalog = tree of main (remediations/<folder>/{remediation.json,detect.ps1,remediate.ps1}) + approvers.json (fail-closed parseApprovers; roles author/approver/emergencyApprover/admin). Installed App permissions (design/script): contents RW, pull_requests RW, checks R, actions R, metadata R. No write code, no PR code, no artifact download.
- Intune (data.mjs/graph.mjs): read-only delegated Graph with 429/503 retry. Drift compares SHA-256 of normalized script text (BOM/CRLF/trailing space) of repo vs Intune, plus publisher/runAs/runAs32Bit/enforceSignatureCheck. It does not know about Authenticode signature blocks and does not compare assignments.
- Audit: no module. Table r360audit (custom role: read + add only for id-r360) and immutable container r360audit-export exist in Phase 0 infrastructure; nothing writes to them yet. Audit page is a stub.
- Tests: node:test unit + integration suite (tests/*.test.mjs); CI = Node tests + PSScriptAnalyzer.

### your-org/remediations
- tools/Publish-Remediation.ps1 (CLI): clean clone at origin/main, waits for PSScriptAnalyzer on HEAD, compares local hashes with the CI artifact manifest remediations-<sha>, author != publisher (or -AllowSelfPublish), Connect-MgGraph delegated DeviceManagementScripts.ReadWrite.All, find by displayName, POST/PATCH /beta/deviceManagement/deviceHealthScripts with base64 script content and description "<desc> [git <sha8> by <authorEmail>; published by <upn>]" (+ "[self-published, four-eyes bypassed]"), then POST .../assign with runSchedule mapped from remediation.json (hourly/daily/once) to assignment.groupId. It uploads the working-tree (unsigned) scripts.
- CI (.github/workflows/psscriptanalyzer.yml): job PSScriptAnalyzer (required check) lints, validates schema via Build-RemediationPackage.ps1, and on push to main uploads artifact remediations-<sha> (copies + manifest.json with SHA-256 per file, 90 days). THERE IS NO SIGNING STEP. Sample-RemediationCanary has enforceSignatureCheck=false.
- Files are CRLF for .ps1 (.gitattributes), LF for json/md/yml.
- approvers.json on main: Aaron (author, approver, emergencyApprover, admin), user1@ (approver).
- Ruleset main-protection (25825962), active, no bypass actors: deletion blocked, non_fast_forward, pull_request (0 approvals, dismiss stale reviews, thread resolution required, require_extra_approval_for_unattributed_changes=true but no effect at 0 approvals, merge/squash/rebase allowed), required status check PSScriptAnalyzer with strict_required_status_checks_policy=true (branch must be up to date). Repo: squash/merge/rebase allowed, no auto-merge, branches not auto-deleted. Actions default token permission = read.
- CODEOWNERS: * @sectechtalk (code-owner review is NOT required by the ruleset).

Implications that shape the plan:
1. Signing must be built first and proven (risk-first). It does not exist.
2. The App can open and merge PRs with the current ruleset without any bypass (0 approvals, check required). No ruleset change is needed in Phase 2.
3. Because strict status checks are on, a merge of an out-of-date PR fails; r360 must call update-branch and wait for CI again.
4. Until the App-only merge rule is on, a human can merge a PR straight to main, and CI would sign it. r360 therefore must carry its own provenance gate at publish (section 4.5).
5. GitHub sees one actor (the App). Approval cannot be a GitHub review (the App cannot approve its own PR); it is an r360 audit record bound to the PR head SHA.

## 3. Target workflow (one pipeline, each step audited)

```
Author (r360 UI) -> branch + PR as App (attributed) -> CI green (PSScriptAnalyzer + schema)
 -> Approve in r360 (approver != author unless testing flag) -> r360 merges (squash, sha-pinned)
 -> CI Sign job on main (OIDC r360-ci-signer -> Key Vault HSM) -> signed artifact + signed manifest, verified on a Windows runner
 -> Publish in r360 (delegated Graph, r360-write token) to Intune with enforceSignatureCheck=true, assigned to CANARY group only
 -> canary soak (>= 7 days, 0 errors, evidence from Intune run states)
 -> Promote: r360 PR changes assignment.groupId to the production group -> same approve/merge/sign -> Publish updates the assignment
```

State machine per change (derived, never held in server memory): Proposed -> CI passed -> Approved(headSha) -> Merged(mergeSha) -> Signed(artifactRunId) -> Published(canary, sha) -> Soaking(day n/7) -> Promotion proposed -> ... -> Published(production, sha).
- The state is recomputed from GitHub (PR, checks, runs, artifacts) plus the audit table. Waiting steps (CI on PR, Sign on main) are observed states, not server-held jobs. The UI polls every 10 s while a change is in flight and enables the next button when the precondition is observed true. This survives scale-to-zero and needs no server-side job runner.
- Every mutating action writes an audit "intent" row first, performs the action, then writes a "result" row. If the audit write fails the action does not run (fail closed).

## 4. Design decisions by area

### 4.1 Write session (r360-write, 8 h)
- New /auth/write/start (GET navigation, state + PKCE + nonce bound to the web session), /auth/write/callback (already registered redirect), POST /auth/write/end.
- Second ConfidentialClientApplication for r360-write (same MI clientAssertion, its own in-memory token cache). Request ONLY https://graph.microsoft.com/DeviceManagementScripts.ReadWrite.All (+ openid/offline_access) in Phase 2; the other consented write scopes stay unused until P3/P4 (least privilege per token).
- session.write = { homeAccountId, oid, since, until = since + R360_ELEVATION_TTL_MINUTES, pim snapshot, acrs }. Server enforces until (refresh tokens outlive it). The write oid must equal the web session oid or the elevation is rejected and audited.
- requireWrite middleware on every mutating route: web session + live write session + oid match + approvers.json role for the action + PIM check (R360_PIM_MODE: warn = log and banner, enforce = block; reuses summarizePim) + acrs check (only when enforced later). Fail closed if approvers.json is invalid.
- CSRF: every non-GET requires Origin == publicUrl AND a per-session X-R360-CSRF token (returned by /api/me, held in JS memory) AND content-type application/json. CSP already blocks inline script.
- Banner: "WRITE SESSION until HH:MM PT" with End button; TESTING MODE banner stays.

### 4.2 Author -> branch + PR as the GitHub App
- Tokens: a read token (contents:read, metadata:read, actions:read, checks:read; cached) and a write token (contents:write, pull_requests:write, metadata:read; minted per action, never cached, discarded after). Both limited to repositories: [remediations]. App permissions already granted in Phase 0 (contents RW, pull_requests RW, checks R, actions R, metadata R), so NO change to the GitHub App is needed. Administration and workflows are not granted: r360 cannot change rulesets or workflow files.
- Path whitelist: only remediations/<folder>/{remediation.json,detect.ps1,remediate.ps1}; folder matches ^[A-Za-z0-9._-]+$ (same regex as the CLI), no traversal, never approvers.json, tools/, schema/, .github/. approvers.json edits via r360 are P5 (four-eyes switch-on).
- Validation before any GitHub call: remediation.json against the same schema as CI (add ajv; test asserts parity with schema/remediation.schema.json), scripts must be UTF-8, <= 150 KB, must NOT contain an existing Authenticode block ("# SIG # Begin signature block"), line endings normalized to the repo convention (CRLF for ps1, LF for json). assignment.groupId for a NEW remediation is forced server-side to R360_CANARY_GROUP_ID; the UI does not offer it.
- Git Data API: get main sha -> create blobs -> tree -> ONE commit -> ref refs/heads/r360/<folder>/<yyyyMMddHHmm>-<oid8> -> POST /pulls. Commit message trailers: `Co-authored-by: <Display Name> <entra-oid@users.r360.invalid>`, `R360-Entra-Oid: <oid>`, `R360-Request-Id: <guid>`. PR body: human summary + signed-off block (submitter oid/UPN, timestamps, audit ids, testing-mode line) + machine block `<!-- r360:{"v":1,"kind":"author","folder":"...","authorOid":"..."} -->`.
- Edit of an existing change pushes a new commit to the same branch (head sha changes, which voids any earlier approval). Discard = close PR + delete branch. Limit: R360_MAX_OPEN_CHANGES=5.
- Only PRs that r360 created (a change.proposed audit row exists and the machine block matches) are approvable/mergeable in r360. PRs opened by hand or by Publish-Remediation.ps1 are listed read-only as "external".
- The PR runs the existing required check PSScriptAnalyzer (App-pushed branches do trigger pull_request workflows; only GITHUB_TOKEN pushes do not).

### 4.3 Approve (four-eyes) and merge
- Approve preconditions (all re-checked server side at click time and again at merge): write session; actor has role approver in approvers.json (read from main, fail closed); PR is r360-created; PR head sha == the sha in the latest change.proposed/updated audit row; check run PSScriptAnalyzer = success on that head sha; PR not draft/closed; no unresolved threads.
- Four-eyes rule (one pure function fourEyes({mode, authorOid, actorOid, step}), used at approve and publish): enforced -> actor oid must differ from author oid (and hold the role); testing -> allowed, result selfApproved=true, red banner, PR comment "Self-approved: yes (testing mode)", Intune description stamp. Matches the design 6.1 and the CLI's -AllowSelfPublish semantics.
- Approval record: audit row change.approved {pr, headSha, approverOid, authorOid, selfApproved, mode} + a PR comment (pull_requests:write). No GitHub review and no extra App permission (no checks:write needed).
- Merge: PUT /pulls/{n}/merge with merge_method=squash, `sha` = approved head sha (GitHub rejects if the head moved), commit message carrying the trailers + `Approved-by` line + selfApproved line. If GitHub answers 405/409 "branch out of date" (strict policy), r360 calls PUT /pulls/{n}/update-branch, records change.branch-updated, and the UI waits for CI and retries once the approval still matches the new head. A new head sha after update-branch does NOT void the approval only when the update is a pure merge-from-main with no changes to the 3 files; r360 verifies the tree of the 3 files is byte-identical to the approved head, otherwise it requires re-approval. Audit change.merged {mergeSha}.
- Reject = comment + close, audit change.rejected.

### 4.4 Sign (where and how)
- Where: GitHub Actions in your-org/remediations on push to main, as the design says. NOT in-app: r360 never holds signing rights and only verifies (design section 7). Identity: r360-ci-signer, federated credential subject repo:your-org/remediations:ref:refs/heads/main (already created), KV roles Crypto User on key r360-codesign and Certificate User on the cert (already assigned by New-R360CodeSigningCert.ps1; re-checked by prereqs). PR branches and forks cannot obtain a token (wrong subject).
- Workflow change (human-merged PR, because the App has no workflows permission): add job Sign to psscriptanalyzer.yml with needs: PSScriptAnalyzer, if push on main, permissions {id-token: write, contents: read}; third-party actions pinned by commit SHA; jsign jar downloaded with a pinned SHA-256.
  1. azure/login (client-id of r360-ci-signer, tenant, allow-no-subscriptions: true) - client/tenant ids are non-secret repo variables, no secrets.
  2. Normalize signed inputs: detect.ps1 / remediate.ps1 as UTF-8 with BOM and CRLF (Windows PowerShell 5.1 safe, deterministic bytes).
  3. jsign --storetype AZUREKEYVAULT --keystore <vault> --alias r360-codesign --storepass <vault access token from az> --tsaurl <public RFC3161 TSA> on each script (key stays in the HSM; sign operation only).
  4. Write manifest-signed.json: commit, run id, thumbprint, signer subject, for each file {path, sourceSha256 (normalized, signature-stripped), signedSha256}, builtUtc.
  5. Upload artifact signed-<sha> (90 days).
  6. Job Verify on windows-latest (needs Sign): download artifact, import the public .cer into CurrentUser Root + TrustedPublisher on the runner, Get-AuthenticodeSignature must be Valid for every script with thumbprint == pinned thumbprint; also a negative check (flip one byte -> HashMismatch). Job fails the push run if anything is off.
- r360 side (verification only): download artifact signed-<sha> (actions:read; zip parsed with a small pure-JS unzip dependency, fflate), check manifest.commit == merge sha, signed file bytes hash == signedSha256, source hash (signature stripped, normalized) == repo blob at that sha, thumbprint == R360_CODESIGN_THUMBPRINT (already in config), SIG block present, cert not expired, run conclusion success for both Sign and Verify jobs. Node cannot validate Authenticode itself; the real chain verification is the CI Verify job plus Intune enforceSignatureCheck and the device. Audit sign.verified.
- Spike first (S1): a signed script must (a) verify on the Windows runner, (b) verify with Get-AuthenticodeSignature on DEVICE01 (Trusted Root + Trusted Publisher profiles are already deployed), (c) run on DEVICE01 through Intune with enforceSignatureCheck=true. Fallback if jsign + HSM + BOM misbehaves: AzureSignTool on windows-latest (same OIDC token and roles).
- Drift fix: catalog.mjs normalizeScript must strip "# SIG # Begin signature block ... # SIG # End signature block" before hashing, so signed Intune content compares equal to the repo source. Add a signed/unsigned indicator (Intune content has a SIG block when meta.enforceSignatureCheck is true).

### 4.5 Publish to Intune (delegated, canary first)
- Action: POST /api/remediations/:folder/publish {sha}. Server-side gates, in order: write session + role approver + PIM check (warn/enforce); sha is the current main HEAD touching the folder (or newer) and has a verified signed artifact; remediation.json enforceSignatureCheck must be true (refuse unsigned); no "Duplicate in Intune" (more than one script with that displayName); four-eyes at publish (fourEyes step=publish: publisher != author in enforced mode, as in the CLI); provenance gate below; assignment group rule below.
- Provenance gate (needed because humans can still merge to main until S7): the commit that last touched the folder must trace (GET /commits/{sha}/pulls) to a PR with audit rows proposed -> approved -> merged for that head sha. Enforced mode: no chain = blocked. Testing mode: blocked unless actor has role admin, then allowed with audit flag provenance=none and a loud banner. This keeps the design's "only four-eyes-approved code is published" claim true before the App-only rule exists.
- Assignment rule: a publish may assign ONLY R360_CANARY_GROUP_ID. Assigning any other group (production) is possible only through the promote path (section 4.6). The group id in remediation.json is verified against the config, not trusted.
- Graph calls with the r360-write token (delegated, user's own identity): find by displayName (beta deviceHealthScripts, paged); POST (create) or PATCH (update) with detectionScriptContent / remediationScriptContent = base64 of the exact artifact bytes (signed), runAsAccount, runAs32Bit, publisher, enforceSignatureCheck=true, description "<desc> [git <sha8> by <authorUpn>; approved by <approverUpn>; published by <upn> via r360]" (+ " [self-approved, testing mode]"); the "[git <sha>" prefix keeps gitStamp() and the Published git column working. Then POST /assign with the schedule mapping identical to Publish-Remediation.ps1 (hourly/daily/once). Idempotent: if Intune already holds the same git sha and content hash and assignment, the action is a no-op ("Already published").
- Post-checks (auto): re-read the script (base64 round trip hash == signedSha256, enforceSignatureCheck true, assignment == canary group), then drift status should be "In sync". Audit publish.canary {intuneId, sha, signedSha256, group, publisherOid, approverOid, selfApproved, pim state, graph request-id}. 
- Not in P2: on-demand run / sync (needs PrivilegedOperations; design P3). Canary evidence in P2 is read-only from deviceRunStates/runSummary (already on Fleet and Remediations; shown there, not duplicated).
- Graph throttling and retries: reuse graph.mjs backoff; surface Graph request-id and client-request-id in the audit row and in the error text.

### 4.6 Promote to production after 7 clean days
- Evidence (pure function, fake-clock tested): canary publish time from the audit row publish.canary for the CURRENT sha (a new sha restarts the clock) >= R360_CANARY_SOAK_DAYS (default 7); latest deviceRunState on every canary device = detection success and (remediation success or not needed); runSummary errors = 0 and no recurred spikes; drift = In sync; no newer unpublished change. The Remediations page gets one new column "Soak" (day n/7 or Ready); the evidence list shows in the promote dialog only.
- Mechanism (matches today's manual procedure, now in-app): Promote opens an r360 PR changing only assignment.groupId from the canary group to R360_PROD_GROUP_ID in remediation.json -> normal approve + merge -> CI sign (hash changes) -> publish step updates the assignment. Reuses S3-S5 end to end, so four-eyes, signing and audit apply unchanged. Server rule: the only change r360 will propose to assignment.groupId is canary -> production, and only when the evidence gate passes.
- Testing today: an audited override R360_CANARY_SOAK_DAYS can be lowered (e.g. 0) for a named test remediation; any value != 7 shows a red SOAK OVERRIDE banner and writes soakDays into every audit row (see open decision 2).

### 4.7 Audit
- audit.mjs: Azure Table insert through REST with the MI token (resource https://storage.azure.com/), PartitionKey = yyyyMM (UTC), RowKey = (9999999999999 - epochMs) zero-padded + "-" + guid (newest first, unique). Fields per design 10: actorOid, actorUpn, approverOid, selfApproved, action, target, gitSha, prNumber, requestId, graphRequestId, githubRequestId, pimInstance/pimState, acrs, result, reason, soakDays, mode flags. MI role stays read + add only (no update/delete possible).
- Immutable export: write each event ALSO as a blob in r360audit-export (retention policy already immutable, 365 days) at yyyy/MM/dd/<rowkey>.json, instead of a nightly job (no scheduler needed with scale-to-zero). Needs one new RBAC assignment: id-r360 -> Storage Blob Data Contributor scoped to that container (the immutability policy blocks overwrite and delete). This deviates from the design's "nightly export" wording and is strictly stronger.
- GET /api/audit with server-side filters (time range, action, actor, target) and a download endpoint (JSON/CSV). Audit page: multi-select checkbox header filters, all checked by default, PT times, one .btn style, no demo data.
- Events: session.elevate, session.elevate.denied, session.end, change.proposed, change.updated, change.discarded, change.approved, change.approval.denied, change.rejected, change.branch-updated, change.merged, sign.verified, sign.verify.failed, publish.canary, publish.denied, promote.proposed, publish.production, plus every "intent"/"result" pair.

### 4.8 UI (no duplicated data, one home per dataset)
- Remediations page: row actions (Edit, Publish, Promote) with greyed buttons and a reason tooltip when unusable; "New remediation" button; new tab "Changes" on the SAME page = the only home of PR/lifecycle data (stepper Proposed > CI > Approved > Merged > Signed > Published > Soak > Production, author, approver, selfApproved pill, links to PR and run).
- Fleet and Certificates pages unchanged. Audit page becomes real. Rollouts/Emergency remain stubs. No new nav items.

## 5. Permissions, consents and configuration

| Item | Needed in Phase 2 | New? |
|---|---|---|
| Entra r360-write Graph delegated | DeviceManagementScripts.ReadWrite.All (requested at elevation) | No new consent: already in requiredResourceAccess and admin-consented (AllPrincipals). Other write scopes stay unrequested. |
| Entra r360-web Graph delegated | existing read scopes (DeviceManagementScripts.Read.All covers assignments read) | No |
| Entra r360-ci-signer | no API permissions; Azure RBAC Crypto User on key r360-codesign + Certificate User on cert | Already assigned in Phase 0; prereqs re-verify |
| Application permissions / secrets | none | none (still forbidden) |
| GitHub App r360-github-app | contents RW, pull_requests RW, checks R, actions R, metadata R | No change. Do not add workflows, administration or checks:write. Code requests narrower tokens per call. |
| GitHub repo remediations | repo variables R360_TENANT_ID, R360_CI_SIGNER_CLIENT_ID, R360_KEY_VAULT_NAME (non-secret) ; new Sign + Verify jobs | New (script) |
| Branch protection / ruleset | none in P2. App can open+merge within the current rules (0 approvals, check required, no bypass). Strict policy handled by update-branch. | App-only merge stays gated (S7) |
| Azure RBAC | id-r360 -> Storage Blob Data Contributor on container r360audit-export (new); table read+add role (exists) | One new assignment (infra script) |
| Container App env | R360_WRITE_CLIENT_ID (exists), R360_AUDIT_STORAGE_ACCOUNT, R360_AUDIT_TABLE=r360audit, R360_AUDIT_EXPORT_CONTAINER=r360audit-export, R360_CANARY_GROUP_ID, R360_PROD_GROUP_ID, R360_CANARY_SOAK_DAYS=7, R360_MAX_OPEN_CHANGES=5 | New (script) |
| Entra groups | sg-r360-operators (exists), sg-remediation-canary (exists), production group (decision 1) | Production group maybe |
| Roles in Entra | Intune Administrator active (PIM) for the publisher; Aaron is Global Admin today (PIM bypass, banner shows warn) | none |

## 6. Slices (ordered, each shippable with tests and a live verification)

Sizes: S small, M medium, L large. Each slice = one PR in the repo it touches, merged only with green CI; deploys use the dated-tag script; every new script has prereq checks, automated waits/polls and -WhatIf.

### S1. CI signing pipeline (remediations repo) - spike first, L
- Deliver: Sign + Verify jobs, tools/Sign-RemediationPackage.ps1 (normalize, jsign, manifest-signed.json), repo certs/r360-codesign.cer (public cert) or fetch from KV, signature-block-aware Build-RemediationPackage manifest, workflow pins. r360 repo: tools/Set-R360CiSigningConfig.ps1 (sets the 3 repo variables, verifies r360-ci-signer FIC subject and KV roles, -WhatIf).
- Tests: PSScriptAnalyzer clean; Verify job (positive + tamper negative); a Pester-style script test of normalization (BOM/CRLF idempotent, signature strip == original).
- Live verification: merge a trivial change on a throwaway remediation folder; confirm artifact signed-<sha>, Verify job green; on DEVICE01 run Get-AuthenticodeSignature on the downloaded script (Valid, thumbprint matches); publish it once with the existing CLI with enforceSignatureCheck=true and confirm the device runs it (Fleet page).
- Exit criteria: all three of runner Valid, DEVICE01 Valid, Intune run success. If not, switch to AzureSignTool and repeat before any app work.
- Risk: BOM/CRLF/Authenticode over UTF-8, TSA availability, jsign with HSM-backed key (supported via sign operation; spike proves it).

### S2. Audit + write session + CSRF foundation (r360), L
- Deliver: audit.mjs (table + immutable blob dual write, intent/result helper), GET /api/audit (+ download), Audit page; write CCA, /auth/write/*, requireWrite middleware, CSRF/origin checks, nonce fix (section 7 R1), banner + Elevate/End UI; config additions (R360_WRITE_CLIENT_ID etc.); tools/New-R360Infrastructure.ps1 update (blob RBAC, env vars), Test-R360Prereqs additions (write app consent present, blob role, env vars).
- Tests (node:test): audit row builder (RowKey ordering, fields, no secrets), fake Table/Blob fetcher incl. insert failure => action blocked; session TTL and oid-mismatch rejection; CSRF/origin matrix (missing header, wrong origin, GET with side effect rejected); requireWrite role matrix from approvers.json (including invalid file fails closed); PIM warn vs enforce; a test that drives the REAL MSAL library through both sign-in and elevation against a fake authority (nonce and PKCE included), so a library bump cannot silently break sign-in.
- Live verification: sign in, Elevate (SSO, no consent prompt), banner shows until time, Audit page shows session.elevate; row is present in table r360audit and as a blob in r360audit-export; attempt to overwrite the blob is refused; sign out/in still works; End session audited.
- Risk: second MSAL client in one process (separate caches); token cache memory; scale-to-zero ends the write session (user re-elevates).

### S3. Author -> branch + PR (r360), L
- Deliver: github.mjs write functions (read/write tokens, git data commit, PR create/update/close, check-run and PR listing), remediation-schema.mjs (ajv), script validators, change.proposed/updated/discarded audit, GET /api/changes, POST /api/changes, Remediations "New"/"Edit" form (metadata fields + two script editors/upload, diff preview) and the Changes tab (stepper, auto poll 10 s).
- Tests: schema parity test against a copy of remediation.schema.json, path whitelist and traversal rejection, SIG-block rejection, CRLF/LF normalization, trailer and PR-body builder (oid, no PII beyond UPN/name), token permission narrowing assertion (write token = contents/pull_requests write only, one repo, not cached), fake GitHub API integration test of the full create sequence and failure rollback (branch deleted if PR creation fails), open-change cap, role author required.
- Live verification: create remediation "STT - r360 Phase2 Test" (harmless registry canary, groupId forced to canary) from the UI; PR appears on GitHub authored by the App with the oid trailers; PSScriptAnalyzer green; Changes tab shows it; audit rows present; discard closes PR and deletes the branch.
- Risk: server-side validation drifting from CI schema (parity test), large pastes, App token minted per action adds ~300 ms.

### S4. Approve + merge + observe signing (r360), M-L
- Deliver: POST /api/changes/:pr/approve, /reject, /merge, fourEyes() function, provenance model, update-branch handling, signed-artifact download/verify (fflate), sign.verified audit, stepper to "Signed".
- Tests: four-eyes matrix (testing/enforced x same/different oid x role x step), approval bound to head sha (new commit voids it), merge refuses when sha differs or check not green, update-branch path with byte-identical 3-file tree check, idempotent double click, artifact verification fixtures (good, wrong commit, wrong thumbprint, missing SIG, hash mismatch, expired cert), audit intent/result ordering.
- Live verification: (a) testing mode: approve own PR (red banner, selfApproved=true audit, PR comment), merge, watch Sign + Verify jobs, stepper reaches Signed; (b) enforced mode: switch R360_FOUR_EYES=enforced on the Container App, self-approval is refused and audited, then approve as the second approver (decision 4), merge, Signed; switch back to testing if you want to keep working solo (the script waits for the healthy revision).
- Risk: update-branch loops while main moves (bounded, auto-wait, clear state); approval/head race (sha pinned); artifact zip handling.

### S5. Publish to Intune, canary only (r360), L
- Deliver: intune.mjs write functions (find, create/PATCH, assign, post-read), POST /api/remediations/:folder/publish, provenance and assignment gates, description stamping, no-op idempotence, catalog.mjs signature-stripping + assignment read + Published/Signed columns, publish.canary audit, UI Publish button with reason tooltip.
- Tests: Graph request builder golden tests (create vs update, base64 of exact signed bytes, schedule mapping hourly/daily/once equals CLI), group gate (only canary allowed), unsigned refused, duplicate-name refused, provenance matrix (r360 chain, hand-merged, enforced vs testing/admin), four-eyes at publish, PIM warn/enforce, no-op when same sha+hash, post-read mismatch => failure state with audit, drift tests with signed content, throttling retry; real-shape fixtures of deviceHealthScript responses.
- Live verification: publish "STT - r360 Phase2 Test" to Intune from r360; Intune portal shows enforceSignatureCheck=Yes, description stamp, assigned to sg-remediation-canary only; Remediations page shows In sync + Published git sha; DEVICE01 runs it (Fleet page); a second publish click is a no-op; the CLI Publish-Remediation.ps1 still works (non-regression); publish by a hand-merged commit is refused (enforced) or admin-flagged (testing).
- Risk: Graph beta shape changes; Intune content-size/encoding; publisher needs Intune role active (warn mode logs, enforce later).

### S6. Promote after soak (r360), M ("P2b", cut line)
- Deliver: soak evaluator (pure), promote action (r360 PR changing only assignment.groupId, canary -> production), Soak column, evidence in the promote dialog, R360_PROD_GROUP_ID / R360_CANARY_SOAK_DAYS handling with SOAK OVERRIDE banner and audited soakDays, publish.production audit.
- Tests: evaluator with fake clock (day 6/7/8, new sha restarts clock, error in runSummary, canary device missing, drift present), promote PR diff contains exactly one changed field, refusal when evidence fails or override not set, production assignment only through promote path, full chain integration test with fakes.
- Live verification: with soak override set to 0 for the test remediation only, promote it; confirm PR, approval, signing, Intune assignment now = production group and canary no longer assigned; then restore R360_CANARY_SOAK_DAYS=7 and confirm the button is greyed with "day n of 7".
- Risk: promoting to a real production group affects real devices (use a small test group first, decision 1).

### S7. Close-out and the gated App-only merge step, S-M
- Deliver: README/design status updates (Phase 2 live), full Test-R360Prereqs -Stage All -RequireDeployed pass, an end-to-end live checklist script (read-only checks), then (gated, only with your explicit approval after S5 is proven) tools/Set-R360RulesetAppOnly.ps1 -WhatIf: GET the ruleset, add the App as the only bypass actor with bypass_mode pull_request plus the update restriction, PUT it back preserving every GitHub-filled parameter (a blind PUT can reset them), re-run prereqs; retire the human merge step of Publish-Remediation.ps1. Org-owner break-glass documented and tested.
- Live verification: a human merge to main is now refused by GitHub; an r360 merge succeeds; provenance gate no longer needs the testing-mode admin exception.

## 7. Risks (real ones)

- R1 MSAL nonce: @azure/msal-node 4+ validates the ID-token nonce inside acquireTokenByCode. r360 sends no nonce and is pinned to ^3.8.0, so a Dependabot major bump would break sign-in. S2 adds nonce generation for both client apps and a real-library test; hold any msal major bump until S2 is merged.
- R2 Signing chain unproven (S1 spike); self-signed cert means trust exists only on devices that received the two Intune profiles (Phase 0 did DEVICE01 only).
- R3 Provenance hole before S7: any human can merge to main and CI will sign it. Mitigated by the r360 provenance gate (S5) and by S7.
- R4 GitHub App compromise (id-r360 token or Key Vault sign access): can open PRs and merge within current rules, not change rulesets or workflows. Mitigations: per-action write tokens, path whitelist, audit before act, KV sign logs, S7 App-only rule keeps humans out but does not reduce this; PIM/c1 enforcement in P5 limits Graph side.
- R5 Four-eyes is only as strong as r360: GitHub cannot tell people apart. Testing mode is loud (banner, audit, PR comment, Intune stamp) with a dated exit.
- R6 Strict status checks: update-branch + CI rerun can delay merges; handled by observed states and bounded auto retry.
- R7 Scale-to-zero: write session and open dialogs are lost; no state is held only in memory, so actions are resumable from GitHub + audit.
- R8 Graph beta (deviceHealthScripts) can change shape; keep golden fixtures and a prereq read check.
- R9 Audit availability is a hard dependency (fail closed); table/blob outage blocks writes by design.
- R10 External dependencies in CI: jsign jar and RFC3161 TSA; pin by SHA-256, set a TSA fallback.

## 8. What you (Aaron) must do, with exact commands

Only things that need your identity or tenant/org admin rights. Everything else is scripted and I will give you the exact command per slice.

Now (before S1 can go live):
1. Confirm tools are present and signed in (read-only check I will wrap in the prereqs script):
   ```
   gh auth status
   az account show
   ```
2. If pushing the workflow change to remediations is refused because the gh token lacks the workflow scope:
   ```
   gh auth refresh -h github.com -s workflow
   ```
3. Merge the S1 PR in your-org/remediations (a human merge is required; the App has no workflows permission):
   ```
   gh pr merge <number> --repo your-org/remediations --squash
   ```
4. Run the config script once it exists (sets the 3 non-secret repo variables, verifies FIC subject and Key Vault roles):
   ```
   pwsh -File C:\path\to\remediation-360\tools\Set-R360CiSigningConfig.ps1 -WhatIf
   pwsh -File C:\path\to\remediation-360\tools\Set-R360CiSigningConfig.ps1
   ```
5. S1 device check on DEVICE01 (one command I will give you with the exact artifact path).

At S2 (infrastructure and deploy):
6. Apply the new blob role and env vars (extended idempotent script), then deploy the dated image:
   ```
   pwsh -File C:\path\to\remediation-360\tools\New-R360Infrastructure.ps1 -WhatIf
   pwsh -File C:\path\to\remediation-360\tools\New-R360Infrastructure.ps1
   pwsh -File C:\path\to\remediation-360\tools\Publish-R360Image.ps1
   ```
7. Sign out and back in to r360, click Elevate once to confirm the write session.

At S4 (to test enforced four-eyes live, optional):
8. Make sure the second approver can sign in (decision 4). For user1 (object id is in approvers.json):
   ```
   az ad group member add --group sg-r360-operators --member-id <user-object-id>
   ```
   user1 also needs the Intune Administrator role active in PIM if they will be the publisher.

At S5 / S6:
9. Name the production group (decision 1); if it does not exist yet, create it in Entra, then I wire R360_PROD_GROUP_ID with the config script.
10. Optional for S6 testing: approve the audited soak override for the test remediation (decision 2).

At S7 (gated): your explicit approval to run Set-R360RulesetAppOnly.ps1 (shows a -WhatIf diff first).

NOT needed: no new Entra consent, no new Graph or Defender scope, no GitHub App permission change, no new app registration, no client secret.

## 9. Open decisions (only the real ones)

1. Production group for promotion: which Entra group (or a small test group first)? Needed before S6 can go live. Recommendation: create sg-remediation-prod-pilot (a couple of devices) for first promotion, switch the config later.
2. Soak override for same-day testing: allow R360_CANARY_SOAK_DAYS to be lowered (audited, red SOAK OVERRIDE banner, scoped to the test remediation) so S6 can be proven today? Recommendation: yes, with the banner.
3. Is S6 (promote) part of Phase 2 or Phase 3 as in the design table? Recommendation: build it as S6 right after S5 is live, and update the design doc phase table to match; cut it if time is short.
4. Second approver for live enforced-mode proof: is user1@contoso.com a real second person or test account that can sign in to r360 (and activate Intune Administrator if they publish)? Recommendation: yes use user1, then return to testing mode afterward.
5. Publish gate for four-eyes: should the publisher differ from the author in enforced mode (as the CLI does today)? Recommendation: yes, same rule as the CLI (approve + publish both checked).

Decided in this plan (tell me if you object): signing in CI with jsign and a Windows Verify job; approval recorded in r360 audit bound to head sha (no GitHub review, no new App permission); r360 only merges and approves PRs it created, hand-opened PRs stay read-only; per-event immutable blob write instead of nightly export; waiting steps are observed states (no server job runner); provenance gate at publish until the App-only merge rule is on; no ruleset change in Phase 2.
## S7 status (2026-10-27)
- App-only merge live on your-org/remediations: ruleset r360-app-only-merge (26006752), update rule, sole bypass actor r360 App 1234567 (bypass_mode pull_request). main-protection (25825962) unchanged, so the App still needs PSScriptAnalyzer. Break-glass (owner): pwsh -File tools\Set-R360RulesetAppOnly.ps1 -Remove, then re-run without -Remove.
- Write sessions stay in memory by design (R7); reconcileLost closes lost elevations in the audit log.

