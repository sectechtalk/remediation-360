import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { unzipSync } from 'fflate';
import { createChanges, ChangeError, machineBlock } from '../server/changes.mjs';
import { createIntune, sha256Hex, HS } from '../server/intune.mjs';
import { SIG_BEGIN } from '../server/signing.mjs';
import { loadConfig } from '../server/config.mjs';
import { metaText } from '../server/remediation-schema.mjs';
import { ENV } from './fixtures.mjs';

// A shared world for the S6 tests. The fixture is a test-signed artifact of fake commit c0ffee00 (tests/data/build-signed-fixture.ps1). In this world its assignment group
// (90000000...) plays the PRODUCTION group, and the canary group is a different one, so the signed fixture bytes can be published to
// production exactly as a promotion would. Only the fetcher (Graph), GitHub and the audit store are fake.
export const AARON = { oid: '94540000-0000-4000-8000-0000000000c3', upn: 'admin@contoso.com', name: 'Aaron Brooks' };
export const USER1 = { oid: '0d000000-0000-4000-8000-0000000000c4', upn: 'user1@contoso.com', name: 'User One' };
export const PROD = '90000000-0000-4000-8000-0000000000c2';
export const CAN = '11111111-1111-4111-8111-111111111111';
export const PILOT = '22222222-2222-4222-8222-222222222222';
export const MAILONLY = '33333333-3333-4333-8333-333333333333';
export const GONE = '44444444-4444-4444-8444-444444444444';
export const TARGET_PROD = { type: 'group', groupId: PROD };
export const T0 = Date.parse('2026-10-27T15:04:00Z');
export const DAY = 86400000;
export const COMMIT = 'c0ffee0000000000000000000000000000000001';
export const CSHA = 'c'.repeat(40);
export const FOLDER = 'Sample-RemediationCanary';
export const HEAD = 'a'.repeat(40);
export const AUTHOR = ['author', 'approver', 'admin'];
export const APPROVER = ['approver'];
export const GREEN = [{ name: 'PSScriptAnalyzer', status: 'completed', conclusion: 'success' }];
const JOBS = [{ name: 'Signing self-test', conclusion: 'success' }, { name: 'Sign (Key Vault HSM)', conclusion: 'success' }, { name: 'Verify (Windows Authenticode)', conclusion: 'success' }];
export const ZIP = readFileSync(new URL('./data/signed-c0ffee00.zip', import.meta.url));
export const parts = Object.fromEntries(Object.entries(unzipSync(new Uint8Array(ZIP))).map(([k, v]) => [k, Buffer.from(v).toString('utf8')]));
export const gitTexts = { 'remediation.json': parts[`remediations/${FOLDER}/remediation.json`], 'detect.ps1': parts[`remediations/${FOLDER}/detect.ps1`].split(SIG_BEGIN)[0], 'remediate.ps1': parts[`remediations/${FOLDER}/remediate.ps1`].split(SIG_BEGIN)[0] };
export const prodMeta = JSON.parse(gitTexts['remediation.json']);
export const canaryMeta = { ...prodMeta, assignment: { ...prodMeta.assignment, groupId: CAN } };
export const canaryRaw = { ...gitTexts, 'remediation.json': metaText(canaryMeta) };
const iso = ms => new Date(ms).toISOString();

export function graph() {
  const sec = (id, displayName, devices, members, extra = {}) => [id, { id, displayName, description: `${displayName} description`, securityEnabled: true, mailEnabled: false, groupTypes: [], membershipRule: null, devices, members, ...extra }];
  const g = { scripts: new Map(), assigns: new Map(), calls: [], n: 0, order: null, fail: null, summary: null, states: [],
    groups: new Map([sec(PROD, 'Production Devices', 41, 58), sec(PILOT, 'Pilot Devices', 6, 9, { groupTypes: ['DynamicMembership'], membershipRule: 'x' }), sec(CAN, 'Remediation Canary', 1, 1),
      [MAILONLY, { id: MAILONLY, displayName: 'Production Mailing List', securityEnabled: false, mailEnabled: true, groupTypes: [], devices: 0, members: 3 }]]), countFail: false };
  const json = (status, body, rid) => new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { 'content-type': 'application/json', 'request-id': rid } });
  g.fetcher = async (url, init = {}) => {
    const u = new URL(url); const method = init.method || 'GET'; const body = init.body ? JSON.parse(init.body) : undefined;
    const rid = `req-${g.calls.length + 1}`;
    g.calls.push({ method, path: u.pathname, search: u.search, origin: u.origin, auth: init.headers?.Authorization, headers: init.headers, body });
    g.order?.push(`graph:${method}`);
    const hooked = g.fail?.(method, u.pathname, g.calls.length); if (hooked) return hooked;
    // Entra groups (v1.0): search by displayName, read one, and the $count of transitive members.
    if (u.pathname.startsWith('/v1.0/groups')) {
      if (method !== 'GET') return json(405, { error: { code: 'MethodNotAllowed', message: 'x' } }, rid);
      const gm = /^\/v1\.0\/groups(?:\/([^/]+)(?:\/transitiveMembers(\/microsoft\.graph\.device)?\/\$count)?)?$/.exec(u.pathname);
      if (!gm) return json(404, { error: { code: 'NotFound', message: 'no route' } }, rid);
      const [, gid, dev] = gm; const isCount = u.pathname.endsWith('/$count');
      const strip = x => { const { devices, members, ...rest } = x; return rest; };
      if (!gid) {
        if (init.headers?.ConsistencyLevel !== 'eventual') return json(400, { error: { code: 'Request_UnsupportedQuery', message: 'needs ConsistencyLevel' } }, rid);
        const s = (u.searchParams.get('$search') || '').replace(/^"displayName:/, '').replace(/"$/, '').toLowerCase();
        return json(200, { value: [...g.groups.values()].filter(x => x.displayName.toLowerCase().includes(s)).slice(0, Number(u.searchParams.get('$top') || 100)).map(strip) }, rid);
      }
      const grp = g.groups.get(gid);
      if (!grp) return json(404, { error: { code: 'Request_ResourceNotFound', message: 'gone' } }, rid);
      // Live Graph (checked Oct 27, 2026): $count needs ConsistencyLevel: eventual and answers HTTP 415 unless Accept allows text/plain.
      if (isCount && init.headers?.ConsistencyLevel !== 'eventual') return json(400, { error: { code: 'Request_BadRequest', message: 'needs ConsistencyLevel' } }, rid);
      if (isCount && !/text\/plain|\*\/\*/.test(String(init.headers?.Accept || ''))) return json(415, { error: { code: 'Request_BadRequest', message: "The request's supported type(s) 'text/plain' do not match the Accept header" } }, rid);
      if (isCount) { if (g.countFail) return json(403, { error: { code: 'Authorization_RequestDenied', message: 'no' } }, rid); return new Response(String(dev ? grp.devices : grp.members), { status: 200, headers: { 'content-type': 'text/plain', 'request-id': rid } }); }
      return json(200, strip(grp), rid);
    }
    const m = /^\/beta\/deviceManagement\/deviceHealthScripts(?:\/([^/]+)(\/assignments|\/assign|\/runSummary|\/deviceRunStates)?)?$/.exec(u.pathname);
    if (!m) return json(404, { error: { code: 'NotFound', message: 'no route' } }, rid);
    const [, id, sub] = m;
    if (!id && method === 'GET') return json(200, { value: [...g.scripts.values()].map(({ id: i, displayName, version }) => ({ id: i, displayName, version })) }, rid);
    if (!id && method === 'POST') { const nid = `intune-${++g.n}`; g.scripts.set(nid, { ...body, id: nid, version: '1' }); g.assigns.set(nid, []); return json(201, g.scripts.get(nid), rid); }
    if (!g.scripts.has(id)) return json(404, { error: { code: 'NotFound', message: 'gone' } }, rid);
    if (sub === '/runSummary' && method === 'GET') return json(200, g.summary, rid);
    if (sub === '/deviceRunStates' && method === 'GET') return json(200, { value: g.states }, rid);
    if (!sub && method === 'GET') return json(200, g.scripts.get(id), rid);
    if (sub === '/assignments' && method === 'GET') return json(200, { value: g.assigns.get(id) }, rid);
    if (!sub && method === 'PATCH') { Object.assign(g.scripts.get(id), body); return new Response(null, { status: 204, headers: { 'request-id': rid } }); }
    if (sub === '/assign' && method === 'POST') { g.assigns.set(id, body.deviceHealthScriptAssignments.map((a, i) => ({ id: `a${i}`, ...a }))); return json(200, {}, rid); }
    return json(405, { error: { code: 'MethodNotAllowed', message: 'x' } }, rid);
  };
  g.writes = () => g.calls.filter(c => c.method !== 'GET');
  return g;
}

// soakDays: how many whole days ago the canary publish happened. opts.prod=false leaves R360_PROD_GROUP_ID unset.
export function world({ mode = 'testing', soakDays = 8, prod = true, canaryAuthor = AARON } = {}) {
  const config = loadConfig({ ...ENV, R360_CANARY_GROUP_ID: CAN, ...(prod ? { R360_PROD_GROUP_ID: PROD } : {}), R360_FOUR_EYES: mode });
  const canaryAt = T0 - soakDays * DAY - 60000;
  const w = { t: T0, seq: 0, mode, config, rows: [], order: [], comments: [], proposals: [], files: {}, mainSha: CSHA, mainMeta: canaryMeta, pr: null, canaryAt, auditDown: false, intentDown: false, proposeFail: null, logs: [],
    canaryPr: { number: 3, state: 'closed', merged: true, draft: false, title: 'canary', url: 'https://github.com/your-org/remediations/pull/3', branch: `r360/${FOLDER}/202610171504-${canaryAuthor.oid.slice(0, 8)}`, headSha: 'd'.repeat(40), headRepo: 'your-org/remediations', base: 'main',
      body: `Proposed through r360 by ${canaryAuthor.upn} on x\n${machineBlock({ folder: FOLDER, authorOid: canaryAuthor.oid })}`, createdAt: iso(canaryAt - DAY), updatedAt: iso(canaryAt), mergedAt: iso(canaryAt - 3600000), mergeSha: CSHA, checks: GREEN } };
  w.g = graph(); w.g.order = w.order;
  const detectB = Buffer.from(parts[`remediations/${FOLDER}/detect.ps1`]), remB = Buffer.from(parts[`remediations/${FOLDER}/remediate.ps1`]);
  w.hashes = { detect: sha256Hex(detectB), remediate: sha256Hex(remB) };
  w.g.scripts.set('intune-canary', { id: 'intune-canary', displayName: 'STT - Remediation Canary', description: `Canary [git ${CSHA.slice(0, 8)} by ${canaryAuthor.upn}; approved by ${canaryAuthor.upn}; published by ${canaryAuthor.upn} via r360]`, publisher: 'SecTechTalk', runAsAccount: 'system', runAs32Bit: false,
    enforceSignatureCheck: true, detectionScriptContent: detectB.toString('base64'), remediationScriptContent: remB.toString('base64'), version: '1' });
  w.g.assigns.set('intune-canary', [{ id: 'a0', target: { '@odata.type': '#microsoft.graph.groupAssignmentTarget', groupId: CAN }, runRemediationScript: true }]);
  w.g.summary = { detectionScriptErrorDeviceCount: 0, remediationScriptErrorDeviceCount: 0, issueReoccurredDeviceCount: 0, noIssueDetectedDeviceCount: 1, issueRemediatedDeviceCount: 0 };
  w.g.states = [{ id: 's1', detectionState: 'success', remediationState: 'skipped', lastStateUpdateDateTime: iso(canaryAt + 3600000), managedDevice: { deviceName: 'DEVICE01' } }];
  const target = `remediations/${FOLDER}`;
  w.rows.push(
    { action: 'change.proposed', result: 'ok', actorOid: canaryAuthor.oid, actorUpn: canaryAuthor.upn, target, prNumber: 3, gitSha: 'd'.repeat(40), at: iso(canaryAt - 2 * DAY) },
    { action: 'publish.canary', result: 'intent', actorOid: AARON.oid, actorUpn: AARON.upn, target, prNumber: 3, gitSha: CSHA, at: iso(canaryAt - 1000) },
    { action: 'publish.canary', result: 'ok', actorOid: AARON.oid, actorUpn: AARON.upn, target, prNumber: 3, gitSha: CSHA, at: iso(canaryAt), detail: { created: true, intuneId: 'intune-canary', displayName: 'STT - Remediation Canary', hashes: w.hashes, groupId: CAN } });
  w.audit = {
    record: async e => {
      if (w.auditDown) throw new Error('down');
      if (w.intentDown && e.result === 'intent') throw new Error('intent down');
      w.order.push(`audit:${e.action}:${e.result}`); w.rows.push({ ...e, at: iso(T0 + (++w.seq) * 1000) }); return e;
    },
    list: async () => { if (w.auditDown) throw new Error('down'); return { rows: [...w.rows].reverse(), truncated: false }; },
  };
  const pulls = () => [w.canaryPr, ...(w.pr ? [w.pr] : [])];
  w.github = {
    catalog: async () => ({ items: [{ folder: FOLDER, meta: w.mainMeta, detect: gitTexts['detect.ps1'], remediate: gitTexts['remediate.ps1'] }], sha: w.mainSha, approvers: [{ entraObjectId: AARON.oid, upn: AARON.upn, roles: AUTHOR }, { entraObjectId: USER1.oid, upn: USER1.upn, roles: APPROVER }] }),
    listPulls: async () => pulls().map(p => ({ ...p })), getPull: async n => { const p = pulls().find(x => x.number === n); if (!p) throw new Error('nf'); return { ...p }; },
    getChecks: async () => GREEN, behindBy: async () => 0, unresolvedThreads: async () => 0,
    commentOnPull: async a => { w.comments.push(a.body); return { id: 1, githubRequestId: 'R-comment' }; },
    proposeChange: async a => {
      if (w.proposeFail) throw w.proposeFail;
      w.proposals.push(a);
      w.pr = { number: 7, state: 'open', merged: false, draft: false, title: a.title, url: 'https://github.com/your-org/remediations/pull/7', branch: a.branch, headSha: HEAD, headRepo: 'your-org/remediations', base: 'main', body: a.body, createdAt: iso(w.t), updatedAt: iso(w.t), mergedAt: null, mergeSha: null, checks: GREEN };
      return { number: 7, url: w.pr.url, headSha: HEAD, githubRequestId: 'R-pr' };
    },
    mergeChange: async a => { if (a.sha !== w.pr.headSha) throw Object.assign(new Error('head moved'), { status: 409 }); w.pr.merged = true; w.pr.state = 'closed'; w.pr.mergeSha = COMMIT; w.pr.mergedAt = iso(w.t); w.mainSha = COMMIT; w.mainMeta = prodMeta; return { mergeSha: COMMIT, branchDeleted: true, githubRequestId: 'R-merge' }; },
    readChangeFiles: async ({ sha }) => { const raw = w.files[sha] || (sha === CSHA ? canaryRaw : gitTexts); return { raw, meta: JSON.parse(raw['remediation.json']) }; },
    signingRun: async () => w.run, downloadSignedArtifact: async () => w.artifact,
  };
  w.run = { id: 40461381266, status: 'completed', conclusion: 'success', url: 'https://github.com/your-org/remediations/actions/runs/40461381266', jobs: JOBS };
  w.artifact = { buffer: ZIP, artifact: { id: 99, runId: 40461381266, bytes: ZIP.length } };
  w.build = (c = config) => { w.c = createChanges({ config: c, github: w.github, audit: w.audit, intune: createIntune({ fetcher: w.g.fetcher, sleep: async () => {} }), now: () => w.t, log: { error: m => w.logs.push(String(m)) } }); return w.c; };
  w.build();
  w.pub = { token: async () => 'WT', readToken: async () => 'RT' };
  w.tokens = { readToken: async () => 'RT' };
  return w;
}

export const body = (extra = {}) => ({ folder: FOLDER, canarySha: CSHA, target: TARGET_PROD, ...extra });
export const promote = (w, u = AARON, roles = AUTHOR, b = body()) => w.c.promote(u, roles, b, w.tokens);
export const evidence = (w, u = AARON, roles = AUTHOR) => w.c.promoteEvidence(u, roles, FOLDER, w.tokens);
export const publish = (w, u = AARON, roles = AUTHOR, b = { mergeSha: COMMIT }) => w.c.publish(u, roles, 7, b, w.pub);
export const fails = (p, status, re) => assert.rejects(p, e => e instanceof ChangeError && e.status === status && (!re || re.test(e.message)), `expected ${status} ${re}`);
export const ofAction = (w, a) => w.rows.filter(r => r.action === a);
export const noGraphWrites = w => assert.deepEqual(w.g.writes(), [], 'no Graph write was made');
// promote (as `promoter`), approve (as `approver`), merge, verify signing: all through the real flows.
export async function promoted(w, { promoter = AARON, promoterRoles = AUTHOR, approver = AARON, approverRoles = AUTHOR, reason } = {}) {
  const r = await promote(w, promoter, promoterRoles, body(reason ? { overrideReason: reason } : {}));
  await w.c.approve(approver, approverRoles, 7, { headSha: HEAD });
  await w.c.merge(AARON, AUTHOR, 7, { headSha: HEAD });
  await w.c.verifySigning(AARON, AUTHOR, 7);
  w.order.length = 0; w.g.calls.length = 0;
  return r;
}
export { ChangeError, iso };
