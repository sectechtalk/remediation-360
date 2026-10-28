import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { unzipSync } from 'fflate';
import { createChanges, ChangeError, machineBlock, stageOf } from '../server/changes.mjs';
import { createIntune, buildDesired, descriptionStamp, intuneDiff, scheduleOf, sha256Hex, HS } from '../server/intune.mjs';
import { SIG_BEGIN } from '../server/signing.mjs';
import { loadConfig } from '../server/config.mjs';
import { ENV } from './fixtures.mjs';

const AARON = { oid: '94540000-0000-4000-8000-0000000000c3', upn: 'admin@contoso.com', name: 'Aaron Brooks' };
const USER1 = { oid: '0d000000-0000-4000-8000-0000000000c4', upn: 'user1@contoso.com', name: 'User One' };
const CANARY = '90000000-0000-4000-8000-0000000000c2';
const T0 = Date.parse('2026-10-27T15:04:00Z');
const ZIP = readFileSync(new URL('./data/signed-c0ffee00.zip', import.meta.url));
const COMMIT = 'c0ffee0000000000000000000000000000000001';
const FOLDER = 'Sample-RemediationCanary';
const HEAD = 'a'.repeat(40);
const GREEN = [{ name: 'PSScriptAnalyzer', status: 'completed', conclusion: 'success' }];
const JOBS = [{ name: 'Signing self-test', conclusion: 'success' }, { name: 'Sign (Key Vault HSM)', conclusion: 'success' }, { name: 'Verify (Windows Authenticode)', conclusion: 'success' }];
const parts = Object.fromEntries(Object.entries(unzipSync(new Uint8Array(ZIP))).map(([k, v]) => [k, Buffer.from(v).toString('utf8')]));
const gitTexts = { 'remediation.json': parts[`remediations/${FOLDER}/remediation.json`], 'detect.ps1': parts[`remediations/${FOLDER}/detect.ps1`].split(SIG_BEGIN)[0], 'remediate.ps1': parts[`remediations/${FOLDER}/remediate.ps1`].split(SIG_BEGIN)[0] };
const AUTHOR = ['author', 'approver', 'admin'];
const APPROVER = ['approver'];

// An in-memory Intune behind the real Graph client: the fetcher is the only fake.
function graph() {
  const g = { scripts: new Map(), assigns: new Map(), calls: [], n: 0, order: null, fail: null, pageSize: 0, afterAssign: null };
  const json = (status, body, rid) => new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { 'content-type': 'application/json', 'request-id': rid } });
  g.fetcher = async (url, init = {}) => {
    const u = new URL(url); const method = init.method || 'GET'; const body = init.body ? JSON.parse(init.body) : undefined;
    const rid = `req-${g.calls.length + 1}`;
    g.calls.push({ method, path: u.pathname, search: u.search, origin: u.origin, auth: init.headers?.Authorization, body });
    g.order?.push(`graph:${method}`);
    const hooked = g.fail?.(method, u.pathname, g.calls.length); if (hooked) return hooked;
    const m = /^\/beta\/deviceManagement\/deviceHealthScripts(?:\/([^/]+)(\/assignments|\/assign)?)?$/.exec(u.pathname);
    if (!m) return json(404, { error: { code: 'NotFound', message: 'no route' } }, rid);
    const [, id, sub] = m;
    if (!id && method === 'GET') {
      const all = [...g.scripts.values()].map(({ id: i, displayName, version }) => ({ id: i, displayName, version }));
      if (!g.pageSize) return json(200, { value: all }, rid);
      const skip = Number(u.searchParams.get('$skip') || 0);
      const next = skip + g.pageSize < all.length ? `https://graph.microsoft.com${HS}?$skip=${skip + g.pageSize}` : undefined;
      return json(200, { value: all.slice(skip, skip + g.pageSize), ...(next ? { '@odata.nextLink': next } : {}) }, rid);
    }
    if (!id && method === 'POST') { const nid = `intune-${++g.n}`; g.scripts.set(nid, { ...body, id: nid, version: '1' }); g.assigns.set(nid, []); return json(201, g.scripts.get(nid), rid); }
    if (!g.scripts.has(id)) return json(404, { error: { code: 'NotFound', message: 'gone' } }, rid);
    if (!sub && method === 'GET') return json(200, g.scripts.get(id), rid);
    if (sub === '/assignments' && method === 'GET') return json(200, { value: g.assigns.get(id) }, rid);
    if (!sub && method === 'PATCH') { Object.assign(g.scripts.get(id), body); return new Response(null, { status: 204, headers: { 'request-id': rid } }); }
    if (sub === '/assign' && method === 'POST') {
      g.assigns.set(id, body.deviceHealthScriptAssignments.map((a, i) => ({ id: `a${i}`, ...a })));
      g.afterAssign?.(g.scripts.get(id));
      return json(200, {}, rid);
    }
    return json(405, { error: { code: 'MethodNotAllowed', message: 'x' } }, rid);
  };
  g.writes = () => g.calls.filter(c => c.method !== 'GET' && !c.path.endsWith('/assignments'));
  return g;
}

function world({ mode = 'testing', cfg } = {}) {
  const config = cfg || loadConfig({ ...ENV, R360_CANARY_GROUP_ID: CANARY, R360_FOUR_EYES: mode });
  const w = { t: T0, seq: 0, mode, rows: [], order: [], comments: [], intentDown: false, auditListDown: false, failResultFor: null, files: {}, artifact: null, mainSha: COMMIT, run: null, extraPulls: [], tokenError: null };
  w.g = graph(); w.g.order = w.order;
  w.pr = { number: 7, state: 'open', merged: false, draft: false, title: `r360: add remediation ${FOLDER}`, url: 'https://github.com/your-org/remediations/pull/7', branch: `r360/${FOLDER}/202610271504-94540000`, headSha: HEAD, headRepo: 'your-org/remediations', base: 'main',
    body: `Proposed through r360 by admin@contoso.com on x\n${machineBlock({ folder: FOLDER, authorOid: AARON.oid })}`, createdAt: 'c', updatedAt: 'u', mergedAt: null, mergeSha: null, checks: GREEN };
  w.audit = {
    record: async e => {
      if (w.auditDown) throw new Error('down');
      if (w.intentDown && e.action === 'publish.canary' && e.result === 'intent') throw new Error('intent down');
      if (w.failResultFor && e.action === w.failResultFor && e.result !== 'intent') throw new Error('result down');
      w.order.push(`audit:${e.action}:${e.result}`); w.rows.push({ ...e, at: new Date(T0 + (++w.seq) * 1000).toISOString() }); return e;
    },
    list: async () => { if (w.auditListDown) throw new Error('down'); return { rows: [...w.rows].reverse(), truncated: false }; },
  };
  w.github = {
    catalog: async () => ({ items: [], sha: w.mainSha, approvers: [{ entraObjectId: AARON.oid, upn: AARON.upn, roles: ['author', 'approver', 'admin'] }, { entraObjectId: USER1.oid, upn: USER1.upn, roles: ['approver'] }] }),
    listPulls: async () => [{ ...w.pr }, ...w.extraPulls], getPull: async n => { if (n !== 7) throw new Error('nf'); return { ...w.pr }; },
    getChecks: async () => w.pr.checks || [], behindBy: async () => 0, unresolvedThreads: async () => 0,
    commentOnPull: async a => { w.comments.push(a.body); return { id: 1, githubRequestId: 'R-comment' }; },
    mergeChange: async a => { if (a.sha !== w.pr.headSha) throw Object.assign(new Error('head moved'), { status: 409 }); w.pr.merged = true; w.pr.state = 'closed'; w.pr.mergeSha = COMMIT; w.pr.mergedAt = new Date(w.t).toISOString(); return { mergeSha: COMMIT, branchDeleted: true, githubRequestId: 'R-merge' }; },
    readChangeFiles: async ({ sha }) => ({ raw: w.files[sha] || gitTexts }),
    signingRun: async () => w.run, downloadSignedArtifact: async () => { if (w.artifact instanceof Error) throw w.artifact; return w.artifact; },
  };
  w.run = { id: 40461381266, status: 'completed', conclusion: 'success', url: 'https://github.com/your-org/remediations/actions/runs/40461381266', jobs: JOBS };
  w.artifact = { buffer: ZIP, artifact: { id: 99, runId: 40461381266, bytes: ZIP.length } };
  w.sleeps = [];
  w.build = (c = config) => { w.c = createChanges({ config: c, github: w.github, audit: w.audit, intune: createIntune({ fetcher: w.g.fetcher, sleep: async ms => { w.sleeps.push(ms); } }), now: () => w.t, log: { error() {} } }); return w.c; };
  w.build();
  w.pub = { token: async () => { if (w.tokenError) throw w.tokenError; return 'WT'; } };
  w.rows.push({ action: 'change.proposed', result: 'ok', actorOid: AARON.oid, actorUpn: AARON.upn, target: `remediations/${FOLDER}`, prNumber: 7, gitSha: HEAD, at: new Date(T0).toISOString() });
  return w;
}
// approve (by `approver`), merge (by Aaron) and verify signing, all through the real flows.
async function ready(w, approver = { u: AARON, roles: AUTHOR }) {
  await w.c.approve(approver.u, approver.roles, 7, { headSha: HEAD });
  await w.c.merge(AARON, AUTHOR, 7, { headSha: HEAD });
  await w.c.verifySigning(AARON, AUTHOR, 7);
  w.order.length = 0; w.g.calls.length = 0;
  return w;
}
const readyEnforced = async () => { const w = world({ mode: 'enforced' }); return ready(w, { u: USER1, roles: APPROVER }); };
const publish = (w, u = AARON, roles = AUTHOR, body = { mergeSha: COMMIT }) => w.c.publish(u, roles, 7, body, w.pub);
const fails = (p, status, re) => assert.rejects(p, e => e instanceof ChangeError && e.status === status && (!re || re.test(e.message)), `expected ${status} ${re}`);
const ofAction = (w, a) => w.rows.filter(r => r.action === a);
const noGraph = w => assert.deepEqual(w.g.calls, [], 'no Graph call was made');

test('publish (testing mode, Aaron alone): intent row BEFORE Graph, signed bytes only, canary only, self-approved flagged everywhere', async () => {
  const w = await ready(world());
  const r = await publish(w);
  assert.deepEqual({ ok: r.ok, created: r.created, selfApproved: r.selfApproved, mergeSha: r.mergeSha }, { ok: true, created: true, selfApproved: true, mergeSha: COMMIT });
  const iIntent = w.order.indexOf('audit:publish.canary:intent'), iGraph = w.order.findIndex(o => o.startsWith('graph:')), iOk = w.order.indexOf('audit:publish.canary:ok');
  assert.ok(iIntent >= 0 && iIntent < iGraph && iGraph < iOk, `order was ${w.order.join(' > ')}`);
  for (const c of w.g.calls) { assert.equal(c.origin, 'https://graph.microsoft.com'); assert.equal(c.auth, 'Bearer WT'); }
  const stored = w.g.scripts.get(r.intuneId);
  assert.equal(stored.displayName, 'STT - Remediation Canary');
  assert.equal(stored.enforceSignatureCheck, true);
  assert.equal(Buffer.from(stored.detectionScriptContent, 'base64').toString('utf8'), parts[`remediations/${FOLDER}/detect.ps1`], 'the signed detect.ps1, byte for byte');
  assert.equal(Buffer.from(stored.remediationScriptContent, 'base64').toString('utf8'), parts[`remediations/${FOLDER}/remediate.ps1`]);
  assert.match(stored.description, new RegExp(`\\[git ${COMMIT.slice(0, 8)} by admin@contoso\\.com; approved by admin@contoso\\.com; published by admin@contoso\\.com via r360\\] \\[self-approved, testing mode\\]$`));
  const a = w.g.assigns.get(r.intuneId);
  assert.equal(a.length, 1); assert.equal(a[0].target.groupId, CANARY); assert.equal(a[0].runSchedule.time, '02:00:00');
  const [i, ok] = ofAction(w, 'publish.canary');
  assert.equal(i.result, 'intent'); assert.equal(ok.result, 'ok');
  assert.equal(ok.actorOid, AARON.oid); assert.equal(ok.selfApproved, true); assert.equal(ok.mode, 'testing'); assert.equal(ok.gitSha, COMMIT); assert.equal(ok.prNumber, 7); assert.equal(ok.requestId, i.requestId); assert.equal(r.requestId, i.requestId);
  assert.equal(ok.detail.created, true); assert.equal(ok.detail.intuneId, r.intuneId); assert.equal(ok.detail.provenance, 'chain'); assert.equal(ok.detail.groupId, CANARY); assert.match(ok.detail.manifestSha256, /^[0-9a-f]{64}$/);
  assert.ok(ok.detail.graphRequestIds.length >= 4); assert.ok(ok.graphRequestId);
  assert.ok(!JSON.stringify(w.rows).includes('WT"'), 'no token in the audit trail');
  assert.ok(!JSON.stringify(w.rows).includes(SIG_BEGIN), 'script content is never put in the audit trail');
});

test('publish is idempotent: a second click finds Intune identical and writes nothing; the list then shows Published', async () => {
  const w = await ready(world());
  const first = await publish(w);
  w.g.calls.length = 0;
  const again = await publish(w);
  assert.equal(again.already, true); assert.equal(again.intuneId, first.intuneId);
  assert.deepEqual(w.g.writes(), [], 'no Graph write on the second click');
  const rows = ofAction(w, 'publish.canary');
  assert.deepEqual(rows.map(r => r.result), ['intent', 'ok', 'intent', 'ok']);
  assert.equal(rows.at(-1).detail.noop, true);
  assert.equal(w.g.scripts.size, 1);
  w.t += 20000;
  const l = (await w.c.list(AARON, AUTHOR)).changes[0];
  assert.equal(l.stage, 'published'); assert.equal(l.published.byOid, AARON.oid); assert.equal(l.published.selfApproved, true); assert.equal(l.canPublish, false); assert.match(l.publishBlock, /already published/i);
});

test('publish updates an existing remediation of the same name (PATCH, then assign), never creates a duplicate, and leaves exactly one canary assignment', async () => {
  const w = await ready(world());
  w.g.scripts.set('old-1', { id: 'old-1', displayName: 'stt - remediation canary', description: 'old [git 11111111 by x]', publisher: 'SecTechTalk', runAsAccount: 'system', runAs32Bit: false, enforceSignatureCheck: false, detectionScriptContent: Buffer.from('old').toString('base64'), remediationScriptContent: Buffer.from('old').toString('base64') });
  w.g.assigns.set('old-1', [{ id: 'x', target: { '@odata.type': '#microsoft.graph.groupAssignmentTarget', groupId: '11111111-1111-4111-8111-111111111111' }, runRemediationScript: true }, { id: 'y', target: { '@odata.type': '#microsoft.graph.allDevicesAssignmentTarget' }, runRemediationScript: true }]);
  const r = await publish(w);
  assert.equal(r.created, false); assert.equal(r.intuneId, 'old-1');
  assert.deepEqual(w.g.writes().map(c => c.method), ['PATCH', 'POST']);
  assert.ok(!w.g.calls.some(c => c.method === 'POST' && c.path.endsWith('deviceHealthScripts')), 'no create');
  assert.equal(w.g.assigns.get('old-1').length, 1); assert.equal(w.g.assigns.get('old-1')[0].target.groupId, CANARY);
  assert.equal(w.g.scripts.get('old-1').enforceSignatureCheck, true);
  assert.equal(ofAction(w, 'publish.canary').at(-1).detail.created, false);
});

test('publish finds the remediation across pages of the Intune list', async () => {
  const w = await ready(world());
  w.g.pageSize = 1;
  for (const [id, n] of [['p1', 'A'], ['p2', 'B'], ['p3', 'STT - Remediation Canary']]) w.g.scripts.set(id, { id, displayName: n, version: '1' });
  w.g.assigns.set('p3', []);
  const r = await publish(w);
  assert.equal(r.intuneId, 'p3'); assert.equal(r.created, false); assert.ok(w.g.calls.filter(c => c.method === 'GET' && c.search.includes('skip')).length >= 1, 'paged');
});

test('enforced mode: the author cannot publish (denial row, no intent row, no Graph call); a different approver can, and it is not self-approved', async () => {
  const w = await readyEnforced();
  await fails(publish(w, AARON, AUTHOR), 403, /different|author/i);
  noGraph(w);
  const d = ofAction(w, 'publish.denied');
  assert.equal(d.length, 1); assert.equal(d[0].result, 'denied'); assert.equal(d[0].reason, 'publisher-must-differ'); assert.equal(d[0].actorOid, AARON.oid);
  assert.equal(ofAction(w, 'publish.canary').length, 0);
  const r = await publish(w, USER1, APPROVER);
  assert.equal(r.selfApproved, false); assert.equal(r.created, true);
  const ok = ofAction(w, 'publish.canary').at(-1);
  assert.equal(ok.actorOid, USER1.oid); assert.equal(ok.selfApproved, false); assert.equal(ok.mode, 'enforced'); assert.equal(ok.approverOid, USER1.oid);
  const desc = w.g.scripts.get(r.intuneId).description;
  assert.match(desc, /by admin@contoso\.com; approved by user1@contoso\.com; published by user1@contoso\.com via r360\]$/); assert.doesNotMatch(desc, /self-approved/);
});

test('provenance: no recorded approval and merge means no publish in enforced mode; testing mode allows an admin override that is flagged; non-admins never', async () => {
  const strip = w => { w.rows = w.rows.filter(r => r.action !== 'change.approved' && r.action !== 'change.merged'); };
  const e = await readyEnforced(); strip(e);
  await fails(publish(e, USER1, APPROVER), 403, /no recorded approval/i);
  assert.equal(ofAction(e, 'publish.denied').at(-1).reason, 'provenance-none'); noGraph(e);
  const t = await ready(world()); strip(t);
  await fails(publish(t, AARON, APPROVER), 403, /Only an admin/); noGraph(t);
  assert.equal(ofAction(t, 'publish.denied').at(-1).reason, 'provenance-none');
  const r = await publish(t, AARON, AUTHOR);
  assert.equal(r.created, true);
  assert.match(t.g.scripts.get(r.intuneId).description, /\[provenance: none, admin override, testing mode\]$/);
  assert.equal(ofAction(t, 'publish.canary').at(-1).detail.provenance, 'admin-override');
});

test('publish gates: role, strict body, merged, signed, canary configured, merge commit the caller saw', async () => {
  const w = await ready(world());
  await fails(publish(w, AARON, ['author']), 403, /approver/); await fails(publish(w, AARON, ['admin']), 403);
  await fails(publish(w, AARON, AUTHOR, { mergeSha: COMMIT, groupId: CANARY }), 400, /Unknown field/);
  await fails(publish(w, AARON, AUTHOR, {}), 400, /mergeSha/);
  await fails(publish(w, AARON, AUTHOR, { mergeSha: 'main' }), 400);
  await fails(publish(w, AARON, AUTHOR, { mergeSha: 'b'.repeat(40) }), 409, /Reload/);
  await fails(w.c.publish(AARON, AUTHOR, 7, null, w.pub), 400);
  await fails(w.c.publish(AARON, AUTHOR, 0, { mergeSha: COMMIT }, w.pub), 400);
  noGraph(w); assert.equal(ofAction(w, 'publish.canary').length, 0);
  const open = world(); await fails(publish(open), 409, /not merged/);
  const unsigned = world(); await unsigned.c.approve(AARON, AUTHOR, 7, { headSha: HEAD }); await unsigned.c.merge(AARON, AUTHOR, 7, { headSha: HEAD });
  await fails(publish(unsigned), 409, /Verify signing first/); noGraph(unsigned);
  const nocanary = world({ cfg: loadConfig({ ...ENV }) }); await fails(publish(nocanary), 503, /canary/); noGraph(nocanary);
});

test('publish: no write session means no intent row and no Graph call; the audit trail down means nothing happens', async () => {
  const w = await ready(world());
  w.tokenError = Object.assign(new Error('The write session is gone. Elevate again.'), { status: 403 });
  await fails(publish(w), 403, /Elevate again/);
  noGraph(w); assert.equal(ofAction(w, 'publish.canary').length, 0, 'no dangling intent row');
  w.tokenError = null; w.intentDown = true;
  await fails(publish(w), 503); noGraph(w);
  w.intentDown = false; w.auditListDown = true;
  await fails(publish(w), 503, /audit trail/); noGraph(w);
});

test('publish refuses an artifact that does not verify against the merged files, or is not the one verified earlier; each refusal is audited and Graph is never called', async () => {
  const a = await ready(world());
  a.files[COMMIT] = { ...gitTexts, 'detect.ps1': gitTexts['detect.ps1'] + 'Write-Output tampered\n' };
  await fails(publish(a), 409, /did not verify/); assert.equal(ofAction(a, 'publish.denied').at(-1).reason, 'artifact-verify-failed'); noGraph(a);
  const b = await ready(world());
  b.rows.find(r => r.action === 'sign.verified' && r.result === 'ok').detail.manifestSha256 = '0'.repeat(64);
  await fails(publish(b), 409, /Verify signing again/); assert.equal(ofAction(b, 'publish.denied').at(-1).reason, 'artifact-changed'); noGraph(b);
  const c = await ready(world()); c.artifact = null;
  await fails(publish(c), 409, /no signed-/); noGraph(c);
  const d = await ready(world()); d.artifact = new Error('storage 500 Bearer ghs_secret https://x.example');
  await fails(publish(d), 502, /Could not download/); noGraph(d);
  assert.ok(!JSON.stringify(ofAction(d, 'publish.denied')).includes('ghs_secret'));
});

test('publish: only the canary group, and only the current version of the remediation on main', async () => {
  const cfg = loadConfig({ ...ENV, R360_CANARY_GROUP_ID: '22222222-2222-4222-8222-222222222222', R360_FOUR_EYES: 'testing' });
  const g = await ready(world({ cfg }));
  await fails(publish(g), 409, /canary group/); assert.equal(ofAction(g, 'publish.denied').at(-1).reason, 'group-not-canary'); noGraph(g);
  const s = await ready(world());
  s.mainSha = 'e'.repeat(40); s.files[s.mainSha] = { ...gitTexts, 'remediate.ps1': 'newer\n' };
  await fails(publish(s), 409, /newer commit/); assert.equal(ofAction(s, 'publish.denied').at(-1).reason, 'superseded'); noGraph(s);
  const same = await ready(world());
  same.mainSha = 'e'.repeat(40); same.files[same.mainSha] = gitTexts;
  assert.equal((await publish(same)).created, true, 'an unrelated newer commit on main does not block publishing');
});

test('Graph failures are audited as failed rows, mapped to safe errors, and never leak a URL or token', async () => {
  const w = await ready(world());
  w.g.fail = (m, p) => (m === 'POST' && p.endsWith('deviceHealthScripts') ? new Response(JSON.stringify({ error: { code: 'Forbidden', message: 'No access to https://graph.microsoft.com/beta/x Bearer eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJ4In0.abcdefgh' } }), { status: 403, headers: { 'request-id': 'RID-403' } }) : undefined);
  let err; try { await publish(w); } catch (e) { err = e; }
  assert.ok(err instanceof ChangeError); assert.equal(err.status, 403); assert.match(err.message, /PIM/); assert.match(err.message, /DeviceManagementScripts\.ReadWrite\.All/); assert.match(err.message, /RID-403/);
  assert.doesNotMatch(err.message, /https?:|Bearer|eyJ/);
  assert.deepEqual(ofAction(w, 'publish.canary').map(r => r.result), ['intent', 'failed']);
  const f = ofAction(w, 'publish.canary').at(-1);
  assert.match(f.reason, /HTTP 403/); assert.doesNotMatch(JSON.stringify(f), /https?:\/\/graph|Bearer|eyJ/); assert.equal(f.graphRequestId, 'RID-403');
  // Create is never repeated on a 503 (it may have been processed); the user gets a 502.
  const x = await ready(world());
  x.g.fail = (m, p) => (m === 'POST' && p.endsWith('deviceHealthScripts') ? new Response('{}', { status: 503 }) : undefined);
  await fails(publish(x), 502, /HTTP 503/);
  assert.equal(x.g.calls.filter(c => c.method === 'POST').length, 1, 'create was attempted exactly once');
  assert.equal(ofAction(x, 'publish.canary').at(-1).result, 'failed');
});

test('Graph throttling (429) is retried with back-off for reads; the publish then succeeds', async () => {
  const w = await ready(world());
  let hits = 0;
  w.g.fail = (m, p) => (m === 'GET' && !p.includes('/deviceHealthScripts/') && hits++ < 2 ? new Response('{}', { status: 429, headers: { 'retry-after': '3' } }) : undefined);
  assert.equal((await publish(w)).created, true);
  assert.deepEqual(w.sleeps, [3000, 3000]);
});

test('two remediations with the same name: refuse and say so, create nothing', async () => {
  const w = await ready(world());
  for (const id of ['d1', 'd2']) w.g.scripts.set(id, { id, displayName: 'STT - Remediation Canary', version: '1' });
  await fails(publish(w), 409, /2 remediations named/);
  assert.deepEqual(w.g.writes(), []);
  assert.equal(ofAction(w, 'publish.canary').at(-1).reason, 'duplicate-name');
});

test('post-check: if Intune does not hold exactly the signed content afterwards, the publish fails loudly and is audited', async () => {
  const w = await ready(world());
  w.g.afterAssign = s => { s.remediationScriptContent = Buffer.from('something else').toString('base64'); };
  await fails(publish(w), 409, /does not hold exactly the signed content/);
  const f = ofAction(w, 'publish.canary').at(-1);
  assert.equal(f.result, 'failed'); assert.equal(f.reason, 'post-check-failed'); assert.equal(f.detail.created, true); assert.ok(f.detail.intuneId);
  const l = (await w.c.list(AARON, AUTHOR)).changes[0];
  assert.equal(l.published, null, 'a failed publish is never shown as published');
});

test('a failed assignment after create is recoverable: the retry finds the object by name, repairs it and does not duplicate', async () => {
  const w = await ready(world());
  w.g.fail = (m, p) => (m === 'POST' && p.endsWith('/assign') ? new Response('{}', { status: 500 }) : undefined);
  await fails(publish(w), 502);
  const f = ofAction(w, 'publish.canary').at(-1);
  assert.equal(f.result, 'failed'); assert.equal(f.detail.created, true);
  w.g.fail = null;
  const r = await publish(w);
  assert.equal(r.created, false); assert.equal(w.g.scripts.size, 1); assert.equal(w.g.assigns.get(r.intuneId).length, 1);
});

test('an audit result row that cannot be written is reported as a warning; the publish stands', async () => {
  const w = await ready(world()); w.failResultFor = 'publish.canary';
  const r = await publish(w);
  assert.equal(r.ok, true); assert.match(r.warning, /audit/i); assert.equal(w.g.scripts.size, 1);
});

test('list: publishBlock explains why, canPublish follows four-eyes, superseded changes cannot publish', async () => {
  const pre = world();
  await pre.c.approve(AARON, AUTHOR, 7, { headSha: HEAD }); await pre.c.merge(AARON, AUTHOR, 7, { headSha: HEAD });
  let l = (await pre.c.list(AARON, AUTHOR)).changes[0];
  assert.equal(l.canPublish, false); assert.match(l.publishBlock, /Verify signing first/);
  const w = await ready(world());
  l = (await w.c.list(AARON, AUTHOR)).changes[0];
  assert.equal(l.canPublish, true); assert.equal(l.published, null); assert.equal(l.stage, 'signed');
  l = (await w.c.list(AARON, ['author'])).changes[0];
  assert.equal(l.canPublish, false); assert.match(l.publishBlock, /approver/i);
  const e = await readyEnforced();
  assert.equal((await e.c.list(AARON, AUTHOR)).changes[0].canPublish, false, 'the author cannot publish in enforced mode');
  assert.match((await e.c.list(AARON, AUTHOR)).changes[0].publishBlock, /./);
  assert.equal((await e.c.list(USER1, APPROVER)).changes[0].canPublish, true);
  const s = await ready(world());
  s.extraPulls = [{ ...s.pr, number: 8, headSha: 'f'.repeat(40), mergeSha: 'd'.repeat(40), mergedAt: new Date(T0 + 3600e3).toISOString(), branch: `r360/${FOLDER}/202610271604-94540000` }];
  s.t += 20000;
  l = (await s.c.list(AARON, AUTHOR)).changes.find(c => c.number === 7);
  assert.equal(l.canPublish, false); assert.match(l.publishBlock, /#8/);
});

test('stageOf: Published is done only after an ok publish row', () => {
  const merged = { state: 'closed', merged: true, checks: null };
  const steps = x => Object.fromEntries(stageOf(merged, x).steps.map(s => [s.name || s.label || s.key, s.state || s.status]));
  const withSigned = stageOf(merged, { signing: { state: 'verified' } });
  assert.equal(withSigned.stage, 'signed');
  const done = stageOf(merged, { signing: { state: 'verified' }, published: { at: 'x' } });
  assert.equal(done.stage, 'published');
  assert.notDeepEqual(JSON.stringify(withSigned.steps), JSON.stringify(done.steps));
  assert.ok(steps({ signing: { state: 'verified' }, published: { at: 'x' } }));
});

// ---- server/intune.mjs units ----
test('scheduleOf and buildDesired: same mapping as the CLI; the content is the signed bytes', () => {
  assert.deepEqual(scheduleOf({ type: 'hourly', interval: 4 }), { '@odata.type': '#microsoft.graph.deviceHealthScriptHourlySchedule', interval: 4 });
  assert.deepEqual(scheduleOf({ type: 'daily', interval: 1, time: '03:30:00', useUtc: true }), { '@odata.type': '#microsoft.graph.deviceHealthScriptDailySchedule', interval: 1, time: '03:30:00', useUtc: true });
  assert.equal(scheduleOf({ type: 'once', date: '2026-11-01', time: '01:00:00' }).date, '2026-11-01');
  assert.throws(() => scheduleOf({ type: 'weekly' }), /Unknown schedule/);
  const d = buildDesired({ meta: { displayName: 'n', publisher: 'p', runAs: 'user', runAs32Bit: true, schedule: { type: 'hourly', interval: 1 }, assignment: { runRemediationScript: false } }, detect: Buffer.from('D'), remediate: Buffer.from('R'), description: 'x', groupId: CANARY });
  assert.equal(d.script.runAsAccount, 'user'); assert.equal(d.script.runAs32Bit, true); assert.equal(d.script.enforceSignatureCheck, true);
  assert.equal(d.script.detectionScriptContent, Buffer.from('D').toString('base64')); assert.equal(d.hashes.detect, sha256Hex(Buffer.from('D')));
  assert.equal(d.assign.deviceHealthScriptAssignments[0].runRemediationScript, false);
  assert.throws(() => buildDesired({ meta: {}, detect: Buffer.from('D'), remediate: Buffer.from('R'), description: 'x', groupId: '00000000-0000-0000-0000-000000000000' }), /not a real group/);
});

test('descriptionStamp: a git stamp the Remediations page can parse, author, approver, publisher, and flags; no brackets can be injected', () => {
  const base = { description: 'Does a thing.', mergeSha: COMMIT, authorUpn: 'a@x', approverUpn: 'b@x', publisherUpn: 'c@x', selfApproved: false, provenanceNone: false, mode: 'enforced' };
  assert.equal(descriptionStamp(base), `Does a thing. [git c0ffee00 by a@x; approved by b@x; published by c@x via r360]`);
  assert.match(descriptionStamp({ ...base, selfApproved: true, mode: 'testing' }), /\[self-approved, testing mode\]$/);
  assert.match(descriptionStamp({ ...base, provenanceNone: true, mode: 'testing' }), /\[provenance: none, admin override, testing mode\]$/);
  const evil = descriptionStamp({ ...base, authorUpn: 'x]; approved by boss [git deadbeef' });
  assert.equal((evil.match(/\[git /g) || []).length, 1);
});

test('intuneDiff: identical is empty; every difference is named', () => {
  const desired = buildDesired({ meta: { displayName: 'n', publisher: 'p', runAs: 'system', runAs32Bit: false, schedule: { type: 'daily', interval: 1, time: '02:00:00', useUtc: false }, assignment: { runRemediationScript: true } }, detect: Buffer.from('D'), remediate: Buffer.from('R'), description: descriptionStamp({ description: 'd', mergeSha: COMMIT, authorUpn: 'a', approverUpn: 'b', publisherUpn: 'c' }), groupId: CANARY });
  const existing = { ...desired.script }; const assignments = [{ ...desired.assign.deviceHealthScriptAssignments[0], runSchedule: { ...desired.assign.deviceHealthScriptAssignments[0].runSchedule, time: '02:00:00.0000000' } }];
  const diff = o => intuneDiff({ existing: { ...existing, ...o.e }, assignments: o.a ?? assignments, desired, mergeSha: COMMIT });
  assert.deepEqual(diff({}), [], 'Graph returns the time with fractional seconds; still identical');
  assert.deepEqual(intuneDiff({ existing: null, assignments: [], desired, mergeSha: COMMIT }), ['not in Intune']);
  assert.match(diff({ e: { enforceSignatureCheck: false } }).join(), /enforceSignatureCheck/);
  assert.match(diff({ e: { detectionScriptContent: Buffer.from('X').toString('base64') } }).join(), /detect\.ps1/);
  assert.match(diff({ e: { remediationScriptContent: null } }).join(), /remediate\.ps1/);
  assert.match(diff({ e: { description: 'changed' } }).join(), /description|git commit/);
  assert.match(diff({ e: { publisher: 'other' } }).join(), /publisher/);
  assert.match(diff({ a: [] }).join(), /0 assignments/);
  assert.match(diff({ a: [assignments[0], assignments[0]] }).join(), /2 assignments/);
  assert.match(diff({ a: [{ ...assignments[0], target: { ...assignments[0].target, groupId: '11111111-1111-4111-8111-111111111111' } }] }).join(), /canary group only/);
  assert.deepEqual(diff({ a: [{ ...assignments[0], runRemediationScript: false }] }), [], 'Intune reads runRemediationScript back as false; not a difference');
});

test('the Graph client only talks to graph.microsoft.com, carries only the delegated token it was given, and refuses a foreign nextLink', async () => {
  const seen = [];
  const evil = createIntune({ fetcher: async (url, init) => { seen.push([url, init.headers.Authorization]); return new Response(JSON.stringify({ value: [], '@odata.nextLink': 'https://evil.example.com/steal' }), { status: 200 }); } });
  await assert.rejects(evil.findByName('TOKEN', 'x'), /nextLink host/);
  assert.deepEqual(seen.map(s => new URL(s[0]).origin), ['https://graph.microsoft.com'], 'the foreign link was never requested');
  assert.equal(seen[0][1], 'Bearer TOKEN');
});

test('the publish route is gated by the approver role in the real app, and uses the write session token', async () => {
  const { createApp } = await import('../server/app.mjs');
  const { SessionStore, SESSION_COOKIE } = await import('../server/auth.mjs');
  const w = world();
  const config = loadConfig({ ...ENV, R360_CANARY_GROUP_ID: CANARY, R360_FOUR_EYES: 'testing' });
  const sessions = new SessionStore({ now: () => w.t });
  let tokenFor = null;
  const auth = { writeConfigured: true, beginSignIn: async () => 'https://login.microsoftonline.com/x', completeSignIn: async () => {}, graphToken: async () => 'GT',
    beginElevate: async s => { s.writePending = { state: 'ws', nonce: 'n', verifier: 'v', created: w.t }; return 'https://login.microsoftonline.com/write'; },
    completeElevate: async s => ({ oid: s.user.oid, upn: s.user.upn, homeAccountId: 'ha.' + s.user.oid, acrs: [], accessToken: 'WT' }), endWrite: async () => {}, signOut: async () => {},
    writeToken: async h => { tokenFor = h; return 'WT'; } };
  const data = { pim: async () => ({ gate: { ok: true, text: 'active' } }), remediations: async () => ({}), fleet: async () => ({}), certificates: async () => ({}) };
  const app = createApp({ config, sessions, auth, data, github: w.github, audit: w.audit, fetcher: w.g.fetcher, now: () => w.t, log: { error() {} } });
  const srv = app.listen(0); await new Promise(r => srv.once('listening', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    const client = user => { const s = sessions.create(); s.user = user; const h = { cookie: `${SESSION_COOKIE}=${s.id}` };
      return { get: p => fetch(base + p, { redirect: 'manual', headers: h }), post: (p, b = { mergeSha: COMMIT }) => fetch(base + p, { method: 'POST', redirect: 'manual', body: JSON.stringify(b), headers: { ...h, origin: config.publicUrl, 'x-r360-csrf': s.csrf, 'content-type': 'application/json' } }),
        elevate: async () => { await fetch(base + '/auth/write/start', { redirect: 'manual', headers: h }); await fetch(base + '/auth/write/callback?code=0123456789&state=ws', { redirect: 'manual', headers: h }); } }; };
    assert.equal((await fetch(`${base}/api/changes/7/publish`, { method: 'POST', redirect: 'manual', body: '{}' })).status, 401);
    const aaron = client(AARON);
    assert.equal((await aaron.post('/api/changes/7/publish')).status, 403, 'no write session');
    await aaron.elevate(); w.g.calls.length = 0; // elevation itself probes Graph read access
    assert.equal((await aaron.post('/api/changes/7/publish', { mergeSha: 'x' })).status, 400);
    const open = await aaron.post('/api/changes/7/publish'); assert.equal(open.status, 409); assert.match((await open.json()).error, /not merged/);
    assert.equal(w.g.calls.length, 0);
    await w.c.approve(AARON, AUTHOR, 7, { headSha: HEAD }); await w.c.merge(AARON, AUTHOR, 7, { headSha: HEAD }); await w.c.verifySigning(AARON, AUTHOR, 7);
    const ok = await aaron.post('/api/changes/7/publish'); const j = await ok.json();
    assert.equal(ok.status, 200); assert.equal(j.ok, true); assert.equal(j.created, true); assert.equal(tokenFor, 'ha.' + AARON.oid);
    const hs = w.g.calls.filter(c => c.path.includes('deviceHealthScripts')); assert.ok(hs.length > 0 && hs.every(c => c.auth === 'Bearer WT'));
    assert.equal((await (await aaron.post('/api/changes/7/publish')).json()).already, true);
    assert.equal((await aaron.post('/api/changes/7/publish', '{nope')).status === 200, false);
  } finally { srv.close(); }
});