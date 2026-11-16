import test from 'node:test';
import assert from 'node:assert/strict';
import { parseDeployTargets, sameOwner } from '../server/deploy-targets.mjs';
import { parsePlanBlock, createGitHubApp } from '../server/github.mjs';
import { runKind, driftOf, outcomeOf, mergeBlock, planRunFor, createDeployments, DEPLOY_FOUR_EYES } from '../server/deployments.mjs';
import { buildAuditRow, toCsv } from '../server/audit.mjs';
import { createApp } from '../server/app.mjs';
import { SessionStore, SESSION_COOKIE } from '../server/auth.mjs';
import { loadConfig, publicSettings } from '../server/config.mjs';
import { ENV } from './fixtures.mjs';

const TENANT = '0f0f0f0f-1111-4222-8333-444444444444';
const TARGET = { id: 'f360-lab', name: 'Federation 360 lab', repo: 'your-org/f-360', branch: 'main', workflow: 'lab.yml', environment: 'lab', tenantId: TENANT, path: 'lab/terraform' };
const DOC = JSON.stringify({ version: 1, targets: [TARGET] });
const config = loadConfig({ ...ENV, R360_DEPLOY_TARGETS: DOC });
const HEAD = 'a'.repeat(40), OLD = 'b'.repeat(40), MERGE = 'c'.repeat(40);
const AARON = { oid: '94540000-0000-4000-8000-000000000001', upn: 'aaron@contoso.example', name: 'Aaron' };
const VIEWER = { oid: '94540000-0000-4000-8000-000000000002', upn: 'viewer@contoso.example', name: 'Viewer' };
const T0 = Date.parse('2026-11-12T06:00:00Z');
const iso = ms => new Date(ms).toISOString();

// ---- R360_DEPLOY_TARGETS ----
test('deploy targets: a valid document gives frozen targets with defaults', () => {
  const [t] = parseDeployTargets(JSON.stringify({ version: 1, targets: [{ id: 'f360-lab', repo: 'your-org/f-360', workflow: 'lab.yml', environment: 'lab' }] }), { owner: 'your-org' });
  assert.equal(t.branch, 'main'); assert.equal(t.name, 'f360-lab'); assert.equal(t.tenantId, null); assert.ok(Object.isFrozen(t));
  assert.deepEqual(parseDeployTargets(DOC, { owner: 'your-org' })[0], { ...TARGET });
});

test('deploy targets: fail closed on anything unexpected', () => {
  const bad = (targets, re, extra = {}) => assert.throws(() => parseDeployTargets(JSON.stringify({ version: 1, targets, ...extra }), { owner: 'your-org' }), re);
  assert.throws(() => parseDeployTargets('{nope'), /not valid JSON/);
  assert.throws(() => parseDeployTargets(JSON.stringify({ version: 2, targets: [] })), /version: 1/);
  bad([{ ...TARGET, repo: 'someoneelse/f-360' }], /must belong to your-org/);
  bad([{ ...TARGET, secret: 'x' }], /unknown field/);
  bad([TARGET, TARGET], /duplicate id/);
  bad([{ ...TARGET, workflow: '../evil.yml' }], /workflow/);
  bad([{ ...TARGET, workflow: 'deploy.sh' }], /workflow/);
  bad([{ ...TARGET, branch: '../main' }], /branch/);
  bad([{ ...TARGET, tenantId: 'nope' }], /GUID/);
  bad([{ ...TARGET, id: 'Has Caps' }], /needs an id/);
  bad([{ ...TARGET, environment: '' }], /environment/);
  bad(Array.from({ length: 21 }, (_, i) => ({ ...TARGET, id: `t-${i}` })), /at most 20/);
  assert.equal(sameOwner('your-org/f-360', 'your-org/remediations'), true);
  // in config: JSON or base64 JSON; invalid stops the app; none means an empty lane
  assert.equal(loadConfig({ ...ENV, R360_DEPLOY_TARGETS: DOC }).deployTargets[0].repo, 'your-org/f-360');
  assert.equal(loadConfig({ ...ENV, R360_DEPLOY_TARGETS: Buffer.from(DOC).toString('base64') }).deployTargets[0].id, 'f360-lab');
  assert.deepEqual(loadConfig(ENV).deployTargets, []);
  assert.throws(() => loadConfig({ ...ENV, R360_DEPLOY_TARGETS: JSON.stringify({ version: 1, targets: [{ ...TARGET, repo: 'evil/x' }] }) }), /must belong to your-org/);
  assert.throws(() => loadConfig({ ...ENV, R360_DEPLOY_TARGETS: 'not json!' }), /JSON or base64/);
  assert.match(publicSettings(loadConfig({ ...ENV, R360_DEPLOY_TARGETS: DOC })).deployTargets, /f360-lab \(your-org\/f-360 lab.yml, environment lab\)/);
  assert.equal(sameOwner('evil/f-360', 'your-org/remediations'), false);
});

// ---- pure helpers ----
test('plan comment line: parsed only when well formed', () => {
  const ok = parsePlanBlock(`x\n<!-- r360:plan {"v":1,"sha":"${HEAD}","add":2,"change":1,"destroy":0,"noChanges":false,"exitCode":2} -->\nmore`);
  assert.deepEqual(ok, { sha: HEAD, add: 2, change: 1, destroy: 0, noChanges: false, exitCode: 2 });
  assert.equal(parsePlanBlock('<!-- r360:plan {"v":1,"sha":"short"} -->'), null);
  assert.equal(parsePlanBlock('<!-- r360:plan {nope} -->'), null);
  assert.equal(parsePlanBlock('no marker'), null);
  assert.equal(parsePlanBlock(`<!-- r360:plan {"v":1,"sha":"${HEAD}","add":-1} -->`).add, null);
});

test('run kind, outcome and drift', () => {
  assert.equal(runKind({ title: 'r360:drift nightly', event: 'workflow_dispatch' }), 'drift');
  assert.equal(runKind({ title: 'x', event: 'pull_request' }), 'plan');
  assert.equal(runKind({ title: 'x', event: 'push' }), 'apply');
  assert.equal(runKind({ title: 'x', event: 'schedule' }), 'drift');
  assert.equal(runKind({ title: 'x', event: 'workflow_dispatch' }), 'manual');
  assert.equal(outcomeOf({ status: 'waiting' }), 'waiting');
  assert.equal(outcomeOf({ status: 'in_progress' }), 'running');
  assert.equal(outcomeOf({ status: 'completed', conclusion: 'success' }), 'succeeded');
  assert.equal(outcomeOf({ status: 'completed', conclusion: 'timed_out' }), 'failed');
  const done = c => ({ status: 'completed', conclusion: c });
  assert.equal(driftOf(null), 'never');
  assert.equal(driftOf({ status: 'queued' }), 'running');
  assert.equal(driftOf(done('success')), 'clean');
  assert.equal(driftOf(done('failure'), [{ steps: [{ name: 'Plan', conclusion: 'success' }, { name: 'Drift detected', conclusion: 'failure' }] }]), 'drift');
  assert.equal(driftOf(done('failure'), [{ steps: [{ name: 'Plan', conclusion: 'failure' }, { name: 'Drift detected', conclusion: 'skipped' }] }]), 'error');
  assert.equal(driftOf(done('failure'), null), 'error', 'unknown jobs are an error, never "clean"');
});

test('mergeBlock: every precondition, and the plan must be for the current head', () => {
  const pr = { state: 'open', merged: false, draft: false, base: 'main', sameRepo: true, headSha: HEAD };
  const planRun = { status: 'completed', conclusion: 'success' };
  const plan = { sha: HEAD, add: 1, change: 0, destroy: 0 };
  assert.equal(mergeBlock({ target: TARGET, pr, planRun, plan }), null);
  assert.match(mergeBlock({ target: TARGET, pr: { ...pr, state: 'closed' }, planRun, plan }), /not open/);
  assert.match(mergeBlock({ target: TARGET, pr: { ...pr, draft: true }, planRun, plan }), /draft/);
  assert.match(mergeBlock({ target: TARGET, pr: { ...pr, base: 'dev' }, planRun, plan }), /does not target main/);
  assert.match(mergeBlock({ target: TARGET, pr: { ...pr, sameRepo: false }, planRun, plan }), /forks/);
  assert.match(mergeBlock({ target: TARGET, pr, planRun: null, plan }), /No plan/);
  assert.match(mergeBlock({ target: TARGET, pr, planRun: { status: 'in_progress' }, plan }), /still running/);
  assert.match(mergeBlock({ target: TARGET, pr, planRun: { status: 'completed', conclusion: 'failure' }, plan }), /plan failed/);
  assert.match(mergeBlock({ target: TARGET, pr, planRun, plan: null }), /comment is missing/);
  assert.match(mergeBlock({ target: TARGET, pr, planRun, plan: { ...plan, sha: OLD } }), /older commit/);
  const runs = [{ title: 'r360:plan', event: 'pull_request', headSha: OLD, createdAt: iso(T0 + 1) }, { title: 'r360:plan', event: 'pull_request', headSha: HEAD, createdAt: iso(T0), id: 2 }];
  assert.equal(planRunFor(runs, pr).id, 2);
});

test('audit rows keep runId, and the CSV has a Run column', () => {
  const row = buildAuditRow({ actorOid: 'github-actions', action: 'deploy.run', runId: '42.1', target: 'deploy/f360-lab', token: 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.sig' }, { now: T0, id: 'x' });
  assert.equal(row.runId, '42.1'); assert.equal(row.token, undefined);
  assert.match(toCsv([row]).split('\r\n')[0], /,runId,/);
});

// ---- the deployments service with a fake GitHub and audit ----
function world(opts = {}) {
  const w = { t: T0, audit: [], merges: [], dispatches: [], jobCalls: 0, auditDown: false, mergeFails: null, ...opts };
  w.runs = opts.runs || [
    { id: 11, title: 'r360:plan', event: 'pull_request', status: 'completed', conclusion: 'success', headSha: HEAD, url: 'https://github.com/your-org/f-360/actions/runs/11', createdAt: iso(T0 - 6e5), updatedAt: iso(T0 - 5e5), startedAt: iso(T0 - 6e5), actor: 'your-org', attempt: 1, pullNumbers: [5] },
    { id: 10, title: 'r360:drift', event: 'schedule', status: 'completed', conclusion: 'failure', headSha: OLD, url: 'https://github.com/your-org/f-360/actions/runs/10', createdAt: iso(T0 - 9e6), updatedAt: iso(T0 - 8e6), startedAt: iso(T0 - 9e6), actor: 'your-org', attempt: 1, pullNumbers: [] },
    { id: 9, title: 'r360:apply', event: 'push', status: 'completed', conclusion: 'success', headSha: OLD, url: 'https://github.com/your-org/f-360/actions/runs/9', createdAt: iso(T0 - 2e7), updatedAt: iso(T0 - 1.9e7), startedAt: iso(T0 - 2e7), actor: 'your-org', attempt: 1, pullNumbers: [] },
  ];
  w.pull = { number: 5, state: 'open', merged: false, draft: false, title: 'Add SCIM test app', url: 'https://github.com/your-org/f-360/pull/5', author: 'your-org', branch: 'scim', headSha: HEAD, headRepo: 'your-org/f-360', base: 'main', sameRepo: true, updatedAt: iso(T0), ...(opts.pull || {}) };
  w.plan = opts.plan === undefined ? { sha: HEAD, add: 3, change: 0, destroy: 0, noChanges: false, url: 'https://github.com/your-org/f-360/pull/5#issuecomment-1' } : opts.plan;
  w.github = {
    catalog: async () => ({ approvers: [{ entraObjectId: AARON.oid, upn: AARON.upn, roles: ['author', 'approver', 'admin'] }, { entraObjectId: VIEWER.oid, upn: VIEWER.upn, roles: ['author'] }] }),
    deployRuns: async () => w.runs,
    deployPulls: async () => [w.pull],
    deployPull: async () => w.pull,
    deployPlanComment: async () => w.plan,
    deployRunJobs: async () => { w.jobCalls++; return [{ name: 'plan', steps: [{ name: 'Plan', conclusion: 'success' }, { name: 'Drift detected', conclusion: 'failure' }] }]; },
    mergeDeployPull: async a => { if (w.mergeFails) throw w.mergeFails; w.merges.push(a); return { mergeSha: MERGE, githubRequestId: 'GH-1' }; },
    dispatchDeployWorkflow: async a => { w.dispatches.push(a); return { githubRequestId: 'GH-2' }; },
  };
  w.auditApi = {
    record: async e => { if (w.auditDown) throw new Error('down'); const r = buildAuditRow(e, { now: w.t }); w.audit.push(r); return r; },
    list: async ({ actions }) => ({ rows: w.audit.filter(r => !actions || actions.includes(r.action)), truncated: false }),
  };
  w.svc = createDeployments({ config: opts.config || config, github: w.github, audit: w.auditApi, now: () => w.t, log: { error() {} } });
  return w;
}
const ofAction = (w, a) => w.audit.filter(r => r.action === a);

test('list: target status, open change with its plan, drift from the failed step, and each finished run audited once', async () => {
  const w = world();
  const d = await w.svc.list();
  assert.equal(d.fourEyes, 'off');
  const [t] = d.targets;
  assert.equal(t.error, null);
  assert.deepEqual(t.lastApply.state, 'succeeded');
  assert.equal(t.drift.state, 'drift');
  assert.equal(t.changes.length, 1);
  assert.equal(t.changes[0].canMerge, true);
  assert.deepEqual(t.changes[0].plan.counts, { add: 3, change: 0, destroy: 0, noChanges: false });
  assert.deepEqual(t.runs.map(r => r.kind), ['plan', 'drift', 'apply']);
  const runs = ofAction(w, 'deploy.run');
  assert.deepEqual(runs.map(r => r.runId).sort(), ['10.1', '11.1', '9.1']);
  assert.ok(runs.every(r => r.actorOid === 'github-actions' && r.target === 'deploy/f360-lab' && r.mode === DEPLOY_FOUR_EYES));
  assert.equal(runs.find(r => r.runId === '10.1').result, 'failure');
  assert.match(runs.find(r => r.runId === '10.1').detail, /"drift":"drift"/);
  // after the cache expires, nothing is recorded twice; a re-run attempt is a new row
  w.t += 60000;
  w.runs = [{ ...w.runs[0], attempt: 2 }, ...w.runs.slice(1)];
  await w.svc.list();
  assert.deepEqual(ofAction(w, 'deploy.run').map(r => r.runId).sort(), ['10.1', '11.1', '11.2', '9.1']);
});

test('list: running runs are not audited yet; no targets gives an empty lane', async () => {
  const w = world({ runs: [{ id: 1, title: 'r360:apply', event: 'push', status: 'waiting', conclusion: null, headSha: HEAD, url: 'https://github.com/x', createdAt: iso(T0), updatedAt: iso(T0), startedAt: iso(T0), actor: 'a', attempt: 1, pullNumbers: [] }] });
  const [t] = (await w.svc.list()).targets;
  assert.equal(t.lastApply.state, 'waiting');
  assert.equal(t.changes.length, 0, 'a pull request the workflow never planned is not a deployment change');
  assert.equal(ofAction(w, 'deploy.run').length, 0);
  const b = world({ config: loadConfig(ENV) });
  assert.deepEqual((await b.svc.list()).targets, []);
});

test('list: a target GitHub cannot read shows an error instead of failing the page', async () => {
  const w = world();
  w.github.deployRuns = async () => { throw Object.assign(new Error('nope'), { permission: true }); };
  const [t] = (await w.svc.list()).targets;
  assert.match(t.error, /cannot read this repository/);
});

test('merge: audited intent then ok, squash pinned to the planned head, no second person needed', async () => {
  const w = world();
  const r = await w.svc.merge(AARON, ['approver'], 'f360-lab', 5, { headSha: HEAD });
  assert.equal(r.ok, true); assert.equal(r.mergeSha, MERGE);
  assert.equal(w.merges.length, 1);
  assert.equal(w.merges[0].sha, HEAD); assert.equal(w.merges[0].repo, 'your-org/f-360');
  assert.match(w.merges[0].message, /four-eyes off/);
  assert.deepEqual(ofAction(w, 'deploy.merged').map(x => x.result), ['intent', 'ok']);
  const ok = ofAction(w, 'deploy.merged')[1];
  assert.equal(ok.prNumber, 5); assert.equal(ok.gitSha, HEAD); assert.equal(ok.runId, '11.1'); assert.equal(ok.mode, 'off');
});

test('merge: refused without touching GitHub when anything is off', async () => {
  const cases = [
    [world(), VIEWER, ['author'], { headSha: HEAD }, 403, /role does not allow/],
    [world(), AARON, ['approver'], { headSha: OLD }, 409, /changed after you loaded it/],
    [world(), AARON, ['approver'], { headSha: HEAD, extra: 1 }, 400, /Unknown field/],
    [world(), AARON, ['approver'], { headSha: 'short' }, 400, /headSha/],
    [world({ plan: { sha: OLD, add: 1, change: 0, destroy: 0 } }), AARON, ['approver'], { headSha: HEAD }, 409, /older commit/],
    [world({ plan: null }), AARON, ['approver'], { headSha: HEAD }, 409, /comment is missing/],
    [world({ pull: { sameRepo: false } }), AARON, ['approver'], { headSha: HEAD }, 409, /forks/],
    [world({ auditDown: true }), AARON, ['approver'], { headSha: HEAD }, 503, /audit trail is unavailable/],
  ];
  for (const [w, u, roles, b, status, re] of cases) {
    await assert.rejects(w.svc.merge(u, roles, 'f360-lab', 5, b), e => e.status === status && re.test(e.message), `${status} ${re}`);
    assert.equal(w.merges.length, 0);
  }
  await assert.rejects(world().svc.merge(AARON, ['approver'], 'nope', 5, { headSha: HEAD }), e => e.status === 404);
});

test('merge: a GitHub refusal is audited as failed and explained', async () => {
  const w = world({ mergeFails: Object.assign(new Error('GitHub PUT /x failed: HTTP 405 Base branch was modified'), { status: 405, githubRequestId: 'GH-9' }) });
  await assert.rejects(w.svc.merge(AARON, ['admin'], 'f360-lab', 5, { headSha: HEAD }), e => e.status === 409 && /Base branch was modified/.test(e.message));
  assert.deepEqual(ofAction(w, 'deploy.merged').map(x => x.result), ['intent', 'failed']);
});

test('dispatch: plan and drift only, on the target branch, audited', async () => {
  const w = world();
  const r = await w.svc.dispatch(VIEWER, ['author'], 'f360-lab', { mode: 'drift' });
  assert.equal(r.ok, true);
  assert.deepEqual(w.dispatches, [{ repo: 'your-org/f-360', workflow: 'lab.yml', ref: 'main', inputs: { mode: 'drift' } }]);
  assert.deepEqual(ofAction(w, 'deploy.dispatched').map(x => x.result), ['intent', 'ok']);
  await assert.rejects(w.svc.dispatch(AARON, ['admin'], 'f360-lab', { mode: 'apply' }), e => e.status === 400, 'apply runs only from a merge');
  await assert.rejects(w.svc.dispatch(AARON, [], 'f360-lab', { mode: 'plan' }), e => e.status === 403);
  assert.equal(w.dispatches.length, 1);
});

// ---- github.mjs: tokens are narrowed to the one target repository ----
test('github: deploy reads and writes mint tokens for the target repository only, and refuse other owners', async () => {
  const mints = [], calls = [];
  const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { 'x-github-request-id': 'GH-REQ' } });
  const fetcher = async (url, init = {}) => {
    const u = String(url), body = init.body ? JSON.parse(init.body) : undefined, method = init.method || 'GET';
    calls.push({ method, u, body });
    if (u.includes('vault.azure.net')) return json({ value: 'c2ln' });
    if (u.endsWith('/access_tokens')) { mints.push(body); return json({ token: `tok-${mints.length}`, expires_at: new Date(Date.now() + 3600e3).toISOString() }); }
    if (u.includes('/actions/workflows/lab.yml/runs')) return json({ workflow_runs: [{ id: 1, display_title: 'r360:plan', event: 'pull_request', status: 'completed', conclusion: 'success', head_sha: HEAD, html_url: 'https://github.com/r', created_at: iso(T0), updated_at: iso(T0), pull_requests: [{ number: 5 }], triggering_actor: { login: 'your-org' } }] });
    if (u.endsWith('/issues/5/comments?per_page=100')) return json([{ user: { login: 'someone', type: 'User' }, body: `<!-- r360:plan {"v":1,"sha":"${OLD}","add":9} -->` }, { user: { login: 'github-actions[bot]', type: 'Bot' }, body: `<!-- r360:plan {"v":1,"sha":"${HEAD}","add":1,"change":0,"destroy":0} -->`, html_url: 'https://github.com/c' }]);
    if (u.endsWith('/pulls/5') && method === 'GET') return json({ number: 5, state: 'open', head: { sha: HEAD, ref: 'b', repo: { full_name: 'your-org/f-360' } }, base: { ref: 'main' } });
    if (u.endsWith('/pulls/5/merge')) return json({ merged: true, sha: MERGE });
    if (u.endsWith('/dispatches')) return new Response(null, { status: 204 });
    throw new Error(`unexpected ${method} ${u}`);
  };
  const gh = createGitHubApp({ config, miToken: async () => 'VT', fetcher });
  const runs = await gh.deployRuns('your-org/f-360', 'lab.yml');
  assert.deepEqual(runs[0].pullNumbers, [5]); assert.equal(runs[0].title, 'r360:plan'); assert.equal(runs[0].actor, 'your-org');
  const plan = await gh.deployPlanComment('your-org/f-360', 5);
  assert.equal(plan.sha, HEAD, 'only the bot comment counts');
  assert.deepEqual(mints[0], { repositories: ['f-360'], permissions: { actions: 'read', contents: 'read', metadata: 'read', pull_requests: 'read', checks: 'read' } });
  assert.equal(mints.length, 1, 'the read token is cached');
  const m = await gh.mergeDeployPull({ repo: 'your-org/f-360', number: 5, sha: HEAD, title: 't', message: 'm' });
  assert.equal(m.mergeSha, MERGE);
  assert.deepEqual(mints[1], { repositories: ['f-360'], permissions: { contents: 'write', pull_requests: 'write', metadata: 'read' } });
  assert.deepEqual(calls.find(c => c.u.endsWith('/merge')).body.sha, HEAD);
  await gh.dispatchDeployWorkflow({ repo: 'your-org/f-360', workflow: 'lab.yml', ref: 'main', inputs: { mode: 'plan' } });
  assert.deepEqual(mints[2], { repositories: ['f-360'], permissions: { actions: 'write', metadata: 'read' } });
  await assert.rejects(gh.deployRuns('evil/f-360', 'lab.yml'), /Refusing repository/);
  await assert.rejects(gh.deployRuns('your-org/f-360', '../x.yml'), /Refusing workflow/);
  await assert.rejects(gh.mergeDeployPull({ repo: 'your-org/f-360', number: 5, sha: OLD, title: 't', message: 'm' }), e => e.status === 409);
  assert.equal(mints.length, 4, 'no token was minted for the refused repository');
});

// ---- HTTP: the routes need sign-in, a write session, the right role and CSRF ----
test('routes: GET is open to signed-in operators; merge and dispatch need a write session, a role and CSRF', async () => {
  const w = world();
  const sessions = new SessionStore({ now: () => w.t });
  const auth = { writeConfigured: true, beginSignIn: async () => 'https://login.microsoftonline.com/x', completeSignIn: async () => {}, graphToken: async () => 'GT',
    beginElevate: async s => { s.writePending = { state: 'ws', nonce: 'n', verifier: 'v', created: w.t }; return 'https://login.microsoftonline.com/write'; },
    completeElevate: async s => ({ oid: s.user.oid, upn: s.user.upn, homeAccountId: 'ha.' + s.user.oid, acrs: [], accessToken: 'WT' }), endWrite: async () => {}, signOut: async () => {}, writeToken: async () => 'WT' };
  const data = { pim: async () => ({ gate: { ok: true, text: 'active' } }) };
  const fetcher = async () => new Response('{}', { status: 200, headers: { 'request-id': 'g' } });
  const app = createApp({ config, sessions, auth, data, github: w.github, audit: w.auditApi, fetcher, now: () => w.t, log: { error() {} } });
  const srv = app.listen(0); await new Promise(r => srv.once('listening', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  const client = user => { const s = sessions.create(); s.user = user; const h = { cookie: `${SESSION_COOKIE}=${s.id}` };
    return { get: p => fetch(base + p, { headers: h }),
      post: (p, b, extra = {}) => fetch(base + p, { method: 'POST', body: JSON.stringify(b), headers: { ...h, origin: config.publicUrl, 'x-r360-csrf': s.csrf, 'content-type': 'application/json', ...extra } }),
      elevate: async () => { await fetch(base + '/auth/write/start', { redirect: 'manual', headers: h }); await fetch(base + '/auth/write/callback?code=0123456789&state=ws', { redirect: 'manual', headers: h }); } }; };
  try {
    assert.equal((await fetch(`${base}/api/deployments`)).status, 401);
    const viewer = client(VIEWER), aaron = client(AARON);
    const g = await viewer.get('/api/deployments'); assert.equal(g.status, 200); assert.equal((await g.json()).targets[0].id, 'f360-lab');
    const mergePath = '/api/deployments/f360-lab/pulls/5/merge';
    assert.equal((await aaron.post(mergePath, { headSha: HEAD })).status, 403, 'no write session');
    await viewer.elevate();
    assert.equal((await viewer.post(mergePath, { headSha: HEAD })).status, 403, 'an author cannot merge');
    assert.equal((await viewer.post('/api/deployments/f360-lab/dispatch', { mode: 'plan' })).status, 200, 'an author can start a plan');
    await aaron.elevate();
    assert.equal((await aaron.post(mergePath, { headSha: HEAD }, { 'x-r360-csrf': 'nope' })).status, 403, 'bad CSRF');
    assert.equal((await aaron.post('/api/deployments/BAD..ID/pulls/5/merge', { headSha: HEAD })).status, 404);
    assert.equal(w.merges.length, 0);
    const ok = await aaron.post(mergePath, { headSha: HEAD }); assert.equal(ok.status, 200); assert.equal((await ok.json()).mergeSha, MERGE);
    assert.equal(w.merges.length, 1);
  } finally { srv.close(); }
});
