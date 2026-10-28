import test from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../server/app.mjs';
import { SessionStore, SESSION_COOKIE } from '../server/auth.mjs';
import { machineBlock } from '../server/changes.mjs';
import { loadConfig } from '../server/config.mjs';
import { ENV } from './fixtures.mjs';

const AARON = { oid: '94540000-0000-4000-8000-0000000000c3', upn: 'admin@contoso.com', name: 'Aaron' };
const USER1 = { oid: '0d000000-0000-4000-8000-0000000000c4', upn: 'user1@contoso.com', name: 'User One' };
const CANARY = '90000000-0000-4000-8000-0000000000c2';
const HEAD = 'a'.repeat(40), MERGE = 'c'.repeat(40);
const GREEN = [{ name: 'PSScriptAnalyzer', status: 'completed', conclusion: 'success' }];

function world({ mode = 'testing', roles = { [AARON.oid]: ['author', 'approver'], [USER1.oid]: ['approver'] } } = {}) {
  const w = { t: Date.parse('2026-10-27T15:04:00Z'), seq: 0, events: [], writes: [], who: AARON, roles, mode };
  w.config = loadConfig({ ...ENV, R360_CANARY_GROUP_ID: CANARY, R360_FOUR_EYES: mode });
  w.pr = { number: 7, state: 'open', merged: false, draft: false, title: 't', url: 'https://github.com/your-org/remediations/pull/7', branch: 'r360/Stt-Http/202610271504-94540000', headSha: HEAD, headRepo: 'your-org/remediations', base: 'main', body: machineBlock({ folder: 'Stt-Http', authorOid: AARON.oid }), checks: GREEN, mergeSha: null, mergedAt: null, createdAt: 'c', updatedAt: 'u' };
  w.audit = { record: async e => { w.events.push({ ...e, at: new Date(w.t + (++w.seq) * 1000).toISOString() }); return e; }, list: async () => ({ rows: [...w.events].reverse(), truncated: false }) };
  w.events.push({ action: 'change.proposed', result: 'ok', actorOid: AARON.oid, target: 'remediations/Stt-Http', prNumber: 7, gitSha: HEAD, at: new Date(w.t).toISOString() });
  w.auth = {
    writeConfigured: true, beginSignIn: async () => 'https://login.microsoftonline.com/x', completeSignIn: async () => {}, graphToken: async () => 'GT',
    beginElevate: async s => { s.writePending = { state: 'ws', nonce: 'n', verifier: 'v', created: w.t }; return 'https://login.microsoftonline.com/write'; },
    completeElevate: async s => ({ oid: s.user.oid, upn: s.user.upn, homeAccountId: 'ha.' + s.user.oid, acrs: ['c1'], accessToken: 'WT' }), endWrite: async () => {}, signOut: async () => {},
  };
  w.github = {
    catalog: async () => ({ sha: 'm', items: [], approvers: Object.entries(w.roles).map(([entraObjectId, r]) => ({ entraObjectId, upn: entraObjectId === AARON.oid ? AARON.upn : USER1.upn, roles: r })) }),
    listPulls: async () => [{ ...w.pr }], getPull: async n => (n === 7 ? { ...w.pr } : undefined),
    getChecks: async () => w.pr.checks, behindBy: async () => 0, unresolvedThreads: async () => 0,
    commentOnPull: async a => { w.writes.push('comment'); return { id: 1, githubRequestId: 'RC' }; },
    rejectChange: async () => { w.writes.push('reject'); w.pr.state = 'closed'; return { githubRequestId: 'RR' }; },
    mergeChange: async a => { w.writes.push('merge'); if (w.mergeThrows) throw new Error(w.mergeThrows); w.pr.merged = true; w.pr.state = 'closed'; w.pr.mergeSha = MERGE; return { mergeSha: MERGE, branchDeleted: true, githubRequestId: 'RM' }; },
    updateBranch: async () => { throw new Error('not expected'); }, readChangeFiles: async () => ({ raw: {} }), signingRun: async () => null, downloadSignedArtifact: async () => null,
  };
  w.data = { pim: async () => ({ gate: { ok: true, text: 'active' } }), remediations: async () => ({}), fleet: async () => ({}), certificates: async () => ({}) };
  w.fetcher = async () => new Response('{}', { status: 200 });
  w.sessions = new SessionStore({ now: () => w.t });
  return w;
}
async function run(w, fn) {
  const app = createApp({ config: w.config, sessions: w.sessions, auth: w.auth, data: w.data, github: w.github, audit: w.audit, fetcher: w.fetcher, now: () => w.t, log: { error() {} } });
  const srv = app.listen(0); await new Promise(r => srv.once('listening', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  const client = user => {
    const s = w.sessions.create(); s.user = user;
    const headers = { cookie: `${SESSION_COOKIE}=${s.id}` };
    const get = p => fetch(base + p, { redirect: 'manual', headers });
    const post = (p, body = { headSha: HEAD }, over = {}) => fetch(base + p, { method: 'POST', redirect: 'manual', body: typeof body === 'string' ? body : JSON.stringify(body), headers: { ...headers, origin: w.config.publicUrl, 'x-r360-csrf': s.csrf, 'content-type': 'application/json', ...over } });
    const elevate = async () => { await get('/auth/write/start'); return get('/auth/write/callback?code=0123456789&state=ws'); };
    return { s, get, post, elevate };
  };
  try { await fn({ base, aaron: client(AARON), user1: client(USER1) }); } finally { srv.close(); }
}
const rows = (w, a) => w.events.filter(e => e.action === a).map(e => e.result);

test('approve, reject, merge need: a session, a live write session, the approver role, and CSRF', async () => {
  const w = world({ roles: { [AARON.oid]: ['author'], [USER1.oid]: ['approver'] } });
  await run(w, async ({ base, aaron, user1 }) => {
    for (const p of ['approve', 'reject', 'merge', 'verify-signing', 'publish']) assert.equal((await fetch(`${base}/api/changes/7/${p}`, { method: 'POST', redirect: 'manual', body: '{}' })).status, 401, `no session ${p}`);
    for (const p of ['approve', 'reject', 'merge', 'verify-signing', 'publish']) assert.equal((await user1.post(`/api/changes/7/${p}`)).status, 403, `no write session ${p}`);
    await aaron.elevate(); await user1.elevate();
    // The author-only user cannot approve, reject or merge even with a write session.
    for (const p of ['approve', 'reject', 'merge', 'publish']) assert.equal((await aaron.post(`/api/changes/7/${p}`, { headSha: HEAD, mergeSha: MERGE, reason: 'because' })).status, 403, `author-only ${p}`);
    assert.deepEqual(w.writes, []);
    for (const [over, code] of [[{ origin: 'https://evil.example.com' }, 'origin'], [{ 'x-r360-csrf': 'nope' }, 'csrf'], [{ 'content-type': 'text/plain' }, 'content-type']]) {
      const r = await user1.post('/api/changes/7/approve', { headSha: HEAD }, over); assert.equal(r.status, 403); assert.equal((await r.json()).code, code);
    }
    assert.deepEqual(w.writes, []);
    assert.equal((await user1.post('/api/changes/7/approve')).status, 200, 'the approver role is enough');
    assert.equal((await user1.post('/api/changes/abc/approve')).status, 400);
    assert.equal((await user1.post('/api/changes/7/approve', { headSha: HEAD, extra: 1 })).status, 400);
    assert.equal((await user1.post('/api/changes/7/approve', '{nope')).status, 400);
  });
});

test('testing mode over HTTP: Aaron approves and merges his own change, everything audited; the list says self-approved', async () => {
  const w = world();
  await run(w, async ({ aaron }) => {
    await aaron.elevate();
    const me = await (await aaron.get('/api/me')).json();
    assert.equal(me.fourEyes, 'testing');
    let a = await aaron.post('/api/changes/7/approve'); const aj = await a.json();
    assert.equal(a.status, 200); assert.equal(aj.selfApproved, true);
    const l = await (await aaron.get('/api/changes')).json();
    assert.equal(l.fourEyes, 'testing'); assert.equal(l.changes[0].approval.selfApproved, true); assert.equal(l.changes[0].canMerge, true);
    const m = await aaron.post('/api/changes/7/merge'); const mj = await m.json();
    assert.equal(m.status, 200); assert.equal(mj.merged, true); assert.equal(mj.mergeSha, MERGE);
    assert.deepEqual(rows(w, 'change.approved'), ['intent', 'ok']); assert.deepEqual(rows(w, 'change.merged'), ['intent', 'ok']);
    assert.deepEqual(w.writes, ['comment', 'merge']);
    assert.equal((await (await aaron.post('/api/changes/7/merge')).json()).already, true);
  });
});

test('enforced mode over HTTP: Aaron cannot approve his own change (403, audited); user1 approves, then Aaron merges', async () => {
  const w = world({ mode: 'enforced' });
  await run(w, async ({ aaron, user1 }) => {
    await aaron.elevate(); await user1.elevate();
    const r = await aaron.post('/api/changes/7/approve');
    assert.equal(r.status, 403); assert.match((await r.json()).error, /different approver/);
    assert.deepEqual(rows(w, 'change.approval.denied'), ['denied']);
    assert.equal((await aaron.post('/api/changes/7/merge')).status, 409);
    assert.deepEqual(w.writes, []);
    const al = await (await aaron.get('/api/changes')).json();
    assert.equal(al.changes[0].canApprove, false); assert.match(al.changes[0].approveBlock, /different approver|authored/);
    const ul = await (await user1.get('/api/changes')).json();
    assert.equal(ul.changes[0].canApprove, true); assert.equal(ul.changes[0].canEdit, false);
    const u = await user1.post('/api/changes/7/approve'); assert.equal(u.status, 200); assert.equal((await u.json()).selfApproved, false);
    const m = await aaron.post('/api/changes/7/merge'); assert.equal(m.status, 200); assert.equal((await m.json()).selfApproved, false);
    assert.deepEqual(w.writes, ['comment', 'merge']);
  });
});

test('reject over HTTP needs a reason; GitHub internals never reach the browser', async () => {
  const w = world();
  await run(w, async ({ aaron }) => {
    await aaron.elevate();
    assert.equal((await aaron.post('/api/changes/7/reject', { headSha: HEAD })).status, 400);
    const r = await aaron.post('/api/changes/7/reject', { headSha: HEAD, reason: 'Detection is too broad' });
    assert.equal(r.status, 200); assert.deepEqual(rows(w, 'change.rejected'), ['intent', 'ok']);
  });
  const w2 = world();
  await run(w2, async ({ aaron }) => {
    await aaron.elevate();
    await aaron.post('/api/changes/7/approve');
    w2.mergeThrows = 'secret internals Bearer ghs_abc https://api.github.com/x';
    const r = await aaron.post('/api/changes/7/merge'); const t = await r.text();
    assert.ok(r.status >= 400 && r.status < 600);
    assert.doesNotMatch(t, /ghs_|Bearer|api\.github\.com/);
    assert.deepEqual(rows(w2, 'change.merged'), ['intent', 'failed']);
  });
});
