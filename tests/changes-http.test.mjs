import test from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../server/app.mjs';
import { SessionStore, SESSION_COOKIE } from '../server/auth.mjs';
import { machineBlock } from '../server/changes.mjs';
import { loadConfig } from '../server/config.mjs';
import { ENV } from './fixtures.mjs';

const OID = '94540000-0000-4000-8000-0000000000c3';
const CANARY = '90000000-0000-4000-8000-0000000000c2';
const config = loadConfig({ ...ENV, R360_CANARY_GROUP_ID: CANARY });
const T0 = Date.parse('2026-10-27T15:04:00Z');
const META = { displayName: 'STT - Http test', description: 'd', publisher: 'p', runAs: 'system', runAs32Bit: false, schedule: { type: 'daily', interval: 1, time: '02:00:00' }, assignment: { runRemediationScript: true } };
const BODY = { kind: 'new', folder: 'Stt-Http', meta: META, detect: 'exit 1\n', remediate: 'fix\n' };

function world({ roles = ['author'], pim = { ok: true, text: 'active' } } = {}) {
  const w = { t: T0, events: [], gh: [], roles, pim, pulls: [] };
  w.audit = { record: async e => { w.events.push(e); return e; }, list: async () => ({ rows: w.events, truncated: false }) };
  w.auth = {
    writeConfigured: true, beginSignIn: async () => 'https://login.microsoftonline.com/x', completeSignIn: async () => {}, graphToken: async () => 'GT',
    beginElevate: async s => { s.writePending = { state: 'ws', nonce: 'n', verifier: 'v', created: w.t }; return 'https://login.microsoftonline.com/write'; },
    completeElevate: async () => ({ oid: OID, upn: 'admin@contoso.com', homeAccountId: 'ha.write', acrs: ['c1'], accessToken: 'WT' }),
    endWrite: async () => {}, signOut: async () => {},
  };
  w.github = {
    catalog: async () => ({ sha: 'm', items: [{ folder: 'Existing', meta: { ...META, displayName: 'Existing', assignment: { groupId: CANARY } }, detect: 'a\n', remediate: 'b\n' }], approvers: [{ entraObjectId: OID, roles: w.roles }] }),
    listPulls: async () => w.pulls, getPull: async n => w.pulls.find(p => p.number === n),
    proposeChange: async a => { w.gh.push(a); return { number: 12, url: 'https://github.com/your-org/remediations/pull/12', headSha: 'c1', githubRequestId: 'R' }; },
    updateChange: async () => ({ headSha: 'c2' }), discardChange: async () => ({}), readChangeFiles: async () => ({ meta: META, detect: 'a\n', remediate: 'b\n' }),
  };
  w.data = { pim: async () => ({ gate: w.pim }), remediations: async () => ({}), fleet: async () => ({}), certificates: async () => ({}) };
  w.fetcher = async () => new Response('{}', { status: 200 });
  w.sessions = new SessionStore({ now: () => w.t });
  return w;
}

async function run(w, fn) {
  const app = createApp({ config, sessions: w.sessions, auth: w.auth, data: w.data, github: w.github, audit: w.audit, fetcher: w.fetcher, now: () => w.t, log: { error() {} } });
  const srv = app.listen(0); await new Promise(r => srv.once('listening', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    const s = w.sessions.create(); s.user = { oid: OID, upn: 'admin@contoso.com', name: 'Aaron' };
    const headers = { cookie: `${SESSION_COOKIE}=${s.id}` };
    const post = (path, body = BODY, over = {}) => fetch(base + path, { method: 'POST', redirect: 'manual', body: typeof body === 'string' ? body : JSON.stringify(body), headers: { ...headers, origin: config.publicUrl, 'x-r360-csrf': s.csrf, 'content-type': 'application/json', ...over } });
    const get = path => fetch(base + path, { redirect: 'manual', headers });
    const elevate = async () => { await get('/auth/write/start'); return get('/auth/write/callback?code=0123456789&state=ws'); };
    await fn({ base, s, headers, post, get, elevate });
  } finally { srv.close(); }
}

test('authoring requires a signed-in session, a live write session, an author or admin role, and CSRF', async () => {
  const w = world();
  await run(w, async ({ base, post, get, elevate }) => {
    assert.equal((await fetch(base + '/api/changes', { redirect: 'manual' })).status, 401, 'no session');
    assert.equal((await fetch(base + '/api/changes', { method: 'POST', redirect: 'manual', body: '{}' })).status, 401);
    // Signed in but not elevated: reads of the list are fine, every authoring endpoint is closed.
    assert.equal((await get('/api/changes')).status, 200);
    for (const [m, p] of [['GET', '/api/changes/source/Existing'], ['GET', '/api/changes/5/source']]) assert.equal((await get(p)).status, 403, `${m} ${p}`);
    for (const p of ['/api/changes', '/api/changes/5/update', '/api/changes/5/discard']) assert.equal((await post(p)).status, 403, p);
    assert.deepEqual(w.gh, []); assert.deepEqual(w.events.filter(e => e.action?.startsWith('change.')), []);
    // Elevated: now the CSRF guard is what stops forged requests.
    assert.equal((await elevate()).status, 302);
    for (const [over, code] of [[{ origin: 'https://evil.example.com' }, 'origin'], [{ 'x-r360-csrf': 'nope' }, 'csrf'], [{ 'content-type': 'text/plain' }, 'content-type']]) {
      const r = await post('/api/changes', BODY, over); assert.equal(r.status, 403, code); assert.equal((await r.json()).code, code);
    }
    assert.deepEqual(w.gh, []);
    assert.equal((await post('/api/changes')).status, 200);
  });
});

test('a role that is not author or admin cannot author even with a write session', async () => {
  const w = world({ roles: ['approver'] });
  await run(w, async ({ post, get, elevate }) => {
    await elevate();
    assert.equal((await post('/api/changes')).status, 403);
    assert.equal((await get('/api/changes/source/Existing')).status, 403);
    assert.deepEqual(w.gh, []);
  });
  const w2 = world({ roles: ['admin'] });
  await run(w2, async ({ post, elevate }) => { await elevate(); assert.equal((await post('/api/changes')).status, 200); });
});

test('propose through the API: result, audit trail, error mapping, and the testing-mode PIM warning', async () => {
  const w = world({ pim: { ok: false, text: 'Intune Administrator is not active.' } });
  await run(w, async ({ post, get, elevate }) => {
    await elevate();
    const r = await post('/api/changes'); const j = await r.json();
    assert.equal(r.status, 200); assert.equal(j.number, 12); assert.match(j.url, /^https:\/\/github\.com\//); assert.ok(j.pimWarning, 'testing mode warns about PIM'); assert.ok(!JSON.stringify(j).includes('Bearer'));
    const acts = w.events.filter(e => e.action === 'change.proposed').map(e => e.result);
    assert.deepEqual(acts, ['intent', 'ok']);
    // Validation errors are 400 with details; unknown fields 400; a malformed body 400; GitHub failures 502 without internals.
    let bad = await post('/api/changes', { ...BODY, meta: { ...META, displayName: 'x' } });
    assert.equal(bad.status, 400); const bj = await bad.json(); assert.match(bj.error, /Validation failed/); assert.ok(bj.details.some(d => /displayName/.test(d)));
    assert.equal((await post('/api/changes', '{not json')).status, 400);
    assert.equal((await post('/api/changes', { ...BODY, nope: 1 })).status, 400);
    w.github.proposeChange = async () => { throw new Error('secret internals https://api.github.com/x'); };
    bad = await post('/api/changes', { ...BODY, folder: 'Other' }); assert.equal(bad.status, 502);
    const g = await get('/api/changes/source/Existing'); assert.equal(g.status, 200); assert.equal((await g.json()).folder, 'Existing');
    assert.equal((await get('/api/changes/source/..%2Fx')).status, 400);
    assert.equal((await get('/api/changes/source/Missing')).status, 404);
  });
});

test('update and discard through the API enforce the author rule', async () => {
  const w = world();
  w.pulls = [{ number: 5, state: 'open', merged: false, title: 't', url: 'https://github.com/your-org/remediations/pull/5', branch: 'r360/Stt-Http/202610271504-94540000', headSha: 'a'.repeat(40), body: machineBlock({ folder: 'Stt-Http', authorOid: OID }), checks: null },
    { number: 6, state: 'open', merged: false, title: 't', url: 'u', branch: 'r360/Other/202610271504-11111111', headSha: 'b'.repeat(40), body: machineBlock({ folder: 'Other', authorOid: '11111111-2222-4333-8444-555555555555' }), checks: null }];
  await run(w, async ({ post, get, elevate }) => {
    await elevate();
    assert.equal((await post('/api/changes/6/discard', {})).status, 403, 'someone else\'s change');
    assert.equal((await post('/api/changes/5/discard', {})).status, 200);
    assert.equal((await post('/api/changes/abc/discard', {})).status, 400);
    assert.equal((await get('/api/changes/5/source')).status, 200);
    const u = await post('/api/changes/5/update', { meta: META, detect: 'changed\n', remediate: 'b\n' });
    assert.equal(u.status, 200);
    const l = await (await get('/api/changes')).json();
    assert.deepEqual(l.changes.map(c => [c.number, c.canEdit]), [[5, true], [6, false]]);
  });
});

test('body size limits: 1 MB on /api/changes, 16 KB everywhere else', async () => {
  const w = world();
  await run(w, async ({ post, elevate }) => {
    await elevate();
    const pad = n => ({ ...BODY, detect: '# ' + 'x'.repeat(n) + '\n' });
    assert.equal((await post('/api/changes', pad(200 * 1024))).status, 400, 'over the script limit is a validation error, not a size error');
    assert.equal((await post('/api/changes', pad(2 * 1024 * 1024))).status, 413);
    assert.equal((await post('/auth/write/end', { pad: 'x'.repeat(20 * 1024) })).status, 413);
  });
});
