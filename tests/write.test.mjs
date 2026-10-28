import test from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../server/app.mjs';
import { SessionStore, SESSION_COOKIE } from '../server/auth.mjs';
import { createWrite, csrfGuard } from '../server/write.mjs';
import { loadConfig } from '../server/config.mjs';
import { ENV } from './fixtures.mjs';

const OID = '94540000-0000-4000-8000-0000000000c3';
const OTHER = '11111111-2222-4333-8444-555555555555';
const config = loadConfig(ENV);
const T0 = Date.parse('2026-10-26T18:30:00Z');

// A controllable world: clock, audit sink (can be broken), approvers, PIM, Graph, and a fake auth whose elevation result the test picks.
function world({ cfg = config, roles = ['author'], approversError = null, pim = { ok: true, text: 'Intune Administrator is active.' }, writeConfigured = true } = {}) {
  const w = { t: T0, events: [], auditDown: false, roles, approversError, pim, ended: [], elevOid: OID, elevFail: null, graphStatus: 200 };
  w.audit = {
    record: async e => { if (w.auditDown) throw Object.assign(new Error('audit down'), { audit: true }); w.events.push(e); return e; },
    list: async () => ({ rows: w.events, truncated: false }),
  };
  w.auth = {
    writeConfigured,
    beginSignIn: async () => 'https://login.microsoftonline.com/x',
    completeSignIn: async s => { s.user = { oid: OID, upn: 'admin@contoso.com', name: 'Aaron' }; },
    graphToken: async () => 'GT',
    beginElevate: async s => { s.writePending = { state: 'ws', nonce: 'n', verifier: 'v', created: w.t }; return 'https://login.microsoftonline.com/write'; },
    completeElevate: async () => { if (w.elevFail) throw w.elevFail; return { oid: w.elevOid, upn: 'admin@contoso.com', homeAccountId: 'ha.write', acrs: ['c1'], accessToken: 'WT' }; },
    endWrite: async id => { w.ended.push(id); },
    signOut: async () => {},
  };
  w.github = { catalog: async () => (w.approversError ? { approversError: w.approversError } : { approvers: w.roles.length ? [{ entraObjectId: OID, roles: w.roles }] : [] }) };
  w.data = { pim: async () => ({ gate: w.pim }), remediations: async () => ({}), fleet: async () => ({}), certificates: async () => ({}) };
  w.fetcher = async () => new Response('{}', { status: w.graphStatus, headers: { 'request-id': 'graph-req-1' } });
  w.sessions = new SessionStore({ now: () => w.t });
  w.cfg = cfg;
  return w;
}

async function run(w, fn) {
  const app = createApp({ config: w.cfg, sessions: w.sessions, auth: w.auth, data: w.data, github: w.github, audit: w.audit, fetcher: w.fetcher, now: () => w.t, log: { error() {} } });
  const srv = app.listen(0); await new Promise(r => srv.once('listening', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    const s = w.sessions.create(); s.user = { oid: OID, upn: 'admin@contoso.com', name: 'Aaron' };
    const headers = { cookie: `${SESSION_COOKIE}=${s.id}` };
    const post = (path, over = {}) => fetch(base + path, { method: 'POST', redirect: 'manual', body: '{}', headers: { ...headers, origin: w.cfg.publicUrl, 'x-r360-csrf': s.csrf, 'content-type': 'application/json', ...over } });
    const get = path => fetch(base + path, { redirect: 'manual', headers });
    const elevate = async () => { await get('/auth/write/start'); return get('/auth/write/callback?code=0123456789&state=ws'); };
    await fn({ base, s, headers, post, get, elevate });
  } finally { srv.close(); }
}
const me = async get => (await get('/api/me')).json();

test('CSRF matrix: origin, per-session token and JSON content type are all required for state-changing requests', async () => {
  const w = world();
  await run(w, async ({ post, s }) => {
    const bad = async (over, code) => { const r = await post('/auth/write/end', over); assert.equal(r.status, 403, JSON.stringify(over)); assert.equal((await r.json()).code, code); };
    await bad({ origin: 'https://evil.example.com' }, 'origin');
    await bad({ origin: '' }, 'origin');
    await bad({ origin: 'null' }, 'origin');
    await bad({ origin: config.publicUrl + '.evil.example.com' }, 'origin');
    await bad({ 'x-r360-csrf': '' }, 'csrf');
    await bad({ 'x-r360-csrf': 'x'.repeat(s.csrf.length) }, 'csrf');
    await bad({ 'x-r360-csrf': s.csrf.slice(1) }, 'csrf');
    await bad({ 'content-type': 'application/x-www-form-urlencoded' }, 'content-type');
    await bad({ 'content-type': 'text/plain' }, 'content-type');
    const ok = await post('/auth/write/end'); assert.equal(ok.status, 200);
  });
  // Reads are never blocked by the guard; GET on a state-changing route does nothing.
  await run(w, async ({ get }) => {
    assert.equal((await get('/api/settings')).status, 200);
    assert.equal((await get('/auth/write/end')).status, 404);
  });
  // The guard in isolation: a second session's token is not accepted.
  const mw = csrfGuard({ config });
  let called = false;
  mw({ method: 'POST', get: h => ({ origin: config.publicUrl, 'x-r360-csrf': 'other' })[h.toLowerCase()], r360: { csrf: 'mine' }, is: () => true }, { status: () => ({ json: () => {} }) }, () => { called = true; });
  assert.equal(called, false);
});

test('unauthenticated write routes redirect to sign-in or return 401', async () => {
  const w = world();
  const app = createApp({ config, sessions: w.sessions, auth: w.auth, data: w.data, github: w.github, audit: w.audit, log: { error() {} } });
  const srv = app.listen(0); await new Promise(r => srv.once('listening', r));
  try {
    const base = `http://127.0.0.1:${srv.address().port}`;
    let r = await fetch(`${base}/auth/write/start`, { redirect: 'manual' }); assert.equal(r.status, 302); assert.equal(r.headers.get('location'), '/auth/signin');
    r = await fetch(`${base}/auth/write/callback?code=x&state=y`, { redirect: 'manual' }); assert.equal(r.status, 302);
    r = await fetch(`${base}/auth/write/end`, { method: 'POST' }); assert.equal(r.status, 401);
    r = await fetch(`${base}/api/audit`); assert.equal(r.status, 401);
  } finally { srv.close(); }
});

test('elevation: audited, 8h server-enforced, banner data in /api/me, ends on expiry with an audit row', async () => {
  const w = world();
  await run(w, async ({ get, post, elevate }) => {
    let m = await me(get);
    assert.equal(m.write.active, false); assert.equal(m.write.canElevate, true); assert.equal(m.write.ttlMinutes, 480); assert.ok(m.csrf);
    const r = await elevate();
    assert.equal(r.status, 302); assert.equal(r.headers.get('location'), '/');
    m = await me(get);
    assert.equal(m.write.active, true);
    assert.equal(m.write.until, new Date(T0 + 480 * 60000).toISOString());
    const ev = w.events.find(e => e.action === 'session.elevate');
    assert.equal(ev.actorOid, OID); assert.equal(ev.result, 'ok'); assert.equal(ev.graphRequestId, 'graph-req-1');
    assert.equal(ev.sessionUntil, new Date(T0 + 480 * 60000).toISOString()); assert.deepEqual(ev.acrs, ['c1']);
    assert.ok(!JSON.stringify(w.events).includes('WT'), 'the write token is never audited');
    // Server enforces the deadline: one minute short of 8h still active, at 8h it is gone and audited as expired.
    w.t = T0 + 479 * 60000; assert.equal((await me(get)).write.active, true);
    w.t = T0 + 480 * 60000; m = await me(get);
    assert.equal(m.write.active, false);
    const end = w.events.filter(e => e.action === 'session.end');
    assert.equal(end.length, 1); assert.equal(end[0].reason, 'expired');
    assert.deepEqual(w.ended, ['ha.write']);
    // A fresh elevation can be ended manually; ending twice records once.
    await elevate(); assert.equal((await me(get)).write.active, true);
    assert.equal((await post('/auth/write/end')).status, 200); assert.equal((await post('/auth/write/end')).status, 200);
    assert.equal(w.events.filter(e => e.action === 'session.end' && e.reason === 'manual').length, 1);
    assert.equal((await me(get)).write.active, false);
  });
});

test('elevation TTL setting is honored (and bounded to 8h by config)', async () => {
  const w = world({ cfg: loadConfig({ ...ENV, R360_ELEVATION_TTL_MINUTES: '30' }) });
  await run(w, async ({ get, elevate }) => {
    await elevate(); w.t = T0 + 29 * 60000; assert.equal((await me(get)).write.active, true);
    w.t = T0 + 30 * 60000; assert.equal((await me(get)).write.active, false);
  });
  for (const bad of ['0', '481', '1.5', 'abc']) assert.throws(() => loadConfig({ ...ENV, R360_ELEVATION_TTL_MINUTES: bad }), /ELEVATION_TTL/);
  assert.throws(() => loadConfig({ ...ENV, R360_AUDIT_STORAGE_ACCOUNT: '' }), /R360_AUDIT_STORAGE_ACCOUNT/);
  assert.throws(() => loadConfig({ ...ENV, R360_WRITE_CLIENT_ID: 'nope' }), /R360_WRITE_CLIENT_ID/);
});

test('elevation is refused and audited: other account, no role, invalid approvers, failed exchange, PIM enforced', async () => {
  const denial = (w, reason) => { const d = w.events.find(e => e.action === 'session.elevate.denied'); assert.ok(d, `denied event for ${reason}`); assert.equal(d.reason, reason); assert.equal(d.result, 'denied'); return d; };
  let w = world(); w.elevOid = OTHER;
  await run(w, async ({ get, elevate }) => {
    const r = await elevate(); assert.equal(r.status, 403);
    assert.equal((await me(get)).write.active, false);
    assert.equal(denial(w, 'oid-mismatch').approverOid, OTHER);
    assert.deepEqual(w.ended, ['ha.write'], 'the foreign write token is dropped');
    assert.ok(!w.events.some(e => e.action === 'session.elevate'));
  });
  w = world({ roles: [] });
  await run(w, async ({ get, elevate }) => {
    const m = await me(get); assert.equal(m.write.canElevate, false); assert.match(m.write.blockedReason, /not listed/);
    const r = await get('/auth/write/start'); assert.equal(r.status, 403); denial(w, 'no-role');
    assert.equal((await me(get)).write.active, false);
    void elevate;
  });
  w = world({ approversError: 'approvers.json is not valid JSON' });
  await run(w, async ({ get }) => {
    const m = await me(get); assert.equal(m.write.canElevate, false);
    const r = await get('/auth/write/start'); assert.equal(r.status, 503); denial(w, 'approvers-invalid');
  });
  w = world(); w.elevFail = Object.assign(new Error('AADSTS70000 bad code'), { status: 403 });
  await run(w, async ({ get, elevate }) => {
    const r = await elevate(); assert.equal(r.status, 403); denial(w, 'exchange-failed'); assert.equal((await me(get)).write.active, false);
  });
  w = world(); w.elevFail = Object.assign(new Error('The sign-in response did not match this browser session.'), { status: 400 });
  await run(w, async ({ elevate }) => { const r = await elevate(); assert.equal(r.status, 400); denial(w, 'callback-invalid'); });
  w = world({ cfg: loadConfig({ ...ENV, R360_PIM_MODE: 'enforce' }), pim: { ok: false, text: 'Intune Administrator is eligible but not active.' } });
  await run(w, async ({ get, elevate }) => {
    const r = await elevate(); assert.equal(r.status, 403); denial(w, 'pim-not-active'); assert.equal((await me(get)).write.active, false);
  });
  w = world({ cfg: loadConfig({ ...ENV, R360_PIM_MODE: 'warn' }), pim: { ok: false, text: 'not active' } });
  await run(w, async ({ get, elevate }) => {
    assert.equal((await elevate()).status, 302); assert.equal((await me(get)).write.active, true);
    assert.match(w.events.find(e => e.action === 'session.elevate').pimState, /not-active/);
  });
  w = world({ writeConfigured: false });
  await run(w, async ({ get }) => { const m = await me(get); assert.equal(m.write.canElevate, false); assert.equal((await get('/auth/write/start')).status, 503); });
});

test('no audit, no elevation: when the audit trail is down the write session never starts', async () => {
  const w = world(); w.auditDown = true;
  await run(w, async ({ get, elevate }) => {
    const r = await elevate(); assert.equal(r.status, 503);
    assert.match(await r.text(), /audit trail is unavailable/);
    assert.equal((await me(get)).write.active, false);
    assert.deepEqual(w.ended, ['ha.write']);
  });
});

test('sign-out ends an active write session and audits it', async () => {
  const w = world();
  await run(w, async ({ get, headers, base, elevate }) => {
    await elevate(); assert.equal((await me(get)).write.active, true);
    const r = await fetch(`${base}/auth/signout`, { method: 'POST', redirect: 'manual', headers });
    assert.equal(r.status, 303);
    assert.equal(w.events.filter(e => e.action === 'session.end' && e.reason === 'signout').length, 1);
  });
});

test('requireWrite: session, role matrix, oid binding, invalid approvers fail closed, PIM warn vs enforce', async () => {
  const call = async (w, { allowed = ['author'], mutate } = {}) => {
    const auth = w.auth;
    const write = createWrite({ config: w.cfg, auth, audit: w.audit, github: w.github, pimGate: async () => { if (w.pimThrows) throw new Error('graph down'); return w.pim; }, now: () => w.t, log: { error() {} } });
    const s = w.sessions.create(); s.user = { oid: OID, upn: 'a@b' };
    s.write = { homeAccountId: 'ha', oid: OID, since: w.t, until: w.t + 3600e3 };
    mutate?.(s);
    const res = { locals: {}, code: 200, body: null, status(c) { this.code = c; return this; }, json(b) { this.body = b; return this; } };
    const req = { r360: s };
    let nexted = false;
    await write.requireWrite({ roles: allowed })(req, res, () => { nexted = true; });
    return { nexted, res, req };
  };
  let w = world({ roles: ['author'] });
  let r = await call(w); assert.equal(r.nexted, true); assert.ok(r.req.r360write);
  r = await call(w, { allowed: ['approver', 'admin'] }); assert.equal(r.nexted, false); assert.equal(r.res.body.code, 'role'); assert.equal(r.res.code, 403);
  r = await call(w, { mutate: s => { s.write = null; } }); assert.equal(r.res.body.code, 'write-required');
  r = await call(w, { mutate: s => { s.write.until = w.t - 1; } }); assert.equal(r.res.body.code, 'write-required');
  assert.equal(w.events.filter(e => e.reason === 'expired').length, 1);
  r = await call(w, { mutate: s => { s.write.oid = OTHER; } }); assert.equal(r.res.body.code, 'oid-mismatch');
  r = await call(w, { mutate: s => { s.user = null; } }); assert.equal(r.res.code, 401);
  w = world({ approversError: 'approvers.json is not valid JSON' });
  r = await call(w); assert.equal(r.nexted, false); assert.equal(r.res.code, 503); assert.equal(r.res.body.code, 'approvers-invalid');
  w = world({ roles: [] }); r = await call(w); assert.equal(r.res.body.code, 'role');
  w = world({ roles: ['admin', 'author'] }); r = await call(w, { allowed: ['admin'] }); assert.equal(r.nexted, true);
  // PIM: warn lets the request through and flags it; enforce blocks it.
  w = world({ pim: { ok: false, text: 'Intune Administrator is eligible but not active.' } });
  r = await call(w); assert.equal(r.nexted, true); assert.match(r.res.locals.pimWarning, /eligible/);
  assert.match(r.res.locals.pimWarning, /informational/i, 'a PIM warning is labelled informational');
  // Only shown when PIM was actually evaluated: an active role and a failed lookup both show nothing.
  w = world({ pim: { ok: true, text: 'active' } }); r = await call(w); assert.equal(r.nexted, true); assert.equal(r.res.locals.pimWarning, undefined);
  w = world({ pim: null }); w.pimThrows = true; r = await call(w); assert.equal(r.nexted, true); assert.equal(r.res.locals.pimWarning, undefined, 'a failed PIM lookup is not shown as a warning');
  w = world({ cfg: loadConfig({ ...ENV, R360_PIM_MODE: 'enforce' }), pim: { ok: false, text: 'not active' } });
  r = await call(w); assert.equal(r.nexted, false); assert.equal(r.res.body.code, 'pim');
  w = world({ cfg: loadConfig({ ...ENV, R360_PIM_MODE: 'enforce' }), pim: { ok: true, text: 'active' } });
  r = await call(w); assert.equal(r.nexted, true);
  assert.throws(() => createWrite({ config, auth: {}, audit: {}, github: {}, pimGate: async () => ({}) }).requireWrite({ roles: [] }), /roles/);
});

test('audit API: filters are validated, download is JSON or CSV, reads are open to signed-in operators', async () => {
  const w = world();
  let seen;
  w.audit.list = async q => { seen = q; return { rows: [{ at: '2026-10-26T18:30:00Z', action: 'session.end', actorUpn: 'a@b', target: '=cmd' }], truncated: false }; };
  await run(w, async ({ get }) => {
    let r = await get('/api/audit?from=2026-10-01&to=2026-10-27&action=session.end,session.elevate&actor=a@b&target=write&limit=50');
    assert.equal(r.status, 200); assert.equal((await r.json()).rows.length, 1);
    assert.deepEqual(seen.actions, ['session.end', 'session.elevate']); assert.equal(seen.actor, 'a@b'); assert.equal(seen.limit, 50); assert.equal(seen.from, Date.parse('2026-10-01'));
    assert.equal((await get('/api/audit?from=garbage')).status, 400);
    assert.equal((await get("/api/audit?action=x'%20or%201")).status, 400);
    r = await get('/api/audit/download?format=csv'); assert.match(r.headers.get('content-disposition'), /attachment; filename="r360-audit-.*\.csv"/);
    assert.match(await r.text(), /'=cmd/);
    r = await get('/api/audit/download'); assert.match(r.headers.get('content-disposition'), /\.json"/); assert.equal((await r.json()).rows.length, 1);
    w.audit.list = async () => { throw Object.assign(new Error('table down'), { audit: true }); };
    r = await get('/api/audit'); assert.equal(r.status, 502); assert.ok(!(await r.text()).includes('table down'));
  });
});
