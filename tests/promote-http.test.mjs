import test from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../server/app.mjs';
import { SessionStore, SESSION_COOKIE } from '../server/auth.mjs';
import { world, body, ofAction, noGraphWrites, AARON, USER1, CSHA, FOLDER, HEAD } from './s6-world.mjs';

const AUTHOR_ONLY = { oid: '33333333-3333-4333-8333-333333333333', upn: 'writer@contoso.com', name: 'Writer' };

async function serve(w) {
  const sessions = new SessionStore({ now: () => w.t });
  const auth = { writeConfigured: true, beginSignIn: async () => 'https://login.microsoftonline.com/x', completeSignIn: async () => {}, graphToken: async () => 'GT',
    beginElevate: async s => { s.writePending = { state: 'ws', nonce: 'n', verifier: 'v', created: w.t }; return 'https://login.microsoftonline.com/write'; },
    completeElevate: async s => ({ oid: s.user.oid, upn: s.user.upn, homeAccountId: 'ha.' + s.user.oid, acrs: [], accessToken: 'WT' }), endWrite: async () => {}, signOut: async () => {}, writeToken: async () => 'WT' };
  const data = { pim: async () => ({ gate: { ok: true, text: 'active' } }), remediations: async () => ({}), fleet: async () => ({}), certificates: async () => ({}) };
  const cat = w.github.catalog;
  w.github.catalog = async () => { const c = await cat(); return { ...c, approvers: [...c.approvers, { entraObjectId: AUTHOR_ONLY.oid, upn: AUTHOR_ONLY.upn, roles: ['author'] }] }; };
  const app = createApp({ config: w.config, sessions, auth, data, github: w.github, audit: w.audit, fetcher: w.g.fetcher, now: () => w.t, log: { error() {} } });
  const srv = app.listen(0); await new Promise(r => srv.once('listening', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  const client = user => { const s = sessions.create(); s.user = user; const h = { cookie: `${SESSION_COOKIE}=${s.id}` };
    return { get: p => fetch(base + p, { redirect: 'manual', headers: h }),
      post: (p, b = body(), extra = {}) => fetch(base + p, { method: 'POST', redirect: 'manual', body: typeof b === 'string' ? b : JSON.stringify(b), headers: { ...h, origin: w.config.publicUrl, 'x-r360-csrf': s.csrf, 'content-type': 'application/json', ...extra } }),
      elevate: async () => { await fetch(base + '/auth/write/start', { redirect: 'manual', headers: h }); await fetch(base + '/auth/write/callback?code=0123456789&state=ws', { redirect: 'manual', headers: h }); } }; };
  return { base, client, close: () => srv.close() };
}

test('the promote routes: sign-in, write session, role and CSRF are all required, and evidence is read with the read token only', async () => {
  const w = world({ soakDays: 8 }); const srv = await serve(w);
  try {
    assert.equal((await fetch(`${srv.base}/api/changes/promote`, { method: 'POST', body: '{}' })).status, 401);
    assert.equal((await fetch(`${srv.base}/api/changes/promote-evidence/${FOLDER}`)).status, 401);
    const aaron = srv.client(AARON);
    assert.equal((await aaron.post('/api/changes/promote')).status, 403, 'no write session');
    const writer = srv.client(AUTHOR_ONLY); await writer.elevate();
    assert.equal((await writer.post('/api/changes/promote')).status, 403, 'an author is not an approver');
    await aaron.elevate(); w.g.calls.length = 0;
    assert.equal((await aaron.post('/api/changes/promote', body(), { 'x-r360-csrf': 'nope' })).status, 403, 'bad CSRF');
    assert.equal(w.g.calls.length, 0); assert.equal(w.proposals.length, 0);
    assert.equal((await aaron.post('/api/changes/promote', '{nope')).status, 400);
    assert.equal((await aaron.post('/api/changes/promote', { ...body(), sneaky: 1 })).status, 400);
    assert.equal(w.proposals.length, 0);

    const e = await aaron.get(`/api/changes/promote-evidence/${FOLDER}`); const ej = await e.json();
    assert.equal(e.status, 200); assert.equal(ej.canPromote, true); assert.equal(ej.canarySha, CSHA); assert.equal(ej.evidence.checks.length, 6);
    assert.equal((await aaron.get('/api/changes/promote-evidence/..%2Fx')).status >= 400, true);

    const ok = await aaron.post('/api/changes/promote'); const j = await ok.json();
    assert.equal(ok.status, 200); assert.equal(j.ok, true); assert.equal(j.number, 7); assert.equal(j.promote, true);
    assert.ok(w.g.calls.length > 0 && w.g.calls.every(c => c.auth === 'Bearer GT'), 'every Graph call was a delegated read');
    noGraphWrites(w);
    assert.deepEqual(ofAction(w, 'promote.proposed').map(r => r.result), ['intent', 'ok']);
    // a second request is refused because a change for the folder is open
    const again = await aaron.post('/api/changes/promote'); assert.equal(again.status, 409);
    // soak short: a denial carries the evidence for the dialog
    const x = world({ soakDays: 2 }); const sx = await serve(x);
    try { const c = sx.client(AARON); await c.elevate(); const r = await c.post('/api/changes/promote'); const rj = await r.json();
      assert.equal(r.status, 409); assert.equal(rj.details?.evidence?.overridable ?? rj.evidence?.overridable, true);
      const o = await c.post('/api/changes/promote', body({ overrideReason: 'Pilot group signed off today.' })); assert.equal(o.status, 200); assert.equal((await o.json()).soakOverride, true);
    } finally { sx.close(); }
  } finally { srv.close(); }
});

test('the publish route passes the read token for the promotion re-check and the write token for Intune', async () => {
  const w = world({ soakDays: 8 }); const srv = await serve(w);
  try {
    const aaron = srv.client(AARON); await aaron.elevate();
    assert.equal((await aaron.post('/api/changes/promote')).status, 200);
    await w.c.approve(AARON, ['author', 'approver', 'admin'], 7, { headSha: HEAD }); await w.c.merge(AARON, ['author', 'approver', 'admin'], 7, { headSha: HEAD }); await w.c.verifySigning(AARON, ['author', 'approver', 'admin'], 7);
    w.g.calls.length = 0;
    const r = await aaron.post('/api/changes/7/publish', { mergeSha: 'c0ffee0000000000000000000000000000000001' }); assert.equal(r.status, 200, JSON.stringify(await r.clone().json()));
    assert.ok(w.g.calls.some(c => c.method === 'GET' && /runSummary/.test(c.path) && c.auth === 'Bearer GT'));
    assert.ok(w.g.writes().length > 0 && w.g.writes().every(c => c.auth === 'Bearer WT'));
  } finally { srv.close(); }
});
