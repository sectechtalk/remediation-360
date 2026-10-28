import test from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { createApp } from '../server/app.mjs';
import { SessionStore, SESSION_COOKIE } from '../server/auth.mjs';
import { createWrite } from '../server/write.mjs';
import { loadConfig } from '../server/config.mjs';
import { ENV } from './fixtures.mjs';

// Drives the real public/app.js in jsdom against the real Express app, so the red banner's End button is tested as a user meets it.
const OID = '94540000-0000-4000-8000-0000000000c3';
const UPN = 'admin@contoso.com';
const config = loadConfig(ENV);
const T0 = Date.now();

function world() {
  const w = { t: T0, events: [] };
  w.audit = { record: async e => { w.events.push({ ...e, at: new Date(w.t).toISOString() }); return e; }, list: async () => ({ rows: [...w.events].reverse(), truncated: false }) };
  w.auth = {
    writeConfigured: true,
    beginSignIn: async () => 'https://login.microsoftonline.com/x',
    completeSignIn: async s => { s.user = { oid: OID, upn: UPN, name: 'Aaron' }; },
    graphToken: async () => 'GT',
    beginElevate: async s => { s.writePending = { state: 'ws', nonce: 'n', verifier: 'v', created: w.t }; return 'https://login.microsoftonline.com/write'; },
    completeElevate: async () => ({ oid: OID, upn: UPN, homeAccountId: 'ha.write', acrs: ['c1'], accessToken: 'WT' }),
    endWrite: async () => {},
    signOut: async () => {},
  };
  w.github = { catalog: async () => ({ approvers: [{ entraObjectId: OID, roles: ['author'] }] }) };
  w.data = { pim: async () => ({ gate: { ok: true, text: 'active' } }), remediations: async () => ({ rows: [] }), fleet: async () => ({}), certificates: async () => ({}) };
  w.fetcher = async () => new Response('{}', { status: 200 });
  w.sessions = new SessionStore({ now: () => w.t });
  return w;
}

async function serve(w) {
  const app = createApp({ config, sessions: w.sessions, auth: w.auth, data: w.data, github: w.github, audit: w.audit, fetcher: w.fetcher, now: () => w.t, log: { error() {} } });
  const srv = app.listen(0); await new Promise(r => srv.once('listening', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  const s = w.sessions.create(); s.user = { oid: OID, upn: UPN, name: 'Aaron' };
  const headers = { cookie: `${SESSION_COOKIE}=${s.id}` };
  const get = p => fetch(base + p, { redirect: 'manual', headers });
  const elevate = async () => { await get('/auth/write/start'); return get('/auth/write/callback?code=0123456789&state=ws'); };
  return { base, s, headers, get, elevate, close: () => srv.close() };
}

// One jsdom page for the file (app.js is an ES module and boots once). The browser's fetch is pointed at the current test server.
const dom = new JSDOM('<!doctype html><div id="banners"></div><span id="who"></span><span id="writectl"></span><nav id="nav"></nav><main id="view"></main>', { url: config.publicUrl + '/' });
const target = { base: '', headers: {} };
const realFetch = globalThis.fetch;
const realSetTimeout = globalThis.setTimeout;
globalThis.setTimeout = (...a) => { const t = realSetTimeout(...a); t.unref?.(); return t; }; // the 8 h banner timer must not keep the test process alive
Object.assign(globalThis, { document: dom.window.document, location: dom.window.location, addEventListener: dom.window.addEventListener.bind(dom.window), alert: () => { throw new Error('alert must not be used'); } });
globalThis.fetch = (path, init = {}) => String(path).startsWith('/')
  ? realFetch(target.base + path, { ...init, headers: { ...init.headers, ...target.headers, origin: config.publicUrl } })
  : realFetch(path, init);

const until = async (cond, what) => { for (let i = 0; i < 200; i++) { if (await cond()) return; await new Promise(r => realSetTimeout(r, 25)); } assert.fail(`timed out waiting for ${what}`); };
const banner = () => document.querySelector('#banners .banner.write');
const endButton = () => banner()?.querySelector('button');

let app;
async function page(srv) {
  target.base = srv.base; target.headers = srv.headers;
  document.getElementById('banners').replaceChildren();
  document.getElementById('view').replaceChildren();
  if (!app) { app = await import('../public/app.js'); }
  else app.boot?.();
  await until(() => document.getElementById('who').textContent === UPN, 'the page to load');
}
const spy = () => { const calls = { reload: 0, signin: 0 }; app.nav.reload = () => { calls.reload++; }; app.nav.signin = () => { calls.signin++; }; return calls; };

test('End write session button is enabled, and clicking it POSTs /auth/write/end which writes session.end', async () => {
  const w = world(); const srv = await serve(w);
  try {
    assert.equal((await srv.elevate()).status, 302);
    await page(srv);
    const calls = spy();
    await until(() => endButton(), 'the write banner');
    const b = endButton();
    assert.equal(b.textContent, 'End write session');
    assert.equal(b.disabled, false, 'the End button must be enabled');
    assert.equal(b.hasAttribute('disabled'), false);
    assert.ok(w.events.some(e => e.action === 'session.elevate'));
    assert.ok(!w.events.some(e => e.action === 'session.end'));
    b.click();
    await until(() => calls.reload === 1, 'the page to reload after ending');
    const ends = w.events.filter(e => e.action === 'session.end');
    assert.equal(ends.length, 1);
    assert.equal(ends[0].reason, 'manual');
    assert.equal(ends[0].actorOid, OID);
    assert.equal(ends[0].target, 'write-session');
    assert.equal(calls.signin, 0);
    assert.equal((await (await srv.get('/api/me')).json()).write.active, false);
  } finally { srv.close(); }
});

test('When the app restarted (all sessions lost), End recovers: re-enabled, explains why, no alert, no stuck button', async () => {
  const w = world(); const srv = await serve(w);
  try {
    await srv.elevate();
    await page(srv);
    const calls = spy();
    await until(() => endButton(), 'the write banner');
    w.sessions.map.clear(); // scale to zero or restart: the replica has no memory of the session
    endButton().click();
    await until(() => /already over/.test(banner().textContent), 'the explanation');
    assert.equal(endButton().disabled, false);
    assert.equal(endButton().textContent, 'End write session');
    assert.equal(calls.reload, 0);
    assert.ok(!w.events.some(e => e.action === 'session.end'), 'nothing could be ended: the session is gone');
  } finally { srv.close(); }
});

test('Audit trail: an elevation lost to a restart is closed with session.end (session-lost) at the next sign-in, once', async () => {
  const w = world(); const srv = await serve(w);
  try {
    await srv.elevate();
    const elev = w.events.find(e => e.action === 'session.elevate');
    w.sessions.map.clear();
    const write = createWrite({ config, auth: w.auth, audit: w.audit, github: w.github, pimGate: async () => ({ ok: true, text: 'active' }), now: () => w.t, log: { error() {} } });
    const user = { oid: OID, upn: UPN, name: 'Aaron' };
    const lost = await write.reconcileLost({ user }, (oid, ms) => w.sessions.hasWrite(oid, ms));
    assert.deepEqual(lost, [elev.sessionUntil]);
    const ends = w.events.filter(e => e.action === 'session.end');
    assert.equal(ends.length, 1);
    assert.equal(ends[0].reason, 'session-lost');
    assert.equal(ends[0].sessionUntil, elev.sessionUntil);
    assert.deepEqual(await write.reconcileLost({ user }, () => false), [], 'idempotent');
    assert.equal(w.events.filter(e => e.action === 'session.end').length, 1);
  } finally { srv.close(); }
});

test('Audit trail: a write session that is still live on this replica is not closed by a second sign-in', async () => {
  const w = world(); const srv = await serve(w);
  try {
    await srv.elevate();
    const write = createWrite({ config, auth: w.auth, audit: w.audit, github: w.github, pimGate: async () => ({ ok: true }), now: () => w.t, log: { error() {} } });
    const lost = await write.reconcileLost({ user: { oid: OID, upn: UPN, name: 'Aaron' } }, (oid, ms) => w.sessions.hasWrite(oid, ms));
    assert.deepEqual(lost, []);
    assert.ok(!w.events.some(e => e.action === 'session.end'));
  } finally { srv.close(); }
});
