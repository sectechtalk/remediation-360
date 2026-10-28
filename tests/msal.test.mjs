import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createApp } from '../server/app.mjs';
import { createAuth, SessionStore, SESSION_COOKIE, GRAPH_READ_SCOPES, WRITE_SCOPES } from '../server/auth.mjs';
import { loadConfig } from '../server/config.mjs';
import { ENV } from './fixtures.mjs';

// Drives the REAL @azure/msal-node library (authorize URL, PKCE, nonce validation, token redemption, token cache) against a
// fake Entra that lives in memory: msal-node is handed a network client instead of the internet.
const config = loadConfig(ENV);
const TID = ENV.ENTRA_TENANT_ID;
const OID = '94540000-0000-4000-8000-0000000000c3';
const OTHER = '11111111-2222-4333-8444-555555555555';
const AUTH = `https://login.microsoftonline.com/${TID}`;
const b64 = o => Buffer.from(typeof o === 'string' ? o : JSON.stringify(o)).toString('base64url');
const jwt = claims => `${b64({ alg: 'none', typ: 'JWT' })}.${b64(claims)}.${b64('sig')}`;

function fakeEntra() {
  const e = { codes: new Map(), posts: [], gets: [], nonceOverride: null, oidFor: {}, now: () => Math.floor(Date.now() / 1000) };
  // Called by the test in place of the browser: follow the authorize URL, "sign in", and get back a code.
  e.authorize = (url, { oid = OID } = {}) => {
    const u = new URL(url);
    assert.equal(u.origin + u.pathname, `${AUTH}/oauth2/v2.0/authorize`);
    const q = Object.fromEntries(u.searchParams);
    const code = `code-${e.codes.size}-${'x'.repeat(12)}`;
    e.codes.set(code, { q, oid });
    return { code, state: q.state, query: q };
  };
  const discovery = () => ({ token_endpoint: `${AUTH}/oauth2/v2.0/token`, authorization_endpoint: `${AUTH}/oauth2/v2.0/authorize`, issuer: `${AUTH}/v2.0`, jwks_uri: `${AUTH}/discovery/v2.0/keys`,
    end_session_endpoint: `${AUTH}/oauth2/v2.0/logout`, tenant_region_scope: null });
  e.network = {
    async sendGetRequestAsync(url) {
      e.gets.push(url);
      if (url.includes('openid-configuration')) return { status: 200, headers: {}, body: discovery() };
      if (url.includes('discovery/instance')) return { status: 200, headers: {}, body: { tenant_discovery_endpoint: `${AUTH}/v2.0/.well-known/openid-configuration`, metadata: [{ preferred_network: 'login.microsoftonline.com', preferred_cache: 'login.windows.net', aliases: ['login.microsoftonline.com', 'login.windows.net'] }] } };
      throw new Error(`fake Entra: unexpected GET ${url}`);
    },
    async sendPostRequestAsync(url, options) {
      assert.equal(url.split('?')[0], `${AUTH}/oauth2/v2.0/token`);
      const form = Object.fromEntries(new URLSearchParams(options.body));
      e.posts.push(form);
      const rec = e.codes.get(form.code);
      if (!rec) return { status: 400, headers: {}, body: { error: 'invalid_grant', error_description: 'AADSTS70000 unknown code' } };
      e.codes.delete(form.code); // single use
      const clientId = rec.q.client_id;
      // PKCE: the verifier must hash to the challenge sent on the authorize request.
      if (createHash('sha256').update(form.code_verifier || '').digest('base64url') !== rec.q.code_challenge) return { status: 400, headers: {}, body: { error: 'invalid_grant', error_description: 'AADSTS50148 PKCE' } };
      const iat = e.now();
      const claims = { iss: `${AUTH}/v2.0`, aud: clientId, tid: TID, oid: rec.oid, sub: 'sub', preferred_username: 'admin@contoso.com', name: 'Aaron', ver: '2.0', iat, nbf: iat, exp: iat + 3600,
        nonce: e.nonceOverride ?? rec.q.nonce, acrs: ['c1'] };
      return { status: 200, headers: { 'request-id': 'fake-req' }, body: { token_type: 'Bearer', scope: rec.q.scope, expires_in: 3600, ext_expires_in: 3600, access_token: jwt({ aud: 'https://graph.microsoft.com', oid: rec.oid, appid: clientId }),
        refresh_token: `rt-${clientId}`, id_token: jwt(claims), client_info: b64({ uid: rec.oid, utid: TID }) } };
    },
  };
  return e;
}

const miCalls = [];
function stack({ entra = fakeEntra(), roles = ['author'] } = {}) {
  const auth = createAuth({ config, miToken: async r => { miCalls.push(r); return 'MI-ASSERTION'; }, msal: { system: { networkClient: entra.network } } });
  const events = [];
  const audit = { record: async ev => { events.push(ev); return ev; }, list: async () => ({ rows: events, truncated: false }) };
  const github = { catalog: async () => ({ approvers: [{ entraObjectId: OID, roles }] }) };
  const data = { pim: async () => ({ gate: { ok: true, text: 'ok' } }) };
  const graphCalls = [];
  const fetcher = async (url, init) => { graphCalls.push({ url: String(url), auth: init.headers.Authorization }); return new Response('{}', { status: 200, headers: { 'request-id': 'graph-1' } }); };
  const sessions = new SessionStore();
  const app = createApp({ config, sessions, auth, data, github, audit, fetcher, log: { error() {} } });
  return { entra, auth, events, graphCalls, sessions, app };
}
async function serve(app, fn) {
  const srv = app.listen(0); await new Promise(r => srv.once('listening', r));
  try { await fn(`http://127.0.0.1:${srv.address().port}`); } finally { srv.close(); }
}
const cookieOf = r => /__Host-r360=([^;]+)/.exec(r.headers.get('set-cookie'))[1];

async function signIn(base, entra, opts) {
  let r = await fetch(`${base}/auth/signin`, { redirect: 'manual' });
  assert.equal(r.status, 302);
  const h = { cookie: `${SESSION_COOKIE}=${cookieOf(r)}` };
  const { code, state } = entra.authorize(r.headers.get('location'), opts);
  r = await fetch(`${base}/auth/callback?code=${code}&state=${state}`, { redirect: 'manual', headers: h });
  return { r, h };
}

test('real MSAL: web sign-in sends PKCE + nonce, redeems with the managed-identity assertion (no secret), and checks the nonce', async () => {
  const st = stack();
  await serve(st.app, async base => {
    let r = await fetch(`${base}/auth/signin`, { redirect: 'manual' });
    const authz = new URL(r.headers.get('location'));
    assert.equal(authz.searchParams.get('client_id'), ENV.R360_WEB_CLIENT_ID);
    assert.equal(authz.searchParams.get('code_challenge_method'), 'S256');
    assert.match(authz.searchParams.get('nonce'), /^[0-9a-f]{48}$/);
    assert.match(authz.searchParams.get('state'), /^[0-9a-f]{48}$/);
    assert.equal(authz.searchParams.get('redirect_uri'), config.redirectUri);
    assert.equal(authz.searchParams.get('prompt'), 'select_account');
    for (const scope of GRAPH_READ_SCOPES) assert.ok(authz.searchParams.get('scope').includes(scope));
    assert.ok(!authz.searchParams.get('scope').includes('ReadWrite'), 'the web app never asks for a write scope');
    const sid = cookieOf(r); const h = { cookie: `${SESSION_COOKIE}=${sid}` };
    const { code, state } = st.entra.authorize(authz.href);
    r = await fetch(`${base}/auth/callback?code=${code}&state=${state}`, { redirect: 'manual', headers: h });
    assert.equal(r.status, 302); assert.equal(r.headers.get('location'), '/');
    const form = st.entra.posts.at(-1);
    assert.equal(form.grant_type, 'authorization_code'); assert.equal(form.client_id, ENV.R360_WEB_CLIENT_ID);
    assert.equal(form.client_assertion, 'MI-ASSERTION');
    assert.equal(form.client_assertion_type, 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
    assert.ok(!('client_secret' in form));
    assert.equal(miCalls.at(-1), 'api://AzureADTokenExchange');
    const me = await (await fetch(`${base}/api/me`, { headers: h })).json();
    assert.equal(me.user.oid, OID); assert.equal(me.write.active, false);
    assert.equal(st.events.filter(e => e.action === 'session.signin').length, 1);
  });
});

test('real MSAL: a token whose nonce is wrong or missing is rejected (replayed/injected response)', async () => {
  for (const nonce of ['attacker-nonce', '']) {
    const st = stack(); st.entra.nonceOverride = nonce;
    await serve(st.app, async base => {
      const { r, h } = await signIn(base, st.entra);
      assert.equal(r.status, 403);
      const me = await fetch(`${base}/api/me`, { headers: h }); assert.equal(me.status, 401, 'no session was established');
    });
  }
  // A code cannot be redeemed twice and state must match.
  const st = stack();
  await serve(st.app, async base => {
    const r1 = await fetch(`${base}/auth/signin`, { redirect: 'manual' });
    const h = { cookie: `${SESSION_COOKIE}=${cookieOf(r1)}` };
    const { code } = st.entra.authorize(r1.headers.get('location'));
    let r = await fetch(`${base}/auth/callback?code=${code}&state=wrong`, { redirect: 'manual', headers: h });
    assert.equal(r.status, 400); assert.equal(st.entra.posts.length, 0, 'a mismatched state never reaches the token endpoint');
    r = await fetch(`${base}/auth/callback?code=${code}&state=anything`, { redirect: 'manual', headers: h });
    assert.equal(r.status, 400, 'the pending sign-in is consumed by the first callback');
  });
});

test('real MSAL: write elevation uses the r360-write app, ONLY the Intune script write scope, a separate cache, and the same person', async () => {
  const st = stack();
  await serve(st.app, async base => {
    const { r, h } = await signIn(base, st.entra);
    assert.equal(r.status, 302);
    const csrf = (await (await fetch(`${base}/api/me`, { headers: h })).json()).csrf;
    let rs = await fetch(`${base}/auth/write/start`, { redirect: 'manual', headers: h });
    assert.equal(rs.status, 302);
    const authz = new URL(rs.headers.get('location'));
    assert.equal(authz.searchParams.get('client_id'), ENV.R360_WRITE_CLIENT_ID);
    assert.equal(authz.searchParams.get('redirect_uri'), config.writeRedirectUri);
    assert.equal(authz.searchParams.get('code_challenge_method'), 'S256');
    assert.match(authz.searchParams.get('nonce'), /^[0-9a-f]{48}$/);
    assert.equal(authz.searchParams.get('login_hint'), 'admin@contoso.com');
    assert.ok(!authz.searchParams.get('prompt'), 'silent SSO when possible');
    const scopes = authz.searchParams.get('scope').split(' ').filter(s => s.startsWith('https://'));
    assert.deepEqual(scopes, WRITE_SCOPES, 'the write app asks for nothing but DeviceManagementScripts.ReadWrite.All');
    const { code, state } = st.entra.authorize(authz.href);
    rs = await fetch(`${base}/auth/write/callback?code=${code}&state=${state}`, { redirect: 'manual', headers: h });
    assert.equal(rs.status, 302);
    const form = st.entra.posts.at(-1);
    assert.equal(form.client_id, ENV.R360_WRITE_CLIENT_ID); assert.equal(form.client_assertion, 'MI-ASSERTION'); assert.ok(!('client_secret' in form));
    const me = await (await fetch(`${base}/api/me`, { headers: h })).json();
    assert.equal(me.write.active, true);
    assert.ok(Math.abs(Date.parse(me.write.until) - Date.now() - 480 * 60000) < 5000);
    const ev = st.events.find(e => e.action === 'session.elevate');
    assert.equal(ev.actorOid, OID); assert.equal(ev.graphRequestId, 'graph-1'); assert.deepEqual(ev.acrs, ['c1']);
    assert.equal(st.graphCalls.length, 1); assert.match(st.graphCalls[0].auth, /^Bearer eyJ/);
    // The write token lives only in the write app's own cache; read token is still the web app's.
    const s = [...st.sessions.map.values()][0];
    assert.ok(await st.auth.writeToken(s.write.homeAccountId).then(t => t.startsWith('eyJ')));
    assert.ok(!JSON.stringify(st.events).includes('eyJ'), 'no token in the audit trail');
    // Ending drops the write account from the write cache.
    const end = await fetch(`${base}/auth/write/end`, { method: 'POST', headers: { ...h, origin: config.publicUrl, 'x-r360-csrf': csrf, 'content-type': 'application/json' }, body: '{}' });
    assert.equal(end.status, 200);
    await assert.rejects(st.auth.writeToken(s.write?.homeAccountId || 'gone'), /write session is gone/);
    assert.equal((await (await fetch(`${base}/api/me`, { headers: h })).json()).write.active, false);
  });
});

test('real MSAL: elevation for a different account is refused, audited, and its token dropped', async () => {
  const st = stack();
  await serve(st.app, async base => {
    const { h } = await signIn(base, st.entra);
    const rs = await fetch(`${base}/auth/write/start`, { redirect: 'manual', headers: h });
    const { code, state } = st.entra.authorize(rs.headers.get('location'), { oid: OTHER });
    const cb = await fetch(`${base}/auth/write/callback?code=${code}&state=${state}`, { redirect: 'manual', headers: h });
    assert.equal(cb.status, 403);
    assert.equal((await (await fetch(`${base}/api/me`, { headers: h })).json()).write.active, false);
    const d = st.events.find(e => e.action === 'session.elevate.denied');
    assert.equal(d.reason, 'oid-mismatch'); assert.equal(d.approverOid, OTHER);
    assert.equal(st.graphCalls.length, 0, 'the foreign token was never used');
    // A write response carrying a wrong nonce is refused too.
    st.entra.nonceOverride = 'forged';
    const rs2 = await fetch(`${base}/auth/write/start`, { redirect: 'manual', headers: h });
    const a2 = st.entra.authorize(rs2.headers.get('location'));
    const cb2 = await fetch(`${base}/auth/write/callback?code=${a2.code}&state=${a2.state}`, { redirect: 'manual', headers: h });
    assert.equal(cb2.status, 403);
    assert.equal((await (await fetch(`${base}/api/me`, { headers: h })).json()).write.active, false);
    assert.equal(st.events.filter(e => e.action === 'session.elevate.denied').length, 2);
  });
});

