import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createVerify, privateEncrypt, constants } from 'node:crypto';
import { createGitHubApp, jwtSigningInput, parseApprovers, b64url } from '../server/github.mjs';
import { createGraph } from '../server/graph.mjs';
import { createManagedIdentity } from '../server/identity.mjs';
import { createApp } from '../server/app.mjs';
import { SessionStore, checkCallback, userFromClaims, parseCookies, SESSION_COOKIE } from '../server/auth.mjs';
import { loadConfig } from '../server/config.mjs';
import { ENV } from './fixtures.mjs';

const config = loadConfig(ENV);
const json = (body, status = 200, headers = {}) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });

test('managed identity token uses id-r360 client_id and caches', async () => {
  let calls = 0;
  const mi = createManagedIdentity({ clientId: 'cid', env: { IDENTITY_ENDPOINT: 'http://169.254.0.1/msi/token', IDENTITY_HEADER: 'h' }, fetcher: async (url, opt) => {
    calls++; assert.equal(url.searchParams.get('client_id'), 'cid'); assert.equal(opt.headers['X-IDENTITY-HEADER'], 'h');
    return json({ access_token: 'T', expires_on: String(Math.floor(Date.now() / 1000) + 3600) }); } });
  assert.equal(await mi('api://AzureADTokenExchange'), 'T'); await mi('api://AzureADTokenExchange');
  assert.equal(calls, 1);
  await assert.rejects(createManagedIdentity({ clientId: 'c', env: {} })('x'), /not available/);
});

test('GitHub App JWT is signed by Key Vault (RS256), token narrowed to read, catalog parsed', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const blobs = {
    m: JSON.stringify({ displayName: 'STT - Remediation Canary', runAs: 'system' }), d: 'exit 0', r: 'fix',
    a: JSON.stringify({ version: 1, approvers: [{ entraObjectId: '94540000-0000-4000-8000-0000000000c3', upn: 'admin@contoso.com', roles: ['author', 'approver'] }] }),
  };
  let jwt = null, tokenBody = null;
  const fetcher = async (url, opt = {}) => {
    const u = String(url);
    if (u.startsWith('https://kv-r360-abc123.vault.azure.net/keys/github-app-r360/sign')) {
      assert.equal(opt.headers.Authorization, 'Bearer VT');
      const { alg, value } = JSON.parse(opt.body); assert.equal(alg, 'RS256');
      // Emulate Key Vault: sign the given SHA-256 digest (PKCS#1 v1.5).
      const sig = privateEncrypt({ key: privateKey, padding: constants.RSA_PKCS1_PADDING }, Buffer.concat([Buffer.from('3031300d060960864801650304020105000420', 'hex'), Buffer.from(value, 'base64url')]));
      return json({ value: b64url(sig) });
    }
    if (u.endsWith('/app/installations/12345678/access_tokens')) { jwt = opt.headers.Authorization.slice(7); tokenBody = JSON.parse(opt.body); return json({ token: 'IT', expires_at: new Date(Date.now() + 3600e3).toISOString() }); }
    assert.equal(opt.headers.Authorization, 'Bearer IT');
    if (u.endsWith('/commits/main')) return json({ sha: 'abc123def456', commit: { message: 'msg\nbody', committer: { date: '2026-10-26T15:00:00Z' } } });
    if (u.includes('/git/trees/abc123def456')) return json({ tree: [
      { type: 'blob', path: 'remediations/Canary/remediation.json', sha: 'm' }, { type: 'blob', path: 'remediations/Canary/detect.ps1', sha: 'd' },
      { type: 'blob', path: 'remediations/Canary/remediate.ps1', sha: 'r' }, { type: 'blob', path: 'approvers.json', sha: 'a' }, { type: 'blob', path: 'README.md', sha: 'x' }] });
    const m = /\/git\/blobs\/(\w+)$/.exec(u);
    if (m) return json({ encoding: 'base64', content: Buffer.from(blobs[m[1]]).toString('base64') });
    throw new Error('unexpected ' + u);
  };
  const gh = createGitHubApp({ config, miToken: async r => { assert.equal(r, 'https://vault.azure.net'); return 'VT'; }, fetcher });
  const cat = await gh.catalog();
  assert.equal(cat.items.length, 1); assert.equal(cat.items[0].detect, 'exit 0'); assert.equal(cat.message, 'msg');
  assert.equal(cat.approvers[0].entraObjectId, '94540000-0000-4000-8000-0000000000c3');
  assert.deepEqual(tokenBody, { repositories: ['remediations'], permissions: { contents: 'read', metadata: 'read' } });
  const [h, p, s] = jwt.split('.');
  assert.equal(JSON.parse(Buffer.from(p, 'base64url')).iss, '1234567');
  assert.ok(createVerify('RSA-SHA256').update(`${h}.${p}`).verify(publicKey, Buffer.from(s, 'base64url')), 'JWT verifies with the app public key');
  assert.match(jwtSigningInput({ appId: 1 }), /^[\w-]+\.[\w-]+$/);
});

test('approvers.json fails closed', () => {
  assert.throws(() => parseApprovers(null), /missing/);
  assert.throws(() => parseApprovers('{"version":2,"approvers":[]}'), /version/);
  assert.throws(() => parseApprovers('{"version":1,"approvers":[{"entraObjectId":"x"}]}'), /entraObjectId/);
  assert.throws(() => parseApprovers('{"version":1,"approvers":[{"entraObjectId":"94540000-0000-4000-8000-0000000000c3","roles":["god"]}]}'), /unknown role/);
});

test('graph pages through nextLink and waits on 429 automatically', async () => {
  let n = 0; const slept = [];
  const g = createGraph({ sleep: async ms => slept.push(ms), fetcher: async url => {
    n++;
    if (n === 1) return new Response('', { status: 429, headers: { 'retry-after': '2' } });
    if (String(url).includes('skip')) return json({ value: [2] });
    return json({ value: [1], '@odata.nextLink': 'https://graph.microsoft.com/beta/x?skip=1' });
  } });
  assert.deepEqual(await g.all('t', '/beta/x'), [1, 2]);
  assert.deepEqual(slept, [2000]);
  const g2 = createGraph({ fetcher: async () => json({ value: [], '@odata.nextLink': 'https://evil.example.com/x' }) });
  await assert.rejects(g2.all('t', '/beta/x').then(() => g2.all('t', 'https://graph.microsoft.com/beta/y')), /Unexpected nextLink host/);
});

test('auth helpers', () => {
  assert.match(checkCallback(null, {}), /No sign-in/);
  const p = { state: 's', created: Date.now() };
  assert.match(checkCallback(p, { state: 'x', code: '0123456789' }), /did not match/);
  assert.equal(checkCallback(p, { state: 's', code: '0123456789' }), null);
  assert.throws(() => userFromClaims({ tid: 'other' }, { tenantId: ENV.ENTRA_TENANT_ID, clientId: ENV.R360_WEB_CLIENT_ID }), /tenant/);
  assert.equal(userFromClaims({ tid: ENV.ENTRA_TENANT_ID, aud: ENV.R360_WEB_CLIENT_ID, oid: '94540000-0000-4000-8000-0000000000c3', preferred_username: 'a@b' }, { tenantId: ENV.ENTRA_TENANT_ID, clientId: ENV.R360_WEB_CLIENT_ID }).oid, '94540000-0000-4000-8000-0000000000c3');
  assert.equal(parseCookies('a=1; __Host-r360=abc')[SESSION_COOKIE], 'abc');
});

async function withServer(deps, fn) {
  const app = createApp({ config, log: { error() {} }, ...deps });
  const srv = app.listen(0); await new Promise(r => srv.once('listening', r));
  try { await fn(`http://127.0.0.1:${srv.address().port}`); } finally { srv.close(); }
}

test('HTTP: unauthenticated users go to Entra sign-in, APIs return 401, read-only API', async () => {
  const sessions = new SessionStore();
  const auth = { beginSignIn: async () => 'https://login.microsoftonline.com/t/oauth2/v2.0/authorize?client_id=x', graphToken: async () => 'GT', completeSignIn: async (s) => { s.user = { oid: 'o', upn: 'u', name: 'n' }; }, signOut: async () => {} };
  const data = { remediations: async t => ({ token: t === 'GT', rows: [] }), fleet: async () => ({ rows: [] }), certificates: async () => ({}), pim: async () => ({}) };
  const github = { catalog: async () => ({ approvers: [{ entraObjectId: 'o', roles: ['approver'] }] }) };
  const audit = { record: async e => e, list: async () => ({ rows: [], truncated: false }) };
  await withServer({ sessions, auth, data, github, audit }, async base => {
    let r = await fetch(`${base}/`, { redirect: 'manual' });
    assert.equal(r.status, 302); assert.equal(r.headers.get('location'), '/auth/signin');
    assert.match(r.headers.get('content-security-policy'), /default-src 'self'/);
    r = await fetch(`${base}/api/remediations`); assert.equal(r.status, 401);
    r = await fetch(`${base}/healthz`); assert.equal(r.status, 200);
    r = await fetch(`${base}/auth/signin`, { redirect: 'manual' });
    assert.equal(r.status, 302); assert.match(r.headers.get('location'), /^https:\/\/login\.microsoftonline\.com\//);
    const cookie = r.headers.get('set-cookie'); assert.match(cookie, /__Host-r360=.*Secure; HttpOnly; SameSite=Lax/);
    const sid = /__Host-r360=([^;]+)/.exec(cookie)[1];
    sessions.get(sid).pending = { state: 's', created: Date.now() };
    r = await fetch(`${base}/auth/callback?state=s&code=0123456789`, { redirect: 'manual', headers: { cookie: `__Host-r360=${sid}` } });
    assert.equal(r.status, 302);
    const h = { cookie: `__Host-r360=${sid}` };
    r = await fetch(`${base}/api/remediations`, { headers: h }); assert.equal(r.status, 200); assert.equal((await r.json()).token, true);
    r = await fetch(`${base}/api/me`, { headers: h }); assert.deepEqual((await r.json()).roles, ['approver']);
    r = await fetch(`${base}/api/remediations`, { method: 'POST', headers: h }); assert.equal(r.status, 403); // no origin / CSRF token: blocked before routing
    const csrf = (await (await fetch(`${base}/api/me`, { headers: h })).json()).csrf;
    r = await fetch(`${base}/api/remediations`, { method: 'POST', headers: { ...h, origin: config.publicUrl, 'x-r360-csrf': csrf, 'content-type': 'application/json' }, body: '{}' }); assert.equal(r.status, 404);
    r = await fetch(`${base}/`, { headers: h }); assert.equal(r.status, 200); assert.match(await r.text(), /Remediations/);
    r = await fetch(`${base}/api/settings`, { headers: h }); assert.ok(!/secret/i.test(await r.text()));
    r = await fetch(`${base}/auth/signout`, { method: 'POST', redirect: 'manual', headers: { ...h, origin: 'https://evil.example.com' } }); assert.equal(r.status, 403);
    r = await fetch(`${base}/auth/signout`, { method: 'POST', redirect: 'manual', headers: h }); assert.equal(r.status, 303);
    r = await fetch(`${base}/api/me`, { headers: h }); assert.equal(r.status, 401);
  });
});
