import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { generateKeyPairSync, createSign } from 'node:crypto';
import { createTokenVerifier, createEx360Snapshots, createSnapshotStore, snapshotSettings, checkSnapshot, SNAPSHOT_SCOPE } from '../server/ex360-snapshots.mjs';

const TENANT = '11111111-1111-4111-8111-111111111111';
const WEB = '22222222-2222-4222-8222-222222222222';
const OID = '33333333-3333-4333-8333-333333333333';
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', use: 'sig' };
const b64 = o => Buffer.from(JSON.stringify(o)).toString('base64url');
const NOW = Date.parse('2026-11-26T20:00:00Z');
function token(claims = {}, key = privateKey, kid = 'k1') {
  const body = { tid: TENANT, iss: `https://login.microsoftonline.com/${TENANT}/v2.0`, aud: `api://${WEB}`, scp: `${SNAPSHOT_SCOPE} openid`, oid: OID, preferred_username: 'admin@contoso.com', exp: NOW / 1000 + 600, nbf: NOW / 1000 - 60, ...claims };
  const input = `${b64({ alg: 'RS256', kid, typ: 'JWT' })}.${b64(body)}`;
  return `${input}.${createSign('RSA-SHA256').update(input).sign(key).toString('base64url')}`;
}
const jwksFetch = async () => ({ ok: true, json: async () => ({ keys: [jwk] }) });
const verify = createTokenVerifier({ tenantId: TENANT, audiences: [WEB, `api://${WEB}`], fetcher: jwksFetch, now: () => NOW });

function snapshot(extra = {}) {
  return { format: 'sectechtalk.mailflow-config', version: 1, readOnly: true, generatedAt: '2026-11-26T19:59:00Z', tenant: { organization: 'contoso.onmicrosoft.com', tenantId: TENANT },
    summary: { sections: 2, ok: 1, empty: 1 }, sections: { a: { status: 'ok', items: [{ Name: 'x' }] }, b: { status: 'empty', items: [] } },
    snapshot: { name: 'ex360-snapshot-contoso.onmicrosoft.com-20261126-195900.json', takenAt: '2026-11-26T19:59:00Z', takenBy: 'admin@contoso.com', label: 'Baseline' }, ...extra };
}

test('a good token is accepted and names the user', async () => {
  const u = await verify(token());
  assert.equal(u.oid, OID);
  assert.equal(u.upn, 'admin@contoso.com');
});

test('bad tokens are refused with the reason', async () => {
  const other = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
  await assert.rejects(verify(token({}, other)), /signature/);
  await assert.rejects(verify(token({ tid: '44444444-4444-4444-8444-444444444444' })), /another tenant/);
  await assert.rejects(verify(token({ aud: 'api://other' })), /not for r360/);
  await assert.rejects(verify(token({ scp: 'User.Read' })), /Snapshots\.ReadWrite/);
  await assert.rejects(verify(token({ exp: NOW / 1000 - 3600 })), /expired/);
  await assert.rejects(verify(token({}, privateKey, 'unknown')), /unknown key/);
  await assert.rejects(verify('nope'), /bearer/);
});

test('settings: off without a repository, and the repository must share the r360 owner', () => {
  assert.equal(snapshotSettings({}, { repo: 'contoso/remediations', webClientId: WEB }).configured, false);
  const s = snapshotSettings({ R360_EX360_SNAPSHOT_REPO: 'contoso/ex360-snapshots' }, { repo: 'contoso/remediations', webClientId: WEB });
  assert.equal(s.configured, true);
  assert.deepEqual(s.audiences, [WEB, `api://${WEB}`]);
  assert.throws(() => snapshotSettings({ R360_EX360_SNAPSHOT_REPO: 'other/x' }, { repo: 'contoso/remediations' }), /same owner/);
});

test('snapshots with secrets, a bad name or the wrong format are refused', () => {
  const ok = snapshot();
  assert.equal(checkSnapshot(ok, JSON.stringify(ok)), '');
  assert.match(checkSnapshot({ ...ok, format: 'x' }, '{}'), /not a mail flow/);
  assert.match(checkSnapshot({ ...ok, snapshot: { name: '../x.json' } }, '{}'), /file name/);
  const jwt = ['ey', 'JhbGciOiJIUzI1NiJ9.', 'eyJzdWIiOiIxMjM0NTY3ODkwIn0.', 'abcdefghijklmnop'].join('');
  assert.match(checkSnapshot(ok, JSON.stringify({ ...ok, note: jwt })), /JSON Web Token/);
});

async function serve({ roles = ['author'], configured = true, store } = {}) {
  const saved = [];
  const audits = [];
  const fakeStore = store || {
    list: async () => saved.map(s => s.entry),
    get: async name => saved.find(s => s.name === name)?.text ?? null,
    save: async (name, text, entry, message) => { saved.push({ name, text, entry, message }); return { commit: 'a'.repeat(40) }; },
  };
  const app = express();
  app.use(createEx360Snapshots({
    config: {}, settings: { configured, repo: 'contoso/ex360-snapshots', branch: 'main' }, github: {}, audit: { record: async e => audits.push(e) },
    resolveRoles: async (g, oid) => ({ roles: oid === OID ? roles : [], approversError: null }), verify, store: fakeStore, log: { error() {} },
  }));
  const server = await new Promise(r => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  return { base, saved, audits, close: () => new Promise(r => server.close(r)) };
}
const auth = t => ({ authorization: `Bearer ${t}`, 'content-type': 'application/json' });

test('save, list and read a snapshot with a bearer token; each save is audited', async () => {
  const s = await serve();
  try {
    let res = await fetch(`${s.base}/api/ex360/snapshots`, { method: 'POST', headers: auth(token()), body: JSON.stringify(snapshot()) });
    const body = await res.json();
    assert.equal(res.status, 200, body.message);
    assert.equal(body.name, 'ex360-snapshot-contoso.onmicrosoft.com-20261126-195900.json');
    assert.equal(s.saved[0].entry.label, 'Baseline');
    assert.match(s.saved[0].message, /Taken by admin@contoso\.com/);
    assert.equal(s.audits[0].action, 'ex360.snapshot.save');
    assert.equal(s.audits[0].result, 'ok');
    res = await fetch(`${s.base}/api/ex360/snapshots`, { headers: auth(token()) });
    assert.equal((await res.json()).value.length, 1);
    res = await fetch(`${s.base}/api/ex360/snapshots/${body.name}`, { headers: auth(token()) });
    assert.equal((await res.json()).snapshot.label, 'Baseline');
    res = await fetch(`${s.base}/api/ex360/snapshots/ex360-snapshot-x-20260101-000000.json`, { headers: auth(token()) });
    assert.equal(res.status, 404);
  } finally { await s.close(); }
});

test('no token, no role, a read-only role or storage not set up are each refused', async () => {
  let s = await serve();
  try {
    assert.equal((await fetch(`${s.base}/api/ex360/snapshots`)).status, 401);
    assert.equal((await fetch(`${s.base}/api/ex360/snapshots`, { headers: auth(token({ oid: '55555555-5555-4555-8555-555555555555' })) })).status, 403);
  } finally { await s.close(); }
  s = await serve({ roles: ['approver'] });
  try {
    const res = await fetch(`${s.base}/api/ex360/snapshots`, { method: 'POST', headers: auth(token()), body: JSON.stringify(snapshot()) });
    assert.equal(res.status, 403);
    assert.match((await res.json()).message, /author or admin/);
    assert.equal((await fetch(`${s.base}/api/ex360/snapshots`, { headers: auth(token()) })).status, 200);
  } finally { await s.close(); }
  s = await serve({ configured: false });
  try { assert.equal((await fetch(`${s.base}/api/ex360/snapshots`, { headers: auth(token()) })).status, 503); } finally { await s.close(); }
});

test('the GitHub store commits the snapshot and index.json together on main', async () => {
  const calls = [];
  const files = {};
  const fetcher = async (url, init = {}) => {
    const path = url.replace('https://api.github.com', '');
    calls.push(`${init.method || 'GET'} ${path.replace(/\?.*/, '')}`);
    const ok = v => ({ ok: true, status: 200, json: async () => v, text: async () => '' });
    if (path.startsWith('/repos/contoso/ex360-snapshots/contents/snapshots/index.json')) return files.index ? ok({ content: Buffer.from(files.index).toString('base64') }) : { ok: false, status: 404, text: async () => '' };
    if (path.endsWith('/git/ref/heads/main')) return ok({ object: { sha: 'p'.repeat(40) } });
    if (path.includes('/git/commits/') && (init.method || 'GET') === 'GET') return ok({ tree: { sha: 't0' } });
    if (path.endsWith('/git/blobs')) return ok({ sha: 'b1' });
    if (path.endsWith('/git/trees')) { const body = JSON.parse(init.body); files.index = body.tree[1].content; return ok({ sha: 't1' }); }
    if (path.endsWith('/git/commits')) return ok({ sha: 'c'.repeat(40) });
    if (path.endsWith('/git/refs/heads/main')) return ok({});
    throw new Error(`unexpected ${path}`);
  };
  const github = { repoToken: async (perm, what, repo) => { assert.equal(repo, 'contoso/ex360-snapshots'); return `tok-${perm.contents}`; } };
  const store = createSnapshotStore({ settings: { repo: 'contoso/ex360-snapshots', branch: 'main' }, github, fetcher });
  const r = await store.save('ex360-snapshot-contoso-20261126-195900.json', '{}', { name: 'ex360-snapshot-contoso-20261126-195900.json', takenAt: '2026-11-26T19:59:00Z' }, 'msg');
  assert.equal(r.commit, 'c'.repeat(40));
  assert.ok(calls.includes('PATCH /repos/contoso/ex360-snapshots/git/refs/heads/main'));
  assert.equal(JSON.parse(files.index).snapshots.length, 1);
  assert.equal((await store.list()).length, 1);
});
