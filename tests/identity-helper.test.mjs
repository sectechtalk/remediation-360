import test from 'node:test';
import assert from 'node:assert/strict';
import { createHelper, arcToken } from '../tools/r360-identity-helper.mjs';

const call = async (handler, { url = '/token?resource=https%3A%2F%2Fvault.azure.net', header = 's3cret', method = 'GET' } = {}) => {
  let code, body;
  const res = { writeHead: c => { code = c; }, end: b => { body = b ? JSON.parse(b) : null; } };
  await handler({ url, method, headers: header ? { 'x-identity-header': header } : {} }, res);
  return { code, body };
};
const exp = () => String(Math.floor(Date.now() / 1000) + 3600);

test('identity helper: needs the shared header, allows only r360 resources, caches tokens', async () => {
  let calls = 0;
  const h = createHelper({ getSecret: () => 's3cret', getToken: async () => { calls++; return { access_token: 'tok', expires_on: exp() }; } });
  assert.equal((await call(h, { header: null })).code, 401);
  assert.equal((await call(h, { header: 's3creX' })).code, 401);
  assert.equal((await call(h, { url: '/token?resource=https%3A%2F%2Fgraph.microsoft.com' })).code, 403);
  assert.equal((await call(h, { url: '/other' })).code, 404);
  const ok = await call(h);
  assert.equal(ok.code, 200);
  assert.equal(ok.body.access_token, 'tok');
  await call(h);
  assert.equal(calls, 1);
  assert.equal((await call(h, { url: '/token?resource=api%3A%2F%2FAzureADTokenExchange' })).code, 200);
});

test('identity helper: Arc challenge only reads a key file in the Arc tokens folder', async () => {
  const challenge = realm => async (url, opt) => opt.headers.Authorization
    ? { ok: true, json: async () => ({ access_token: 'arc', expires_on: exp(), auth: opt.headers.Authorization }) }
    : { ok: false, status: 401, headers: new Headers({ 'www-authenticate': `Basic realm=${realm}` }) };
  const good = await arcToken('https://vault.azure.net', { fetcher: challenge(String.raw`C:\ProgramData\AzureConnectedMachineAgent\Tokens\abc.key`), read: () => 'KEY\n' });
  assert.equal(good.auth, 'Basic KEY');
  await assert.rejects(arcToken('https://vault.azure.net', { fetcher: challenge(String.raw`C:\Users\x\evil.key`), read: () => 'x' }), /challenge/);
  await assert.rejects(arcToken('https://vault.azure.net', { fetcher: challenge(String.raw`C:\ProgramData\AzureConnectedMachineAgent\Tokens\..\..\x.key`), read: () => 'x' }), /challenge/);
});
