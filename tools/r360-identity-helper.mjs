// r360 local identity helper (DEVICE02). Runs on the host as SYSTEM, started by the scheduled task that
// tools/Install-R360Local.ps1 registers. It serves tokens for this PC's Azure Arc managed identity to the local r360
// container over the same protocol Azure Container Apps uses (IDENTITY_ENDPOINT + X-IDENTITY-HEADER), so r360's own
// code is unchanged: no secret, certificate or key reaches the container, only short-lived tokens.
//
// Guard rails: listens on 127.0.0.1 only, every request needs the shared header value from the install's data folder,
// and only the three resources r360 uses can be requested. Tokens are never logged.
import http from 'node:http';
import { readFileSync, appendFileSync, mkdirSync } from 'node:fs';
import { timingSafeEqual } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const DATA = process.env.R360_LOCAL_DATA || 'C:\\ProgramData\\r360-local';
const PORT = Number(process.env.R360_IDENTITY_PORT || 3661);
const ARC = process.env.R360_ARC_ENDPOINT || 'http://localhost:40342/metadata/identity/oauth2/token';
const TOKENS_DIR = 'c:\\programdata\\azureconnectedmachineagent\\tokens\\';
export const ALLOWED = new Set(['api://AzureADTokenExchange', 'https://vault.azure.net', 'https://storage.azure.com/']);

const LOG_DIR = path.join(DATA, 'logs');
const log = msg => { try { mkdirSync(LOG_DIR, { recursive: true }); appendFileSync(path.join(LOG_DIR, 'identity-helper.log'), `${new Date().toISOString()} ${msg}\n`); } catch { /* logging never breaks token service */ } };

const secret = () => readFileSync(path.join(DATA, 'identity-header'), 'utf8').trim();
const same = (a, b) => typeof a === 'string' && a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));

// Arc's challenge flow: the first call returns 401 with a key file path that only SYSTEM/Administrators can read.
export async function arcToken(resource, { fetcher = fetch, read = p => readFileSync(p, 'utf8') } = {}) {
  const url = `${ARC}?api-version=2020-06-01&resource=${encodeURIComponent(resource)}`;
  const first = await fetcher(url, { headers: { Metadata: 'true' }, signal: AbortSignal.timeout(15000) });
  if (first.ok) return first.json();
  const realm = /realm=([^,\s]+)/i.exec(first.headers.get('www-authenticate') || '')?.[1] || '';
  if (first.status !== 401 || !realm.toLowerCase().startsWith(TOKENS_DIR) || !realm.toLowerCase().endsWith('.key') || realm.includes('..')) {
    throw new Error(`Arc identity endpoint answered HTTP ${first.status} without a usable challenge`);
  }
  const res = await fetcher(url, { headers: { Metadata: 'true', Authorization: `Basic ${read(realm).trim()}` }, signal: AbortSignal.timeout(15000) });
  if (!res.ok) throw new Error(`Arc identity token for ${resource} failed: HTTP ${res.status}`);
  return res.json();
}

export function createHelper({ getSecret = secret, getToken = arcToken, now = () => Date.now() } = {}) {
  const cache = new Map();
  return async (req, res) => {
    const send = (code, body) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(body)); };
    const u = new URL(req.url, 'http://127.0.0.1');
    if (req.method !== 'GET' || u.pathname !== '/token') return send(404, { error: 'not found' });
    if (!same(req.headers['x-identity-header'], getSecret())) { log('denied: bad or missing X-IDENTITY-HEADER'); return send(401, { error: 'unauthorized' }); }
    const resource = u.searchParams.get('resource') || '';
    if (!ALLOWED.has(resource)) { log(`denied: resource ${resource.slice(0, 80)} is not on the allow list`); return send(403, { error: 'resource not allowed' }); }
    try {
      const hit = cache.get(resource);
      if (!hit || Number(hit.expires_on) * 1000 - 300000 < now()) {
        const t = await getToken(resource);
        if (!t?.access_token || !Number.isFinite(Number(t.expires_on))) throw new Error('Arc returned an unexpected token response');
        cache.set(resource, { access_token: t.access_token, expires_on: String(t.expires_on), resource, token_type: 'Bearer' });
        log(`issued ${resource}, expires ${new Date(Number(t.expires_on) * 1000).toISOString()}`);
      }
      return send(200, cache.get(resource));
    } catch (e) {
      log(`error ${resource}: ${e.message}`);
      return send(502, { error: e.message });
    }
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const handler = createHelper();
  http.createServer((req, res) => { handler(req, res).catch(() => { try { res.writeHead(500); res.end(); } catch { /* closed */ } }); })
    .listen(PORT, '127.0.0.1', () => log(`listening on 127.0.0.1:${PORT}`));
}
