// Exchange 360 config snapshots, kept by r360 (2026-11-26, Aaron: snapshots are stored "Only in r360").
// Exchange 360 reads the mail flow configuration on the owner's PC (read-only Get- cmdlets) and sends the JSON here
// with the signed-in person's own Entra token for r360's API (scope Snapshots.ReadWrite). r360 checks the token
// (signature, tenant, audience, scope) and the person's approvers.json role, then commits the file to the private
// snapshots repository with the r360 GitHub App. Every snapshot is one commit: Git keeps the history.
// Off until R360_EX360_SNAPSHOT_REPO is set. Nothing here touches Exchange Online or Intune.
import express from 'express';
import { createPublicKey, createVerify } from 'node:crypto';
import { sameOwner } from './deploy-targets.mjs';

export const SNAPSHOT_SCOPE = 'Snapshots.ReadWrite';
export const SAVE_ROLES = ['author', 'admin'];
export const SNAPSHOT_FORMAT = 'sectechtalk.mailflow-config';
const NAME = /^ex360-snapshot-[a-z0-9.-]{1,60}-\d{8}-\d{6}\.json$/;
const MAX_BYTES = 20 * 1024 * 1024;
const SECRET_PATTERNS = [
  ['JSON Web Token', /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/],
  ['private key block', /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
  ['SAS signature', /[?&]sig=[A-Za-z0-9%+/=]{20,}/],
];

export function snapshotSettings(env = process.env, config = {}) {
  const repo = String(env.R360_EX360_SNAPSHOT_REPO || '').trim();
  if (repo && !/^[A-Za-z0-9-]+\/[A-Za-z0-9._-]+$/.test(repo)) throw new Error('R360_EX360_SNAPSHOT_REPO must be owner/repo');
  if (repo && config.repo && !sameOwner(repo, config.repo)) throw new Error(`R360_EX360_SNAPSHOT_REPO must belong to the same owner as ${config.repo}`);
  const extra = String(env.R360_EX360_API_AUDIENCE || '').trim();
  const audiences = [config.webClientId, config.webClientId ? `api://${config.webClientId}` : '', extra].filter(Boolean);
  return { configured: Boolean(repo), repo, branch: String(env.R360_EX360_SNAPSHOT_BRANCH || 'main'), audiences };
}

const b64urlDecode = s => Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64');

/** Verifies an Entra access token for r360's API. Returns { oid, upn, name } or throws with status 401/403. */
export function createTokenVerifier({ tenantId, audiences, fetcher = fetch, now = () => Date.now() }) {
  let keys = null;
  let keysAt = 0;
  async function jwks(force = false) {
    if (!force && keys && now() - keysAt < 6 * 3600 * 1000) return keys;
    const res = await fetcher(`https://login.microsoftonline.com/${tenantId}/discovery/v2.0/keys`, { signal: AbortSignal.timeout(10000) });
    if (!res.ok) throw Object.assign(new Error(`Entra signing keys could not be read: HTTP ${res.status}`), { status: 503 });
    keys = (await res.json()).keys || [];
    keysAt = now();
    return keys;
  }
  const deny = (message, status = 401) => Object.assign(new Error(message), { status });
  return async function verify(token) {
    const parts = String(token || '').split('.');
    if (parts.length !== 3) throw deny('No bearer token.');
    let header, claims;
    try { header = JSON.parse(b64urlDecode(parts[0])); claims = JSON.parse(b64urlDecode(parts[1])); } catch { throw deny('The token is not readable.'); }
    if (header.alg !== 'RS256' || !header.kid) throw deny('The token is not signed with RS256.');
    let jwk = (await jwks()).find(k => k.kid === header.kid);
    if (!jwk) jwk = (await jwks(true)).find(k => k.kid === header.kid);
    if (!jwk) throw deny('The token was signed with an unknown key.');
    const ok = createVerify('RSA-SHA256').update(`${parts[0]}.${parts[1]}`).verify(createPublicKey({ key: { kty: jwk.kty, n: jwk.n, e: jwk.e }, format: 'jwk' }), b64urlDecode(parts[2]));
    if (!ok) throw deny('The token signature is not valid.');
    const t = Math.floor(now() / 1000);
    if (typeof claims.exp !== 'number' || claims.exp < t - 60) throw deny('The token has expired. Sign in to Exchange 360 again.');
    if (typeof claims.nbf === 'number' && claims.nbf > t + 60) throw deny('The token is not valid yet.');
    if (claims.tid !== tenantId) throw deny('The token is from another tenant.', 403);
    const issuers = [`https://login.microsoftonline.com/${tenantId}/v2.0`, `https://sts.windows.net/${tenantId}/`];
    if (!issuers.includes(claims.iss)) throw deny('The token issuer is not this tenant.', 403);
    if (!audiences.includes(claims.aud)) throw deny('The token is not for r360.', 403);
    const scopes = String(claims.scp || '').split(' ');
    if (!scopes.includes(SNAPSHOT_SCOPE)) throw deny(`The token does not carry the ${SNAPSHOT_SCOPE} permission. An admin grants it to the Exchange 360 app registration.`, 403);
    if (!/^[0-9a-f-]{36}$/i.test(claims.oid || '')) throw deny('The token has no user.', 403);
    return { oid: claims.oid.toLowerCase(), upn: claims.preferred_username || claims.upn || '', name: claims.name || '' };
  };
}

// The facts the list shows for one snapshot. Kept in snapshots/index.json so the list needs one read.
export function describeSnapshot(cfg, name, bytes) {
  const s = cfg?.summary || {};
  return {
    name, bytes,
    takenAt: cfg?.snapshot?.takenAt || cfg?.generatedAt || '',
    takenBy: cfg?.snapshot?.takenBy || cfg?.tenant?.signedInAs || '',
    label: String(cfg?.snapshot?.label || '').slice(0, 120),
    organization: cfg?.tenant?.organization || cfg?.tenant?.defaultDomain || '',
    tenantId: cfg?.tenant?.tenantId || '',
    mailbox: cfg?.mailbox?.address || '',
    sections: s.sections ?? Object.keys(cfg?.sections || {}).length,
    ok: s.ok ?? 0, empty: s.empty ?? 0,
    notRead: (s.error || 0) + (s.unavailable || 0) + (s.skipped || 0),
  };
}

export function checkSnapshot(body, text) {
  if (!body || typeof body !== 'object' || body.format !== SNAPSHOT_FORMAT || body.version !== 1 || !body.sections || typeof body.sections !== 'object') return 'This is not a mail flow configuration snapshot (format sectechtalk.mailflow-config, version 1).';
  if (body.readOnly !== true) return 'The snapshot does not say it was read-only.';
  if (!NAME.test(String(body.snapshot?.name || ''))) return 'The snapshot has no valid file name.';
  const found = SECRET_PATTERNS.filter(([, re]) => re.test(text)).map(([n]) => n);
  if (found.length) return `The snapshot was refused: it contains text shaped like a ${found.join(', ')}. Nothing was stored.`;
  return '';
}

/** GitHub storage: one commit per snapshot (the file plus an updated index.json), on the snapshots repository. */
export function createSnapshotStore({ settings, github, fetcher = fetch }) {
  const api = 'https://api.github.com';
  const ua = { 'User-Agent': 'r360', 'X-GitHub-Api-Version': '2022-11-28', Accept: 'application/vnd.github+json' };
  const { repo, branch } = settings;
  const call = async (token, method, path, body) => {
    const res = await fetcher(`${api}${path}`, { method, headers: { ...ua, Authorization: `Bearer ${token}`, ...(body ? { 'Content-Type': 'application/json' } : {}) }, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(30000) });
    if (!res.ok) {
      const detail = (await res.text().catch(() => '')).slice(0, 200).replace(/\s+/g, ' ');
      throw Object.assign(new Error(`GitHub ${method} ${path.replace(/\?.*/, '')} failed: HTTP ${res.status} ${detail}`.trim()), { status: res.status });
    }
    return res.status === 204 ? null : res.json();
  };
  const read = () => github.repoToken({ contents: 'read', metadata: 'read' }, 'snapshots-read', repo);
  const fileText = async (token, path) => {
    try {
      const f = await call(token, 'GET', `/repos/${repo}/contents/${path}?ref=${encodeURIComponent(branch)}`);
      if (f.content) return Buffer.from(f.content, 'base64').toString('utf8');
      const blob = await call(token, 'GET', `/repos/${repo}/git/blobs/${f.sha}`);
      return Buffer.from(blob.content, 'base64').toString('utf8');
    } catch (e) { if (e.status === 404) return null; throw e; }
  };
  async function list() {
    const token = await read();
    const text = await fileText(token, 'snapshots/index.json');
    const index = text ? JSON.parse(text) : { version: 1, snapshots: [] };
    return (index.snapshots || []).slice().sort((a, b) => String(b.takenAt).localeCompare(String(a.takenAt)));
  }
  async function get(name) {
    if (!NAME.test(name)) return null;
    const text = await fileText(await read(), `snapshots/${name}`);
    return text == null ? null : text;
  }
  async function save(name, text, entry, message) {
    const token = await github.repoToken({ contents: 'write', metadata: 'read' }, 'snapshots-write', repo);
    // Retry once if main moved between reading the index and writing (two snapshots at the same moment).
    for (let attempt = 0; ; attempt += 1) {
      const ref = await call(token, 'GET', `/repos/${repo}/git/ref/heads/${encodeURIComponent(branch)}`);
      const current = await fileText(token, 'snapshots/index.json');
      const index = current ? JSON.parse(current) : { version: 1, snapshots: [] };
      index.snapshots = [...(index.snapshots || []).filter(s => s.name !== name), entry];
      const parent = await call(token, 'GET', `/repos/${repo}/git/commits/${ref.object.sha}`);
      const blob = await call(token, 'POST', `/repos/${repo}/git/blobs`, { content: Buffer.from(text).toString('base64'), encoding: 'base64' });
      const tree = await call(token, 'POST', `/repos/${repo}/git/trees`, { base_tree: parent.tree.sha, tree: [
        { path: `snapshots/${name}`, mode: '100644', type: 'blob', sha: blob.sha },
        { path: 'snapshots/index.json', mode: '100644', type: 'blob', content: `${JSON.stringify(index, null, 2)}\n` },
      ] });
      const commit = await call(token, 'POST', `/repos/${repo}/git/commits`, { message, tree: tree.sha, parents: [ref.object.sha] });
      try {
        await call(token, 'PATCH', `/repos/${repo}/git/refs/heads/${encodeURIComponent(branch)}`, { sha: commit.sha, force: false });
        return { commit: commit.sha };
      } catch (e) { if (attempt >= 1 || e.status !== 422) throw e; }
    }
  }
  return { list, get, save };
}

/**
 * The /api/ex360/snapshots routes. Mounted before r360's browser sign-in: the caller is the Exchange 360 server,
 * which sends the person's bearer token. No cookie is read, so the CSRF guard does not apply.
 */
export function createEx360Snapshots({ config, settings, github, audit, resolveRoles, verify, store, log = console }) {
  const router = express.Router();
  const json = express.json({ limit: MAX_BYTES, type: 'application/json' });
  const off = res => res.status(503).json({ ok: false, configured: false, message: 'Snapshot storage in r360 is not set up yet (R360_EX360_SNAPSHOT_REPO is not set).' });
  const who = async (req, res) => {
    const m = /^Bearer\s+(\S+)$/.exec(req.get('authorization') || '');
    try {
      const user = await verify(m ? m[1] : '');
      const { roles, approversError } = await resolveRoles(github, user.oid);
      if (!roles.length) { res.status(403).json({ ok: false, message: approversError ? `r360 could not read approvers.json: ${approversError}` : `${user.upn || user.oid} has no r360 role in approvers.json.` }); return null; }
      return { ...user, roles };
    } catch (e) {
      res.status(e.status === 403 || e.status === 503 ? e.status : 401).json({ ok: false, message: e.message });
      return null;
    }
  };
  const note = async event => { try { await audit.record(event); } catch (e) { log.error?.(`ex360 snapshot audit failed: ${e.message}`); } };

  router.get('/api/ex360/snapshots', async (req, res) => {
    if (!settings.configured) return off(res);
    const user = await who(req, res);
    if (!user) return;
    try { res.json({ ok: true, configured: true, repo: settings.repo, value: await store.list() }); }
    catch (e) { log.error?.(`ex360 snapshots list: ${e.message}`); res.status(502).json({ ok: false, message: `r360 could not read the snapshots: ${e.message}` }); }
  });
  router.get('/api/ex360/snapshots/:name', async (req, res) => {
    if (!settings.configured) return off(res);
    const user = await who(req, res);
    if (!user) return;
    try {
      const text = await store.get(req.params.name);
      if (text == null) return res.status(404).json({ ok: false, message: `${req.params.name} is not in r360.` });
      res.type('application/json').send(text);
    } catch (e) { log.error?.(`ex360 snapshot read: ${e.message}`); res.status(502).json({ ok: false, message: `r360 could not read the snapshot: ${e.message}` }); }
  });
  router.post('/api/ex360/snapshots', json, async (req, res) => {
    if (!settings.configured) return off(res);
    const user = await who(req, res);
    if (!user) return;
    if (!user.roles.some(r => SAVE_ROLES.includes(r))) return res.status(403).json({ ok: false, message: `Saving a snapshot needs the ${SAVE_ROLES.join(' or ')} role in approvers.json.` });
    const text = JSON.stringify(req.body, null, 2);
    const problem = checkSnapshot(req.body, text);
    if (problem) {
      await note({ actorOid: user.oid, actorUpn: user.upn, action: 'ex360.snapshot.save', result: 'denied', target: settings.repo, reason: problem.slice(0, 200) });
      return res.status(400).json({ ok: false, message: problem });
    }
    const name = req.body.snapshot.name;
    const entry = describeSnapshot(req.body, name, Buffer.byteLength(text));
    try {
      const { commit } = await store.save(name, text, entry, `Exchange 360 snapshot ${name}${entry.label ? `: ${entry.label}` : ''}\n\nTaken by ${user.upn || user.oid} (read-only). Saved by r360.`);
      await note({ actorOid: user.oid, actorUpn: user.upn, action: 'ex360.snapshot.save', result: 'ok', target: `${settings.repo}:snapshots/${name}`, gitSha: commit });
      res.json({ ok: true, name, commit, repo: settings.repo, entry });
    } catch (e) {
      log.error?.(`ex360 snapshot save: ${e.message}`);
      await note({ actorOid: user.oid, actorUpn: user.upn, action: 'ex360.snapshot.save', result: 'error', target: settings.repo, reason: e.message.slice(0, 200) });
      res.status(502).json({ ok: false, message: `r360 could not store the snapshot: ${e.message}` });
    }
  });
  return router;
}
