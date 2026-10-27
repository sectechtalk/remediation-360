import { createHash } from 'node:crypto';
import { VAULT_RESOURCE } from './identity.mjs';

// r360 reads GitHub as the GitHub App r360-github-app. The app JWT (RS256) is signed by the Key Vault key
// github-app-r360 (RSA-HSM, non-exportable) through the managed identity. The key never leaves Key Vault and no
// personal access token is used. Installation tokens live in memory only and are narrowed to read access.

export const b64url = buf => Buffer.from(buf).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');

export function jwtSigningInput({ appId, now = Date.now() }) {
  const iat = Math.floor(now / 1000) - 60;
  const header = { alg: 'RS256', typ: 'JWT' };
  const payload = { iat, exp: iat + 540, iss: String(appId) };
  return `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
}

export function createGitHubApp({ config, miToken, fetcher = fetch, now = () => Date.now() }) {
  const api = 'https://api.github.com';
  const ua = { 'User-Agent': 'r360', 'X-GitHub-Api-Version': '2022-11-28' };
  let inst = null;

  async function appJwt() {
    const input = jwtSigningInput({ appId: config.githubAppId, now: now() });
    const digest = b64url(createHash('sha256').update(input).digest());
    const vt = await miToken(VAULT_RESOURCE);
    const res = await fetcher(`${config.vaultUri}/keys/${encodeURIComponent(config.githubKeyName)}/sign?api-version=7.4`, {
      method: 'POST', headers: { Authorization: `Bearer ${vt}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ alg: 'RS256', value: digest }), signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) throw new Error(`Key Vault sign with ${config.githubKeyName} failed: HTTP ${res.status}`);
    const { value } = await res.json();
    if (!value) throw new Error('Key Vault sign returned no signature');
    return `${input}.${value}`;
  }

  async function installationToken() {
    if (inst && inst.expires - 300000 > now()) return inst.token;
    const jwt = await appJwt();
    const repoName = config.repo.split('/')[1];
    const res = await fetcher(`${api}/app/installations/${config.githubInstallationId}/access_tokens`, {
      method: 'POST', headers: { ...ua, Accept: 'application/vnd.github+json', Authorization: `Bearer ${jwt}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ repositories: [repoName], permissions: { contents: 'read', metadata: 'read' } }), signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) throw new Error(`GitHub installation token failed: HTTP ${res.status}`);
    const data = await res.json();
    inst = { token: data.token, expires: Date.parse(data.expires_at) };
    return inst.token;
  }

  async function get(path) {
    const token = await installationToken();
    const res = await fetcher(`${api}${path}`, { headers: { ...ua, Accept: 'application/vnd.github+json', Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(20000) });
    if (!res.ok) throw new Error(`GitHub GET ${path} failed: HTTP ${res.status}`);
    return res.json();
  }

  const blobCache = new Map();
  async function blobText(sha) {
    if (blobCache.has(sha)) return blobCache.get(sha);
    const b = await get(`/repos/${config.repo}/git/blobs/${sha}`);
    const text = Buffer.from(b.content || '', b.encoding === 'base64' ? 'base64' : 'utf8').toString('utf8');
    blobCache.set(sha, text);
    return text;
  }

  let snapshot = null;
  // Remediations catalog from merged main: remediations/<folder>/{remediation.json,detect.ps1,remediate.ps1} + approvers.json
  async function catalog() {
    const head = await get(`/repos/${config.repo}/commits/${encodeURIComponent(config.branch)}`);
    if (snapshot && snapshot.sha === head.sha) return snapshot;
    const tree = await get(`/repos/${config.repo}/git/trees/${head.sha}?recursive=1`);
    const files = new Map(tree.tree.filter(t => t.type === 'blob').map(t => [t.path, t.sha]));
    const folders = [...new Set([...files.keys()].map(p => /^remediations\/([^/]+)\/remediation\.json$/.exec(p)?.[1]).filter(Boolean))].sort();
    const items = [];
    for (const f of folders) {
      const base = `remediations/${f}`;
      let meta = null, metaError = null;
      try { meta = JSON.parse(await blobText(files.get(`${base}/remediation.json`))); } catch (e) { metaError = `remediation.json: ${e.message}`; }
      const read = async n => files.has(`${base}/${n}`) ? blobText(files.get(`${base}/${n}`)) : null;
      items.push({ folder: f, path: base, meta, metaError, detect: await read('detect.ps1'), remediate: await read('remediate.ps1') });
    }
    let approvers = null, approversError = null;
    try { approvers = parseApprovers(files.has('approvers.json') ? await blobText(files.get('approvers.json')) : null); } catch (e) { approversError = e.message; }
    snapshot = { sha: head.sha, date: head.commit?.committer?.date || null, message: head.commit?.message?.split('\n')[0] || '', items, approvers, approversError };
    return snapshot;
  }

  return { appJwt, installationToken, catalog };
}

// approvers.json: fail closed when missing or invalid (design section 5).
export const APPROVER_ROLES = ['author', 'approver', 'emergencyApprover', 'admin'];
export function parseApprovers(text) {
  if (text == null) throw new Error('approvers.json is missing on main');
  const j = JSON.parse(text);
  if (j.version !== 1 || !Array.isArray(j.approvers)) throw new Error('approvers.json: expected { version: 1, approvers: [] }');
  const seen = new Set();
  return j.approvers.map((a, i) => {
    if (!/^[0-9a-f-]{36}$/i.test(a.entraObjectId || '')) throw new Error(`approvers.json: entry ${i} has no valid entraObjectId`);
    if (seen.has(a.entraObjectId.toLowerCase())) throw new Error(`approvers.json: duplicate ${a.entraObjectId}`);
    seen.add(a.entraObjectId.toLowerCase());
    const roles = Array.isArray(a.roles) ? a.roles : [];
    const bad = roles.filter(r => !APPROVER_ROLES.includes(r));
    if (bad.length) throw new Error(`approvers.json: unknown role(s) ${bad.join(', ')}`);
    return { entraObjectId: a.entraObjectId.toLowerCase(), upn: a.upn || '', roles };
  });
}
