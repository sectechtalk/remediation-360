import { createHash } from 'node:crypto';
import { VAULT_RESOURCE } from './identity.mjs';
import { BRANCH_RE, allowedPath } from './remediation-schema.mjs';

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

export function createGitHubApp({ config, miToken, fetcher = fetch, now = () => Date.now(), sleep = ms => new Promise(r => setTimeout(r, ms)) }) {
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

  // One installation token, narrowed to this repository and to exactly the permissions asked for.
  async function mint(permissions, what) {
    const jwt = await appJwt();
    const repoName = config.repo.split('/')[1];
    const res = await fetcher(`${api}/app/installations/${config.githubInstallationId}/access_tokens`, {
      method: 'POST', headers: { ...ua, Accept: 'application/vnd.github+json', Authorization: `Bearer ${jwt}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ repositories: [repoName], permissions }), signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) {
      const detail = (await res.text().catch(() => '')).slice(0, 200).replace(/\s+/g, ' ');
      throw Object.assign(new Error(`GitHub ${what} token failed: HTTP ${res.status}${res.status === 422 || res.status === 403 ? ' (the GitHub App installation may lack a permission: ' + Object.entries(permissions).map(([k, v]) => k + ':' + v).join(', ') + ')' : ''} ${detail}`.trim()), { permission: res.status === 422 || res.status === 403 });
    }
    const data = await res.json();
    return { token: data.token, expires: Date.parse(data.expires_at) };
  }

  async function installationToken() {
    if (inst && inst.expires - 300000 > now()) return inst.token;
    inst = await mint({ contents: 'read', metadata: 'read' }, 'read');
    return inst.token;
  }

  // Reading pull requests and their checks (the Changes tab). Cached, read only, separate from the catalog token so that
  // a missing permission here can never break the Phase 1 pages.
  let readInst = null;
  async function changesToken() {
    if (readInst && readInst.expires - 300000 > now()) return readInst.token;
    readInst = await mint({ contents: 'read', metadata: 'read', pull_requests: 'read', checks: 'read' }, 'changes-read');
    return readInst.token;
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

  // ---- author: branch + pull request in the remediations repo (S3) ----
  // The write token is minted per action, narrowed to this one repository and to contents:write + pull_requests:write, used for
  // that action and dropped. It is never cached and never logged.
  const repo = config.repo;
  const baseBranch = config.branch;
  let lastRequestId = null;
  const call = async (token, method, path, body) => {
    const res = await fetcher(`${api}${path}`, {
      method, headers: { ...ua, Accept: 'application/vnd.github+json', Authorization: `Bearer ${token}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(20000),
    });
    lastRequestId = res.headers?.get?.('x-github-request-id') || lastRequestId;
    if (!res.ok) {
      const detail = (await res.text().catch(() => '')).slice(0, 200).replace(/\s+/g, ' ');
      throw Object.assign(new Error(`GitHub ${method} ${path.replace(/\?.*/, '')} failed: HTTP ${res.status} ${detail}`.trim()), { status: res.status, githubRequestId: lastRequestId });
    }
    return res.status === 204 ? null : res.json();
  };
  const readCall = async path => call(await changesToken(), 'GET', path);
  const checkFiles = files => {
    if (!Array.isArray(files) || !files.length) throw new Error('No files to commit');
    for (const f of files) if (!allowedPath(f.path) || typeof f.content !== 'string') throw new Error(`Refusing to write ${f.path}: not an allowed remediation path`);
  };
  const checkBranch = b => { if (!BRANCH_RE.test(b || '')) throw new Error(`Refusing branch ${b}: not an r360 change branch`); };
  const commitOn = async (token, parentSha, message, files) => {
    const parent = await call(token, 'GET', `/repos/${repo}/git/commits/${parentSha}`);
    const tree = await call(token, 'POST', `/repos/${repo}/git/trees`, { base_tree: parent.tree.sha, tree: files.map(f => ({ path: f.path, mode: '100644', type: 'blob', content: f.content })) });
    const commit = await call(token, 'POST', `/repos/${repo}/git/commits`, { message, tree: tree.sha, parents: [parentSha] });
    return commit.sha;
  };

  // Open pull requests and recently closed ones created by r360 (head branch r360/...), with their check runs.
  async function listPulls({ state = 'all', withChecks = true, max = 30 } = {}) {
    const pulls = await readCall(`/repos/${repo}/pulls?state=${state}&sort=updated&direction=desc&per_page=${Math.min(max, 100)}`);
    const mine = pulls.filter(p => BRANCH_RE.test(p.head?.ref || '') && p.head?.repo?.full_name === repo && p.base?.ref === baseBranch);
    const out = [];
    for (const p of mine) {
      let checks = null;
      if (withChecks && p.state === 'open') {
        try { checks = (await readCall(`/repos/${repo}/commits/${p.head.sha}/check-runs?per_page=50`)).check_runs.map(c => ({ name: c.name, status: c.status, conclusion: c.conclusion })); }
        catch { checks = null; }
      }
      out.push({ number: p.number, state: p.state, merged: !!p.merged_at, title: p.title, url: p.html_url, branch: p.head.ref, headSha: p.head.sha, mergeSha: p.merged_at ? p.merge_commit_sha || null : null, body: p.body || '', createdAt: p.created_at, updatedAt: p.updated_at, mergedAt: p.merged_at || null, checks });
    }
    return out;
  }
  async function getPull(number) {
    const p = await readCall(`/repos/${repo}/pulls/${Number(number)}`);
    return { number: p.number, state: p.state, merged: !!p.merged_at, draft: !!p.draft, title: p.title, url: p.html_url, branch: p.head?.ref, headSha: p.head?.sha, mergeSha: p.merged_at ? p.merge_commit_sha || null : null, headRepo: p.head?.repo?.full_name, base: p.base?.ref, body: p.body || '' };
  }

  async function proposeChange({ branch, files, message, title, body }) {
    checkBranch(branch); checkFiles(files);
    const { token } = await mint({ contents: 'write', pull_requests: 'write', metadata: 'read' }, 'write');
    const ref = await call(token, 'GET', `/repos/${repo}/git/ref/heads/${encodeURIComponent(baseBranch)}`);
    const sha = await commitOn(token, ref.object.sha, message, files);
    await call(token, 'POST', `/repos/${repo}/git/refs`, { ref: `refs/heads/${branch}`, sha });
    try {
      const pr = await call(token, 'POST', `/repos/${repo}/pulls`, { title, head: branch, base: baseBranch, body });
      return { number: pr.number, url: pr.html_url, headSha: sha, branch, githubRequestId: lastRequestId };
    } catch (e) {
      // Roll back: no orphan branch is left behind when the pull request could not be opened.
      let rolledBack = true;
      try { await call(token, 'DELETE', `/repos/${repo}/git/refs/heads/${branch}`); } catch { rolledBack = false; }
      throw Object.assign(e, { rolledBack });
    }
  }

  // Push one more commit to an open change. Not a force push: if the branch moved meanwhile this fails.
  async function updateChange({ number, branch, expectHeadSha, files, message, body }) {
    checkBranch(branch); checkFiles(files);
    const { token } = await mint({ contents: 'write', pull_requests: 'write', metadata: 'read' }, 'write');
    const pr = await call(token, 'GET', `/repos/${repo}/pulls/${Number(number)}`);
    if (pr.state !== 'open' || pr.head.ref !== branch || pr.head.repo?.full_name !== repo) throw Object.assign(new Error('The pull request is not an open r360 change.'), { status: 409 });
    if (expectHeadSha && pr.head.sha !== expectHeadSha) throw Object.assign(new Error('The change was updated elsewhere. Reload it first.'), { status: 409 });
    const sha = await commitOn(token, pr.head.sha, message, files);
    await call(token, 'PATCH', `/repos/${repo}/git/refs/heads/${branch}`, { sha, force: false });
    if (typeof body === 'string') await call(token, 'PATCH', `/repos/${repo}/pulls/${Number(number)}`, { body });
    return { number: Number(number), headSha: sha, branch, githubRequestId: lastRequestId };
  }

  async function discardChange({ number, branch }) {
    checkBranch(branch);
    const { token } = await mint({ contents: 'write', pull_requests: 'write', metadata: 'read' }, 'write');
    const pr = await call(token, 'GET', `/repos/${repo}/pulls/${Number(number)}`);
    if (pr.state !== 'open' || pr.head.ref !== branch || pr.head.repo?.full_name !== repo) throw Object.assign(new Error('The pull request is not an open r360 change.'), { status: 409 });
    await call(token, 'PATCH', `/repos/${repo}/pulls/${Number(number)}`, { state: 'closed' });
    await call(token, 'DELETE', `/repos/${repo}/git/refs/heads/${branch}`);
    return { number: Number(number), branch, githubRequestId: lastRequestId };
  }

  // ---- approve, merge and watch signing (S4) ----
  // Reads of the Actions API (signing runs and artifacts) use their own cached read-only token so that a missing "actions"
  // permission can never break the Changes tab. Writes use the same per-action write token as S3.
  let actInst = null;
  async function actionsToken() {
    if (actInst && actInst.expires - 300000 > now()) return actInst.token;
    actInst = await mint({ actions: 'read', contents: 'read', metadata: 'read' }, 'actions-read');
    return actInst.token;
  }
  const actionsCall = async path => call(await actionsToken(), 'GET', path);
  const SHA = /^[0-9a-f]{40}$/;
  const needSha = s => { if (!SHA.test(s || '')) throw new Error('Refusing: not a commit sha'); return s; };
  const conflict = m => Object.assign(new Error(m), { status: 409 });
  const writeToken = async () => (await mint({ contents: 'write', pull_requests: 'write', metadata: 'read' }, 'write')).token;
  // The pull request as GitHub has it right now, and only if it is an r360 change branch of this repository.
  const ownPull = async (token, number, { open = true } = {}) => {
    const pr = await call(token, 'GET', `/repos/${repo}/pulls/${Number(number)}`);
    if (pr.head?.repo?.full_name !== repo || !BRANCH_RE.test(pr.head?.ref || '') || pr.base?.ref !== baseBranch) throw conflict('That pull request is not an r360 change.');
    if (open && pr.state !== 'open') throw conflict('The pull request is not open.');
    return pr;
  };

  async function getChecks(sha) {
    needSha(sha);
    return (await readCall(`/repos/${repo}/commits/${sha}/check-runs?per_page=50`)).check_runs.map(c => ({ name: c.name, status: c.status, conclusion: c.conclusion }));
  }
  // How far the head is behind main (strict "up to date" rule).
  async function behindBy(sha) {
    needSha(sha);
    const c = await readCall(`/repos/${repo}/compare/${encodeURIComponent(baseBranch)}...${sha}`);
    return Number(c.behind_by) || 0;
  }
  async function unresolvedThreads(number) {
    const [owner, name] = repo.split('/');
    const token = await changesToken();
    const res = await fetcher(`${api}/graphql`, {
      method: 'POST', headers: { ...ua, Accept: 'application/vnd.github+json', Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: 'query($o:String!,$n:String!,$p:Int!){repository(owner:$o,name:$n){pullRequest(number:$p){reviewThreads(first:100){nodes{isResolved}}}}}', variables: { o: owner, n: name, p: Number(number) } }), signal: AbortSignal.timeout(20000),
    });
    if (!res.ok) throw new Error(`GitHub GraphQL failed: HTTP ${res.status}`);
    const j = await res.json();
    if (j.errors?.length) throw new Error(`GitHub GraphQL: ${String(j.errors[0].message).slice(0, 120)}`);
    return (j.data?.repository?.pullRequest?.reviewThreads?.nodes || []).filter(n => !n.isResolved).length;
  }

  async function commentOnPull({ number, body }) {
    const token = await writeToken();
    await ownPull(token, number);
    const c = await call(token, 'POST', `/repos/${repo}/issues/${Number(number)}/comments`, { body: String(body).slice(0, 60000) });
    return { id: c?.id, githubRequestId: lastRequestId };
  }
  // Comment and close. The branch is left in place so that the rejected commits can still be read.
  async function rejectChange({ number, comment }) {
    const token = await writeToken();
    const pr = await ownPull(token, number);
    await call(token, 'POST', `/repos/${repo}/issues/${Number(number)}/comments`, { body: String(comment).slice(0, 60000) });
    await call(token, 'PATCH', `/repos/${repo}/pulls/${Number(number)}`, { state: 'closed' });
    return { number: Number(number), branch: pr.head.ref, githubRequestId: lastRequestId };
  }
  // Squash merge pinned to the exact head sha: GitHub refuses (409) if the branch moved after the approval was given.
  async function mergeChange({ number, sha, title, message }) {
    needSha(sha);
    const token = await writeToken();
    const pr = await ownPull(token, number);
    if (pr.head.sha !== sha) throw conflict('The change was updated after it was approved. Reload it and approve the new commit.');
    const m = await call(token, 'PUT', `/repos/${repo}/pulls/${Number(number)}/merge`, { merge_method: 'squash', sha, commit_title: String(title).slice(0, 250), commit_message: String(message).slice(0, 60000) });
    const githubRequestId = lastRequestId;
    if (!m?.merged || !SHA.test(m.sha || '')) throw Object.assign(new Error(`GitHub did not merge the pull request: ${String(m?.message || 'no reason given').slice(0, 150)}`), { status: 409, githubRequestId });
    let branchDeleted = false;
    try { await call(token, 'DELETE', `/repos/${repo}/git/refs/heads/${pr.head.ref}`); branchDeleted = true; } catch { /* the merge stands; a leftover branch is harmless */ }
    return { mergeSha: m.sha, branchDeleted, githubRequestId };
  }
  // Merge main into the change branch (the "up to date" rule). Waits briefly for GitHub to move the head.
  async function updateBranch({ number, expectHeadSha }) {
    needSha(expectHeadSha);
    const token = await writeToken();
    const pr = await ownPull(token, number);
    if (pr.head.sha !== expectHeadSha) throw conflict('The change was updated elsewhere. Reload it first.');
    await call(token, 'PUT', `/repos/${repo}/pulls/${Number(number)}/update-branch`, { expected_head_sha: expectHeadSha });
    const githubRequestId = lastRequestId;
    for (let i = 0; i < 8; i++) {
      await sleep(1500);
      const p = await call(token, 'GET', `/repos/${repo}/pulls/${Number(number)}`);
      if (p.head.sha !== expectHeadSha) return { headSha: p.head.sha, pending: false, githubRequestId };
    }
    return { headSha: expectHeadSha, pending: true, githubRequestId };
  }

  // The "Sign and Verify" run for a merge commit, with its jobs once it has finished.
  async function signingRun(sha) {
    needSha(sha);
    const j = await actionsCall(`/repos/${repo}/actions/runs?head_sha=${sha}&event=push&per_page=20`);
    const run = (j.workflow_runs || []).filter(r => r.head_sha === sha && (r.name === 'Sign and Verify' || String(r.path || '').endsWith('sign-and-verify.yml')))
      .sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at))[0];
    if (!run) return null;
    let jobs = null;
    if (run.status === 'completed') jobs = ((await actionsCall(`/repos/${repo}/actions/runs/${run.id}/jobs?per_page=30`)).jobs || []).map(x => ({ name: x.name, status: x.status, conclusion: x.conclusion }));
    return { id: run.id, status: run.status, conclusion: run.conclusion || null, url: run.html_url, jobs };
  }
  // The artifact "signed-<sha>" of the workflow run for that commit. GitHub answers with a redirect to a pre-signed storage URL;
  // that second request carries no GitHub credential.
  const ARTIFACT_HOSTS = [/\.blob\.core\.windows\.net$/, /\.githubusercontent\.com$/];
  async function downloadSignedArtifact(sha, { maxBytes = 8 * 1024 * 1024 } = {}) {
    needSha(sha);
    const name = `signed-${sha}`;
    const j = await actionsCall(`/repos/${repo}/actions/artifacts?name=${encodeURIComponent(name)}&per_page=10`);
    const a = (j.artifacts || []).filter(x => x.name === name && !x.expired && x.workflow_run?.head_sha === sha).sort((x, y) => Date.parse(y.created_at) - Date.parse(x.created_at))[0];
    if (!a) return null;
    if (!(a.size_in_bytes <= maxBytes)) throw new Error('The signed artifact is larger than the limit');
    const token = await actionsToken();
    const res = await fetcher(`${api}/repos/${repo}/actions/artifacts/${Number(a.id)}/zip`, { headers: { ...ua, Accept: 'application/vnd.github+json', Authorization: `Bearer ${token}` }, redirect: 'manual', signal: AbortSignal.timeout(20000) });
    if (res.status !== 302) throw new Error(`GitHub artifact download did not redirect: HTTP ${res.status}`);
    let loc;
    try { loc = new URL(res.headers.get('location') || ''); } catch { throw new Error('GitHub artifact download gave no usable location'); }
    if (loc.protocol !== 'https:' || !ARTIFACT_HOSTS.some(re => re.test(loc.hostname))) throw new Error('GitHub artifact download redirected to an unexpected host');
    const dl = await fetcher(loc.toString(), { redirect: 'error', signal: AbortSignal.timeout(30000) });
    if (!dl.ok) throw new Error(`Artifact storage answered HTTP ${dl.status}`);
    const buffer = Buffer.from(await dl.arrayBuffer());
    if (buffer.length > maxBytes) throw new Error('The signed artifact is larger than the limit');
    return { buffer, artifact: { id: a.id, runId: a.workflow_run?.id || null, bytes: buffer.length } };
  }
  // The three files of one remediation as they are at a given commit (the head of an open change).
  async function readChangeFiles({ sha, folder }) {
    const out = {};
    for (const n of ['remediation.json', 'detect.ps1', 'remediate.ps1']) {
      const p = `remediations/${folder}/${n}`;
      if (!allowedPath(p) || !/^[0-9a-f]{40}$/.test(sha || '')) throw new Error('Refusing to read that path');
      const j = await readCall(`/repos/${repo}/contents/${p}?ref=${sha}`);
      out[n] = Buffer.from(j.content || '', 'base64').toString('utf8');
    }
    return { meta: JSON.parse(out['remediation.json']), detect: out['detect.ps1'], remediate: out['remediate.ps1'], raw: out };
  }

  return { appJwt, installationToken, catalog, readChangeFiles, listPulls, getPull, proposeChange, updateChange, discardChange,
    getChecks, behindBy, unresolvedThreads, commentOnPull, rejectChange, mergeChange, updateBranch, signingRun, downloadSignedArtifact };
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
