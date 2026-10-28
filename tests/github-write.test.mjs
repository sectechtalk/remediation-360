import test from 'node:test';
import assert from 'node:assert/strict';
import { createGitHubApp } from '../server/github.mjs';
import { loadConfig } from '../server/config.mjs';
import { ENV } from './fixtures.mjs';

const config = loadConfig(ENV);
const REPO = config.repo;
const BRANCH = 'r360/Stt-Test/202610271504-94540000';
const FILES = [{ path: 'remediations/Stt-Test/detect.ps1', content: 'a\n' }, { path: 'remediations/Stt-Test/remediate.ps1', content: 'b\n' }];
const json = (o, status = 200, headers = {}) => new Response(status === 204 ? null : JSON.stringify(o), { status, headers: { 'x-github-request-id': 'GH-REQ-1', ...headers } });

// A fake GitHub + Key Vault. Records every call; the failures are switchable.
function fake(opts = {}) {
  const f = { calls: [], mints: [], fail: { mint: null, pull: false, patchRef: false }, headSha: 'headsha', prState: 'open', prRef: BRANCH, ...opts };
  f.fetcher = async (url, init = {}) => {
    const u = String(url), method = init.method || 'GET', body = init.body ? JSON.parse(init.body) : undefined;
    const path = u.replace('https://api.github.com', '');
    f.calls.push({ method, path, body, auth: init.headers?.Authorization });
    if (u.includes('vault.azure.net')) return json({ value: 'c2ln' });
    if (path.endsWith('/access_tokens')) {
      f.mints.push(body);
      if (f.fail.mint) return json({ message: 'denied' }, f.fail.mint);
      return json({ token: `tok-${f.mints.length}`, expires_at: new Date(Date.now() + 3600e3).toISOString() });
    }
    if (path.endsWith('/git/ref/heads/main')) return json({ object: { sha: 'basesha' } });
    if (/\/git\/commits\/\w+$/.test(path) && method === 'GET') return json({ tree: { sha: 'basetree' } });
    if (path.endsWith('/git/trees')) return json({ sha: 'newtree' });
    if (path.endsWith('/git/commits')) return json({ sha: 'newcommit' });
    if (path.endsWith('/git/refs') && method === 'POST') return json({});
    if (/\/git\/refs\/heads\//.test(path) && method === 'PATCH') return f.fail.patchRef ? json({ message: 'not ff' }, 422) : json({});
    if (/\/git\/refs\/heads\//.test(path) && method === 'DELETE') return json(null, 204);
    if (path.endsWith('/pulls') && method === 'POST') return f.fail.pull ? json({ message: 'nope' }, 422) : json({ number: 7, html_url: `https://github.com/${REPO}/pull/7` });
    if (/\/pulls\/7$/.test(path) && method === 'GET') return json({ number: 7, state: f.prState, merged_at: null, title: 't', html_url: 'u', body: 'b', head: { ref: f.prRef, sha: f.headSha, repo: { full_name: REPO } }, base: { ref: 'main' } });
    if (/\/pulls\/7$/.test(path) && method === 'PATCH') return json({});
    if (/\/contents\//.test(path)) return json({ content: Buffer.from(path.includes('remediation.json') ? '{"displayName":"X"}' : 'script\n').toString('base64') });
    if (/\/pulls\?/.test(path)) return json([
      { number: 7, state: 'open', merged_at: null, title: 't', html_url: 'u7', body: 'b', created_at: 'c', updated_at: 'u', head: { ref: BRANCH, sha: 'h7', repo: { full_name: REPO } }, base: { ref: 'main' } },
      { number: 8, state: 'open', merged_at: null, title: 'human', html_url: 'u8', body: '', head: { ref: 'feature/x', sha: 'h8', repo: { full_name: REPO } }, base: { ref: 'main' } },
      { number: 9, state: 'open', merged_at: null, title: 'fork', html_url: 'u9', body: '', head: { ref: BRANCH, sha: 'h9', repo: { full_name: 'evil/fork' } }, base: { ref: 'main' } },
      { number: 10, state: 'open', merged_at: null, title: 'wrong base', html_url: 'u10', body: '', head: { ref: BRANCH, sha: 'h10', repo: { full_name: REPO } }, base: { ref: 'dev' } }]);
    if (/\/check-runs/.test(path)) return json({ check_runs: [{ name: 'PSScriptAnalyzer', status: 'completed', conclusion: 'success', extra: 'dropped' }] });
    throw new Error(`unexpected ${method} ${path}`);
  };
  f.gh = createGitHubApp({ config, miToken: async () => 'VT', fetcher: f.fetcher });
  f.writeMints = () => f.mints.filter(m => m.permissions.contents === 'write');
  return f;
}

test('write token: minted per action, never cached, exactly contents+pull_requests write and metadata read, one repository', async () => {
  const f = fake();
  const args = { branch: BRANCH, files: FILES, message: 'm', title: 't', body: 'b' };
  await f.gh.proposeChange(args);
  await f.gh.proposeChange(args);
  assert.equal(f.writeMints().length, 2, 'a new token for every action');
  for (const m of f.writeMints()) {
    assert.deepEqual(m, { repositories: ['remediations'], permissions: { contents: 'write', pull_requests: 'write', metadata: 'read' } });
  }
  assert.ok(f.calls.some(c => c.auth === 'Bearer tok-1') && f.calls.some(c => c.auth === 'Bearer tok-2'));
  // The read token is a different, cached, read-only token.
  await f.gh.installationToken(); await f.gh.installationToken();
  const reads = f.mints.filter(m => m.permissions.contents === 'read' && !m.permissions.pull_requests);
  assert.equal(reads.length, 1);
  assert.deepEqual(reads[0].permissions, { contents: 'read', metadata: 'read' });
});

test('propose: ref, commit, tree with inline blobs on the base tree, branch, then pull request; nothing is forced', async () => {
  const f = fake();
  const r = await f.gh.proposeChange({ branch: BRANCH, files: FILES, message: 'msg', title: 'T', body: 'B' });
  assert.deepEqual({ number: r.number, url: r.url, headSha: r.headSha, githubRequestId: r.githubRequestId }, { number: 7, url: `https://github.com/${REPO}/pull/7`, headSha: 'newcommit', githubRequestId: 'GH-REQ-1' });
  const steps = f.calls.filter(c => !c.path.includes('access_tokens') && !c.path.includes('vault')).map(c => `${c.method} ${c.path.replace(`/repos/${REPO}`, '')}`);
  assert.deepEqual(steps, ['GET /git/ref/heads/main', 'GET /git/commits/basesha', 'POST /git/trees', 'POST /git/commits', 'POST /git/refs', 'POST /pulls']);
  const tree = f.calls.find(c => c.path.endsWith('/git/trees')).body;
  assert.equal(tree.base_tree, 'basetree');
  assert.deepEqual(tree.tree, FILES.map(x => ({ path: x.path, mode: '100644', type: 'blob', content: x.content })));
  assert.deepEqual(f.calls.find(c => c.path.endsWith('/git/commits') && c.method === 'POST').body, { message: 'msg', tree: 'newtree', parents: ['basesha'] });
  assert.deepEqual(f.calls.find(c => c.path.endsWith('/git/refs')).body, { ref: `refs/heads/${BRANCH}`, sha: 'newcommit' });
  assert.deepEqual(f.calls.find(c => c.path.endsWith('/pulls') && c.method === 'POST').body, { title: 'T', head: BRANCH, base: 'main', body: 'B' });
});

test('propose: when the pull request cannot be opened the branch is deleted (rollback)', async () => {
  const f = fake(); f.fail.pull = true;
  await assert.rejects(f.gh.proposeChange({ branch: BRANCH, files: FILES, message: 'm', title: 't', body: 'b' }), e => e.rolledBack === true && /422/.test(e.message));
  assert.ok(f.calls.some(c => c.method === 'DELETE' && c.path.endsWith(`/git/refs/heads/${BRANCH}`)));
});

test('write paths and branches outside the whitelist are refused before any token is minted', async () => {
  const f = fake();
  const bad = [
    { branch: 'main', files: FILES }, { branch: 'r360/x/1-2', files: FILES }, { branch: BRANCH, files: [] },
    { branch: BRANCH, files: [{ path: 'approvers.json', content: 'x' }] },
    { branch: BRANCH, files: [{ path: '.github/workflows/ci.yml', content: 'x' }] },
    { branch: BRANCH, files: [{ path: 'remediations/../approvers.json', content: 'x' }] },
    { branch: BRANCH, files: [{ path: 'remediations/a/detect.ps1', content: 5 }] },
  ];
  for (const b of bad) await assert.rejects(f.gh.proposeChange({ ...b, message: 'm', title: 't', body: 'b' }), /Refusing|No files/);
  await assert.rejects(f.gh.updateChange({ number: 7, branch: 'main', files: FILES, message: 'm' }), /Refusing/);
  await assert.rejects(f.gh.discardChange({ number: 7, branch: 'main' }), /Refusing/);
  assert.equal(f.mints.length, 0);
});

test('a permission problem on the write token is reported as such, naming the permissions', async () => {
  for (const status of [422, 403]) {
    const f = fake(); f.fail.mint = status;
    await assert.rejects(f.gh.proposeChange({ branch: BRANCH, files: FILES, message: 'm', title: 't', body: 'b' }), e => e.permission === true && /contents:write, pull_requests:write, metadata:read/.test(e.message));
    assert.equal(f.calls.filter(c => c.path.includes('/git/')).length, 0, 'no git call without a token');
  }
  const f = fake(); f.fail.mint = 500;
  await assert.rejects(f.gh.proposeChange({ branch: BRANCH, files: FILES, message: 'm', title: 't', body: 'b' }), e => !e.permission);
});

test('update is a non-force fast-forward and refuses a moved or foreign branch; discard closes the PR then deletes the branch', async () => {
  const f = fake();
  const r = await f.gh.updateChange({ number: 7, branch: BRANCH, expectHeadSha: 'headsha', files: FILES, message: 'm', body: 'new body' });
  assert.equal(r.headSha, 'newcommit');
  const patch = f.calls.find(c => c.method === 'PATCH' && c.path.includes('/git/refs/heads/'));
  assert.deepEqual(patch.body, { sha: 'newcommit', force: false });
  assert.equal(f.calls.find(c => c.method === 'POST' && c.path.endsWith('/git/commits')).body.parents[0], 'headsha');
  assert.deepEqual(f.calls.find(c => c.method === 'PATCH' && c.path.endsWith('/pulls/7')).body, { body: 'new body' });

  await assert.rejects(f.gh.updateChange({ number: 7, branch: BRANCH, expectHeadSha: 'stale', files: FILES, message: 'm' }), e => e.status === 409 && /updated elsewhere/.test(e.message));
  f.prRef = 'r360/Other/202610271504-94540000';
  await assert.rejects(f.gh.updateChange({ number: 7, branch: BRANCH, files: FILES, message: 'm' }), e => e.status === 409);
  f.prRef = BRANCH; f.prState = 'closed';
  await assert.rejects(f.gh.discardChange({ number: 7, branch: BRANCH }), e => e.status === 409);

  const g = fake();
  await g.gh.discardChange({ number: 7, branch: BRANCH });
  const order = g.calls.filter(c => ['PATCH', 'DELETE'].includes(c.method)).map(c => `${c.method} ${c.path.replace(`/repos/${REPO}`, '')}`);
  assert.deepEqual(order, ['PATCH /pulls/7', `DELETE /git/refs/heads/${BRANCH}`]);
  assert.deepEqual(g.calls.find(c => c.method === 'PATCH').body, { state: 'closed' });
});

test('a rejected non-fast-forward update surfaces as a failure (no force)', async () => {
  const f = fake(); f.fail.patchRef = true;
  await assert.rejects(f.gh.updateChange({ number: 7, branch: BRANCH, files: FILES, message: 'm' }), e => e.status === 422);
});

test('listing: only r360 branches in this repo into main, check runs reduced to name/status/conclusion, read-only token with pull_requests and checks read', async () => {
  const f = fake();
  const list = await f.gh.listPulls();
  assert.deepEqual(list.map(p => p.number), [7]);
  assert.deepEqual(list[0].checks, [{ name: 'PSScriptAnalyzer', status: 'completed', conclusion: 'success' }]);
  assert.deepEqual(f.mints.at(-1).permissions, { contents: 'read', metadata: 'read', pull_requests: 'read', checks: 'read' });
  assert.equal(f.writeMints().length, 0, 'listing never mints a write token');
  const noChecks = await f.gh.listPulls({ withChecks: false });
  assert.equal(noChecks[0].checks, null);
  // The changes read token is cached; a second listing mints nothing new.
  const n = f.mints.length; await f.gh.listPulls(); assert.equal(f.mints.length, n);
});

test('reading the files of a change: only whitelisted paths at a full commit sha', async () => {
  const f = fake();
  const r = await f.gh.readChangeFiles({ sha: 'a'.repeat(40), folder: 'Stt-Test' });
  assert.deepEqual(r.meta, { displayName: 'X' }); assert.equal(r.detect, 'script\n');
  await assert.rejects(f.gh.readChangeFiles({ sha: 'main', folder: 'Stt-Test' }), /Refusing/);
  await assert.rejects(f.gh.readChangeFiles({ sha: 'a'.repeat(40), folder: '../x' }), /Refusing/);
});
