import test from 'node:test';
import assert from 'node:assert/strict';
import { createGitHubApp } from '../server/github.mjs';
import { loadConfig } from '../server/config.mjs';
import { ENV } from './fixtures.mjs';

const config = loadConfig(ENV);
const REPO = config.repo;
const BRANCH = 'r360/Stt-Test/202610271504-94540000';
const HEAD = 'a'.repeat(40);
const NEW = 'b'.repeat(40);
const MERGE = 'c'.repeat(40);
const json = (o, status = 200, headers = {}) => new Response(status === 204 ? null : JSON.stringify(o), { status, headers: { 'x-github-request-id': 'GH-REQ-9', ...headers } });

function fake(opts = {}) {
  const f = { calls: [], mints: [], sleeps: 0, head: HEAD, state: 'open', ref: BRANCH, repo: REPO, base: 'main', headAfterUpdate: NEW, merge: { status: 200, body: { merged: true, sha: MERGE } },
    runs: [], jobs: [], artifacts: [], redirect: 'https://productionresultssa1.blob.core.windows.net/x?sig=1', zip: new Uint8Array([80, 75, 3, 4]), mintFail: null, ...opts };
  f.fetcher = async (url, init = {}) => {
    const u = String(url), method = init.method || 'GET', body = init.body ? JSON.parse(init.body) : undefined;
    const path = u.replace('https://api.github.com', '');
    f.calls.push({ method, u, path, body, auth: init.headers?.Authorization, redirect: init.redirect });
    if (u.includes('vault.azure.net')) return json({ value: 'c2ln' });
    if (path.endsWith('/access_tokens')) {
      f.mints.push(body);
      if (f.mintFail && body.permissions.actions) return json({ message: 'Resource not accessible' }, f.mintFail);
      return json({ token: `tok-${f.mints.length}`, expires_at: new Date(Date.now() + 3600e3).toISOString() });
    }
    if (/\/pulls\/7$/.test(path) && method === 'GET') return json({ number: 7, state: f.state, merged_at: null, title: 't', html_url: 'u', body: 'b', head: { ref: f.ref, sha: f.head, repo: { full_name: f.repo } }, base: { ref: f.base } });
    if (/\/pulls\/7\/merge$/.test(path)) return json(f.merge.body, f.merge.status);
    if (/\/pulls\/7\/update-branch$/.test(path)) { f.updated = true; f.head = f.headAfterUpdate; return json({ message: 'Updating pull request branch.' }, 202); }
    if (/\/pulls\/7$/.test(path) && method === 'PATCH') return json({});
    if (/\/issues\/7\/comments$/.test(path)) return json({ id: 55 }, 201);
    if (/\/git\/refs\/heads\//.test(path) && method === 'DELETE') return f.deleteFails ? json({ message: 'nope' }, 422) : json(null, 204);
    if (/\/compare\//.test(path)) return json({ behind_by: f.behind ?? 0 });
    if (/\/check-runs/.test(path)) return json({ check_runs: [{ name: 'PSScriptAnalyzer', status: 'completed', conclusion: 'success', extra: 'x' }] });
    if (path === '/graphql') return json({ data: { repository: { pullRequest: { reviewThreads: { nodes: f.threads || [] } } } } });
    if (/\/actions\/runs\?/.test(path)) return json({ workflow_runs: f.runs });
    if (/\/actions\/runs\/\d+\/jobs/.test(path)) return json({ jobs: f.jobs });
    if (/\/actions\/artifacts\?/.test(path)) return json({ artifacts: f.artifacts });
    if (/\/actions\/artifacts\/\d+\/zip$/.test(path)) return f.redirect === null ? json({}, 200) : new Response(null, { status: 302, headers: { location: f.redirect } });
    if (u.startsWith('https://productionresultssa1.blob.core.windows.net/') || u.startsWith('https://evil.example.com/')) return new Response(f.zip, { status: 200 });
    throw new Error(`unexpected ${method} ${u}`);
  };
  f.gh = createGitHubApp({ config, miToken: async () => 'VT', fetcher: f.fetcher, sleep: async () => { f.sleeps++; } });
  return f;
}
const rejects = (p, re) => assert.rejects(p, re);
const writeMints = f => f.mints.filter(m => m.permissions.contents === 'write');

test('mergeChange: squash, pinned to the approved head sha, branch deleted, merge sha returned', async () => {
  const f = fake();
  const r = await f.gh.mergeChange({ number: 7, sha: HEAD, title: 'T (#7)', message: 'M' });
  assert.deepEqual(r, { mergeSha: MERGE, branchDeleted: true, githubRequestId: 'GH-REQ-9' });
  const put = f.calls.find(c => c.method === 'PUT');
  assert.deepEqual(put.body, { merge_method: 'squash', sha: HEAD, commit_title: 'T (#7)', commit_message: 'M' });
  assert.ok(f.calls.some(c => c.method === 'DELETE' && c.path.endsWith(`/git/refs/heads/${BRANCH}`)));
  assert.deepEqual(writeMints(f)[0], { repositories: ['remediations'], permissions: { contents: 'write', pull_requests: 'write', metadata: 'read' } });
});

test('mergeChange: refuses if the head moved, with no merge call at all', async () => {
  const f = fake({ head: NEW });
  await rejects(f.gh.mergeChange({ number: 7, sha: HEAD, title: 't', message: 'm' }), e => e.status === 409 && /updated after it was approved/.test(e.message));
  assert.equal(f.calls.filter(c => c.method === 'PUT').length, 0);
});

test('mergeChange: only r360 branches of this repository, onto main, while open', async () => {
  for (const over of [{ ref: 'feature/x' }, { repo: 'evil/fork' }, { base: 'dev' }, { state: 'closed' }]) {
    const f = fake(over);
    await rejects(f.gh.mergeChange({ number: 7, sha: HEAD, title: 't', message: 'm' }), e => e.status === 409, JSON.stringify(over));
    assert.equal(f.calls.filter(c => c.method === 'PUT' || c.method === 'DELETE').length, 0);
  }
  await rejects(fake().gh.mergeChange({ number: 7, sha: 'abc', title: 't', message: 'm' }), /not a commit sha/);
});

test('mergeChange: a refusal from GitHub keeps its status, "merged:false" is an error, a failed branch delete is not', async () => {
  const f = fake({ merge: { status: 405, body: { message: 'Required status check is expected' } } });
  await rejects(f.gh.mergeChange({ number: 7, sha: HEAD, title: 't', message: 'm' }), e => e.status === 405 && /Required status check/.test(e.message));
  const g = fake({ merge: { status: 200, body: { merged: false, message: 'nope' } } });
  await rejects(g.gh.mergeChange({ number: 7, sha: HEAD, title: 't', message: 'm' }), e => e.status === 409);
  const h = fake({ deleteFails: true });
  assert.equal((await h.gh.mergeChange({ number: 7, sha: HEAD, title: 't', message: 'm' })).branchDeleted, false);
});

test('rejectChange comments, then closes; commentOnPull only comments', async () => {
  const f = fake();
  await f.gh.rejectChange({ number: 7, comment: 'no' });
  const seq = f.calls.filter(c => c.method !== 'GET' && c.u.startsWith('https://api.github.com') && !c.path.endsWith('/access_tokens')).map(c => `${c.method} ${c.path.replace(`/repos/${REPO}`, '')}`);
  assert.deepEqual(seq, ['POST /issues/7/comments', 'PATCH /pulls/7']);
  assert.deepEqual(f.calls.find(c => c.method === 'PATCH').body, { state: 'closed' });
  const g = fake();
  const c = await g.gh.commentOnPull({ number: 7, body: 'hi' });
  assert.equal(c.id, 55);
  assert.equal(g.calls.filter(x => x.method === 'PATCH').length, 0);
  await rejects(fake({ ref: 'feature/x' }).gh.commentOnPull({ number: 7, body: 'x' }), e => e.status === 409);
});

test('updateBranch: expected_head_sha is sent, the new head is awaited; a stale caller is refused', async () => {
  const f = fake();
  const r = await f.gh.updateBranch({ number: 7, expectHeadSha: HEAD });
  assert.deepEqual(f.calls.find(c => /update-branch/.test(c.path)).body, { expected_head_sha: HEAD });
  assert.equal(r.headSha, NEW); assert.equal(r.pending, false);
  const g = fake({ head: NEW });
  await rejects(g.gh.updateBranch({ number: 7, expectHeadSha: HEAD }), e => e.status === 409);
  assert.equal(g.calls.filter(c => /update-branch/.test(c.path)).length, 0);
  const h = fake({ headAfterUpdate: HEAD });
  const p = await h.gh.updateBranch({ number: 7, expectHeadSha: HEAD });
  assert.deepEqual({ pending: p.pending, headSha: p.headSha }, { pending: true, headSha: HEAD });
  assert.equal(h.sleeps, 8, 'bounded wait');
});

test('read helpers: checks, behind_by, unresolved review threads (GraphQL) use the read token', async () => {
  const f = fake({ behind: 3, threads: [{ isResolved: true }, { isResolved: false }, { isResolved: false }] });
  assert.deepEqual(await f.gh.getChecks(HEAD), [{ name: 'PSScriptAnalyzer', status: 'completed', conclusion: 'success' }]);
  assert.equal(await f.gh.behindBy(HEAD), 3);
  assert.equal(await f.gh.unresolvedThreads(7), 2);
  assert.equal(writeMints(f).length, 0, 'no write token for reads');
  await rejects(f.gh.getChecks('x'), /not a commit sha/);
  const q = f.calls.find(c => c.path === '/graphql');
  assert.match(q.auth, /^Bearer tok-/);
});

test('signingRun: the Sign and Verify run for exactly that commit, jobs only once completed; read-only actions token', async () => {
  const run = (over = {}) => ({ id: 1, name: 'Sign and Verify', path: '.github/workflows/sign-and-verify.yml', head_sha: MERGE, status: 'completed', conclusion: 'success', html_url: 'https://github.com/x/y/actions/runs/1', created_at: '2026-10-27T15:00:00Z', ...over });
  const f = fake({ runs: [run({ id: 2, head_sha: HEAD }), run({ id: 3, name: 'Other', path: 'x.yml' }), run()], jobs: [{ name: 'Sign (Key Vault HSM)', status: 'completed', conclusion: 'success', x: 1 }] });
  const r = await f.gh.signingRun(MERGE);
  assert.deepEqual({ id: r.id, status: r.status, conclusion: r.conclusion }, { id: 1, status: 'completed', conclusion: 'success' });
  assert.deepEqual(r.jobs, [{ name: 'Sign (Key Vault HSM)', status: 'completed', conclusion: 'success' }]);
  assert.deepEqual(f.mints.find(m => m.permissions.actions).permissions, { actions: 'read', contents: 'read', metadata: 'read' });
  const g = fake({ runs: [run({ status: 'in_progress', conclusion: null })] });
  assert.equal((await g.gh.signingRun(MERGE)).jobs, null);
  assert.equal(await fake({ runs: [] }).gh.signingRun(MERGE), null);
  assert.equal(await fake({ runs: [run({ head_sha: HEAD })] }).gh.signingRun(MERGE), null);
});

test('a missing actions permission fails only the signing read, and says so', async () => {
  const f = fake({ mintFail: 422 });
  await rejects(f.gh.signingRun(MERGE), e => e.permission === true && /actions:read/.test(e.message));
  assert.equal((await f.gh.getChecks(HEAD)).length, 1, 'the Changes tab reads still work');
});

test('downloadSignedArtifact: finds signed-<sha>, follows the 302 to allowed storage without the GitHub token', async () => {
  const art = (over = {}) => ({ id: 9, name: `signed-${MERGE}`, expired: false, size_in_bytes: 4, created_at: '2026-10-27T15:00:00Z', workflow_run: { id: 1, head_sha: MERGE }, ...over });
  const f = fake({ artifacts: [art({ id: 8, expired: true }), art({ id: 7, workflow_run: { id: 2, head_sha: HEAD } }), art()] });
  const d = await f.gh.downloadSignedArtifact(MERGE);
  assert.equal(d.artifact.id, 9); assert.equal(d.buffer.length, 4);
  const zipCall = f.calls.find(c => /\/zip$/.test(c.path));
  assert.equal(zipCall.redirect, 'manual');
  assert.match(zipCall.auth, /^Bearer /);
  const storage = f.calls.find(c => c.u.startsWith('https://productionresultssa1'));
  assert.equal(storage.auth, undefined, 'the storage request carries no GitHub credential');
  assert.equal(await fake({ artifacts: [art({ expired: true })] }).gh.downloadSignedArtifact(MERGE), null);
  assert.equal(await fake({ artifacts: [] }).gh.downloadSignedArtifact(MERGE), null);
});

test('downloadSignedArtifact: unexpected redirect host, non-redirect, oversize', async () => {
  const art = { id: 9, name: `signed-${MERGE}`, expired: false, size_in_bytes: 4, created_at: 'c', workflow_run: { id: 1, head_sha: MERGE } };
  for (const redirect of ['https://evil.example.com/x', 'http://x.blob.core.windows.net/x', 'https://blob.core.windows.net.evil.com/x', 'not a url']) {
    const f = fake({ artifacts: [art], redirect });
    await rejects(f.gh.downloadSignedArtifact(MERGE), /redirect|location/, redirect);
    assert.equal(f.calls.some(c => c.u.startsWith('https://evil.example.com')), false);
  }
  await rejects(fake({ artifacts: [art], redirect: null }).gh.downloadSignedArtifact(MERGE), /did not redirect/);
  await rejects(fake({ artifacts: [{ ...art, size_in_bytes: 9e9 }] }).gh.downloadSignedArtifact(MERGE), /larger than the limit/);
  await rejects(fake({ artifacts: [art], zip: new Uint8Array(20) }).gh.downloadSignedArtifact(MERGE, { maxBytes: 10 }), /larger than the limit/);
});
