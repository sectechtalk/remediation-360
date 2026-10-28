import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { unzipSync } from 'fflate';
import { createChanges, ChangeError, machineBlock, stageOf, ledgerFor, currentApproval, equivalentShas } from '../server/changes.mjs';
import { SIG_BEGIN } from '../server/signing.mjs';
import { loadConfig } from '../server/config.mjs';
import { ENV } from './fixtures.mjs';

const AARON = { oid: '94540000-0000-4000-8000-0000000000c3', upn: 'admin@contoso.com', name: 'Aaron Brooks' };
const USER1 = { oid: '0d000000-0000-4000-8000-0000000000c4', upn: 'user1@contoso.com', name: 'User One' };
const CANARY = '90000000-0000-4000-8000-0000000000c2';
const T0 = Date.parse('2026-10-27T15:04:00Z');
const FOLDER = 'Stt-New';
const HEAD = 'a'.repeat(40);
const HEAD2 = 'b'.repeat(40);
const MERGE = 'c'.repeat(40);
const GREEN = [{ name: 'PSScriptAnalyzer', status: 'completed', conclusion: 'success' }];
const cfgOf = mode => loadConfig({ ...ENV, R360_CANARY_GROUP_ID: CANARY, R360_FOUR_EYES: mode });
const AUTHOR = ['author', 'approver', 'admin'];

function world({ mode = 'testing', folder = FOLDER, authorOid = AARON.oid, pr: over = {} } = {}) {
  const w = { t: T0, seq: 0, mode, rows: [], order: [], comments: [], merges: [], auditDown: false, failResultFor: null, behind: 0, threads: 0, threadsError: false, checksError: null, files: {}, run: null, artifact: null, mergeError: null, commentError: null, updateError: null };
  w.pr = { number: 7, state: 'open', merged: false, draft: false, title: `r360: add remediation ${folder}`, url: 'https://github.com/your-org/remediations/pull/7', branch: `r360/${folder}/202610271504-94540000`, headSha: HEAD, headRepo: 'your-org/remediations', base: 'main',
    body: `Proposed through r360 by admin@contoso.com on x\n${machineBlock({ folder, authorOid })}`, createdAt: 'c', updatedAt: 'u', mergedAt: null, mergeSha: null, checks: GREEN, ...over };
  w.audit = {
    record: async e => { if (w.auditDown) throw new Error('down'); if (w.failResultFor && e.action === w.failResultFor && e.result !== 'intent') throw new Error('result down'); w.order.push(`audit:${e.action}:${e.result}`); w.rows.push({ ...e, at: new Date(T0 + (++w.seq) * 1000).toISOString() }); return e; },
    list: async () => { if (w.auditListDown) throw new Error('down'); return { rows: [...w.rows].reverse(), truncated: false }; },
  };
  w.github = {
    catalog: async () => ({ items: [], sha: 'm', approvers: [{ entraObjectId: AARON.oid, upn: AARON.upn, roles: ['author', 'approver'] }, { entraObjectId: USER1.oid, upn: USER1.upn, roles: ['approver'] }] }),
    listPulls: async () => [{ ...w.pr }], getPull: async n => { if (n !== 7) throw new Error('nf'); return { ...w.pr }; },
    getChecks: async () => { w.order.push('gh:checks'); if (w.checksError) throw new Error(w.checksError); return w.pr.checks || []; },
    behindBy: async () => w.behind,
    unresolvedThreads: async () => { if (w.threadsError) throw new Error('graphql down'); return w.threads; },
    commentOnPull: async a => { w.order.push('gh:comment'); if (w.commentError) throw Object.assign(new Error(w.commentError), { status: 502, githubRequestId: 'RC' }); w.comments.push(a.body); return { id: 1, githubRequestId: 'R-comment' }; },
    rejectChange: async a => { w.order.push('gh:reject'); w.comments.push(a.comment); w.pr.state = 'closed'; return { githubRequestId: 'R-reject' }; },
    mergeChange: async a => {
      w.order.push('gh:merge'); w.merges.push(a);
      if (w.mergeError) throw Object.assign(new Error(w.mergeError.message), { status: w.mergeError.status, githubRequestId: 'RM' });
      if (a.sha !== w.pr.headSha) throw Object.assign(new Error('head moved'), { status: 409 });
      w.pr.merged = true; w.pr.state = 'closed'; w.pr.mergeSha = MERGE; w.pr.mergedAt = new Date(w.t).toISOString();
      return { mergeSha: MERGE, branchDeleted: true, githubRequestId: 'R-merge' };
    },
    updateBranch: async a => { w.order.push('gh:update-branch'); if (w.updateError) throw Object.assign(new Error(w.updateError), { status: 422, githubRequestId: 'RU' }); if (a.expectHeadSha !== w.pr.headSha) throw Object.assign(new Error('moved'), { status: 409 }); w.pr.headSha = HEAD2; return { headSha: HEAD2, pending: false, githubRequestId: 'R-ub' }; },
    readChangeFiles: async ({ sha }) => { if (w.files[sha] instanceof Error) throw w.files[sha]; return { raw: w.files[sha] || { 'remediation.json': '{"a":1}\n', 'detect.ps1': 'd\n', 'remediate.ps1': 'r\n' } }; },
    signingRun: async () => { if (w.run instanceof Error) throw w.run; return w.run; },
    downloadSignedArtifact: async () => { if (w.artifact instanceof Error) throw w.artifact; return w.artifact; },
  };
  w.c = createChanges({ config: cfgOf(mode), github: w.github, audit: w.audit, now: () => w.t, log: { error() {} } });
  // The row that proves r360 proposed this pull request.
  w.seed = (over2 = {}) => w.rows.push({ action: 'change.proposed', result: 'ok', actorOid: authorOid, actorUpn: 'admin@contoso.com', target: `remediations/${folder}`, prNumber: 7, gitSha: HEAD, at: new Date(T0 + (++w.seq) * 1000).toISOString(), ...over2 });
  w.seed();
  return w;
}
const fails = (p, status, re) => assert.rejects(p, e => e instanceof ChangeError && e.status === status && (!re || re.test(e.message)), `expected ${status} ${re}`);
const approve = (w, u = AARON, roles = AUTHOR, body = { headSha: w.pr.headSha }) => w.c.approve(u, roles, 7, body);
const merge = (w, u = AARON, roles = AUTHOR, body = { headSha: w.pr.headSha }) => w.c.merge(u, roles, 7, body);
const ofAction = (w, a) => w.rows.filter(r => r.action === a);
const noWrites = w => assert.deepEqual(w.order.filter(o => /^gh:(comment|merge|reject|update-branch)/.test(o)), [], 'no GitHub write was made');

test('approve (testing mode, self): intent row, then the PR comment, then the ok row; selfApproved everywhere', async () => {
  const w = world();
  const r = await approve(w);
  assert.deepEqual({ ok: r.ok, selfApproved: r.selfApproved, headSha: r.headSha }, { ok: true, selfApproved: true, headSha: HEAD });
  assert.deepEqual(w.order.filter(o => o.startsWith('audit:change.approved') || o === 'gh:comment'), ['audit:change.approved:intent', 'gh:comment', 'audit:change.approved:ok']);
  const [i, ok] = ofAction(w, 'change.approved');
  assert.equal(i.result, 'intent'); assert.equal(ok.result, 'ok');
  assert.equal(ok.actorOid, AARON.oid); assert.equal(ok.approverOid, AARON.oid); assert.equal(ok.selfApproved, true); assert.equal(ok.gitSha, HEAD); assert.equal(ok.prNumber, 7); assert.equal(ok.mode, 'testing'); assert.equal(ok.requestId, i.requestId);
  assert.equal(ok.githubRequestId, 'R-comment');
  assert.match(w.comments[0], /SELF-APPROVED/); assert.match(w.comments[0], new RegExp(HEAD.slice(0, 12)));
});

test('approve by a different approver (user1): not self-approved, comment says so', async () => {
  const w = world();
  const r = await approve(w, USER1, ['approver']);
  assert.equal(r.selfApproved, false);
  assert.equal(ofAction(w, 'change.approved').at(-1).approverOid, USER1.oid);
  assert.doesNotMatch(w.comments[0], /SELF-APPROVED/);
});

test('approve is idempotent: a second click by the same person writes nothing', async () => {
  const w = world();
  await approve(w);
  const rows = w.rows.length, comments = w.comments.length;
  const again = await approve(w);
  assert.equal(again.already, true); assert.equal(again.selfApproved, true);
  assert.equal(w.rows.length, rows); assert.equal(w.comments.length, comments);
});

test('approve in enforced mode: the author is refused with a denial row and no GitHub write; a different approver is fine', async () => {
  const w = world({ mode: 'enforced' });
  await fails(approve(w), 403, /different approver/);
  noWrites(w);
  const d = ofAction(w, 'change.approval.denied');
  assert.equal(d.length, 1); assert.equal(d[0].result, 'denied'); assert.equal(d[0].reason, 'author-cannot-approve'); assert.equal(d[0].actorOid, AARON.oid);
  assert.equal((await approve(w, USER1, ['approver'])).selfApproved, false);
});

test('approve needs the approver role', async () => {
  const w = world();
  await fails(approve(w, AARON, ['author']), 403, /approver/);
  await fails(approve(w, AARON, ['admin']), 403);
  noWrites(w);
});

test('approve: the head the caller saw must be the head now, and the body is strict', async () => {
  const w = world();
  await fails(approve(w, AARON, AUTHOR, { headSha: HEAD2 }), 409, /moved/);
  await fails(approve(w, AARON, AUTHOR, {}), 400, /headSha/);
  await fails(approve(w, AARON, AUTHOR, { headSha: 'main' }), 400);
  await fails(approve(w, AARON, AUTHOR, { headSha: HEAD, approverOid: USER1.oid }), 400, /Unknown field/);
  await fails(w.c.approve(AARON, AUTHOR, 7, null), 400);
  await fails(w.c.approve(AARON, AUTHOR, 0, { headSha: HEAD }), 400);
  noWrites(w);
  assert.equal(ofAction(w, 'change.approved').length, 0);
});

test('approve: CI must have passed; open, not a draft, no unresolved conversations (GitHub also enforces that at merge)', async () => {
  const w = world({ pr: { checks: [{ name: 'PSScriptAnalyzer', status: 'in_progress', conclusion: null }] } });
  await fails(approve(w), 409, /not finished/);
  w.pr.checks = [{ name: 'PSScriptAnalyzer', status: 'completed', conclusion: 'failure' }];
  await fails(approve(w), 409, /CI failed \(PSScriptAnalyzer\)/);
  w.pr.checks = [{ name: 'Other', status: 'completed', conclusion: 'success' }];
  await fails(approve(w), 409, /not finished/, 'the required check must be present');
  w.pr.checks = GREEN; w.pr.draft = true;
  await fails(approve(w), 409, /draft/);
  w.pr.draft = false; w.pr.state = 'closed';
  await fails(approve(w), 409, /closed/);
  w.pr.state = 'open'; w.threads = 2;
  await fails(approve(w), 409, /2 review conversation/);
  w.threads = 0; w.threadsError = true;
  assert.equal((await approve(w)).ok, true, 'a failing thread lookup does not block (GitHub enforces it at merge)');
  noWrites(Object.assign({}, w, { order: w.order.slice(0, w.order.indexOf('audit:change.approved:intent')) }));
});

test('approve: only changes r360 itself proposed, with the head r360 recorded', async () => {
  for (const over of [{ headRepo: 'evil/fork' }, { branch: 'feature/x' }, { base: 'dev' }, { body: 'no machine block' }]) {
    const w = world({ pr: over });
    await fails(approve(w), 409, /not an r360 change/);
    noWrites(w);
  }
  const noProposal = world(); noProposal.rows = [];
  await fails(approve(noProposal), 409, /no audit record/);
  const forged = world(); forged.rows = []; forged.seed({ actorOid: USER1.oid });
  await fails(approve(forged), 409, /no audit record/, 'a proposal by someone else than the machine-block author does not count');
  const handPushed = world({ pr: { headSha: HEAD2 } });
  await fails(approve(handPushed, AARON, AUTHOR, { headSha: HEAD2 }), 409, /outside r360/);
  noWrites(handPushed);
});

test('approve: the audit trail down means nothing is changed; a comment failure means no effective approval', async () => {
  const w = world(); w.auditListDown = true;
  await fails(approve(w), 503, /audit trail is unavailable/);
  noWrites(w);
  const w2 = world(); w2.commentError = 'boom';
  await fails(approve(w2), 502, /approval/);
  assert.deepEqual(ofAction(w2, 'change.approved').map(r => r.result), ['intent', 'failed']);
  assert.equal(currentApproval(ledgerFor(w2.rows, 7), HEAD, { mode: 'testing', authorOid: AARON.oid }).approval, null);
  await fails(merge(w2), 409, /not been approved/);
  const w3 = world(); w3.failResultFor = 'change.approved';
  await fails(approve(w3), 503, /did not take effect/);
  await fails(merge(w3), 409, /not been approved/);
});

test('a new commit voids the approval; an update-branch with identical files carries it', async () => {
  const w = world();
  await approve(w);
  // The author pushes an update: a new head, recorded as change.updated.
  w.pr.headSha = HEAD2; w.seed({ action: 'change.updated', gitSha: HEAD2 });
  const l = await w.c.list(AARON, AUTHOR);
  assert.equal(l.changes[0].approval, null);
  assert.match(l.changes[0].mergeBlock, /Approve this commit first/);
  await fails(merge(w), 409, /not been approved/);
  noWrites(Object.assign({}, w, { order: w.order.filter(o => o !== 'gh:comment') }));
  // Same sha lineage: head X approved, branch updated to Y with identical files.
  const L = ledgerFor([
    { action: 'change.proposed', result: 'ok', prNumber: 7, gitSha: HEAD, at: '1' }, { action: 'change.approved', result: 'ok', prNumber: 7, gitSha: HEAD, approverOid: AARON.oid, at: '2' },
    { action: 'change.branchupdated', result: 'ok', prNumber: 7, gitSha: HEAD2, detail: JSON.stringify({ previousHeadSha: HEAD, treeIdentical: true }), at: '3' }], 7);
  assert.deepEqual([...equivalentShas(L, HEAD2)].sort(), [HEAD, HEAD2].sort());
  assert.equal(currentApproval(L, HEAD2, { mode: 'testing', authorOid: AARON.oid }).approval.sha, HEAD);
  const L2 = ledgerFor([...L.rows.slice(0, 2), { ...L.rows[2], detail: { previousHeadSha: HEAD, treeIdentical: false } }], 7);
  assert.equal(currentApproval(L2, HEAD2, { mode: 'testing', authorOid: AARON.oid }).approval, null);
});

test('merge (testing, self-approved): intent, squash merge pinned to the head, ok row with the merge sha, trailers in the commit', async () => {
  const w = world();
  await approve(w);
  w.order.length = 0;
  const r = await merge(w);
  assert.deepEqual({ ok: r.ok, merged: r.merged, mergeSha: r.mergeSha, selfApproved: r.selfApproved }, { ok: true, merged: true, mergeSha: MERGE, selfApproved: true });
  assert.deepEqual(w.order.filter(o => /merged|gh:merge/.test(o)), ['audit:change.merged:intent', 'gh:merge', 'audit:change.merged:ok']);
  assert.equal(w.merges[0].sha, HEAD);
  assert.match(w.merges[0].title, /\(#7\)$/);
  for (const t of [`R360-Entra-Oid: ${AARON.oid}`, `R360-Approver-Oid: ${AARON.oid}`, `R360-Merged-By-Oid: ${AARON.oid}`, 'R360-Self-Approved: true', 'R360-Request-Id: ', `Co-authored-by: ${AARON.oid} <${AARON.oid}@users.r360.invalid>`, 'SELF-APPROVED']) assert.ok(w.merges[0].message.includes(t), t);
  const ok = ofAction(w, 'change.merged').at(-1);
  assert.equal(ok.result, 'ok'); assert.equal(ok.selfApproved, true); assert.equal(ok.approverOid, AARON.oid); assert.equal(ok.gitSha, HEAD); assert.equal(ok.detail.mergeSha, MERGE); assert.equal(ok.githubRequestId, 'R-merge');
  // A second click after the merge is not a second merge.
  const again = await merge(w);
  assert.deepEqual({ already: again.already, mergeSha: again.mergeSha }, { already: true, mergeSha: MERGE });
  assert.equal(w.merges.length, 1);
});

test('merge by a different approver records both people', async () => {
  const w = world();
  await approve(w, USER1, ['approver']);
  const r = await merge(w, AARON, AUTHOR);
  assert.equal(r.selfApproved, false);
  assert.match(w.merges[0].message, new RegExp(`R360-Approver-Oid: ${USER1.oid}`));
  assert.match(w.merges[0].message, new RegExp(`R360-Merged-By-Oid: ${AARON.oid}`));
  assert.match(w.merges[0].message, /R360-Self-Approved: false/);
});

test('merge in enforced mode: a self-approval (even one recorded in testing mode) does not count; user1 approving does', async () => {
  const w = world();
  await approve(w); // recorded while the mode was testing
  const enforced = createChanges({ config: cfgOf('enforced'), github: w.github, audit: w.audit, now: () => w.t, log: { error() {} } });
  await assert.rejects(enforced.merge(AARON, AUTHOR, 7, { headSha: HEAD }), e => e.status === 409 && /self-approval/i.test(e.message));
  assert.equal(w.merges.length, 0);
  await enforced.approve(USER1, ['approver'], 7, { headSha: HEAD });
  const r = await enforced.merge(AARON, AUTHOR, 7, { headSha: HEAD });
  assert.equal(r.selfApproved, false);
  assert.equal(w.merges.length, 1);
  assert.match(w.merges[0].message, new RegExp(`R360-Approver-Oid: ${USER1.oid}`));
});

test('merge refuses: no approval, red or pending CI, a moved head, no approver role, an external PR; nothing reaches GitHub', async () => {
  const w = world();
  await fails(merge(w), 409, /not been approved/);
  await approve(w);
  w.pr.checks = [{ name: 'PSScriptAnalyzer', status: 'completed', conclusion: 'failure' }];
  await fails(merge(w), 409, /CI failed/);
  w.pr.checks = [{ name: 'PSScriptAnalyzer', status: 'queued', conclusion: null }];
  await fails(merge(w), 409, /not finished/);
  w.pr.checks = GREEN;
  await fails(merge(w, AARON, AUTHOR, { headSha: HEAD2 }), 409, /moved/);
  await fails(merge(w, AARON, ['author']), 403, /approver/);
  w.threads = 1;
  await fails(merge(w), 409, /unresolved/);
  w.threads = 0; w.pr.headRepo = 'evil/fork';
  await fails(merge(w), 409, /not an r360 change/);
  assert.equal(w.merges.length, 0);
  assert.equal(ofAction(w, 'change.merged').length, 0, 'refusals before the action leave no merge rows');
});

test('merge: GitHub refusing it (405) leaves a failed row and a 409; the approval stays', async () => {
  const w = world();
  await approve(w);
  w.mergeError = { status: 405, message: 'Required status check "PSScriptAnalyzer" is expected.' };
  await fails(merge(w), 409, /Required status check/);
  assert.deepEqual(ofAction(w, 'change.merged').map(r => r.result), ['intent', 'failed']);
  assert.match(ofAction(w, 'change.merged').at(-1).reason, /Required status check/);
  w.mergeError = null;
  assert.equal((await merge(w)).merged, true, 'the same approval still works once GitHub allows it');
});

test('merge: the audit trail down means no merge; a result row that cannot be written is reported, the merge stands', async () => {
  const w = world();
  await approve(w);
  w.auditListDown = true;
  await fails(merge(w), 503, /audit trail is unavailable/);
  assert.equal(w.merges.length, 0);
  w.auditListDown = false; w.failResultFor = 'change.merged';
  const r = await merge(w);
  assert.equal(r.merged, true); assert.match(r.warning, /result row could not be written/);
});

test('merge when behind main: updates the branch first (audited), identical files keep the approval, the user merges again', async () => {
  const w = world();
  await approve(w);
  w.behind = 2;
  const r = await merge(w);
  assert.deepEqual({ merged: r.merged, branchUpdated: r.branchUpdated, headSha: r.headSha, approvalKept: r.approvalKept }, { merged: false, branchUpdated: true, headSha: HEAD2, approvalKept: true });
  assert.equal(w.merges.length, 0);
  assert.deepEqual(ofAction(w, 'change.branchupdated').map(x => x.result), ['intent', 'ok']);
  const row = ofAction(w, 'change.branchupdated').at(-1);
  assert.equal(row.gitSha, HEAD2); assert.equal(row.detail.previousHeadSha, HEAD); assert.equal(row.detail.treeIdentical, true);
  assert.match(r.message, /approval still applies/);
  // CI runs on the new head, then the second click merges it.
  w.behind = 0;
  const list = await w.c.list(AARON, AUTHOR);
  assert.equal(list.changes[0].approval.sha, HEAD, 'the approval carries to the new head');
  const m = await merge(w);
  assert.equal(m.merged, true); assert.equal(w.merges[0].sha, HEAD2);
  assert.equal(ofAction(w, 'change.merged').at(-1).detail.approvalSha, HEAD);
});

test('merge when behind main with changed files: the approval is gone and says so', async () => {
  const w = world();
  await approve(w);
  w.behind = 1;
  w.files[HEAD2] = { 'remediation.json': '{"a":1}\n', 'detect.ps1': 'CHANGED\n', 'remediate.ps1': 'r\n' };
  const r = await merge(w);
  assert.deepEqual({ branchUpdated: r.branchUpdated, approvalKept: r.approvalKept }, { branchUpdated: true, approvalKept: false });
  assert.match(r.message, /approval no longer applies/);
  assert.equal(ofAction(w, 'change.branchupdated').at(-1).detail.treeIdentical, false);
  w.behind = 0;
  await fails(merge(w), 409, /not been approved/);
  assert.equal(w.merges.length, 0);
});

test('update-branch trouble: a GitHub refusal leaves a failed row; unreadable files never carry the approval', async () => {
  const w = world();
  await approve(w);
  w.behind = 1; w.updateError = 'merge conflict';
  await fails(merge(w), 409, /merge conflict/);
  assert.deepEqual(ofAction(w, 'change.branchupdated').map(x => x.result), ['intent', 'failed']);
  const w2 = world();
  await approve(w2);
  w2.behind = 1; w2.files[HEAD2] = new Error('unreadable');
  const r = await merge(w2);
  assert.equal(r.approvalKept, false);
});

test('reject: approver only, a reason is required, audited intent then result, the PR is closed', async () => {
  const w = world();
  await fails(w.c.reject(AARON, ['author'], 7, { headSha: HEAD, reason: 'nope' }), 403);
  await fails(w.c.reject(AARON, AUTHOR, 7, { headSha: HEAD, reason: ' ' }), 400, /reason/);
  await fails(w.c.reject(AARON, AUTHOR, 7, { headSha: HEAD2, reason: 'wrong head' }), 409, /moved/);
  noWrites(w);
  const r = await w.c.reject(USER1, ['approver'], 7, { headSha: HEAD, reason: 'The detection is too broad.' });
  assert.deepEqual({ ok: r.ok, rejected: r.rejected }, { ok: true, rejected: true });
  assert.deepEqual(w.order.filter(o => /rejected|gh:reject/.test(o)), ['audit:change.rejected:intent', 'gh:reject', 'audit:change.rejected:ok']);
  assert.equal(ofAction(w, 'change.rejected').at(-1).reason, 'The detection is too broad.');
  assert.match(w.comments[0], /too broad/);
  assert.equal(w.pr.state, 'closed');
});

test('list: approval, self-approval pill data, per-user flags, stage; an unreadable audit trail disables the actions', async () => {
  const w = world();
  let l = (await w.c.list(AARON, AUTHOR)).changes[0];
  assert.deepEqual({ approval: l.approval, canApprove: l.canApprove, canMerge: l.canMerge, canReject: l.canReject, stage: l.stage }, { approval: null, canApprove: true, canMerge: false, canReject: true, stage: 'ci-passed' });
  assert.match(l.mergeBlock, /Approve this commit first/);
  await approve(w); w.t += 6000;
  l = (await w.c.list(AARON, AUTHOR)).changes[0];
  assert.equal(l.approval.selfApproved, true); assert.equal(l.approval.approverOid, AARON.oid); assert.equal(l.approval.approverUpn, AARON.upn);
  assert.deepEqual({ canMerge: l.canMerge, canApprove: l.canApprove, stage: l.stage }, { canMerge: true, canApprove: false, stage: 'approved' });
  assert.equal(l.steps.find(s => s.id === 'approved').state, 'done');
  const viewer = (await w.c.list(AARON, ['author'])).changes[0];
  assert.equal(viewer.canApprove, false); assert.equal(viewer.canMerge, false); assert.match(viewer.approveBlock, /approver/);
  const blocked = world(); blocked.auditListDown = true;
  const bl = await blocked.c.list(AARON, AUTHOR);
  assert.match(bl.warning, /audit trail could not be read/);
  assert.equal(bl.changes[0].canApprove, false); assert.equal(bl.changes[0].canMerge, false);
  // enforced: only the author's own approval exists, so it is shown as ignored and the merge is blocked
  const e = createChanges({ config: cfgOf('enforced'), github: w.github, audit: w.audit, now: () => w.t + 10000, log: { error() {} } });
  const el = (await e.list(AARON, AUTHOR)).changes[0];
  assert.equal(el.approval, null); assert.equal(el.ignoredSelfApproval, true); assert.equal(el.canMerge, false); assert.match(el.mergeBlock, /Enforced mode/);
  assert.match(el.approveBlock, /different approver|authored/);
});

test('list: a pull request nobody proposed through r360 is read-only', async () => {
  const w = world(); w.rows = [];
  const l = (await w.c.list(AARON, AUTHOR)).changes[0];
  assert.match(l.provenanceError, /no audit record/);
  assert.deepEqual({ a: l.canApprove, m: l.canMerge, r: l.canReject }, { a: false, m: false, r: false });
});

test('stageOf stays backward compatible and knows the later stages', () => {
  const merged = { merged: true, state: 'closed', checks: null };
  assert.equal(stageOf(merged).stage, 'merged');
  assert.equal(stageOf(merged).steps.find(s => s.id === 'signed').state, 'todo');
  assert.equal(stageOf(merged, { signing: { state: 'running' } }).stage, 'signing');
  assert.equal(stageOf(merged, { signing: { state: 'verified' } }).stage, 'signed');
  assert.equal(stageOf(merged, { signing: { state: 'verified' } }).steps.find(s => s.id === 'signed').state, 'done');
  assert.equal(stageOf(merged, { signing: { state: 'verify-failed' } }).stage, 'sign-failed');
  assert.equal(stageOf({ state: 'open', merged: false, checks: GREEN }).stage, 'ci-passed');
  assert.equal(stageOf({ state: 'open', merged: false, checks: GREEN }, { approval: { sha: HEAD } }).stage, 'approved');
  assert.equal(stageOf({ state: 'closed', merged: false, checks: null }).stage, 'discarded');
});

// ---- signing verification ----
const ZIP = readFileSync(new URL('./data/signed-c0ffee00.zip', import.meta.url));
const SIGNED_COMMIT = 'c0ffee0000000000000000000000000000000001';
const SIGNED_FOLDER = 'Sample-RemediationCanary';
const parts = Object.fromEntries(Object.entries(unzipSync(new Uint8Array(ZIP))).map(([k, v]) => [k, Buffer.from(v).toString('utf8')]));
const gitTexts = { 'remediation.json': parts[`remediations/${SIGNED_FOLDER}/remediation.json`], 'detect.ps1': parts[`remediations/${SIGNED_FOLDER}/detect.ps1`].split(SIG_BEGIN)[0], 'remediate.ps1': parts[`remediations/${SIGNED_FOLDER}/remediate.ps1`].split(SIG_BEGIN)[0] };
const JOBS = [{ name: 'Signing self-test', conclusion: 'success' }, { name: 'Sign (Key Vault HSM)', conclusion: 'success' }, { name: 'Verify (Windows Authenticode)', conclusion: 'success' }];
function mergedWorld(over = {}) {
  const w = world({ folder: SIGNED_FOLDER, pr: { state: 'closed', merged: true, headSha: HEAD, mergeSha: SIGNED_COMMIT, mergedAt: new Date(T0 - 3600e3).toISOString(), checks: null, ...over } });
  w.files[SIGNED_COMMIT] = gitTexts;
  w.run = { id: 40461381266, status: 'completed', conclusion: 'success', url: 'https://github.com/your-org/remediations/actions/runs/40461381266', jobs: JOBS };
  w.artifact = { buffer: ZIP, artifact: { id: 99, runId: 40461381266, bytes: ZIP.length } };
  w.t = Date.parse('2026-10-27T15:04:00Z');
  return w;
}

test('verify signing: a good artifact writes intent then an ok row; a second call is idempotent; the list shows Signed', async () => {
  const w = mergedWorld();
  let l = (await w.c.list(AARON, AUTHOR)).changes[0];
  assert.equal(l.signing.state, 'ready'); assert.equal(l.canVerify, true); assert.equal(l.stage, 'signing');
  const r = await w.c.verifySigning(AARON, AUTHOR, 7);
  assert.equal(r.ok, true); assert.match(r.manifestSha256, /^[0-9a-f]{64}$/); assert.equal(r.signerNotAfter, '2029-10-26T12:55:48.000Z');
  assert.deepEqual(ofAction(w, 'sign.verified').map(x => x.result), ['intent', 'ok']);
  const ok = ofAction(w, 'sign.verified').at(-1);
  assert.equal(ok.gitSha, SIGNED_COMMIT); assert.equal(ok.detail.artifactId, 99); assert.equal(ok.detail.files.length, 3);
  assert.equal((await w.c.verifySigning(AARON, AUTHOR, 7)).already, true);
  assert.equal(ofAction(w, 'sign.verified').length, 2);
  w.t += 20000;
  l = (await w.c.list(AARON, AUTHOR)).changes[0];
  assert.deepEqual({ state: l.signing.state, stage: l.stage, canVerify: l.canVerify }, { state: 'verified', stage: 'signed', canVerify: false });
});

test('verify signing: not ready, failed workflow, no artifact, tampered artifact, git mismatch; failures are audited and the tab says why', async () => {
  const w = mergedWorld();
  w.run = null;
  await fails(w.c.verifySigning(AARON, AUTHOR, 7), 409, /not started/);
  w.run = { id: 1, status: 'in_progress', conclusion: null, url: 'u', jobs: null };
  await fails(w.c.verifySigning(AARON, AUTHOR, 7), 409, /still running/);
  assert.equal(ofAction(w, 'sign.verified').length, 0, 'nothing is audited until a check really starts');
  w.run = { id: 1, status: 'completed', conclusion: 'failure', url: 'https://github.com/x', jobs: JOBS };
  assert.equal((await w.c.verifySigning(AARON, AUTHOR, 7)).ok, false);
  w.run = { id: 1, status: 'completed', conclusion: 'success', url: 'https://github.com/x', jobs: JOBS.slice(0, 2) };
  assert.match((await w.c.verifySigning(AARON, AUTHOR, 7)).problems[0], /did not succeed/);
  w.run = { id: 1, status: 'completed', conclusion: 'success', url: 'https://github.com/x', jobs: JOBS };
  w.artifact = null;
  assert.match((await w.c.verifySigning(AARON, AUTHOR, 7)).problems[0], /no signed-/);
  w.artifact = new Error('storage 500');
  assert.match((await w.c.verifySigning(AARON, AUTHOR, 7)).problems[0], /Could not download/);
  w.artifact = { buffer: ZIP, artifact: { id: 99 } };
  w.files[SIGNED_COMMIT] = { ...gitTexts, 'detect.ps1': gitTexts['detect.ps1'] + 'evil\n' };
  const bad = await w.c.verifySigning(AARON, AUTHOR, 7);
  assert.equal(bad.ok, false); assert.match(bad.problems.join(' '), /detect\.ps1: the signed content is not what is in git/);
  w.files[SIGNED_COMMIT] = new Error('cannot read git');
  assert.match((await w.c.verifySigning(AARON, AUTHOR, 7)).problems.join(' '), /could not be read/);
  assert.ok(ofAction(w, 'sign.verify.failed').every(r => r.result === 'failed' && r.reason));
  assert.equal(ofAction(w, 'sign.verified').filter(r => r.result === 'ok').length, 0);
  w.t += 20000;
  const l = (await w.c.list(AARON, AUTHOR)).changes[0];
  assert.equal(l.signing.state, 'verify-failed'); assert.equal(l.canVerify, true); assert.equal(l.stage, 'sign-failed');
});

test('verify signing: role, merged, and audit preconditions; the list never breaks when GitHub signing reads fail', async () => {
  const w = mergedWorld();
  await fails(w.c.verifySigning(AARON, ['viewer'], 7), 403);
  const open = world();
  await fails(open.c.verifySigning(AARON, AUTHOR, 7), 409, /not merged yet/);
  const noProp = mergedWorld(); noProp.rows = [];
  await fails(noProp.c.verifySigning(AARON, AUTHOR, 7), 409, /no audit record/);
  const down = mergedWorld(); down.auditListDown = true;
  await fails(down.c.verifySigning(AARON, AUTHOR, 7), 503);
  w.run = new Error('Resource not accessible by integration');
  const l = (await w.c.list(AARON, AUTHOR)).changes[0];
  assert.equal(l.signing.state, 'unknown'); assert.match(l.signing.note, /Resource not accessible/);
  await fails(w.c.verifySigning(AARON, AUTHOR, 7), 502, /Could not read the signing workflow/);
});

test('list: signing states from the workflow run', async () => {
  const w = mergedWorld();
  const state = async () => { w.t += 20000; return (await w.c.list(AARON, AUTHOR)).changes[0].signing.state; };
  w.run = null; w.pr.mergedAt = new Date(w.t - 60e3).toISOString();
  assert.equal(await state(), 'waiting');
  w.pr.mergedAt = new Date(w.t - 3600e3).toISOString();
  assert.equal(await state(), 'missing');
  w.run = { id: 1, status: 'in_progress', conclusion: null, url: 'https://github.com/x', jobs: null };
  assert.equal(await state(), 'running');
  w.run = { id: 1, status: 'completed', conclusion: 'failure', url: 'https://github.com/x', jobs: JOBS };
  assert.equal(await state(), 'workflow-failed');
  w.run = { id: 1, status: 'completed', conclusion: 'success', url: 'https://github.com/x', jobs: JOBS };
  assert.equal(await state(), 'ready');
});
