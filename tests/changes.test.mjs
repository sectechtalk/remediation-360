import test from 'node:test';
import assert from 'node:assert/strict';
import { createChanges, ChangeError, machineBlock } from '../server/changes.mjs';
import { metaText } from '../server/remediation-schema.mjs';
import { loadConfig } from '../server/config.mjs';
import { ENV } from './fixtures.mjs';

const OID = '94540000-0000-4000-8000-0000000000c3';
const OTHER = '11111111-2222-4333-8444-555555555555';
const CANARY = '90000000-0000-4000-8000-0000000000c2';
const PROD = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
const user = { oid: OID, upn: 'admin@contoso.com', name: 'Aaron Brooks' };
const config = loadConfig({ ...ENV, R360_CANARY_GROUP_ID: CANARY, R360_MAX_OPEN_CHANGES: '2' });
const T0 = Date.parse('2026-10-27T15:04:00Z');
const META = { displayName: 'STT - Test remediation', description: 'Does a thing', publisher: 'SecTechTalk', runAs: 'system', runAs32Bit: false, schedule: { type: 'daily', interval: 1, time: '02:00:00' }, assignment: { runRemediationScript: true } };
const NEW = { kind: 'new', folder: 'Stt-New', meta: META, detect: 'exit 1\r\n', remediate: 'Write-Output fixed' };
const MAIN_META = { displayName: 'STT - Existing', description: 'old', publisher: 'SecTechTalk', runAs: 'system', runAs32Bit: false, schedule: { type: 'daily', interval: 1, time: '03:00:00' }, assignment: { groupId: PROD, runRemediationScript: true } };

function world({ items, cfg = config, open = [] } = {}) {
  const w = { t: T0, events: [], order: [], gh: [], auditDown: false, ghFail: null, pulls: open };
  w.audit = { record: async e => { if (w.auditDown) throw new Error('down'); w.order.push(`audit:${e.action}:${e.result}`); w.events.push(e); return e; } };
  w.items = items ?? [{ folder: 'Stt-Existing', meta: MAIN_META, detect: 'exit 1\n', remediate: 'fix\n' }, { folder: 'Other', meta: { ...MAIN_META, displayName: 'STT - Other' }, detect: 'a\n', remediate: 'b\n' }];
  w.github = {
    catalog: async () => ({ items: w.items, sha: 'main1', approvers: [{ entraObjectId: OID, upn: user.upn, roles: ['author'] }] }),
    listPulls: async () => w.pulls,
    getPull: async n => { const p = w.pulls.find(x => x.number === n); if (!p) throw new Error('nf'); return p; },
    readChangeFiles: async ({ sha, folder }) => w.head ?? { meta: { ...MAIN_META, ...META, assignment: { groupId: CANARY, runRemediationScript: true } }, detect: 'exit 1\n', remediate: 'Write-Output fixed\n' },
    proposeChange: async a => { w.order.push('gh:propose'); w.gh.push(['propose', a]); if (w.ghFail) throw Object.assign(new Error(w.ghFail), { githubRequestId: 'R1', rolledBack: true }); return { number: 7, url: 'https://github.com/your-org/remediations/pull/7', headSha: 'c1', githubRequestId: 'R2' }; },
    updateChange: async a => { w.order.push('gh:update'); w.gh.push(['update', a]); if (w.ghFail) throw Object.assign(new Error(w.ghFail), { status: w.ghStatus }); return { headSha: 'c2', githubRequestId: 'R3' }; },
    discardChange: async a => { w.order.push('gh:discard'); w.gh.push(['discard', a]); if (w.ghFail) throw Object.assign(new Error(w.ghFail), { status: w.ghStatus }); return { githubRequestId: 'R4' }; },
  };
  w.c = createChanges({ config: cfg, github: w.github, audit: w.audit, now: () => w.t, log: { error() {} } });
  return w;
}
const pr = (number, folder, authorOid = OID, over = {}) => ({ number, state: 'open', merged: false, title: 't', url: `https://github.com/your-org/remediations/pull/${number}`, branch: `r360/${folder}/202610271504-94540000`, headSha: 'h'.repeat(40).replace(/h/g, 'a'), body: `Proposed through r360 by admin@contoso.com on x\n${machineBlock({ folder, authorOid })}`, createdAt: 'c', updatedAt: 'u', mergedAt: null, checks: null, ...over });
const fails = (p, status, re) => assert.rejects(p, e => e instanceof ChangeError && e.status === status && (!re || re.test(e.message + (e.details || []).join('|'))), `expected ${status} ${re}`);

test('propose (new): intent row BEFORE GitHub, result row after, canary group forced, scripts normalized, trailers present', async () => {
  const w = world();
  const r = await w.c.propose(user, { ...NEW, meta: { ...META, assignment: { groupId: PROD, runRemediationScript: true } } }); // the caller tries to pick the production group
  assert.equal(r.ok, true); assert.equal(r.number, 7); assert.equal(r.kind, 'new');
  assert.deepEqual(w.order, ['audit:change.proposed:intent', 'gh:propose', 'audit:change.proposed:ok']);
  const [, a] = w.gh[0];
  assert.equal(a.branch, 'r360/Stt-New/202610271504-94540000');
  assert.deepEqual(a.files.map(f => f.path), ['remediations/Stt-New/remediation.json', 'remediations/Stt-New/detect.ps1', 'remediations/Stt-New/remediate.ps1']);
  const meta = JSON.parse(a.files[0].content);
  assert.equal(meta.assignment.groupId, CANARY, 'the group is decided by the server');
  assert.equal(a.files[1].content, 'exit 1\n'); assert.equal(a.files[2].content, 'Write-Output fixed\n');
  assert.match(a.message, /R360-Entra-Oid: 94540000/); assert.match(a.message, /Co-authored-by: Aaron Brooks <94540000-0000-4000-8000-0000000000c3@users\.r360\.invalid>/);
  assert.match(a.body, /canary group only/); assert.match(a.body, /Four-eyes mode: \*\*testing\*\*/); assert.match(a.body, /r360:\{"v":1,"kind":"author","folder":"Stt-New"/);
  const [i, ok] = w.events;
  assert.equal(i.result, 'intent'); assert.equal(i.actorOid, OID); assert.equal(i.target, 'remediations/Stt-New'); assert.equal(i.mode, 'testing');
  assert.equal(ok.result, 'ok'); assert.equal(ok.prNumber, 7); assert.equal(ok.gitSha, 'c1'); assert.equal(ok.githubRequestId, 'R2'); assert.equal(ok.requestId, i.requestId); assert.equal(r.requestId, i.requestId);
  assert.ok(JSON.stringify(w.events).indexOf('Write-Output') < 0, 'script content is never put in the audit trail');
});

test('propose: the audit trail down means no GitHub call at all', async () => {
  const w = world(); w.auditDown = true;
  await fails(w.c.propose(user, NEW), 503, /audit trail/);
  assert.deepEqual(w.gh, []);
});

test('propose: GitHub failure writes a failed result row and surfaces a 502 (permission problems named)', async () => {
  const w = world(); w.ghFail = 'HTTP 422';
  await fails(w.c.propose(user, NEW), 502, /rejected/);
  assert.deepEqual(w.events.map(e => e.result), ['intent', 'failed']);
  assert.equal(w.events[1].githubRequestId, 'R1'); assert.match(w.events[1].reason, /422/); assert.equal(w.events[1].detail.rolledBack, true);
  const w2 = world();
  w2.github.proposeChange = async () => { throw Object.assign(new Error('GitHub write token failed: HTTP 422 (the GitHub App installation may lack a permission: pull_requests:write)'), { permission: true }); };
  await fails(w2.c.propose(user, NEW), 502, /refused the write token.*pull_requests:write/);
});

test('propose: an audit result row that cannot be written is reported, but the change stands', async () => {
  const w = world(); let n = 0;
  w.audit.record = async e => { if (++n === 2) throw new Error('down'); w.events.push(e); };
  const r = await w.c.propose(user, NEW);
  assert.equal(r.ok, true); assert.match(r.warning, /could not be written to the audit trail/);
});

test('propose: validation errors are 400 with details; unknown fields rejected; nothing is written', async () => {
  const w = world();
  await fails(w.c.propose(user, { ...NEW, meta: { ...META, displayName: 'x' } }), 400, /displayName/);
  await fails(w.c.propose(user, { ...NEW, detect: '' }), 400, /detect\.ps1: the script is empty/);
  await fails(w.c.propose(user, { ...NEW, remediate: '# SIG # Begin signature block\nx\n' }), 400, /signature block/);
  await fails(w.c.propose(user, { ...NEW, extra: 1 }), 400, /Unknown field/);
  await fails(w.c.propose(user, { ...NEW, folder: '../evil' }), 400, /folder/);
  await fails(w.c.propose(user, { ...NEW, kind: 'delete' }), 400, /kind/);
  await fails(w.c.propose(user, { ...NEW, meta: 'x' }), 400, /meta/);
  await fails(w.c.propose(user, null), 400);
  await fails(w.c.propose(user, { ...NEW, meta: { ...META, displayName: 'stt - OTHER' } }), 400, /already used/);
  assert.deepEqual(w.gh, []); assert.deepEqual(w.events, []);
});

test('propose: new vs edit must match what is on main; the canary group must be configured', async () => {
  const w = world();
  await fails(w.c.propose(user, { ...NEW, folder: 'Stt-Existing' }), 409, /already exists/);
  await fails(w.c.propose(user, { ...NEW, kind: 'edit', folder: 'Nope' }), 404, /does not exist/);
  const w2 = world({ cfg: loadConfig({ ...ENV }) });
  await fails(w2.c.propose(user, NEW), 503, /R360_CANARY_GROUP_ID/);
});

test('propose (edit): the main group is kept even if the caller sends another; only changed files are committed; identical is refused', async () => {
  const w = world();
  const meta = { ...MAIN_META, description: 'new description', assignment: { groupId: CANARY, runRemediationScript: true } };
  const r = await w.c.propose(user, { kind: 'edit', folder: 'Stt-Existing', meta, detect: 'exit 1\r\n', remediate: 'fix\n' });
  assert.equal(r.kind, 'edit');
  const [, a] = w.gh[0];
  assert.deepEqual(a.files.map(f => f.path), ['remediations/Stt-Existing/remediation.json']);
  assert.equal(JSON.parse(a.files[0].content).assignment.groupId, PROD);
  assert.deepEqual(r.files.map(f => f.status), ['modified', 'unchanged', 'unchanged']);
  await fails(w.c.propose(user, { kind: 'edit', folder: 'Stt-Existing', meta: MAIN_META, detect: 'exit 1\n', remediate: 'fix\n' }), 400, /Nothing changed/);
  const w2 = world({ items: [{ folder: 'Stt-Existing', meta: { ...MAIN_META, assignment: {} }, detect: 'a\n', remediate: 'b\n' }] });
  await fails(w2.c.propose(user, { kind: 'edit', folder: 'Stt-Existing', meta: MAIN_META, detect: 'x\n', remediate: 'b\n' }), 409, /no valid assignment group/);
});

test('propose: one open change per folder (409) and an open-change cap (429)', async () => {
  const w = world({ open: [pr(3, 'Stt-New')] });
  await fails(w.c.propose(user, NEW), 409, /#3/);
  const w2 = world({ open: [pr(3, 'A'), pr(4, 'B'), pr(5, 'not-r360', OID, { body: 'human PR' })] });
  await fails(w2.c.propose(user, NEW), 429, /limit 2/);
  const w3 = world({ open: [pr(3, 'A'), pr(5, 'x', OID, { body: 'human PR' })] });
  assert.equal((await w3.c.propose(user, NEW)).ok, true, 'PRs without the machine block do not count');
});

test('propose with dryRun: validates and reports, with no audit row and no GitHub write', async () => {
  const w = world();
  const r = await w.c.propose(user, { ...NEW, dryRun: true });
  assert.equal(r.dryRun, true); assert.equal(r.groupId, CANARY); assert.equal(r.openChanges, 0); assert.equal(r.maxOpenChanges, 2);
  assert.deepEqual(r.files.map(f => f.status), ['added', 'added', 'added']);
  assert.deepEqual(w.gh, []); assert.deepEqual(w.events, []);
  await fails(w.c.propose(user, { ...NEW, dryRun: true, detect: '' }), 400);
});

test('update: only the author or an admin; compares with the branch head (a reverted file is committed); uses expectHeadSha; audited', async () => {
  const w = world({ open: [pr(7, 'Stt-New')] });
  w.head = { meta: { ...META, assignment: { groupId: CANARY, runRemediationScript: true } }, detect: 'changed on the branch\n', remediate: 'Write-Output fixed\n' };
  await fails(w.c.update({ ...user, oid: OTHER }, ['author'], 7, { meta: META, detect: 'exit 1\n', remediate: 'Write-Output fixed\n' }), 403, /author or an admin/);
  await fails(w.c.update(user, ['author'], 7, { meta: META, detect: 'exit 1\n', remediate: 'Write-Output fixed\n', folder: 'Other' }), 400, /Unknown field/);
  assert.deepEqual(w.gh, []);
  const r = await w.c.update(user, ['author'], 7, { meta: META, detect: 'exit 1\r\n', remediate: 'Write-Output fixed\n', expectHeadSha: 'f'.repeat(40) });
  assert.equal(r.ok, true);
  const [, a] = w.gh[0];
  assert.deepEqual(a.files.map(f => f.path), ['remediations/Stt-New/detect.ps1'], 'only the file that differs from the branch head');
  assert.equal(a.expectHeadSha, 'f'.repeat(40)); assert.equal(a.number, 7); assert.equal(a.branch, 'r360/Stt-New/202610271504-94540000');
  assert.match(a.body, /r360:\{"v":1,"kind":"author","folder":"Stt-New","authorOid":"94540000/);
  assert.deepEqual(w.order.slice(-3), ['audit:change.updated:intent', 'gh:update', 'audit:change.updated:ok']);
  // Admin may update someone else's change; the author recorded in the machine block does not change.
  const w2 = world({ open: [pr(7, 'Stt-New', OTHER)] }); w2.head = w.head;
  await w2.c.update(user, ['admin'], 7, { meta: META, detect: 'exit 1\n', remediate: 'Write-Output fixed\n' });
  assert.match(w2.gh[0][1].body, new RegExp(`"authorOid":"${OTHER}"`));
  // An update with nothing new is refused.
  await fails(w2.c.update(user, ['admin'], 7, { meta: META, detect: 'changed on the branch\n', remediate: 'Write-Output fixed\n' }), 400, /Nothing changed/);
});

test('update and discard: audit down means no GitHub call; a 409 from GitHub stays a 409; a closed PR is refused', async () => {
  const w = world({ open: [pr(7, 'Stt-New')] }); w.auditDown = true;
  await fails(w.c.discard(user, ['author'], 7), 503);
  await fails(w.c.update(user, ['author'], 7, { meta: META, detect: 'x\n', remediate: 'y\n' }), 503);
  assert.deepEqual(w.gh, []);
  const w2 = world({ open: [pr(7, 'Stt-New')] }); w2.ghFail = 'The change was updated elsewhere.'; w2.ghStatus = 409;
  w2.head = { meta: META, detect: 'a\n', remediate: 'b\n' };
  await fails(w2.c.update(user, ['author'], 7, { meta: META, detect: 'x\n', remediate: 'y\n' }), 409, /elsewhere/);
  assert.deepEqual(w2.events.map(e => e.result), ['intent', 'failed']);
  const w3 = world({ open: [pr(7, 'Stt-New', OID, { state: 'closed' })] });
  await fails(w3.c.discard(user, ['author'], 7), 409, /not an open r360 change/);
  const w4 = world({ open: [pr(7, 'Stt-New', OID, { body: 'a human PR' })] });
  await fails(w4.c.discard(user, ['admin'], 7), 409, /not an open r360 change/);
  await fails(w4.c.discard(user, ['admin'], -1), 400, /Invalid/);
});

test('discard: only the author or an admin; intent, GitHub, result', async () => {
  const w = world({ open: [pr(7, 'Stt-New', OTHER)] });
  await fails(w.c.discard(user, ['author', 'approver'], 7), 403);
  assert.deepEqual(w.gh, []);
  const r = await w.c.discard(user, ['admin'], 7);
  assert.equal(r.ok, true);
  assert.deepEqual(w.order, ['audit:change.discarded:intent', 'gh:discard', 'audit:change.discarded:ok']);
  assert.deepEqual(w.gh[0][1], { number: 7, branch: 'r360/Stt-New/202610271504-94540000' });
  assert.equal(w.events[1].githubRequestId, 'R4');
});

test('list: only r360 changes, canEdit by author or admin, a 5 s cache that mutations bust', async () => {
  const w = world({ open: [pr(7, 'Stt-New'), pr(8, 'Other', OTHER), pr(9, 'x', OID, { body: 'human' }), pr(6, 'Old', OID, { state: 'closed', merged: true })] });
  let calls = 0; const lp = w.github.listPulls; w.github.listPulls = async o => { calls++; return lp(o); };
  const l = await w.c.list(user, ['author']);
  assert.deepEqual(l.changes.map(c => [c.number, c.canEdit, c.stage]), [[7, true, 'ci-running'], [8, false, 'ci-running'], [6, false, 'merged']]);
  assert.equal(l.changes[0].authorUpn, user.upn); assert.equal(l.openCount, 2); assert.equal(l.maxOpenChanges, 2); assert.ok(l.fetchedAt);
  assert.equal((await w.c.list(user, ['admin'])).changes[1].canEdit, true);
  assert.equal(calls, 1);
  w.t += 6000; await w.c.list(user, []); assert.equal(calls, 2);
  await w.c.discard(user, ['author'], 7); await w.c.list(user, []); assert.equal(calls, 3);
});

test('source: current main content for an edit; changeSource: head of an open change, same author rule', async () => {
  const w = world({ open: [pr(7, 'Stt-New')] });
  const s = await w.c.source('Stt-Existing');
  assert.equal(s.meta.displayName, 'STT - Existing'); assert.equal(s.detect, 'exit 1\n');
  await fails(w.c.source('Missing'), 404); await fails(w.c.source('../x'), 400);
  const cs = await w.c.changeSource(user, ['author'], 7);
  assert.equal(cs.folder, 'Stt-New'); assert.equal(cs.headSha, 'a'.repeat(40));
  await fails(w.c.changeSource({ ...user, oid: OTHER }, ['author'], 7), 403);
});

test('propose: an empty or missing description defaults to the display name (client and server agree), a real one is kept', async () => {
  for (const description of ['', '   ', undefined, null]) {
    const w = world();
    const meta = { ...META, displayName: 'STT - Fresh' };
    if (description === undefined) delete meta.description; else meta.description = description;
    const r = await w.c.propose(user, { ...NEW, meta });
    assert.equal(r.ok, true, 'accepted: ' + JSON.stringify(description));
    assert.equal(JSON.parse(w.gh[0][1].files[0].content).description, 'STT - Fresh');
  }
  const w = world();
  await w.c.propose(user, { ...NEW, meta: { ...META, description: 'Does a thing' } });
  assert.equal(JSON.parse(w.gh[0][1].files[0].content).description, 'Does a thing');
  // A blank display name is still rejected (nothing to default to).
  await fails(world().c.propose(user, { ...NEW, meta: { ...META, displayName: '', description: '' } }), 400);
});
