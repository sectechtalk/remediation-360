import test from 'node:test';
import assert from 'node:assert/strict';
import { ALL_DEVICES, MAX_GROUPS, NULL_GUID, parseTargetRequest, targetOf, assignmentFor, promotionDiff, targetKey, targetFromKey, targetOfAssignments, graphTargets, isCanaryTarget, isCanaryOnly, groupsTarget } from '../server/target.mjs';
import { buildDesired, intuneDiff, descriptionStamp, createIntune } from '../server/intune.mjs';
import { validateMeta } from '../server/remediation-schema.mjs';
import { world, body, promote, publish, evidence, fails, ofAction, noGraphWrites, AARON, AUTHOR, PROD, PILOT, CAN, GONE, MAILONLY, COMMIT, HEAD, prodMeta } from './s6-world.mjs';

const G3 = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const guid = i => `${String(i).padStart(8, '0')}-0000-4000-8000-000000000000`;
const GROUPS = ids => ({ type: 'groups', groupIds: ids });
const grp = id => ({ '@odata.type': '#microsoft.graph.groupAssignmentTarget', groupId: id });
const ALLT = { '@odata.type': '#microsoft.graph.allDevicesAssignmentTarget' };

test('multi-target parsing: 1..20 unique real groups, one group normalizes to the single form, sorted and lowercased', () => {
  assert.deepEqual(parseTargetRequest(GROUPS([PROD.toUpperCase(), PILOT])).target, { kind: 'groups', groupIds: [PILOT, PROD] });
  assert.deepEqual(parseTargetRequest(GROUPS([PROD])).target, { kind: 'group', groupId: PROD });
  assert.equal(parseTargetRequest(GROUPS(Array.from({ length: MAX_GROUPS }, (_, i) => guid(i + 1)))).target.groupIds.length, 20);
  for (const bad of [GROUPS([]), GROUPS(Array.from({ length: 21 }, (_, i) => guid(i + 1))), GROUPS([PROD, PROD.toUpperCase()]), GROUPS([PROD, 'nope']), GROUPS([PROD, NULL_GUID]), GROUPS(PROD),
    { type: 'groups', groupIds: [PROD], groupId: PILOT }, { type: 'group', groupId: PROD, groupIds: [PILOT] }, { ...GROUPS([PROD]), extra: 1 }]) assert.ok(parseTargetRequest(bad).error, JSON.stringify(bad));
});

test('exclusivity: All devices never combines with groups, in the request, in remediation.json, in Graph', () => {
  for (const bad of [{ type: 'allDevices', groupIds: [PROD] }, { type: 'allDevices', groupId: PROD }, GROUPS([PROD, 'allDevices'])]) assert.match(parseTargetRequest(bad).error, /All devices|takes no groups/);
  assert.match(parseTargetRequest(GROUPS([PROD, 'allDevices'])).error, /cannot be combined with groups/);
  assert.equal(targetOf({ groupIds: [PROD], target: 'allDevices' }), null);
  assert.equal(targetOf({ groupIds: [PROD], groupId: PILOT }), null);
  assert.equal(targetOfAssignments([{ target: ALLT }, { target: grp(PROD) }]), null);
  assert.equal(targetOfAssignments([{ target: ALLT }, { target: ALLT }]), null);
  const m = a => ({ ...prodMeta, assignment: a });
  assert.equal(validateMeta(m({ groupIds: [PROD, PILOT] })).ok, true);
  assert.equal(validateMeta(m({ groupIds: [PROD], runRemediationScript: false })).ok, true);
  for (const bad of [{ groupIds: [PROD], target: 'allDevices' }, { groupIds: [PROD], groupId: PILOT }, { groupIds: [] }, { groupIds: [PROD, PROD] }, { groupIds: [NULL_GUID] }, { groupIds: ['x'] },
    { groupIds: Array.from({ length: 21 }, (_, i) => guid(i + 1)) }]) assert.equal(validateMeta(m(bad)).ok, false, JSON.stringify(bad));
});

test('canary exclusion: the canary group anywhere in the set is a canary target; only the canary alone is canary-only', () => {
  const t = groupsTarget([PROD, CAN.toUpperCase()]);
  assert.equal(isCanaryTarget(t, CAN), true); assert.equal(isCanaryOnly(t, CAN), false);
  assert.equal(isCanaryOnly({ kind: 'group', groupId: CAN }, CAN), true); assert.equal(isCanaryTarget(groupsTarget([PROD, PILOT]), CAN), false);
});

test('remediation.json and keys for several groups: groupIds sorted, only the assignment leaves differ, keys round-trip', () => {
  const t = groupsTarget([PROD, PILOT]);
  assert.deepEqual(assignmentFor(t, { groupId: CAN, runRemediationScript: true }), { groupIds: [PILOT, PROD], runRemediationScript: true });
  assert.deepEqual(assignmentFor({ kind: 'group', groupId: PROD }, { groupIds: [PILOT, G3] }), { groupId: PROD });
  assert.equal(promotionDiff(t), 'assignment.groupId,assignment.groupIds');
  assert.equal(targetKey(t), `groups:${PILOT},${PROD}`);
  assert.deepEqual(targetFromKey(targetKey(t)), t); assert.deepEqual(targetFromKey(`group:${PROD}`), { kind: 'group', groupId: PROD }); assert.deepEqual(targetFromKey('allDevices'), { kind: ALL_DEVICES });
  assert.equal(targetFromKey(`groups:${PROD},${PILOT}`), null, 'an unsorted key is not canonical'); assert.equal(targetFromKey(`groups:${PROD}`), null, 'one group uses the group: key');
});

test('multi-target Intune diff: one assignment per group, compared as an exact set; runRemediationScript is not compared', () => {
  const t = groupsTarget([PROD, PILOT, G3]);
  const detect = Buffer.from('d'), rem = Buffer.from('r');
  const meta = { ...prodMeta, assignment: assignmentFor(t, prodMeta.assignment) };
  const description = descriptionStamp({ description: 'x', mergeSha: COMMIT, authorUpn: 'a@x', approverUpn: 'b@x', publisherUpn: 'c@x', target: t, targetName: ['Pilot [1]', 'Prod', 'Third'] });
  assert.match(description, new RegExp(`\\[promoted to 3 groups: Pilot 1 ${PILOT}, Prod ${PROD}, Third ${G3}\\]`));
  const desired = buildDesired({ meta, detect, remediate: rem, description, target: t });
  const A = desired.assign.deviceHealthScriptAssignments;
  assert.equal(A.length, 3); assert.deepEqual(A.map(a => a.target.groupId).sort(), [PILOT, PROD, G3].sort());
  assert.ok(A.every(a => JSON.stringify(a.runSchedule) === JSON.stringify(A[0].runSchedule)));
  assert.deepEqual(graphTargets(t), A.map(a => a.target));
  const live = { description, publisher: meta.publisher, runAsAccount: desired.script.runAsAccount, runAs32Bit: desired.script.runAs32Bit, enforceSignatureCheck: true, detectionScriptContent: desired.script.detectionScriptContent, remediationScriptContent: desired.script.remediationScriptContent };
  const d = list => intuneDiff({ existing: live, assignments: list, desired, mergeSha: COMMIT, groupLabel: 'target' });
  assert.deepEqual(d([...A].reverse().map(a => ({ ...a, target: { ...a.target, groupId: a.target.groupId.toUpperCase() } }))), [], 'order and case do not matter');
  assert.deepEqual(d(A.map(a => ({ ...a, runRemediationScript: false }))), [], 'Intune reads runRemediationScript back as false; it is not compared');
  assert.deepEqual(d(A.slice(0, 2)), ['2 assignments instead of exactly 3']);
  assert.deepEqual(d([...A, { ...A[0], target: grp(CAN) }]), ['4 assignments instead of exactly 3']);
  assert.deepEqual(d([A[0], A[1], { ...A[2], target: grp(CAN) }]), ['not assigned to exactly the 3 chosen groups']);
  assert.deepEqual(d([A[0], A[1], { ...A[2], target: grp(A[0].target.groupId) }]), ['not assigned to exactly the 3 chosen groups'], 'a duplicate is not the set');
  assert.deepEqual(d([A[0], A[1], { ...A[2], runSchedule: { '@odata.type': '#microsoft.graph.deviceHealthScriptHourlySchedule', interval: 9 } }]), ['the schedule differs']);
  assert.throws(() => buildDesired({ meta, detect, remediate: rem, description, target: { kind: 'groups', groupIds: [PROD, 'x'] } }));
});

test('the assign call and post-check for several groups: one call carries all assignments and the read back matches exactly', async () => {
  const w = world();
  const t = groupsTarget([PROD, PILOT]);
  const desired = buildDesired({ meta: { ...prodMeta, assignment: assignmentFor(t, prodMeta.assignment) }, detect: Buffer.from('d'), remediate: Buffer.from('r'), description: 'x', target: t });
  const g = createIntune({ fetcher: w.g.fetcher, sleep: async () => {} }).scope();
  await g.assign('WT', 'intune-canary', desired.assign);
  const assigns = w.g.calls.filter(c => c.path.endsWith('/assign'));
  assert.equal(assigns.length, 1); assert.equal(assigns[0].body.deviceHealthScriptAssignments.length, 2);
  const after = await g.read('WT', 'intune-canary');
  assert.equal(targetKey(targetOfAssignments(after.assignments)), targetKey(t));
  assert.deepEqual(intuneDiff({ existing: after.script, assignments: after.assignments, desired, mergeSha: COMMIT }).filter(p => /assign|schedule/.test(p)), []);
});

test('group counts: $count is asked for as text/plain with ConsistencyLevel eventual (Graph answers 415 to application/json)', async () => {
  const w = world();
  const g = createIntune({ fetcher: w.g.fetcher, sleep: async () => {} }).scope();
  assert.deepEqual(await g.groupCounts('RT', PROD), { deviceCount: 41, memberCount: 58 });
  const counts = w.g.calls.filter(c => c.path.endsWith('/$count'));
  assert.equal(counts.length, 2);
  for (const c of counts) { assert.equal(c.headers.Accept, 'text/plain'); assert.equal(c.headers.ConsistencyLevel, 'eventual'); assert.equal(c.auth, 'Bearer RT'); }
  // The default Accept for everything else is unchanged.
  await g.getGroup('RT', PROD); assert.equal(w.g.calls.at(-1).headers.Accept, 'application/json');
  // And the fake Graph really refuses the old header, so this test fails if the fix is reverted.
  const r = await w.g.fetcher(`https://graph.microsoft.com/v1.0/groups/${PROD}/transitiveMembers/$count`, { headers: { Accept: 'application/json', ConsistencyLevel: 'eventual' } });
  assert.equal(r.status, 415);
});

test('promote to several groups: one PR with groupIds, every group checked and counted, the full list audited', async () => {
  const w = world({ soakDays: 8 });
  const r = await promote(w, AARON, AUTHOR, body({ target: GROUPS([PROD, PILOT]) }));
  assert.equal(r.number, 7); assert.equal(r.target.kind, 'groups'); assert.deepEqual(r.target.groupIds, [PILOT, PROD]); assert.deepEqual(r.target.names, ['Pilot Devices', 'Production Devices']);
  const p = w.proposals[0];
  const next = JSON.parse(p.files[0].content);
  assert.deepEqual(next.assignment.groupIds, [PILOT, PROD]); assert.equal('groupId' in next.assignment, false); assert.equal('target' in next.assignment, false);
  assert.match(p.title, /to 2 groups$/);
  assert.match(p.message, new RegExp(`R360-Target: groups:${PILOT},${PROD}`)); assert.match(p.message, new RegExp(`R360-Target-Name: ${PILOT} Pilot Devices`)); assert.match(p.message, new RegExp(`R360-Target-Name: ${PROD} Production Devices`));
  assert.match(p.body, /\| Pilot Devices \| `2222/); assert.match(p.body, /\| 6 \| 9 \|/); assert.match(p.body, /\| 41 \| 58 \|/);
  for (const x of ofAction(w, 'promote.proposed')) assert.equal(x.toTarget, `groups:${PILOT},${PROD}`);
  const ok = ofAction(w, 'promote.proposed').find(x => x.result === 'ok');
  assert.deepEqual(ok.detail.toGroups, [PILOT, PROD]); assert.deepEqual(ok.detail.targetNames, ['Pilot Devices', 'Production Devices']);
  assert.deepEqual(ok.detail.groupCounts, [{ groupId: PILOT, deviceCount: 6, memberCount: 9 }, { groupId: PROD, deviceCount: 41, memberCount: 58 }]);
  for (const id of [PILOT, PROD]) assert.ok(w.g.calls.some(c => c.path === `/v1.0/groups/${id}`), `${id} was checked`);
  noGraphWrites(w);
  const list = await w.c.list(AARON, AUTHOR);
  const row = list.changes.find(c => c.number === 7);
  assert.deepEqual({ kind: row.promoteInfo.target.kind, ids: row.promoteInfo.target.groupIds, names: row.promoteInfo.target.names }, { kind: 'groups', ids: [PILOT, PROD], names: ['Pilot Devices', 'Production Devices'] });
});

test('promote to several groups refuses the canary group in the set, All devices mixed in, and any missing or mail-only group', async () => {
  const w = world({ soakDays: 8 });
  await fails(promote(w, AARON, AUTHOR, body({ target: GROUPS([PROD, CAN.toUpperCase()]) })), 400, /canary group is one of the chosen groups/);
  assert.equal(ofAction(w, 'promote.denied').at(-1).reason, 'target-is-canary'); assert.equal(ofAction(w, 'promote.denied').at(-1).toTarget, `groups:${[PROD, CAN].sort().join(',')}`);
  await fails(promote(w, AARON, AUTHOR, body({ target: { type: 'allDevices', groupIds: [PROD] } })), 400, /cannot be combined with groups|takes no groups/);
  await fails(promote(w, AARON, AUTHOR, body({ target: GROUPS([PROD, GONE]) })), 409, new RegExp(`Group ${GONE} does not exist`));
  await fails(promote(w, AARON, AUTHOR, body({ target: GROUPS([PROD, MAILONLY]) })), 409, /not a security group/);
  assert.equal(w.proposals.length, 0); noGraphWrites(w);
});

test('soak evidence with several groups: already promoted only when the live set is exactly the chosen set', async () => {
  const w = world({ soakDays: 8 });
  w.g.assigns.set('intune-canary', [{ id: 'a0', target: grp(PROD), runRemediationScript: true }, { id: 'a1', target: grp(PILOT), runRemediationScript: true }]);
  assert.match(String((await evidence(w)).block), /already assigns this remediation outside the canary group/);
  await fails(promote(w, AARON, AUTHOR, body({ target: GROUPS([PILOT, PROD]) })), 409, /Already assigned to 2 groups/);
  await fails(promote(w, AARON, AUTHOR, body({ target: GROUPS([PILOT, G3]) })), 409);
  // The canary group plus another is drift, not a promotion.
  w.g.assigns.set('intune-canary', [{ id: 'a0', target: grp(CAN), runRemediationScript: true }, { id: 'a1', target: grp(PILOT), runRemediationScript: true }]);
  const v = await evidence(w); assert.equal(v.canPromote, false); assert.match(JSON.stringify(v.evidence.checks), /exactly one assignment, the canary group \(2 found\)/);
  assert.equal(w.proposals.length, 0);
});

test('publish of a multi-group promotion: the target comes from the audit row, must agree with toGroups, and must match the signed artifact', async () => {
  // The signed test artifact assigns one group (PROD), so a recorded 2-group promotion must be refused as a mismatch before any write.
  const run = async tamper => {
    const w = world({ soakDays: 8 });
    await promote(w, AARON, AUTHOR, body({ target: GROUPS([PROD, PILOT]) }));
    await w.c.approve(AARON, AUTHOR, 7, { headSha: HEAD }); await w.c.merge(AARON, AUTHOR, 7, { headSha: HEAD }); await w.c.verifySigning(AARON, AUTHOR, 7);
    w.g.calls.length = 0;
    for (const x of ofAction(w, 'promote.proposed')) if (x.detail) tamper?.(x.detail);
    return w;
  };
  let w = await run();
  await fails(publish(w), 409, /not the target that was chosen/); noGraphWrites(w);
  assert.deepEqual(ofAction(w, 'publish.denied').at(-1).detail.recorded, `groups:${PILOT},${PROD}`);
  w = await run(d => { d.toGroups = [PROD, G3]; });
  await fails(publish(w), 409, /does not name a valid target/); noGraphWrites(w);
  w = await run(d => { d.toTarget = `groups:${[CAN, PROD].sort().join(',')}`; d.toGroups = [PROD, CAN]; });
  await fails(publish(w), 409, /canary group/); noGraphWrites(w);
});
