import test from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../server/app.mjs';
import { SessionStore, SESSION_COOKIE } from '../server/auth.mjs';
import { ALL_DEVICES, targetOf, parseTargetRequest, assignmentFor, promotionDiff, targetKey, targetOfGraph, graphTarget, isCanaryTarget, cleanName, NULL_GUID } from '../server/target.mjs';
import { buildDesired, intuneDiff, descriptionStamp, sha256Hex } from '../server/intune.mjs';
import { validateMeta } from '../server/remediation-schema.mjs';
import { world, body, promote, publish, promoted, evidence, fails, ofAction, noGraphWrites, AARON, USER1, AUTHOR, APPROVER, PROD, PILOT, CAN, MAILONLY, GONE, COMMIT, CSHA, FOLDER, HEAD, prodMeta } from './s6-world.mjs';

const GROUP = id => ({ type: 'group', groupId: id });
const ALL = { type: 'allDevices' };

test('target parsing: exactly one valid form, strict keys, the null GUID and bad ids refused', () => {
  assert.deepEqual(parseTargetRequest(GROUP(PROD.toUpperCase())).target, { kind: 'group', groupId: PROD });
  assert.deepEqual(parseTargetRequest(ALL).target, { kind: ALL_DEVICES });
  for (const bad of [undefined, null, 'x', [], {}, { type: 'group' }, { type: 'group', groupId: 'nope' }, GROUP(NULL_GUID), { type: 'allDevices', groupId: PROD }, { type: 'allDevices', extra: 1 }, { type: 'user', groupId: PROD }, { ...GROUP(PROD), sneaky: true }]) assert.ok(parseTargetRequest(bad).error, JSON.stringify(bad));
  assert.deepEqual(targetOf({ groupId: PROD }), { kind: 'group', groupId: PROD });
  assert.deepEqual(targetOf({ target: 'allDevices', runRemediationScript: true }), { kind: ALL_DEVICES });
  for (const bad of [{}, null, { groupId: PROD, target: 'allDevices' }, { target: 'everyone' }, { groupId: 'x' }]) assert.equal(targetOf(bad), null);
  assert.deepEqual(assignmentFor({ kind: ALL_DEVICES }, { groupId: CAN, runRemediationScript: true }), { target: 'allDevices', runRemediationScript: true });
  assert.deepEqual(assignmentFor({ kind: 'group', groupId: PROD }, { target: 'allDevices', runRemediationScript: false }), { groupId: PROD, runRemediationScript: false });
  assert.equal(promotionDiff({ kind: ALL_DEVICES }), 'assignment.groupId,assignment.target'); assert.equal(promotionDiff({ kind: 'group' }), 'assignment.groupId');
  assert.equal(isCanaryTarget({ kind: 'group', groupId: CAN }, CAN.toUpperCase()), true); assert.equal(isCanaryTarget({ kind: ALL_DEVICES }, CAN), false);
  assert.equal(cleanName('a[b]<c>|`d`\n;e'), 'a b c d e');
});

test('schema: groupId alone and target allDevices alone are valid; both or neither are not', () => {
  const m = a => ({ ...prodMeta, assignment: a });
  assert.equal(validateMeta(m({ groupId: PROD })).ok, true);
  assert.equal(validateMeta(m({ target: 'allDevices' })).ok, true);
  assert.equal(validateMeta(m({ target: 'allDevices', runRemediationScript: false })).ok, true);
  for (const bad of [{ groupId: PROD, target: 'allDevices' }, {}, { target: 'allUsers' }, { groupId: 'nope' }]) assert.equal(validateMeta(m(bad)).ok, false, JSON.stringify(bad));
});

test('Intune side of All devices: the desired assignment, the diff against what is live, and the description stamp', () => {
  assert.deepEqual(graphTarget({ kind: ALL_DEVICES }), { '@odata.type': '#microsoft.graph.allDevicesAssignmentTarget' });
  assert.deepEqual(targetOfGraph({ '@odata.type': '#microsoft.graph.allDevicesAssignmentTarget' }), { kind: ALL_DEVICES });
  assert.equal(targetOfGraph({ '@odata.type': '#microsoft.graph.exclusionGroupAssignmentTarget', groupId: PROD }), null);
  assert.equal(targetKey(targetOfGraph({ '@odata.type': '#microsoft.graph.groupAssignmentTarget', groupId: PROD.toUpperCase() })), `group:${PROD}`);
  const detect = Buffer.from('d'), rem = Buffer.from('r');
  const meta = { ...prodMeta, assignment: { target: 'allDevices' } };
  const description = descriptionStamp({ description: 'x', mergeSha: COMMIT, authorUpn: 'a@x', approverUpn: 'b@x', publisherUpn: 'c@x', target: { kind: ALL_DEVICES } });
  assert.match(description, /\[promoted to All devices\]/);
  const desired = buildDesired({ meta, detect, remediate: rem, description, target: { kind: ALL_DEVICES } });
  assert.deepEqual(desired.assign.deviceHealthScriptAssignments[0].target, { '@odata.type': '#microsoft.graph.allDevicesAssignmentTarget' });
  const live = { description, publisher: meta.publisher, runAsAccount: desired.script.runAsAccount, runAs32Bit: desired.script.runAs32Bit, enforceSignatureCheck: true, detectionScriptContent: desired.script.detectionScriptContent, remediationScriptContent: desired.script.remediationScriptContent };
  const sched = desired.assign.deviceHealthScriptAssignments[0];
  assert.deepEqual(intuneDiff({ existing: live, assignments: [{ ...sched }], desired, mergeSha: COMMIT }), []);
  assert.deepEqual(intuneDiff({ existing: live, assignments: [{ ...sched, target: graphTarget({ kind: 'group', groupId: CAN }) }], desired, mergeSha: COMMIT }), ['not assigned to All devices only']);
  const g = descriptionStamp({ description: 'x', mergeSha: COMMIT, authorUpn: 'a@x', approverUpn: 'b@x', publisherUpn: 'c@x', target: { kind: 'group', groupId: PROD }, targetName: 'Prod [ring] 1' });
  assert.match(g, new RegExp(`\\[promoted to group Prod ring 1 ${PROD}\\]`));
});

test('promote with a chosen group: the PR, commit trailers and audit rows carry the target, and the group is read with the read token', async () => {
  const w = world({ soakDays: 8, prod: false });
  const r = await promote(w, AARON, AUTHOR, body({ target: GROUP(PILOT) }));
  assert.equal(r.number, 7); assert.deepEqual({ kind: r.target.kind, groupId: r.target.groupId, name: r.target.name }, { kind: 'group', groupId: PILOT, name: 'Pilot Devices' });
  const p = w.proposals[0];
  assert.equal(JSON.parse(p.files[0].content).assignment.groupId, PILOT);
  assert.match(p.title, /to group "Pilot Devices"/);
  assert.match(p.message, new RegExp(`R360-Target: group:${PILOT}`)); assert.match(p.message, /R360-Target-Name: Pilot Devices/);
  assert.match(p.body, /Promote .* to group "Pilot Devices"/); assert.match(p.body, /6 devices and 9 members/); assert.match(p.body, new RegExp(PILOT));
  const ok = ofAction(w, 'promote.proposed').find(x => x.result === 'ok'); const intent = ofAction(w, 'promote.proposed').find(x => x.result === 'intent');
  for (const x of [ok, intent]) assert.equal(x.toTarget, `group:${PILOT}`);
  assert.deepEqual({ t: ok.detail.toTarget, n: ok.detail.targetName, d: ok.detail.deviceCount, m: ok.detail.memberCount }, { t: `group:${PILOT}`, n: 'Pilot Devices', d: 6, m: 9 });
  noGraphWrites(w);
  for (const c of w.g.calls) assert.equal(c.auth, 'Bearer RT');
  assert.ok(w.g.calls.some(c => c.path === `/v1.0/groups/${PILOT}`), 'the group was checked before it was proposed');
});

test('promote to All devices: the PR assigns the built-in target, with a blast-radius note, and nothing else changes', async () => {
  const w = world({ soakDays: 8 });
  const r = await promote(w, AARON, AUTHOR, body({ target: ALL }));
  assert.equal(r.target.kind, ALL_DEVICES);
  const next = JSON.parse(w.proposals[0].files[0].content);
  assert.deepEqual(next.assignment, { target: 'allDevices', ...(prodMeta.assignment.runRemediationScript !== undefined ? { runRemediationScript: prodMeta.assignment.runRemediationScript } : {}) });
  assert.match(w.proposals[0].title, /to All devices/); assert.match(w.proposals[0].message, /R360-Target: allDevices/); assert.doesNotMatch(w.proposals[0].message, /R360-Target-Name/);
  assert.match(w.proposals[0].body, /every device Intune manages/);
  assert.equal(ofAction(w, 'promote.proposed').at(-1).toTarget, 'allDevices');
  assert.equal(w.g.calls.filter(c => c.path.startsWith('/v1.0/groups')).length, 0, 'All devices needs no group lookup');
});

test('the canary group is refused on the server, audited, and nothing is created', async () => {
  const w = world({ soakDays: 8 });
  await fails(promote(w, AARON, AUTHOR, body({ target: GROUP(CAN) })), 400, /canary group/);
  assert.equal(w.proposals.length, 0);
  const d = ofAction(w, 'promote.denied').at(-1); assert.equal(d.reason, 'target-is-canary'); assert.equal(d.toTarget, `group:${CAN}`);
  await fails(promote(w, AARON, AUTHOR, body({ target: GROUP(CAN.toUpperCase()) })), 400, /canary group/);
});

test('a group that does not exist, a mail-only list, a malformed target and a Graph refusal are all refused before anything is proposed', async () => {
  const w = world({ soakDays: 8 });
  await fails(promote(w, AARON, AUTHOR, body({ target: GROUP(GONE) })), 409, /does not exist/);
  assert.equal(ofAction(w, 'promote.denied').at(-1).reason, 'target-group-missing');
  await fails(promote(w, AARON, AUTHOR, body({ target: GROUP(MAILONLY) })), 409, /not a security group/);
  assert.equal(ofAction(w, 'promote.denied').at(-1).reason, 'target-group-unsuitable');
  await fails(promote(w, AARON, AUTHOR, body({ target: GROUP('not-a-guid') })), 400);
  await fails(promote(w, AARON, AUTHOR, body({ target: { type: 'allDevices', groupId: PROD } })), 400);
  assert.equal(w.proposals.length, 0);
  w.g.fail = (m, path) => (path === `/v1.0/groups/${PROD}` ? new Response(JSON.stringify({ error: { code: 'Authorization_RequestDenied', message: 'no' } }), { status: 403 }) : null);
  await fails(promote(w), 403, /GroupMember\.Read\.All/);
  assert.equal(w.proposals.length, 0);
});

test('counts are best effort: if Graph refuses them the promotion still goes ahead with unknown counts', async () => {
  const w = world({ soakDays: 8 }); w.g.countFail = true;
  const r = await promote(w); assert.equal(r.number, 7);
  assert.match(w.proposals[0].body, /unknown devices and unknown members/);
});

test('the group search: names, ids and counts; canary and mail-only lists excluded; short queries refused; approvers only', async () => {
  const w = world({ soakDays: 8 });
  const s = await w.c.promoteGroups(AARON, AUTHOR, 'devices', w.tokens);
  assert.deepEqual(s.groups.map(g => [g.displayName, g.id, g.deviceCount, g.memberCount, g.dynamic]), [['Pilot Devices', PILOT, 6, 9, true], ['Production Devices', PROD, 41, 58, false]]);
  assert.ok(w.g.calls.filter(c => c.path === '/v1.0/groups').every(c => c.headers.ConsistencyLevel === 'eventual' && c.auth === 'Bearer RT'));
  const c = await w.c.promoteGroups(AARON, AUTHOR, 'canary', w.tokens); assert.deepEqual(c.groups, []); assert.equal(c.canaryHidden, true);
  const byId = await w.c.promoteGroups(AARON, AUTHOR, CAN.toUpperCase(), w.tokens); assert.deepEqual(byId.groups, []);
  assert.deepEqual((await w.c.promoteGroups(AARON, AUTHOR, PILOT, w.tokens)).groups.map(g => g.id), [PILOT]);
  assert.deepEqual((await w.c.promoteGroups(AARON, AUTHOR, 'production', w.tokens)).groups.map(g => g.id), [PROD], 'the mail-only list is not offered');
  for (const q of ['', ' a ', 'x'.repeat(65), undefined]) await fails(w.c.promoteGroups(AARON, AUTHOR, q, w.tokens), 400);
  await fails(w.c.promoteGroups(AARON, ['author'], 'pilot', w.tokens), 403);
  w.g.countFail = true; const n = await w.c.promoteGroups(AARON, AUTHOR, 'pilot', w.tokens);
  assert.deepEqual([n.groups[0].deviceCount, n.groups[0].memberCount], [null, null]);
  assert.equal(w.g.writes().length, 0);
});

test('the evidence view offers the optional default and the canary group id, and no longer needs a production group', async () => {
  const a = await evidence(world({ soakDays: 8 })); assert.deepEqual(a.defaultTarget, { type: 'group', groupId: PROD }); assert.equal(a.canaryGroupId, CAN); assert.equal(a.canPromote, true);
  const b = await evidence(world({ soakDays: 8, prod: false })); assert.equal(b.defaultTarget, null); assert.equal(b.canPromote, true);
});

test('publish: the description records the target, the audit row records toTarget, and the live check is relative to the chosen target', async () => {
  const w = world({ soakDays: 8 }); await promoted(w);
  const r = await publish(w); assert.equal(r.ok, true);
  const s = w.g.scripts.get('intune-canary');
  assert.match(s.description, new RegExp(`\\[promoted to group Production Devices ${PROD}\\]`));
  assert.equal(w.g.assigns.get('intune-canary')[0].target.groupId, PROD);
  assert.equal(ofAction(w, 'publish.production').at(-1).toTarget, `group:${PROD}`);
  assert.ok(w.g.calls.some(c => c.path === `/v1.0/groups/${PROD}` && c.auth === 'Bearer RT'), 'the group was checked again before publishing');
});

test('publish re-validates the group: one deleted after it was proposed is denied before any write', async () => {
  const w = world({ soakDays: 8 }); await promoted(w);
  w.g.groups.delete(PROD);
  await fails(publish(w), 409, /does not exist/); noGraphWrites(w);
  assert.equal(ofAction(w, 'publish.denied').at(-1).reason, 'target-group-missing');
});

test('publish refuses a target that is not the one that was proposed, the canary group, or an unreadable record', async () => {
  for (const [tamper, reason, re] of [
    [d => { d.toTarget = 'allDevices'; delete d.toGroup; }, 'target-mismatch', /not the target that was chosen/],
    [d => { d.toTarget = `group:${PILOT}`; d.toGroup = PILOT; }, 'target-mismatch', /not the target that was chosen/],
    [d => { d.toTarget = `group:${CAN}`; d.toGroup = CAN; }, 'target-is-canary', /canary group/],
    [d => { d.toTarget = 'something'; delete d.toGroup; }, 'promotion-record-invalid', /does not name a valid target/],
  ]) {
    const w = world({ soakDays: 8 }); await promoted(w);
    for (const x of ofAction(w, 'promote.proposed')) if (x.detail) tamper(x.detail);
    await fails(publish(w), 409, re); noGraphWrites(w);
    assert.equal(ofAction(w, 'publish.denied').at(-1).reason, reason);
  }
});

test('soak evidence: already promoted means the one assignment is the chosen target, not just any non-canary assignment', async () => {
  const w = world({ soakDays: 8 });
  w.g.assigns.set('intune-canary', [{ id: 'a0', target: { '@odata.type': '#microsoft.graph.allDevicesAssignmentTarget' }, runRemediationScript: true }]);
  const view = await evidence(w); assert.match(String(view.block), /already assigns this remediation outside the canary group/); assert.equal(view.canPromote, false);
  w.g.assigns.set('intune-canary', [{ id: 'a0', target: { '@odata.type': '#microsoft.graph.groupAssignmentTarget', groupId: PILOT }, runRemediationScript: true }]);
  await fails(promote(w, AARON, AUTHOR, body({ target: GROUP(PILOT) })), 409, /Already assigned to group/);
  await fails(promote(w, AARON, AUTHOR, body({ target: GROUP(PROD) })), 409);
  assert.equal(w.proposals.length, 0);
});

test('R360_PROD_GROUP_ID is not needed anywhere, and its value cannot override what the request says', async () => {
  const w = world({ soakDays: 8, prod: false });
  await promote(w, AARON, AUTHOR, body({ target: GROUP(PILOT) }));
  assert.equal(JSON.parse(w.proposals[0].files[0].content).assignment.groupId, PILOT);
  const l = await w.c.list(AARON, AUTHOR); assert.equal(l.prodDefault, null);
  assert.equal(l.changes.find(c => c.number === 7).promoteInfo.target.name, 'Pilot Devices');
});

async function serve(w) {
  const sessions = new SessionStore({ now: () => w.t });
  const auth = { writeConfigured: true, beginSignIn: async () => 'x', completeSignIn: async () => {}, graphToken: async () => 'GT',
    beginElevate: async s => { s.writePending = { state: 'ws', nonce: 'n', verifier: 'v', created: w.t }; return 'https://login.microsoftonline.com/write'; },
    completeElevate: async s => ({ oid: s.user.oid, upn: s.user.upn, homeAccountId: 'ha', acrs: [], accessToken: 'WT' }), endWrite: async () => {}, signOut: async () => {}, writeToken: async () => 'WT' };
  const data = { pim: async () => ({ gate: { ok: true, text: 'active' } }), remediations: async () => ({}), fleet: async () => ({}), certificates: async () => ({}) };
  const cat = w.github.catalog;
  w.github.catalog = async () => { const c = await cat(); return { ...c, approvers: [...c.approvers, { entraObjectId: '55555555-5555-4555-8555-555555555555', upn: 'writer@contoso.com', roles: ['author'] }] }; };
  const app = createApp({ config: w.config, sessions, auth, data, github: w.github, audit: w.audit, fetcher: w.g.fetcher, now: () => w.t, log: { error() {} } });
  const srv = app.listen(0); await new Promise(r => srv.once('listening', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  const client = user => { const s = sessions.create(); s.user = user; return { get: p => fetch(base + p, { redirect: 'manual', headers: { cookie: `${SESSION_COOKIE}=${s.id}` } }) }; };
  return { base, client, close: () => srv.close() };
}

test('GET /api/changes/promote-groups: sign-in required, approvers only, delegated read token, no Graph write', async () => {
  const w = world({ soakDays: 8 }); const srv = await serve(w);
  try {
    assert.equal((await fetch(`${srv.base}/api/changes/promote-groups?q=pilot`)).status, 401);
    const writer = srv.client({ oid: '55555555-5555-4555-8555-555555555555', upn: 'writer@contoso.com', name: 'W' });
    assert.equal((await writer.get('/api/changes/promote-groups?q=pilot')).status, 403);
    const a = srv.client(AARON);
    const r = await a.get('/api/changes/promote-groups?q=pilot'); const j = await r.json();
    assert.equal(r.status, 200); assert.deepEqual(j.groups.map(g => g.displayName), ['Pilot Devices']);
    assert.equal((await a.get('/api/changes/promote-groups?q=a')).status, 400);
    assert.equal((await a.get('/api/changes/promote-groups')).status, 400);
    assert.ok(w.g.calls.length > 0 && w.g.calls.every(c => c.auth === 'Bearer GT' && c.method === 'GET'));
    const t = JSON.stringify(j); assert.equal(/Bearer|GT/.test(t.replace(/Pilot|Devices/g, '')), false);
  } finally { srv.close(); }
});
