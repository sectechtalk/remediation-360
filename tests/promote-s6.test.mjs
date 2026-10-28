import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateSoak, soakClock, validReason, cleanReason, DAY_MS, MIN_REASON, MAX_REASON } from '../server/soak.mjs';
import { fourEyes } from '../server/foureyes.mjs';
import { loadConfig } from '../server/config.mjs';
import { metaDiff, machineBlock, stageOf } from '../server/changes.mjs';
import { ENV } from './fixtures.mjs';
import { world, promote, promoted, publish, evidence, body, ofAction, fails, noGraphWrites, iso,
  AARON, USER1, CAN, PROD, T0, DAY, CSHA, COMMIT, FOLDER, HEAD, AUTHOR, APPROVER, canaryRaw, gitTexts } from './s6-world.mjs';

const ok = { runStates: null };
const clean = (at, name = 'DEVICE01') => ({ detectionState: 'success', remediationState: 'skipped', lastStateUpdateDateTime: iso(at), managedDevice: { deviceName: name } });
const zero = { detectionScriptErrorDeviceCount: 0, remediationScriptErrorDeviceCount: 0, issueReoccurredDeviceCount: 0 };
const ev = (days, over = {}) => evaluateSoak({ now: T0, soakDays: 7, publishedAt: iso(T0 - days * DAY_MS - 1000), runStates: [clean(T0 - 1000)], summary: zero, canaryDevice: 'DEVICE01', ...over });

// ---- the pure soak rule ----
test('the soak gate: day 6 is not enough, day 7 and 8 are', () => {
  assert.equal(ev(6).soakMet, false); assert.equal(ev(6).ready, false);
  assert.deepEqual(ev(6).failing, ['soak']); assert.equal(ev(6).overridable, true);
  assert.equal(ev(7).ready, true); assert.equal(ev(7).overridable, false);
  assert.equal(ev(8).ready, true); assert.equal(ev(8).daysSoaked, 8);
  // exactly 7 x 24 h is enough, one second less is not
  assert.equal(evaluateSoak({ now: T0, publishedAt: iso(T0 - 7 * DAY_MS), runStates: [clean(T0)], summary: zero, canaryDevice: 'DEVICE01' }).soakMet, true);
  assert.equal(evaluateSoak({ now: T0, publishedAt: iso(T0 - 7 * DAY_MS + 1000), runStates: [clean(T0)], summary: zero, canaryDevice: 'DEVICE01' }).soakMet, false);
});

test('only the soak days are overridable, every other failure is a hard stop', () => {
  const cases = {
    published: ev(9, { publishedAt: null }), newer: ev(9, { newerOnMain: true }), drift: ev(9, { driftProblems: ['x'] }), driftPromoted: ev(9, { alreadyPromoted: true }),
    devicesFail: ev(9, { runStates: [{ ...clean(T0), detectionState: 'fail' }] }), devicesStale: ev(9, { runStates: [clean(T0 - 20 * DAY_MS)] }), devicesNone: ev(9, { runStates: [] }), devicesUnread: ev(9, { runStates: null }),
    devicesMissing: ev(9, { runStates: [clean(T0, 'OTHER')] }), errDetect: ev(9, { summary: { ...zero, detectionScriptErrorDeviceCount: 1 } }), errRemed: ev(9, { summary: { ...zero, remediationScriptErrorDeviceCount: 2 } }),
    errRecur: ev(9, { summary: { ...zero, issueReoccurredDeviceCount: 1 } }), errUnread: ev(9, { summary: null }) };
  for (const [name, r] of Object.entries(cases)) { assert.equal(r.ready, false, name); assert.equal(r.overridable, false, name); }
  // soak short AND something else failing is still not overridable
  assert.equal(ev(2, { summary: { ...zero, issueReoccurredDeviceCount: 1 } }).overridable, false);
  assert.equal(ev(2, { newerOnMain: true }).overridable, false);
  assert.deepEqual(ev(9, { alreadyPromoted: true }).failing, ['drift']);
});

test('one clean canary device among bad ones does not pass, and the soak clock label is exact', () => {
  assert.equal(ev(9, { runStates: [clean(T0), { ...clean(T0, 'B'), detectionState: 'fail' }] }).ready, false);
  assert.equal(ev(9, { runStates: [clean(T0), clean(T0, 'B')] }).ready, true);
  assert.equal(soakClock({ now: T0, soakDays: 7, publishedAt: iso(T0 - 2 * DAY_MS - 5000) }).label, 'Day 2 of 7');
  assert.equal(soakClock({ now: T0, soakDays: 7, publishedAt: iso(T0 - 8 * DAY_MS) }).label, 'Day 8, soak complete');
  assert.equal(soakClock({ now: T0, soakDays: 7, publishedAt: iso(T0 - 8 * DAY_MS) }).met, true);
  assert.equal(soakClock({ now: T0, soakDays: 7, publishedAt: null }), null);
  assert.equal(soakClock({ now: T0, soakDays: 7, publishedAt: 'nonsense' }), null);
});

test('the override reason: at least 10 visible characters, control characters flattened, capped at 500', () => {
  assert.equal(MIN_REASON, 10); assert.equal(MAX_REASON, 500);
  assert.equal(validReason('too short'), false); assert.equal(validReason('          x         '), false);
  assert.equal(validReason('Pilot team signed off.'), true); assert.equal(validReason(null), false); assert.equal(validReason(undefined), false);
  assert.equal(cleanReason('a\r\nb\u0000c\t d  e'), 'a b c d e');
  assert.equal(cleanReason('x'.repeat(900)).length, 500);
});

test('metaDiff lists exactly the differing leaf paths', () => {
  const a = { a: 1, b: { c: 2, d: [1, 2] }, e: 'x' };
  assert.deepEqual(metaDiff(a, JSON.parse(JSON.stringify(a))), []);
  assert.deepEqual(metaDiff(a, { ...a, b: { ...a.b, c: 3 } }), ['b.c']);
  assert.deepEqual(metaDiff(a, { ...a, e: 'y', f: 1 }), ['e', 'f']);
  assert.ok(metaDiff(a, { ...a, b: { ...a.b, d: [1, 3] } }).length >= 1);
});

// ---- config ----
test('config: the production group is a GUID that differs from the canary group, soak days are bounded', () => {
  const base = { ...ENV, R360_CANARY_GROUP_ID: CAN };
  assert.equal(loadConfig(base).prodGroupId, '', 'unset is allowed, promote is then disabled');
  assert.equal(loadConfig(base).canarySoakDays, 7);
  assert.equal(loadConfig({ ...base, R360_PROD_GROUP_ID: PROD.toUpperCase() }).prodGroupId, PROD);
  assert.throws(() => loadConfig({ ...base, R360_PROD_GROUP_ID: 'not-a-guid' }), /R360_PROD_GROUP_ID/);
  assert.throws(() => loadConfig({ ...base, R360_PROD_GROUP_ID: CAN }), /R360_PROD_GROUP_ID/);
  assert.equal(loadConfig({ ...base, R360_CANARY_SOAK_DAYS: '14' }).canarySoakDays, 14);
  assert.equal(loadConfig({ ...base, R360_CANARY_SOAK_DAYS: '0' }).canarySoakDays, 0);
  for (const bad of ['-1', '91', '1.5', 'abc']) assert.throws(() => loadConfig({ ...base, R360_CANARY_SOAK_DAYS: bad }), /R360_CANARY_SOAK_DAYS/, bad);
  assert.equal(loadConfig({ ...base, R360_PROD_GROUP_ID: PROD }).canarySoakDays, 7);
});

// ---- four-eyes, promote step ----
test('four-eyes promote step: enforced bars the author, testing allows and flags it', () => {
  const f = (mode, a, b) => fourEyes({ mode, step: 'promote', authorOid: a, actorOid: b });
  assert.deepEqual([f('enforced', AARON.oid, AARON.oid).allowed, f('enforced', AARON.oid, AARON.oid).reason], [false, 'promoter-must-differ']);
  assert.equal(f('enforced', AARON.oid, AARON.oid.toUpperCase()).allowed, false, 'case does not matter');
  assert.equal(f('enforced', AARON.oid, USER1.oid).allowed, true);
  const t = f('testing', AARON.oid, AARON.oid); assert.equal(t.allowed, true); assert.equal(t.selfApproved, true); assert.equal(t.reason, 'self-promote-testing');
  assert.equal(f('testing', AARON.oid, USER1.oid).selfApproved, false);
});

// ---- promote: creating the pull request ----
test('promote at day 8 creates one pull request that changes only assignment.groupId, and audits intent before result', async () => {
  const w = world({ soakDays: 8 });
  const r = await promote(w);
  assert.equal(r.ok, true); assert.equal(r.number, 7); assert.equal(r.promote, true); assert.equal(r.soakOverride, false); assert.equal(r.soakDays, 8); assert.equal(r.soakRequired, 7);
  assert.equal(w.proposals.length, 1);
  const p = w.proposals[0];
  assert.deepEqual(p.files.map(f => f.path), [`remediations/${FOLDER}/remediation.json`], 'one file, the scripts are not touched');
  const next = JSON.parse(p.files[0].content);
  assert.equal(next.assignment.groupId, PROD);
  assert.deepEqual(metaDiff(JSON.parse(canaryRaw['remediation.json']), next), ['assignment.groupId']);
  assert.match(p.title, /promote remediation Sample-RemediationCanary to group "Production Devices"/); assert.doesNotMatch(p.title, /OVERRIDE/);
  assert.match(p.message, /R360-Soak-Override: false/);
  assert.match(p.body, /"promote":true/); assert.doesNotMatch(p.body, /SOAK OVERRIDE/);
  assert.deepEqual(w.order.filter(o => o.startsWith('audit:promote')), ['audit:promote.proposed:intent', 'audit:promote.proposed:ok']);
  const okRow = ofAction(w, 'promote.proposed').find(x => x.result === 'ok');
  assert.equal(okRow.prNumber, 7); assert.equal(okRow.gitSha, HEAD); assert.equal(okRow.soakDays, 8);
  assert.equal(okRow.detail.canarySha, CSHA); assert.equal(okRow.detail.soakOverride, false); assert.equal(okRow.detail.toGroup, PROD); assert.equal(okRow.detail.fromGroup, CAN);
  assert.equal(okRow.toTarget, `group:${PROD}`); assert.equal(okRow.detail.targetName, 'Production Devices'); assert.equal(okRow.detail.deviceCount, 41); assert.equal(okRow.detail.memberCount, 58);
  noGraphWrites(w);
  for (const c of w.g.calls) assert.equal(c.auth, 'Bearer RT', 'evidence is read with the read token only');
  assert.equal(JSON.stringify(w.rows).includes('Bearer'), false);
});

test('testing mode: the canary author may promote, and that is flagged in the reply, the PR and the audit row', async () => {
  const w = world({ mode: 'testing' });
  const r = await promote(w, AARON);
  assert.equal(r.selfPromoted, true);
  assert.match(w.proposals[0].body, /SELF-PROMOTED/);
  assert.equal(ofAction(w, 'promote.proposed').find(x => x.result === 'ok').selfApproved, true);
  const w2 = world({ mode: 'testing' });
  assert.equal((await promote(w2, USER1, APPROVER)).selfPromoted, false);
  assert.doesNotMatch(w2.proposals[0].body, /SELF-PROMOTED/);
});

test('soak not met and no reason: refused with 409, a denied row, no pull request', async () => {
  const w = world({ soakDays: 3 });
  await fails(promote(w), 409, /3 of 7 canary days/);
  assert.equal(w.proposals.length, 0); assert.equal(ofAction(w, 'promote.proposed').length, 0);
  const d = ofAction(w, 'promote.denied'); assert.equal(d.length, 1); assert.equal(d[0].reason, 'soak-not-met'); assert.equal(d[0].result, 'denied'); assert.equal(d[0].soakDays, 3);
  await fails(promote(w, AARON, AUTHOR, body({ overrideReason: '' })), 409, /canary days/);
});

test('a short or blank reason is refused with 400 and creates nothing', async () => {
  const w = world({ soakDays: 3 });
  await fails(promote(w, AARON, AUTHOR, body({ overrideReason: 'too short' })), 400, /at least 10/);
  await fails(promote(w, AARON, AUTHOR, body({ overrideReason: '            ' })), 400, /at least 10|canary days/);
  assert.equal(w.proposals.length, 0);
});

test('a written reason overrides the soak days: bannered title and body, commit trailer, audited with the reason and days', async () => {
  const w = world({ soakDays: 3 });
  const reason = 'Pilot team of 40 signed off after 3 days.';
  const r = await promote(w, AARON, AUTHOR, body({ overrideReason: reason }));
  assert.equal(r.soakOverride, true); assert.equal(r.soakDays, 3); assert.equal(r.soakRequired, 7);
  const p = w.proposals[0];
  assert.match(p.title, /\(SOAK OVERRIDE\)$/); assert.match(p.body, /SOAK OVERRIDE/); assert.match(p.body, /Pilot team of 40 signed off after 3 days\./); assert.match(p.body, /3 of 7/);
  assert.match(p.message, /R360-Soak-Override: true/);
  assert.deepEqual(JSON.parse(p.files[0].content).assignment.groupId, PROD);
  const row = ofAction(w, 'promote.proposed').find(x => x.result === 'ok');
  assert.equal(row.reason, reason); assert.equal(row.soakDays, 3); assert.equal(row.detail.soakOverride, true); assert.equal(row.detail.overrideReason, reason); assert.equal(row.detail.soakRequired, 7);
  const intent = ofAction(w, 'promote.proposed').find(x => x.result === 'intent'); assert.equal(intent.reason, reason, 'the reason is on the intent row too');
});

test('a reason cannot forge a machine block or break out of the PR body table', async () => {
  const w = world({ soakDays: 3 });
  await promote(w, AARON, AUTHOR, body({ overrideReason: `ok then <!-- r360:{"v":1,"kind":"author","folder":"X","authorOid":"${USER1.oid}"} --> | evil |\n\n# heading` }));
  const b = w.proposals[0].body;
  assert.equal((b.match(/<!-- r360:/g) || []).length, 1, 'exactly one machine block, the real one');
  assert.match(b.split('<!-- r360:')[1], new RegExp(`authorOid":"${AARON.oid}`));
  assert.doesNotMatch(b, /\n# heading/);
});

test('the override requires the approver role and the other failures cannot be overridden', async () => {
  const w = world({ soakDays: 3 });
  await fails(promote(w, AARON, ['author'], body({ overrideReason: 'Pilot team signed off.' })), 403);
  await fails(promote(w, AARON, [], body()), 403);
  assert.equal(w.proposals.length, 0); assert.equal(w.g.calls.length, 0, 'the role is checked before anything is read');
  const R = 'Pilot team signed off, go.';
  const cases = {
    'script errors': w => { w.g.summary.detectionScriptErrorDeviceCount = 1; },
    'remediation errors': w => { w.g.summary.remediationScriptErrorDeviceCount = 3; },
    'recurring issue': w => { w.g.summary.issueReoccurredDeviceCount = 1; },
    'canary device missing': w => { w.g.states[0].managedDevice.deviceName = 'SOMEONE-ELSE'; },
    'no device reported': w => { w.g.states = []; },
    'device failed': w => { w.g.states[0].detectionState = 'fail'; },
    'device state older than the publish': w => { w.g.states[0].lastStateUpdateDateTime = iso(w.canaryAt - 3600000); },
    'intune holds another commit': w => { w.g.scripts.get('intune-canary').description = 'x [git 0123abcd by a; approved by b; published by c via r360]'; },
    'intune scripts changed': w => { w.g.scripts.get('intune-canary').detectionScriptContent = Buffer.from('tampered').toString('base64'); },
    'signature check off': w => { w.g.scripts.get('intune-canary').enforceSignatureCheck = false; },
    'assigned to someone else': w => { w.g.assigns.get('intune-canary')[0].target.groupId = '22222222-2222-4222-8222-222222222222'; },
    'two assignments': w => { w.g.assigns.get('intune-canary').push({ id: 'a1', target: { groupId: CAN } }); },
    'newer change on main': w => { w.mainSha = 'e'.repeat(40); w.files[w.mainSha] = { ...canaryRaw, 'detect.ps1': 'changed' }; },
    'no canary publish on record': w => { w.rows = w.rows.filter(r => r.action !== 'publish.canary'); },
  };
  for (const [name, mutate] of Object.entries(cases)) {
    const x = world({ soakDays: 3 }); mutate(x);
    await fails(promote(x, AARON, AUTHOR, body({ overrideReason: R })), 409, undefined);
    assert.equal(x.proposals.length, 0, name);
    assert.match(ofAction(x, 'promote.denied').at(-1)?.reason, name === 'no canary publish on record' ? /canary-changed|evidence-failed/ : /^evidence-failed$/, name);
    // and the same break at day 8 with no override asked for is refused just the same
    const y = world({ soakDays: 8 }); mutate(y);
    await fails(promote(y), 409); assert.equal(y.proposals.length, 0, name + ' (day 8)');
  }
});

test('a promote against a stale canary version is refused with canary-changed', async () => {
  const w = world();
  await fails(promote(w, AARON, AUTHOR, body({ canarySha: 'b'.repeat(40) })), 409, /canary version is now/);
  assert.equal(ofAction(w, 'promote.denied').at(-1).reason, 'canary-changed'); assert.equal(w.proposals.length, 0);
});

test('the soak clock restarts on a new published commit but not on a no-op re-publish', async () => {
  const w = world({ soakDays: 9 });
  const target = `remediations/${FOLDER}`;
  w.rows.push({ action: 'publish.canary', result: 'ok', actorOid: AARON.oid, target, prNumber: 3, gitSha: CSHA, at: iso(T0 - 1 * DAY), detail: { noop: true, intuneId: 'intune-canary' } });
  const e1 = await evidence(w); assert.equal(e1.evidence.daysSoaked, 9, 'a no-op row does not restart the clock'); assert.equal(e1.canPromote, true);
  w.rows.push({ action: 'publish.canary', result: 'ok', actorOid: AARON.oid, target, prNumber: 4, gitSha: 'f'.repeat(40), at: iso(T0 - DAY + 5000), detail: { created: false, intuneId: 'intune-canary', displayName: 'STT - Remediation Canary', hashes: w.hashes } });
  const e2 = await evidence(w); assert.equal(e2.canarySha, 'f'.repeat(40)); assert.equal(e2.evidence.daysSoaked, 0); assert.equal(e2.evidence.soakMet, false);
  await fails(promote(w), 409, /canary version is now/);
});

test('enforced mode: the canary author may not promote, another person may, an unknown author is refused', async () => {
  const w = world({ mode: 'enforced' });
  await fails(promote(w, AARON), 403, /different person/);
  assert.equal(ofAction(w, 'promote.denied').at(-1).reason, 'promoter-must-differ'); assert.equal(w.proposals.length, 0);
  const r = await promote(w, USER1, APPROVER); assert.equal(r.selfPromoted, false); assert.equal(w.proposals.length, 1);
  const u = world({ mode: 'enforced' }); u.rows = u.rows.filter(r => r.action !== 'change.proposed');
  await fails(promote(u, USER1, APPROVER), 403, /cannot tell who authored/);
  assert.equal(ofAction(u, 'promote.denied').at(-1).reason, 'author-unknown');
  const t = world({ mode: 'testing' }); t.rows = t.rows.filter(r => r.action !== 'change.proposed');
  assert.equal((await promote(t, USER1, APPROVER)).ok, true, 'testing mode tolerates an unknown author');
});

test('the evidence view tells each person what they may do', async () => {
  const w = world({ mode: 'enforced', soakDays: 3 });
  const a = await evidence(w, AARON, AUTHOR);
  assert.equal(a.canPromote, false); assert.equal(a.canOverride, false); assert.match(a.block, /different person/);
  const b = await evidence(w, USER1, APPROVER);
  assert.equal(b.canPromote, false, 'soak not met'); assert.equal(b.canOverride, true); assert.equal(b.requiredReasonLength, 10); assert.equal(b.evidence.overridable, true);
  assert.equal('item' in b.evidence, false, 'no internals leak');
  const n = await evidence(w, AARON, ['author']); assert.equal(n.canOverride, false); assert.equal(n.canPromote, false);
  const d8 = await evidence(world({ soakDays: 8 })); assert.equal(d8.canPromote, true); assert.equal(d8.canOverride, false);
});

test('promote does not need R360_PROD_GROUP_ID: the target comes from the request, and a request without one is refused', async () => {
  const w = world({ prod: false });
  await fails(promote(w, AARON, AUTHOR, { folder: FOLDER, canarySha: CSHA }), 400, /target/i);
  assert.equal(w.proposals.length, 0);
  const l = (await w.c.list(AARON, AUTHOR)); assert.equal(l.prodDefault, null);
  assert.equal((await promote(w)).number, 7);
  assert.equal(JSON.parse(w.proposals[0].files[0].content).assignment.groupId, PROD);
});

test('strict body, folder and sha validation', async () => {
  const w = world();
  await fails(promote(w, AARON, AUTHOR, { ...body(), extra: 1 }), 400);
  await fails(promote(w, AARON, AUTHOR, body({ folder: '../x' })), 400);
  await fails(promote(w, AARON, AUTHOR, body({ folder: 'No-Such' })), 404);
  await fails(promote(w, AARON, AUTHOR, body({ canarySha: 'abc' })), 400);
  await fails(promote(w, AARON, AUTHOR, { folder: FOLDER }), 400);
  assert.equal(w.proposals.length, 0);
});

test('a second open change for the folder is refused', async () => {
  const w = world(); await promote(w);
  w.canaryAt; await fails(promote(w), 409, /already an open change/);
  assert.equal(w.proposals.length, 1);
});

test('if Intune cannot be read, nothing is created (502), and a refused read is a 403', async () => {
  const w = world();
  w.g.fail = (m, path) => (path.endsWith('/runSummary') ? new Response('{}', { status: 500 }) : null);
  await fails(promote(w), 502, /run summary failed/); assert.equal(w.proposals.length, 0); assert.equal(ofAction(w, 'promote.proposed').length, 0);
  const x = world(); x.g.fail = () => new Response('{"error":{"code":"Forbidden"}}', { status: 403, headers: { 'content-type': 'application/json' } });
  await fails(promote(x), 403, /refused/);
});

test('audit down: promote refuses before anything is read from Graph or written to GitHub', async () => {
  const w = world(); w.auditDown = true;
  await fails(promote(w), 503); assert.equal(w.proposals.length, 0); assert.equal(w.g.calls.length, 0);
  const x = world(); x.intentDown = true;
  await fails(promote(x), 503); assert.equal(x.proposals.length, 0, 'no intent row, no pull request');
});

test('a GitHub failure is recorded as a failed result row', async () => {
  const w = world(); w.proposeFail = new Error('rate limited');
  await fails(promote(w), 502, /rejected the promotion/);
  const rows = ofAction(w, 'promote.proposed'); assert.deepEqual(rows.map(r => r.result), ['intent', 'failed']);
  assert.match(rows[1].reason, /rate limited/);
});

// ---- the whole chain ----
test('promote, approve, merge, verify signing and publish: production gets exactly one assignment, the stamp carries the override', async () => {
  const w = world({ soakDays: 3 });
  await promoted(w, { reason: 'Pilot team signed off after three days.' });
  const pr = await publish(w);
  assert.equal(pr.ok, true); assert.equal(pr.created, false); assert.equal(pr.intuneId, 'intune-canary');
  const s = w.g.scripts.get('intune-canary');
  assert.match(s.description, /\[SOAK OVERRIDE: 3 of 7 days, reason in the r360 audit trail\]/);
  assert.doesNotMatch(s.description, /Pilot team/, 'the reason stays in the audit trail');
  const a = w.g.assigns.get('intune-canary'); assert.equal(a.length, 1); assert.equal(a[0].target.groupId, PROD);
  assert.equal(s.enforceSignatureCheck, true);
  assert.ok(w.g.writes().length >= 2);
  for (const c of w.g.calls) { assert.equal(c.origin, 'https://graph.microsoft.com'); }
  assert.ok(w.g.writes().every(c => c.auth === 'Bearer WT'), 'writes use the write token');
  assert.ok(w.g.calls.filter(c => c.method === 'GET' && /runSummary|deviceRunStates/.test(c.path)).every(c => c.auth === 'Bearer RT'), 'evidence uses the read token');
  assert.deepEqual(w.order.filter(o => o.startsWith('audit:publish')), ['audit:publish.production:intent', 'audit:publish.production:ok']);
  assert.ok(w.order.indexOf('audit:publish.production:intent') < w.order.findIndex(o => o.startsWith('graph:') && o !== 'graph:GET'), 'intent is written before the first Graph write');
  const row = ofAction(w, 'publish.production').find(x => x.result === 'ok');
  assert.equal(row.soakDays, 3); assert.equal(row.detail.promote, true); assert.equal(row.detail.canarySha, CSHA); assert.equal(row.detail.soakOverride, true); assert.equal(row.detail.soakRequired, 7); assert.equal(row.gitSha, COMMIT);
  assert.equal(ofAction(w, 'publish.canary').length, 2, 'no canary row was added by the promotion');
  assert.equal(JSON.stringify(w.rows).includes('Bearer'), false); assert.equal(JSON.stringify(w.rows).includes('WT'), false);
});

test('a promotion with no override leaves no override stamp, and a second publish is a no-op with no Graph write', async () => {
  const w = world({ soakDays: 8 });
  await promoted(w);
  await publish(w);
  assert.doesNotMatch(w.g.scripts.get('intune-canary').description, /SOAK OVERRIDE/);
  w.g.calls.length = 0;
  const again = await publish(w); assert.equal(again.already, true); noGraphWrites(w);
  assert.equal(ofAction(w, 'publish.production').filter(r => r.result === 'ok').length, 2);
  assert.equal(ofAction(w, 'publish.production').filter(r => r.result === 'ok').at(-1).detail.noop, true);
});

test('publish re-checks the evidence: errors that appear after the promotion was proposed stop it', async () => {
  const w = world({ soakDays: 8 }); await promoted(w);
  w.g.summary.detectionScriptErrorDeviceCount = 2;
  await fails(publish(w), 409, /no longer clean/); noGraphWrites(w);
  assert.equal(ofAction(w, 'publish.denied').at(-1).reason, 'evidence-failed');
  assert.equal(ofAction(w, 'publish.production').filter(r => r.result === 'ok').length, 0);
});

test('a promotion proposed without an override cannot lean on one at publish time', async () => {
  const w = world({ soakDays: 8 }); await promoted(w);
  // time has not gone backwards, but the evidence says soak is short now (the canary was republished): override was never recorded
  w.rows.find(r => r.action === 'publish.canary' && r.result === 'ok').at = iso(T0 - 2 * DAY);
  await fails(publish(w), 409, /no longer clean/); noGraphWrites(w);
});

test('an override recorded at proposal time is honoured, but only for the soak days', async () => {
  const w = world({ soakDays: 3 }); await promoted(w, { reason: 'Pilot team signed off after three days.' });
  w.g.states[0].detectionState = 'fail';
  await fails(publish(w), 409, /no longer clean/); noGraphWrites(w);
});

test('the audit row is the authority, not the PR text: a promote PR with no promote.proposed record cannot be published', async () => {
  const w = world({ soakDays: 8 }); await promoted(w);
  w.rows = w.rows.filter(r => r.action !== 'promote.proposed');
  await assert.rejects(publish(w), /no audit record that it proposed this change/); noGraphWrites(w);
});

test('integrity: a promotion whose scripts differ from the canary version, or whose json differs in any other field, is denied', async () => {
  const w = world({ soakDays: 8 }); await promoted(w);
  w.files[CSHA] = { ...canaryRaw, 'detect.ps1': gitTexts['detect.ps1'] + '\n# different' };
  await fails(publish(w), 409, /more than the assignment/); noGraphWrites(w);
  assert.equal(ofAction(w, 'publish.denied').at(-1).reason, 'promotion-changed-more-than-assignment');
  const x = world({ soakDays: 8 }); await promoted(x);
  const m = JSON.parse(canaryRaw['remediation.json']); m.description = 'something else';
  x.files[CSHA] = { ...canaryRaw, 'remediation.json': JSON.stringify(m) };
  await fails(publish(x), 409, /more than the assignment/); noGraphWrites(x);
});

test('production is reachable only through promote: an ordinary change that carries the production group is denied', async () => {
  const w = world({ soakDays: 8 });
  // an ordinary change (no promote flag) whose signed artifact assigns production
  w.pr = { ...w.canaryPr, number: 7, state: 'open', merged: false, mergedAt: null, mergeSha: null, headSha: HEAD, branch: `r360/${FOLDER}/202610271504-94540000`, title: 'ordinary', body: `x\n${machineBlock({ folder: FOLDER, authorOid: AARON.oid })}` };
  w.rows.push({ action: 'change.proposed', result: 'ok', actorOid: AARON.oid, actorUpn: AARON.upn, target: `remediations/${FOLDER}`, prNumber: 7, gitSha: HEAD, at: iso(T0 - 1000) });
  await w.c.approve(AARON, AUTHOR, 7, { headSha: HEAD }); await w.c.merge(AARON, AUTHOR, 7, { headSha: HEAD }); await w.c.verifySigning(AARON, AUTHOR, 7);
  w.g.calls.length = 0;
  await fails(publish(w), 409, /only be assigned through Promote/); noGraphWrites(w);
  assert.equal(ofAction(w, 'publish.canary').filter(r => r.prNumber === 7 && r.result === 'ok').length, 0);
  assert.equal(ofAction(w, 'publish.denied').at(-1).reason, 'group-not-canary');
});

test('enforced mode at publish: the promotion PR author may not publish it, another approver may', async () => {
  const w = world({ mode: 'enforced', soakDays: 8 });
  await promote(w, USER1, APPROVER);
  await w.c.approve(AARON, AUTHOR, 7, { headSha: HEAD }); await w.c.merge(AARON, AUTHOR, 7, { headSha: HEAD }); await w.c.verifySigning(AARON, AUTHOR, 7);
  await fails(publish(w, USER1, APPROVER), 403); noGraphWrites(w);
  const r = await publish(w, AARON, AUTHOR); assert.equal(r.ok, true);
  assert.equal(w.g.assigns.get('intune-canary')[0].target.groupId, PROD);
});

test('a promotion cannot be edited, and the list describes it', async () => {
  const w = world({ soakDays: 3 });
  await promote(w, AARON, AUTHOR, body({ overrideReason: 'Pilot team signed off.' }));
  await fails(w.c.update(AARON, AUTHOR, 7, { headSha: HEAD, meta: {} }), 409, /cannot be edited/);
  const l = await w.c.list(AARON, AUTHOR);
  const c = l.changes.find(x => x.number === 7);
  assert.equal(c.promote, true); assert.equal(c.promoteInfo.soakOverride, true); assert.equal(c.promoteInfo.soakDays, 3); assert.equal(c.promoteInfo.soakRequired, 7);
  assert.equal(c.promoteInfo.canarySha, CSHA); assert.equal(c.promoteInfo.overrideReason, 'Pilot team signed off.');
  assert.equal(l.prodDefault, PROD); assert.equal(l.soakDays, 7);
  assert.deepEqual({ kind: c.promoteInfo.target.kind, groupId: c.promoteInfo.target.groupId, name: c.promoteInfo.target.name }, { kind: 'group', groupId: PROD, name: 'Production Devices' });
});

test('the list shows the soak clock on the canary change and offers Promote only where it applies', async () => {
  const w = world({ soakDays: 3 });
  const l = await w.c.list(AARON, AUTHOR); const c = l.changes.find(x => x.number === 3);
  assert.equal(c.soak.label, 'Day 3 of 7'); assert.equal(c.soak.met, false); assert.ok(c.published);
  const u = await w.c.list(AARON, ['author']); assert.equal(u.changes.find(x => x.number === 3).canPromote, false);
  const d8 = await world({ soakDays: 8 }).c.list(AARON, AUTHOR); assert.equal(d8.changes.find(x => x.number === 3).soak.label, 'Day 8, soak complete');
  const e = world({ mode: 'enforced' }); const le = await e.c.list(AARON, AUTHOR);
  assert.match(String(le.changes.find(x => x.number === 3).promoteBlock || ''), /different person/);
  const lu = await e.c.list(USER1, APPROVER); assert.equal(lu.changes.find(x => x.number === 3).promoteBlock || null, null);
  const np = await world({ prod: false }).c.list(AARON, AUTHOR); assert.equal(np.changes.find(x => x.number === 3).canPromote, true);
});


