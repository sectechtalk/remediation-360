import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { SCHEMA, validateMeta, prepareScript, folderError, allowedPath, BRANCH_RE, canonicalMeta, metaText, MAX_SCRIPT_BYTES } from '../server/remediation-schema.mjs';
import { branchName, commitMessage, prBody, machineBlock, parseMachineBlock, stageOf } from '../server/changes.mjs';

const GROUP = '90000000-0000-4000-8000-0000000000c2';
export const META = { displayName: 'STT - Test remediation', description: 'Does a thing', publisher: 'SecTechTalk', runAs: 'system', runAs32Bit: false, enforceSignatureCheck: true,
  schedule: { type: 'daily', interval: 1, time: '02:00:00' }, assignment: { groupId: GROUP, runRemediationScript: true } };

test('the vendored schema is identical to the pinned upstream copy (parity)', () => {
  const upstream = JSON.parse(readFileSync(new URL('./remediation.schema.upstream.json', import.meta.url), 'utf8'));
  assert.deepEqual(SCHEMA, upstream);
});

test('metadata validation matrix', () => {
  assert.equal(validateMeta(META).ok, true);
  const bad = (mut, re) => { const m = structuredClone(META); mut(m); const r = validateMeta(m); assert.equal(r.ok, false, re); assert.match(r.errors.join('\n'), re); };
  bad(m => { delete m.publisher; }, /publisher/);
  bad(m => { m.extra = 1; }, /extra/);
  bad(m => { m.displayName = 'ab'; }, /displayName/);
  bad(m => { m.displayName = ' padded '; }, /leading or trailing/);
  bad(m => { m.displayName = 'tab\there'; }, /control characters/);
  bad(m => { m.runAs = 'root'; }, /runAs/);
  bad(m => { m.runAs32Bit = 'no'; }, /runAs32Bit/);
  bad(m => { m.schedule.interval = 24; }, /interval/);
  bad(m => { m.schedule.interval = 1.5; }, /interval/);
  bad(m => { m.schedule.time = '25:00:00'; }, /time/);
  bad(m => { m.schedule.type = 'weekly'; }, /type/);
  bad(m => { m.schedule = { type: 'once', interval: 1 }; }, /date: required/);
  bad(m => { m.assignment.groupId = 'not-a-guid'; }, /groupId/);
  bad(m => { m.assignment.other = 1; }, /other/);
  assert.equal(validateMeta({ ...META, schedule: { type: 'once', interval: 1, date: '2026-12-01' } }).ok, true);
  assert.equal(validateMeta([]).ok, false);
  assert.equal(validateMeta(null).ok, false);
  // Unique displayName among other folders (case-insensitive).
  const dup = validateMeta(META, { siblingNames: ['stt - test REMEDIATION'], folder: 'Mine' });
  assert.equal(dup.ok, false); assert.match(dup.errors[0], /already used/);
  assert.equal(validateMeta(META, { siblingNames: ['Other'] }).ok, true);
});

test('canonical remediation.json is stable: key order fixed, trailing newline, absent optionals stay absent', () => {
  const scrambled = { assignment: { runRemediationScript: true, groupId: GROUP }, schedule: { time: '02:00:00', interval: 1, type: 'daily' }, runAs: 'system', publisher: 'p', description: 'd', displayName: 'Name 1', runAs32Bit: false };
  const text = metaText(scrambled);
  assert.ok(text.endsWith('}\n'));
  assert.deepEqual(Object.keys(JSON.parse(text)), ['displayName', 'description', 'publisher', 'runAs', 'runAs32Bit', 'schedule', 'assignment']);
  assert.deepEqual(Object.keys(canonicalMeta(scrambled).schedule), ['type', 'interval', 'time']);
  assert.equal(metaText(JSON.parse(text)), text);
});

test('script validation: unsigned only, size, encoding normalization', () => {
  assert.equal(prepareScript('', 'detect.ps1').ok, false);
  assert.equal(prepareScript('   \n', 'detect.ps1').ok, false);
  assert.equal(prepareScript(undefined, 'detect.ps1').ok, false);
  const signed = prepareScript('Write-Output 1\n# SIG # Begin signature block\nMIIabc\n# SIG # End signature block\n', 'detect.ps1');
  assert.equal(signed.ok, false); assert.match(signed.errors[0], /signature block/);
  const big = prepareScript('#'.repeat(MAX_SCRIPT_BYTES + 1), 'remediate.ps1');
  assert.equal(big.ok, false); assert.match(big.errors[0], /150 KB/);
  assert.equal(prepareScript('#'.repeat(MAX_SCRIPT_BYTES - 1), 'remediate.ps1').ok, true);
  assert.equal(prepareScript('a\u0000b', 'x.ps1').ok, false);
  const n = prepareScript('\uFEFFline1\r\nline2\rline3', 'detect.ps1');
  assert.equal(n.ok, true); assert.equal(n.text, 'line1\nline2\nline3\n');
  assert.equal(prepareScript('ok\n', 'd.ps1').text, 'ok\n');
});

test('folder names and write paths are whitelisted', () => {
  for (const f of ['Stt-Test', 'a', 'A.b_c-1', 'x'.repeat(64)]) assert.equal(folderError(f), null, f);
  for (const f of ['', null, undefined, '.hidden', '-lead', '../x', 'a/b', 'a\\b', 'a b', 'x'.repeat(65), 'a..b', 'end.', 'x.lock', 'x.LOCK', 'Ünï', 'a\nb']) assert.ok(folderError(f), JSON.stringify(f));
  for (const n of ['remediation.json', 'detect.ps1', 'remediate.ps1']) assert.equal(allowedPath(`remediations/Stt-Test/${n}`), true);
  for (const p of ['approvers.json', '.github/workflows/x.yml', 'remediations/x/other.ps1', 'remediations/../approvers.json', 'remediations//detect.ps1', 'remediations/a/b/detect.ps1', '/remediations/a/detect.ps1', 'schema/remediation.schema.json', 'remediations/a/detect.ps1\n', null, 5]) assert.equal(allowedPath(p), false, String(p));
});

test('branch names: r360/<folder>/<yyyyMMddHHmm>-<oid8>, validated', () => {
  const b = branchName({ folder: 'Stt-Test', ms: Date.parse('2026-10-27T15:04:59Z'), oid: '94540000-0000-4000-8000-0000000000c3' });
  assert.equal(b, 'r360/Stt-Test/202610271504-94540000');
  assert.ok(BRANCH_RE.test(b));
  for (const x of ['main', 'r360/x', 'r360/x/1-2', 'r360/../x/202610271504-94540000', 'r360/x/202610271504-9454ABCD', 'feature/x/202610271504-94540000', b + '/extra', b + '\n']) assert.equal(BRANCH_RE.test(x), false, x);
});

test('commit message carries the Entra identity trailers; PR body ends with the machine block', () => {
  const user = { oid: '94540000-0000-4000-8000-0000000000c3', upn: 'admin@contoso.com', name: 'Aaron <Brooks>\nInjected: yes' };
  const msg = commitMessage({ kind: 'new', folder: 'Stt-Test', displayName: 'Line1\nLine2', user, requestId: 'req-1' });
  const lines = msg.split('\n');
  assert.equal(lines[0], 'r360: add remediation Stt-Test');
  assert.ok(lines.includes(`R360-Entra-Oid: ${user.oid}`)); assert.ok(lines.includes('R360-Request-Id: req-1'));
  assert.ok(lines.some(l => /^Co-authored-by: Aaron\s+Brooks\s+Injected: yes <94540000-0000-4000-8000-0000000000c3@users\.r360\.invalid>$/.test(l)), msg);
  assert.equal(lines.filter(l => l.startsWith('Injected')).length, 0);
  const body = prBody({ kind: 'new', folder: 'Stt-Test', displayName: 'N|ame', proposer: 'admin@contoso.com', authorOid: user.oid, requestId: 'req-1', ms: 0, fourEyes: 'testing', groupNote: 'g',
    files: [{ path: 'remediations/Stt-Test/detect.ps1', status: 'added', bytes: 3, sha256: 'a'.repeat(64) }] });
  assert.ok(body.trimEnd().endsWith(machineBlock({ folder: 'Stt-Test', authorOid: user.oid })));
  assert.deepEqual(parseMachineBlock(body), { v: 1, kind: 'author', folder: 'Stt-Test', authorOid: user.oid });
  assert.match(body, /testing mode/);
  assert.equal(parseMachineBlock('no block'), null);
  assert.equal(parseMachineBlock('<!-- r360:{"v":2,"kind":"author","folder":"a","authorOid":"b"} -->'), null);
  assert.equal(parseMachineBlock('<!-- r360:{broken} -->'), null);
});

test('stageOf: pending, running, passed, failed, merged, discarded', () => {
  const open = checks => stageOf({ state: 'open', merged: false, checks });
  assert.equal(open(null).stage, 'ci-running'); assert.equal(open(null).ci, 'pending');
  assert.equal(open([{ name: 'PSScriptAnalyzer', status: 'in_progress', conclusion: null }]).stage, 'ci-running');
  const passed = open([{ name: 'PSScriptAnalyzer', status: 'completed', conclusion: 'success' }]);
  assert.equal(passed.stage, 'ci-passed'); assert.equal(passed.steps.find(s => s.id === 'ci').state, 'done'); assert.equal(passed.steps.find(s => s.id === 'merged').state, 'todo');
  assert.equal(open([{ name: 'PSScriptAnalyzer', status: 'completed', conclusion: 'failure' }]).stage, 'ci-failed');
  assert.equal(open([{ name: 'Other', status: 'completed', conclusion: 'success' }]).stage, 'ci-running'); // the required check is missing
  assert.equal(open([{ name: 'PSScriptAnalyzer', status: 'completed', conclusion: 'success' }, { name: 'X', status: 'queued', conclusion: null }]).stage, 'ci-running');
  const merged = stageOf({ state: 'closed', merged: true, checks: null });
  assert.equal(merged.stage, 'merged'); assert.equal(merged.steps.at(-1).state, 'todo'); assert.deepEqual(merged.steps.map(s => s.label), ['Proposed', 'CI checks', 'Approved', 'Merged', 'Signed', 'Published', 'Soak', 'Production']);
  const closed = stageOf({ state: 'closed', merged: false, checks: null });
  assert.equal(closed.stage, 'discarded'); assert.ok(closed.steps.slice(1).every(s => s.state === 'skipped'));
});
