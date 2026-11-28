// Chaos Monkey templates: HeatMap 360 links to #new/chaos-<ID>?from=heatmap-360 and the New remediation form opens filled in.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { CHAOS_TESTS, chaosPreset } from '../public/chaos.js';
import { validateMeta, folderError } from '../server/remediation-schema.mjs';

test('77 tests with unique ids in three tiers (19 probes, 23 this-machine, 35 AD checks)', () => {
  assert.equal(CHAOS_TESTS.length, 77);
  assert.equal(new Set(CHAOS_TESTS.map(t => t[0])).size, 77);
  const n = tier => CHAOS_TESTS.filter(t => t[1] === tier).length;
  assert.deepEqual([n('probe'), n('local'), n('ad')], [19, 23, 35]);
});

test('every template is a valid remediation that never remediates and runs the real test', async () => {
  const { CHAOS_DETECT } = await import('../public/chaos-scripts.js');
  for (const [id] of CHAOS_TESTS) {
    const p = await chaosPreset(`chaos-${id}?from=heatmap-360`);
    assert.equal(p.folder, `Chaos-${id}`);
    assert.equal(folderError(p.folder), null, `${id} folder`);
    assert.equal(p.from, 'HeatMap 360');
    assert.equal(p.meta.assignment.runRemediationScript, false);
    assert.equal(p.meta.enforceSignatureCheck, true);
    assert.equal(p.meta.runAs, 'system');
    assert.match(p.meta.displayName, new RegExp(`^STT - Chaos - ${id} `));
    assert.equal(p.detect, CHAOS_DETECT[id], `${id} detect.ps1 is the built test`);
    assert.doesNotMatch(p.detect, /NOT BUILT/);
    assert.match(p.remediate, /\nexit 0\n$/);
    assert.doesNotMatch(p.remediate, /Set-|Remove-|New-|Stop-|Restart-/, 'remediate.ps1 changes nothing');
  }
});

test('the built scripts are up to date with chaos/tests and chaos/lib.ps1', () => {
  const out = execFileSync(process.execPath, [fileURLToPath(new URL('../tools/build-chaos.mjs', import.meta.url)), '--check'], { encoding: 'utf8' });
  assert.match(out, /up to date/);
  const bodies = readdirSync(new URL('../chaos/tests/', import.meta.url)).map(f => f.replace(/\.ps1$/, '')).sort();
  assert.deepEqual(bodies, CHAOS_TESTS.map(t => t[0]).sort(), 'one test script per id, no extras');
});

test('every test only reads: no state-changing cmdlets, no remoting, verdicts on every path', async () => {
  const { CHAOS_DETECT } = await import('../public/chaos-scripts.js');
  const change = /\b(Set|Remove|Clear|Stop|Restart|Start|Install|Uninstall|Enable|Disable|Rename|Reset|Update|Register|Unregister|Grant|Revoke|Move|Copy|Suspend|Resume|Lock|Unlock|Mount|Dismount)-[A-Z][A-Za-z]*|\bNew-(?!Object\b)[A-Z][A-Za-z]*/g;
  for (const [id, s] of Object.entries(CHAOS_DETECT)) {
    const hits = (s.match(change) || []).filter(h => h !== 'Set-ADSyncRestrictedPermissions');
    assert.deepEqual(hits, [], `${id} changes something`);
    assert.doesNotMatch(s, /Invoke-Command|Enter-PSSession|New-PSSession|Invoke-Expression|\biex\b|reg(\.exe)? (add|delete)|sc(\.exe)? (config|stop|start|delete)/i, `${id} remoting or changes`);
    assert.match(s, /^\[CmdletBinding\(\)\]\nparam\(\)$/m, `${id} starts with param()`);
    assert.match(s, /\$script:ChaosId = '[A-Z]\d{1,2}'\ntry \{/, `${id} sets its id`);
    assert.match(s, /\} catch \{\n    Write-Verdict -Verdict 'COULD NOT TEST'/, `${id} reports a stopped test as COULD NOT TEST`);
    assert.ok(Buffer.byteLength(s) < 150 * 1024, `${id} under the 150 KB script limit`);
    const body = s.slice(s.indexOf("try {\n"));
    assert.match(body, /Write-Verdict -Verdict '(PASS|FAIL|COULD NOT TEST)'[^\n]*\n\} catch/, `${id} ends with a verdict`);
    const tooLong = [...body.matchAll(/-Summary '([^']*)'/g)].filter(m => m[1].length > 400);
    assert.deepEqual(tooLong, [], `${id} summaries stay short`);
  }
});

test('only PASS exits 0: Write-Verdict exits 1 for FAIL and COULD NOT TEST', () => {
  const lib = readFileSync(new URL('../chaos/lib.ps1', import.meta.url), 'utf8').replace(/\r\n/g, '\n'); // CRLF on a Windows checkout
  assert.match(lib, /if \(\$Verdict -eq 'PASS'\) \{ exit 0 \}\n    exit 1\n/);
});

test('every template passes the server schema check once the server adds the canary group', async () => {
  for (const [id] of CHAOS_TESTS) {
    const p = await chaosPreset(`chaos-${id}`);
    const r = validateMeta({ ...p.meta, assignment: { groupId: '00000000-0000-4000-8000-0000000000b2', ...p.meta.assignment } }, { folder: p.folder });
    assert.equal(r.ok, true, `${id}: ${JSON.stringify(r.errors)}`);
  }
});

test('unknown or malformed links give no template', async () => {
  for (const a of ['', 'chaos-Z9', 'chaos-n1', 'chaos-N1x', 'other', 'chaos-N1/../x', undefined]) assert.equal(await chaosPreset(a), null, String(a));
  assert.equal((await chaosPreset('chaos-N1?from=elsewhere')).from, null);
});

test('the link survives sign-in and Elevate to write', () => {
  const app = readFileSync(new URL('../public/app.js', import.meta.url), 'utf8');
  const re = s => new RegExp(app.match(new RegExp(`const ${s} = /(.+)/;`))[1]);
  assert.ok(re('HANDOFF').test('#new/chaos-N1?from=heatmap-360'));
  assert.ok(re('RESTORE').test('#new/chaos-N1?from=heatmap-360'));
  assert.ok(!re('HANDOFF').test('#new'), 'a plain New remediation link is not kept');
  assert.ok(!re('HANDOFF').test('#offboard'), 'unchanged for the bare Offboard page');
});

test('templates are plain ASCII, so PSScriptAnalyzer never asks for a BOM', async () => {
  for (const [id] of CHAOS_TESTS) {
    const p = await chaosPreset(`chaos-${id}`);
    assert.doesNotMatch(p.detect + p.remediate + JSON.stringify(p.meta), /[^\x00-\x7f]/, id);
  }
});

test('auto-create only for a fresh go-ahead from HeatMap on this computer, used once', async () => {
  const { markChaosAuto, takeChaosAuto, CHAOS_AUTO_KEY } = await import('../public/chaos.js');
  const store = () => { const m = new Map(); return { getItem: k => m.get(k) ?? null, setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k), m }; };
  const link = '#new/chaos-N1?from=heatmap-360';
  let s = store();
  assert.equal(markChaosAuto(link, 'http://localhost:3460/', s, 1000), true);
  assert.equal(takeChaosAuto('S1', s, 2000), false, 'another test never runs on this go-ahead');
  assert.equal(s.getItem(CHAOS_AUTO_KEY), null, 'and it is dropped');
  s = store(); markChaosAuto(link, 'http://127.0.0.1:3460/', s, 1000);
  assert.equal(takeChaosAuto('N1', s, 2000), true);
  assert.equal(takeChaosAuto('N1', s, 3000), false, 'used once');
  s = store(); markChaosAuto(link, 'http://localhost:3460/', s, 0);
  assert.equal(takeChaosAuto('N1', s, 16 * 60 * 1000), false, 'expires after 15 minutes');
  for (const [hash, ref] of [[link, ''], [link, 'https://evil.example/'], [link, 'http://localhost:3461/'], ['#new/chaos-N1', 'http://localhost:3460/'],
    ['#new/chaos-N1?from=other', 'http://localhost:3460/'], ['#new/chaos-Z9?from=heatmap-360', 'http://localhost:3460/'], ['#offboard/x', 'http://localhost:3460/']]) {
    s = store();
    assert.equal(markChaosAuto(hash, ref, s), false, `${hash} from ${ref}`);
    assert.equal(s.m.size, 0);
  }
});
