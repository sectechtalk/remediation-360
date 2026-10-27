import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeScript, scriptHash, buildCatalog, driftReasons, runOutcome, fleetRows, gitStamp } from '../server/catalog.mjs';
import { sha1Thumbprint, profileCertCheck, certDeviceRows } from '../server/certs.mjs';
import { summarizePim, ROLE_TEMPLATES } from '../server/pim.mjs';
import { loadConfig, publicSettings } from '../server/config.mjs';
import { distinctValues, applyFilters, sortRows, cellText } from '../public/table.js';

const b64 = s => Buffer.from(s, 'utf8').toString('base64');
import { ENV } from './fixtures.mjs';

test('config fails closed when settings are missing (no demo mode)', () => {
  assert.throws(() => loadConfig({}), /missing settings/);
  assert.throws(() => loadConfig({ ...ENV, R360_PUBLIC_URL: 'http://x' }), /https/);
  assert.throws(() => loadConfig({ ...ENV, R360_KEY_VAULT_URI: 'https://evil.example.com' }), /vault/);
  const c = loadConfig(ENV);
  assert.equal(c.redirectUri, 'https://app-r360.example.westus3.azurecontainerapps.io/auth/callback');
  assert.equal(c.fourEyes, 'testing'); assert.equal(c.pimMode, 'warn');
  assert.ok(!JSON.stringify(publicSettings(c)).match(/secret|token/i));
  const { R360_KEY_VAULT_URI: _v, R360_PUBLIC_URL: _u, ...rest } = ENV;
  const d = loadConfig({ ...rest, R360_KEY_VAULT: 'kv-r360-abc123', CONTAINER_APP_NAME: 'app-r360', CONTAINER_APP_ENV_DNS_SUFFIX: 'example-00000000.westus3.azurecontainerapps.io' });
  assert.equal(d.vaultUri, 'https://kv-r360-abc123.vault.azure.net');
  assert.equal(d.redirectUri, 'https://app-r360.example-00000000.westus3.azurecontainerapps.io/auth/callback');
});

test('script normalization ignores BOM, CRLF and trailing whitespace only', () => {
  assert.equal(normalizeScript('\uFEFFa  \r\nb\r\n\r\n'), 'a\nb');
  assert.equal(scriptHash('x\r\ny'), scriptHash('x\ny\n'));
  assert.notEqual(scriptHash('x\ny'), scriptHash('x\nz'));
});

const repoItem = { folder: 'Sample-RemediationCanary', meta: { displayName: 'STT - Remediation Canary', publisher: 'SecTechTalk', runAs: 'system', runAs32Bit: false, enforceSignatureCheck: false }, detect: 'exit 0\n', remediate: 'Set-Thing\n' };
const intune = { id: 'i1', displayName: 'STT - Remediation Canary', publisher: 'SecTechTalk', runAsAccount: 'system', runAs32Bit: false, enforceSignatureCheck: false,
  detectionScriptContent: b64('\uFEFFexit 0\r\n'), remediationScriptContent: b64('Set-Thing\r\n'), description: 'x [git 3dfaf50a by a; published by b]', lastModifiedDateTime: '2026-10-26T15:00:00Z' };

test('catalog: in sync, drift, not in Intune, Intune only, duplicate', () => {
  assert.deepEqual(driftReasons(repoItem, intune), []);
  const drifted = { ...intune, remediationScriptContent: b64('Other'), enforceSignatureCheck: true };
  assert.deepEqual(driftReasons(repoItem, drifted), ['remediate.ps1 differs', 'enforceSignatureCheck differs']);
  const rows = buildCatalog({ repoItems: [repoItem, { folder: 'New', meta: { displayName: 'New one' } }], intuneScripts: [intune, { id: 'i9', displayName: 'Manual thing' }],
    summaries: new Map([['i1', { noIssueDetectedDeviceCount: 1, issueRemediatedDeviceCount: 2, detectionScriptErrorDeviceCount: 1, remediationScriptErrorDeviceCount: 1 }]]) });
  const by = Object.fromEntries(rows.map(r => [r.name, r]));
  assert.equal(by['STT - Remediation Canary'].status, 'In sync');
  assert.equal(by['STT - Remediation Canary'].publishedGit, '3dfaf50a');
  assert.equal(by['STT - Remediation Canary'].errors, 2);
  assert.equal(by['New one'].status, 'Not in Intune');
  assert.equal(by['Manual thing'].status, 'Intune only');
  const dup = buildCatalog({ repoItems: [repoItem], intuneScripts: [intune, { ...intune, id: 'i2' }] });
  assert.equal(dup[0].status, 'Duplicate in Intune');
  const bad = buildCatalog({ repoItems: [{ folder: 'Broken', metaError: 'remediation.json: bad' }], intuneScripts: [] });
  assert.equal(bad[0].status, 'Invalid in repo');
  assert.equal(gitStamp('no stamp'), null);
});

test('fleet outcomes map deviceRunStates', () => {
  assert.equal(runOutcome({ detectionState: 'success', remediationState: 'skipped' }), 'Without issues');
  assert.equal(runOutcome({ detectionState: 'fail', remediationState: 'success' }), 'Issue fixed');
  assert.equal(runOutcome({ detectionState: 'fail', remediationState: 'remediationFailed' }), 'Failed');
  assert.equal(runOutcome({ detectionState: 'scriptError' }), 'Failed');
  assert.equal(runOutcome({ detectionState: 'pending' }), 'Pending');
  assert.equal(runOutcome({ detectionState: 'fail', remediationState: 'skipped' }), 'Issue detected');
  const rows = fleetRows('R', 'i1', [{ id: 's', detectionState: 'success', managedDevice: { deviceName: 'DEVICE01' } }]);
  assert.equal(rows[0].device, 'DEVICE01'); assert.equal(rows[0].remediation, 'R');
});

test('certificate thumbprint check for Root and TrustedPublisher profiles', () => {
  const der = Buffer.from('not-a-real-cert');
  const tp = sha1Thumbprint(der.toString('base64'));
  assert.match(tp, /^[0-9A-F]{40}$/);
  assert.equal(profileCertCheck({ '@odata.type': '#microsoft.graph.windows81TrustedRootCertificate', trustedRootCertificate: der.toString('base64') }, tp).matches, true);
  assert.equal(profileCertCheck({ '@odata.type': '#microsoft.graph.windows81TrustedRootCertificate', trustedRootCertificate: der.toString('base64') }, 'A'.repeat(40)).matches, false);
  const oma = { '@odata.type': '#microsoft.graph.windows10CustomConfiguration', omaSettings: [{ omaUri: `./Device/Vendor/MSFT/RootCATrustedCertificates/TrustedPublisher/${tp.toLowerCase()}/EncodedCertificate` }] };
  assert.equal(profileCertCheck(oma, tp).matches, true);
  assert.equal(profileCertCheck(null, tp).found, false);
  assert.equal(certDeviceRows('Root', [{ deviceDisplayName: 'DEVICE01', status: 'compliant' }, { deviceDisplayName: 'X', status: 'error' }]).filter(r => r.deployed).length, 1);
});

test('PIM summary: GA bypass, eligible-only warning, expired rows dropped', () => {
  const definitions = [{ id: 'd-ga', displayName: 'Global Administrator', templateId: ROLE_TEMPLATES.globalAdmin }, { id: 'd-in', displayName: 'Intune Administrator', templateId: ROLE_TEMPLATES.intuneAdmin }];
  const now = Date.parse('2026-10-26T15:00:00Z');
  const ga = summarizePim({ active: [{ roleDefinitionId: 'd-ga', assignmentType: 'Assigned' }], eligible: [{ roleDefinitionId: 'd-in' }], definitions, now });
  assert.equal(ga.gate.ok, true); assert.match(ga.gate.text, /Global Administrator/);
  const elig = summarizePim({ active: [], eligible: [{ roleDefinitionId: 'd-in' }], definitions, now });
  assert.equal(elig.gate.ok, false); assert.match(elig.gate.text, /eligible but not active/);
  const act = summarizePim({ active: [{ roleDefinitionId: 'd-in', assignmentType: 'Activated', endDateTime: '2026-10-26T20:00:00Z' }, { roleDefinitionId: 'd-ga', assignmentType: 'Activated', endDateTime: '2026-10-26T10:00:00Z' }], definitions, now });
  assert.equal(act.gate.ok, true); assert.equal(act.rows.length, 1); assert.equal(act.rows[0].state, 'Active (PIM)');
});

test('table helpers: multi-select filters, sorting, blanks', () => {
  const rows = [{ a: 'x', n: 10 }, { a: 'y', n: 2 }, { a: null, n: 1 }];
  assert.deepEqual(distinctValues(rows, 'a'), ['(blank)', 'x', 'y']);
  assert.equal(applyFilters(rows, { a: new Set(['x', '(blank)']) }).length, 2);
  assert.equal(applyFilters(rows, { a: undefined }).length, 3);
  assert.deepEqual(sortRows(rows, 'n', 'asc').map(r => r.n), [1, 2, 10]);
  assert.deepEqual(sortRows(rows, 'n', 'desc').map(r => r.n), [10, 2, 1]);
  assert.equal(cellText([]), '(blank)'); assert.equal(cellText(['a', 'b']), 'a; b');
});
