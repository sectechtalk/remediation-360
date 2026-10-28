import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { zipSync, unzipSync, strToU8 } from 'fflate';
import { verifySignedArtifact, signableText, unsignedHash, rawHash, unzipArtifact, SIG_BEGIN, MAX_ZIP_BYTES } from '../server/signing.mjs';

// A real artifact produced by the "Sign and Verify" workflow (run 40461381266) for the sample remediation.
const ZIP = readFileSync(new URL('./data/signed-c0ffee00.zip', import.meta.url));
const COMMIT = 'c0ffee0000000000000000000000000000000001';
const FOLDER = 'Sample-RemediationCanary';
const THUMB = 'DCFE9BD52139FB88200D26B420D25E5C41C00780';
const base = `remediations/${FOLDER}/`;
const entries = () => Object.fromEntries(Object.entries(unzipSync(new Uint8Array(ZIP))).map(([k, v]) => [k, Buffer.from(v)]));
const rezip = e => Buffer.from(zipSync(Object.fromEntries(Object.entries(e).map(([k, v]) => [k, new Uint8Array(v)]))));
const strip = t => t.slice(0, t.indexOf(SIG_BEGIN));
const gitFrom = e => ({ 'remediation.json': e[base + 'remediation.json'].toString('utf8'), 'detect.ps1': strip(e[base + 'detect.ps1'].toString('utf8')), 'remediate.ps1': strip(e[base + 'remediate.ps1'].toString('utf8')) });
const verify = (over = {}) => verifySignedArtifact({ zip: ZIP, commit: COMMIT, folder: FOLDER, thumbprint: THUMB, repo: gitFrom(entries()), now: Date.parse('2026-10-27T12:00:00Z'), ...over });
const has = (r, re) => assert.ok(r.problems.some(p => re.test(p)), `expected a problem matching ${re}, got ${JSON.stringify(r.problems)}`);

test('signing: the real CI artifact verifies against the pinned thumbprint, the commit and git', () => {
  const r = verify();
  assert.deepEqual(r.problems, []);
  assert.equal(r.ok, true);
  assert.equal(r.files.length, 3);
  assert.match(r.manifestSha256, /^[0-9a-f]{64}$/);
  assert.equal(r.signerNotAfter, '2029-10-26T12:55:48.000Z');
});

test('signing: wrong commit, wrong thumbprint, no pin', () => {
  has(verify({ commit: 'f'.repeat(40) }), /not the merge commit/);
  has(verify({ thumbprint: '0'.repeat(40) }), /not the pinned code-signing certificate/);
  has(verify({ thumbprint: '' }), /No code-signing thumbprint is pinned/);
});

test('signing: an expired or not yet valid certificate fails', () => {
  has(verify({ now: Date.parse('2029-10-27T00:00:00Z') }), /expired/);
  has(verify({ now: Date.parse('2020-01-01T00:00:00Z') }), /not valid yet/);
});

test('signing: a changed manifest breaks the signature and nothing else is trusted', () => {
  const e = entries();
  e['manifest-signed.json'] = Buffer.from(e['manifest-signed.json'].toString('utf8').replace(COMMIT, 'a'.repeat(40)));
  const r = verifySignedArtifact({ zip: rezip(e), commit: 'a'.repeat(40), folder: FOLDER, thumbprint: THUMB, repo: gitFrom(entries()), now: Date.parse('2026-10-27T12:00:00Z') });
  assert.equal(r.ok, false);
  has(r, /signature does not verify/);
});

test('signing: a garbage or missing signature fails', () => {
  const e = entries();
  e['manifest-signed.sig'] = Buffer.from('AAAA');
  has(verify({ zip: rezip(e) }), /signature does not verify/);
  const e2 = entries(); delete e2['manifest-signed.sig'];
  has(verify({ zip: rezip(e2) }), /missing the manifest/);
});

test('signing: a file changed after signing no longer matches the manifest', () => {
  const e = entries();
  e[base + 'remediation.json'] = Buffer.from(e[base + 'remediation.json'].toString('utf8').replace('"', '"x', 1));
  has(verify({ zip: rezip(e) }), /remediation\.json: the file does not match the manifest hash/);
  const e2 = entries();
  e2[base + 'detect.ps1'] = Buffer.from(e2[base + 'detect.ps1'].toString('utf8') + '\r\n# extra\r\n');
  has(verify({ zip: rezip(e2) }), /detect\.ps1: the signed file does not match/);
});

test('signing: a script without its signature block fails', () => {
  const e = entries();
  e[base + 'remediate.ps1'] = Buffer.from(strip(e[base + 'remediate.ps1'].toString('utf8')));
  has(verify({ zip: rezip(e) }), /remediate\.ps1: (the script has no signature block|the signed file does not match)/);
});

test('signing: extra and missing files', () => {
  const e = entries();
  e['remediations/Other/detect.ps1'] = Buffer.from('x');
  has(verify({ zip: rezip(e) }), /is in the artifact but not in the signed manifest/);
  const e2 = entries(); delete e2[base + 'detect.ps1'];
  has(verify({ zip: rezip(e2) }), /is in the manifest but not in the artifact/);
});

test('signing: an entry outside the allowed names is refused before anything is read', () => {
  const e = entries();
  e['evil.txt'] = Buffer.from('x');
  has(verify({ zip: rezip(e) }), /unexpected entry: evil\.txt/);
  const e2 = entries();
  e2['remediations/../../x.ps1'] = Buffer.from('x');
  has(verify({ zip: rezip(e2) }), /unexpected entry/);
  assert.throws(() => unzipArtifact(Buffer.alloc(0)), /empty/);
  assert.throws(() => unzipArtifact(Buffer.alloc(MAX_ZIP_BYTES + 1)), /larger than/);
  has(verify({ zip: Buffer.from('not a zip at all') }), /./);
});

test('signing: what was signed must be what is in git', () => {
  has(verify({ repo: null }), /could not be read/);
  const g = gitFrom(entries());
  has(verify({ repo: { ...g, 'detect.ps1': g['detect.ps1'] + 'Write-Host "hi"\n' } }), /detect\.ps1: the signed content is not what is in git/);
  has(verify({ repo: { ...g, 'remediation.json': g['remediation.json'] + ' ' } }), /remediation\.json: the signed file is not what is in git/);
  has(verify({ repo: { ...g, 'remediate.ps1': undefined } }), /not readable at the merge commit/);
  has(verify({ folder: 'Some-Other-Folder' }), /not in the signed manifest/);
});

test('signing: the signable text rules (BOM, line endings, trailing blank lines, signature block)', () => {
  assert.equal(signableText('\uFEFFa\nb\n\n\n'), 'a\r\nb\r\n');
  assert.equal(signableText('a\r\nb'), 'a\r\nb\r\n');
  assert.equal(signableText(`a\n${SIG_BEGIN}\nxx\n# SIG # End signature block\n`), 'a\r\n');
  assert.throws(() => signableText(`a\n${SIG_BEGIN}\nxx`), /no end marker/);
  assert.equal(unsignedHash('a\nb\n'), unsignedHash('\uFEFFa\r\nb'));
  assert.notEqual(rawHash('a\n'), rawHash('a\r\n'));
});
