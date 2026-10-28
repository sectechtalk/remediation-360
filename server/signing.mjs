import { createHash, createVerify, X509Certificate } from 'node:crypto';
import { unzipSync } from 'fflate';

// Verification of the artifact that the "Sign and Verify" workflow in the remediations repo produces after a merge.
// r360 never signs anything. This checks, in Node and independently of the workflow's own Windows check:
//   - the manifest signature (RSA PKCS#1 v1.5, SHA-256) with the certificate shipped in the artifact,
//   - that certificate is the pinned code-signing certificate (SHA-1 thumbprint) and is currently valid,
//   - the manifest names the merge commit and exactly the files of that commit's remediation folder,
//   - every file matches the hash the signed manifest declares, each script carries a signature block,
//   - and what was signed is what is in git at the merge commit.
// Pure: bytes in, verdict out. The GitHub download is in github.mjs.

export const SIG_BEGIN = '# SIG # Begin signature block';
export const SIG_END = '# SIG # End signature block';
export const MAX_ZIP_BYTES = 8 * 1024 * 1024;
const MAX_ENTRY_BYTES = 2 * 1024 * 1024;
const MAX_ENTRIES = 600;
const ENTRY_RE = /^(manifest-signed\.json|manifest-signed\.sig|r360-codesign\.cer|remediations\/[A-Za-z0-9._-]+\/(?:detect\.ps1|remediate\.ps1|remediation\.json))$/;
const sha256 = b => createHash('sha256').update(b).digest('hex');

// The text that CI signs: no BOM, no signature block, CRLF, no trailing blank lines, one final CRLF.
export function signableText(text) {
  let t = String(text).replace(/^\uFEFF+/, '');
  const i = t.indexOf(SIG_BEGIN);
  if (i >= 0) {
    if (t.indexOf(SIG_END, i) < 0) throw new Error('Signature block has no end marker');
    t = t.slice(0, i);
  }
  return t.replace(/\r\n|\r|\n/g, '\r\n').trimEnd() + '\r\n';
}
export const unsignedHash = text => sha256(Buffer.from(signableText(text), 'utf8'));
export const rawHash = text => sha256(Buffer.from(String(text), 'utf8'));

export function unzipArtifact(zip) {
  if (!zip || !zip.length) throw new Error('The artifact is empty');
  if (zip.length > MAX_ZIP_BYTES) throw new Error('The artifact is larger than the 8 MB limit');
  let count = 0;
  const files = unzipSync(new Uint8Array(zip), {
    filter: f => {
      if (f.name.endsWith('/')) return false;
      if (++count > MAX_ENTRIES) throw new Error('The artifact has too many entries');
      if (!ENTRY_RE.test(f.name)) throw new Error(`The artifact contains an unexpected entry: ${f.name.slice(0, 80)}`);
      if (f.originalSize > MAX_ENTRY_BYTES) throw new Error(`The artifact entry ${f.name} is larger than 2 MB`);
      return true;
    },
  });
  return new Map(Object.entries(files).map(([k, v]) => [k, Buffer.from(v)]));
}

const decodeSig = b => {
  const s = Buffer.from(b).toString('ascii').replace(/\s+/g, '');
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(s)) return null;
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
};

// zip: the artifact bytes. commit: the merge commit sha. folder: the remediation folder of the change.
// repo: { 'remediation.json': text, 'detect.ps1': text, 'remediate.ps1': text } as at the merge commit, or null when unavailable
// (then the check against git cannot pass, which is a failure, not a skip).
export function verifySignedArtifact({ zip, commit, folder, thumbprint, repo, now = Date.now() }) {
  const problems = [];
  const bad = m => problems.push(m);
  const out = () => ({ ok: problems.length === 0, problems, ...info });
  const info = { manifestSha256: null, signerNotAfter: null, signedUtc: null, files: [] };
  let files;
  try { files = unzipArtifact(zip); } catch (e) { bad(e.message); return out(); }
  const manifestBytes = files.get('manifest-signed.json'), sigBytes = files.get('manifest-signed.sig'), cerBytes = files.get('r360-codesign.cer');
  if (!manifestBytes || !sigBytes || !cerBytes) { bad('The artifact is missing the manifest, its signature or the certificate'); return out(); }
  info.manifestSha256 = sha256(manifestBytes);

  let cert;
  try { cert = new X509Certificate(cerBytes); } catch { bad('The certificate in the artifact cannot be read'); return out(); }
  const thumb = createHash('sha1').update(cert.raw).digest('hex').toUpperCase();
  const pin = String(thumbprint || '').toUpperCase();
  if (!/^[0-9A-F]{40}$/.test(pin)) bad('No code-signing thumbprint is pinned');
  else if (thumb !== pin) bad(`The artifact certificate (${thumb}) is not the pinned code-signing certificate (${pin})`);
  const from = Date.parse(cert.validFrom), to = Date.parse(cert.validTo);
  info.signerNotAfter = Number.isFinite(to) ? new Date(to).toISOString() : null;
  if (!(from <= now)) bad('The code-signing certificate is not valid yet');
  if (!(to > now)) bad('The code-signing certificate has expired');

  const sig = decodeSig(sigBytes);
  let sigOk = false;
  try { sigOk = !!sig && createVerify('RSA-SHA256').update(manifestBytes).verify(cert.publicKey, sig); } catch { sigOk = false; }
  if (!sigOk) { bad('The manifest signature does not verify with the certificate'); return out(); }

  let m;
  try { m = JSON.parse(manifestBytes.toString('utf8')); } catch { bad('The manifest is not valid JSON'); return out(); }
  if (m.schema !== 1 || !Array.isArray(m.files)) { bad('The manifest has an unexpected shape'); return out(); }
  info.signedUtc = m.signedUtc || null;
  if (String(m.signer?.thumbprint || '').toUpperCase() !== pin) bad('The manifest names a different signer than the pinned certificate');
  if (m.commit !== commit) bad(`The manifest is for commit ${String(m.commit).slice(0, 12)}, not the merge commit ${String(commit).slice(0, 12)}`);

  const declared = new Set(m.files.map(f => f.path));
  if (declared.size !== m.files.length) bad('The manifest lists a file twice');
  const present = new Set([...files.keys()].filter(k => k.startsWith('remediations/')));
  for (const p of declared) if (!present.has(p)) bad(`${p} is in the manifest but not in the artifact`);
  for (const p of present) if (!declared.has(p)) bad(`${p} is in the artifact but not in the signed manifest`);

  for (const e of m.files) {
    const bytes = files.get(e.path);
    const row = { path: e.path, type: e.type };
    info.files.push(row);
    if (!bytes) continue;
    if (e.type === 'script') {
      const text = bytes.toString('utf8');
      if (sha256(bytes) !== e.signedSha256) bad(`${e.path}: the signed file does not match the manifest hash`);
      if (e.signed !== true || !text.includes(SIG_BEGIN) || !text.includes(SIG_END)) bad(`${e.path}: the script has no signature block`);
      else { try { if (unsignedHash(text) !== e.unsignedSha256) bad(`${e.path}: the content without its signature does not match the manifest`); } catch (x) { bad(`${e.path}: ${x.message}`); } }
    } else if (e.type === 'data') {
      if (sha256(bytes) !== e.sha256) bad(`${e.path}: the file does not match the manifest hash`);
    } else bad(`${e.path}: unknown file type in the manifest`);
  }

  // What was signed must be what is in git at the merge commit, for the folder this change touched.
  const base = `remediations/${folder}/`;
  const mine = m.files.filter(f => f.path.startsWith(base));
  const expected = ['remediation.json', 'detect.ps1', 'remediate.ps1'];
  if (!repo) bad('The files at the merge commit could not be read, so the signed content cannot be compared with git');
  else {
    for (const n of expected) {
      const e = mine.find(f => f.path === base + n);
      if (!e) { bad(`${base}${n} is not in the signed manifest`); continue; }
      const git = repo[n];
      if (typeof git !== 'string') { bad(`${base}${n}: not readable at the merge commit`); continue; }
      if (n === 'remediation.json') { if (e.type !== 'data' || e.sha256 !== rawHash(git)) bad(`${base}${n}: the signed file is not what is in git`); }
      else { try { if (e.type !== 'script' || e.unsignedSha256 !== unsignedHash(git)) bad(`${base}${n}: the signed content is not what is in git`); } catch (x) { bad(`${base}${n}: ${x.message}`); } }
    }
  }
  return out();
}
