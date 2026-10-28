import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import Ajv from 'ajv';

// Validation for what r360 is allowed to commit to your-org/remediations. The schema is a vendored copy of
// remediations/schema/remediation.schema.json (a test pins it to the upstream copy), so r360 rejects exactly what the repo's CI would.
export const SCHEMA = JSON.parse(readFileSync(fileURLToPath(new URL('./schema/remediation.schema.json', import.meta.url)), 'utf8'));
const ajv = new Ajv({ allErrors: true, strict: false });
const schemaCheck = ajv.compile(SCHEMA);

export const FILES = ['remediation.json', 'detect.ps1', 'remediate.ps1'];
export const MAX_SCRIPT_BYTES = 150 * 1024;
export const GUID = /^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$/;
const META_ORDER = ['displayName', 'description', 'publisher', 'runAs', 'runAs32Bit', 'enforceSignatureCheck', 'schedule', 'assignment'];
const SCHEDULE_ORDER = ['type', 'interval', 'time', 'date', 'useUtc'];
const ASSIGNMENT_ORDER = ['groupId', 'groupIds', 'target', 'runRemediationScript'];

export const sha256 = text => createHash('sha256').update(text).digest('hex');

// Folder names become a path segment and a branch segment, so they are tightly limited.
export function folderError(f) {
  if (typeof f !== 'string' || !f) return 'folder is required';
  if (f.length > 64) return 'folder must be 64 characters or fewer';
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(f)) return 'folder may only contain letters, digits, dot, underscore and hyphen, and must start with a letter or digit';
  if (f.includes('..') || f.endsWith('.') || f.toLowerCase().endsWith('.lock')) return 'folder name is not allowed';
  return null;
}

// The only paths r360 may ever write.
export const allowedPath = p => typeof p === 'string' && /^remediations\/[A-Za-z0-9][A-Za-z0-9._-]*\/(remediation\.json|detect\.ps1|remediate\.ps1)$/.test(p) && !p.includes('..');
export const BRANCH_RE = /^r360\/[A-Za-z0-9][A-Za-z0-9._-]*\/\d{12}-[0-9a-f]{8}$/;

const order = (o, keys) => Object.fromEntries(keys.filter(k => o[k] !== undefined).map(k => [k, o[k]]));
export function canonicalMeta(meta) {
  return { ...order(meta, META_ORDER), schedule: order(meta.schedule || {}, SCHEDULE_ORDER), assignment: order(meta.assignment || {}, ASSIGNMENT_ORDER) };
}
export const metaText = meta => JSON.stringify(canonicalMeta(meta), null, 2) + '\n';

const fmtErrors = errs => (errs || []).map(e => `${(e.instancePath || '(root)').replace(/^\//, '').replace(/\//g, '.') || '(root)'}: ${e.message}${e.params?.additionalProperty ? ` (${e.params.additionalProperty})` : ''}`);

// Schema + the rules CI enforces on top of it.
export function validateMeta(meta, { siblingNames = [], folder } = {}) {
  const errors = [];
  if (!meta || typeof meta !== 'object' || Array.isArray(meta)) return { ok: false, errors: ['remediation.json must be an object'] };
  if (!schemaCheck(meta)) errors.push(...fmtErrors(schemaCheck.errors));
  for (const k of ['displayName', 'publisher']) if (typeof meta[k] === 'string' && /[\u0000-\u001f\u007f]/.test(meta[k])) errors.push(`${k}: control characters are not allowed`);
  if (typeof meta.description === 'string' && /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(meta.description)) errors.push('description: control characters are not allowed');
  if (typeof meta.displayName === 'string' && meta.displayName.trim() !== meta.displayName) errors.push('displayName: no leading or trailing spaces');
  if (meta.schedule?.type === 'once' && !meta.schedule.date) errors.push('schedule.date: required when schedule.type is "once"');
  if (typeof meta.displayName === 'string' && siblingNames.some(n => String(n).toLowerCase() === meta.displayName.toLowerCase())) errors.push(`displayName: "${meta.displayName}" is already used by another remediation${folder ? ` (not ${folder})` : ''}`);
  return { ok: errors.length === 0, errors };
}

// Scripts: UTF-8 text, <= 150 KB, never pre-signed (CI signs after merge). Stored LF, which is what git keeps for *.ps1
// (.gitattributes "*.ps1 text eol=crlf" checks out CRLF but the committed blob is LF).
export function prepareScript(text, name) {
  const errors = [];
  if (typeof text !== 'string' || !text.trim()) return { ok: false, errors: [`${name}: the script is empty`] };
  let t = text.replace(/^\uFEFF/, '');
  if (Buffer.from(t, 'utf8').toString('utf8') !== t) errors.push(`${name}: is not valid UTF-8 text`);
  if (t.includes('\u0000')) errors.push(`${name}: contains a NUL character`);
  if (Buffer.byteLength(t, 'utf8') > MAX_SCRIPT_BYTES) errors.push(`${name}: is larger than ${MAX_SCRIPT_BYTES / 1024} KB`);
  if (/^#\s*SIG\s*#\s*Begin signature block/mi.test(t) || /^#\s*SIG\s*#\s*End signature block/mi.test(t)) errors.push(`${name}: contains a signature block. Scripts must be unsigned; CI signs them after merge`);
  t = t.replace(/\r\n?/g, '\n');
  if (!t.endsWith('\n')) t += '\n';
  return { ok: errors.length === 0, errors, text: t };
}
