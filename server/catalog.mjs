import { createHash } from 'node:crypto';

// Pure logic: repo vs Intune catalog and drift. Content is compared after normalization (BOM, CRLF, trailing space)
// because git stores LF and the publish script uploads the Windows CRLF checkout. The repo holds unsigned scripts and
// Intune holds the CI-signed copies, so the trailing Authenticode block is removed before comparing: it is a signature
// over the script, not part of its content (the signature itself is verified by Publish-Remediation.ps1 and on the device).
const SIG_BLOCK = /(^|\n)# SIG # Begin signature block\n[\s\S]*?\n# SIG # End signature block[ \t]*(\n|$)/;
export function stripSignature(text) {
  if (text == null) return null;
  const t = String(text).replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n');
  const m = SIG_BLOCK.exec(t);
  // Only a block that ends the file counts; the same text in the middle of a script is script content.
  return m && t.slice(m.index + m[0].length).trim() === '' ? t.slice(0, m.index) : t;
}
export function normalizeScript(text) {
  if (text == null) return null;
  return stripSignature(text).split('\n').map(l => l.replace(/[ \t]+$/, '')).join('\n').replace(/\n+$/, '');
}
export const scriptHash = text => text == null ? null : createHash('sha256').update(normalizeScript(text), 'utf8').digest('hex');
export function decodeIntuneScript(b64) {
  if (!b64) return null;
  return Buffer.from(b64, 'base64').toString('utf8');
}
const runAsAccount = runAs => String(runAs || 'system').toLowerCase() === 'user' ? 'user' : 'system';
export const gitStamp = description => /\[git ([0-9a-f]{7,40})\b/i.exec(description || '')?.[1] || null;

export function driftReasons(repo, intune) {
  const r = [];
  const m = repo.meta || {};
  if (scriptHash(repo.detect) !== scriptHash(decodeIntuneScript(intune.detectionScriptContent))) r.push('detect.ps1 differs');
  if (scriptHash(repo.remediate) !== scriptHash(decodeIntuneScript(intune.remediationScriptContent))) r.push('remediate.ps1 differs');
  if (m.publisher && m.publisher !== intune.publisher) r.push('publisher differs');
  if (runAsAccount(m.runAs) !== String(intune.runAsAccount || '').toLowerCase()) r.push('runAs differs');
  if (Boolean(m.runAs32Bit) !== Boolean(intune.runAs32Bit)) r.push('runAs32Bit differs');
  if (Boolean(m.enforceSignatureCheck) !== Boolean(intune.enforceSignatureCheck)) r.push('enforceSignatureCheck differs');
  return r;
}

const summaryCols = s => ({
  withoutIssues: s?.noIssueDetectedDeviceCount ?? null,
  issueFixed: s?.issueRemediatedDeviceCount ?? null,
  issueRecurred: s?.issueReoccurredDeviceCount ?? null,
  errors: s == null ? null : (s.detectionScriptErrorDeviceCount || 0) + (s.remediationScriptErrorDeviceCount || 0),
  pending: s?.detectionScriptPendingDeviceCount ?? null,
  lastRun: s?.lastScriptRunDateTime ?? null,
});

// repoItems: [{folder, meta, metaError, detect, remediate}], intuneScripts: deviceHealthScripts (with content),
// summaries: Map(id -> runSummary). One row per remediation; the drift status lives only here.
export function buildCatalog({ repoItems, intuneScripts, summaries = new Map(), repoSha = null }) {
  const byName = new Map();
  for (const s of intuneScripts) {
    const k = (s.displayName || '').toLowerCase();
    if (!byName.has(k)) byName.set(k, []);
    byName.get(k).push(s);
  }
  const rows = [];
  const used = new Set();
  for (const item of repoItems) {
    const name = item.meta?.displayName || item.folder;
    const matches = byName.get(name.toLowerCase()) || [];
    const base = { name, folder: item.folder, inRepo: true, repoSha };
    if (item.metaError) { rows.push({ ...base, status: 'Invalid in repo', reasons: [item.metaError], ...summaryCols(null) }); continue; }
    if (matches.length === 0) { rows.push({ ...base, status: 'Not in Intune', reasons: [], ...summaryCols(null), publisher: item.meta.publisher || null, enforceSignatureCheck: Boolean(item.meta.enforceSignatureCheck) }); continue; }
    matches.forEach(s => used.add(s.id));
    if (matches.length > 1) { rows.push({ ...base, status: 'Duplicate in Intune', reasons: [`${matches.length} Intune scripts named '${name}'`], intuneId: matches.map(s => s.id).join(', '), ...summaryCols(null) }); continue; }
    const s = matches[0];
    const reasons = driftReasons(item, s);
    rows.push({ ...base, status: reasons.length ? 'Drift' : 'In sync', reasons, ...intuneCols(s), ...summaryCols(summaries.get(s.id)) });
  }
  for (const s of intuneScripts) {
    if (used.has(s.id)) continue;
    rows.push({ name: s.displayName, folder: null, inRepo: false, status: 'Intune only', reasons: [], ...intuneCols(s), ...summaryCols(summaries.get(s.id)) });
  }
  return rows.sort((a, b) => a.name.localeCompare(b.name));
}
function intuneCols(s) {
  return { intuneId: s.id, version: s.version ?? null, publisher: s.publisher ?? null, runAs: s.runAsAccount ?? null, runAs32Bit: Boolean(s.runAs32Bit),
    enforceSignatureCheck: Boolean(s.enforceSignatureCheck), publishedGit: gitStamp(s.description), lastModified: s.lastModifiedDateTime ?? null };
}

// Fleet: one row per device per remediation (deviceRunStates).
export function runOutcome(st) {
  const d = String(st.detectionState || '').toLowerCase();
  const r = String(st.remediationState || '').toLowerCase();
  if (d === 'pending') return 'Pending';
  if (d === 'scripterror' || r === 'scripterror' || r === 'remediationfailed') return 'Failed';
  if (r === 'success') return 'Issue fixed';
  if (d === 'fail') return 'Issue detected';
  if (d === 'success') return 'Without issues';
  if (d === 'notapplicable') return 'Not applicable';
  return 'Unknown';
}
export function fleetRows(scriptName, scriptId, states) {
  return states.map(st => ({
    device: st.managedDevice?.deviceName || st.managedDeviceId || st.id,
    user: st.managedDevice?.userPrincipalName || null,
    os: st.managedDevice?.osVersion || null,
    remediation: scriptName, intuneId: scriptId,
    outcome: runOutcome(st), detection: st.detectionState || null, remediationState: st.remediationState || null,
    lastUpdate: st.lastStateUpdateDateTime || null, lastSync: st.lastSyncDateTime || null,
    output: st.postRemediationDetectionScriptOutput || st.preRemediationDetectionScriptOutput || '',
    error: st.remediationScriptError || st.preRemediationDetectionScriptError || st.postRemediationDetectionScriptError || '',
  }));
}
