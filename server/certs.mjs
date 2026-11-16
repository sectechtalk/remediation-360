import { createHash } from 'node:crypto';

// Pure logic: code-signing certificate deployment through the two Intune profiles.
export const sha1Thumbprint = b64 => b64 ? createHash('sha1').update(Buffer.from(b64, 'base64')).digest('hex').toUpperCase() : null;

export function profileCertCheck(profile, thumbprint) {
  const want = thumbprint.toUpperCase();
  if (!profile) return { found: false, matches: false, detail: 'profile not found' };
  const type = profile['@odata.type'] || '';
  if (/TrustedRootCertificate$/i.test(type)) {
    const tp = sha1Thumbprint(profile.trustedRootCertificate);
    return { found: true, matches: tp === want, detail: tp ? `certificate ${tp}` : 'certificate not returned', store: profile.destinationStore || null };
  }
  const oma = (profile.omaSettings || []).filter(o => /TrustedPublisher/i.test(o.omaUri || ''));
  if (!oma.length) return { found: true, matches: false, detail: 'no TrustedPublisher OMA-URI setting' };
  const hit = oma.find(o => (o.omaUri || '').toUpperCase().includes(want));
  return { found: true, matches: Boolean(hit), detail: hit ? hit.omaUri : `OMA-URI ${oma.map(o => o.omaUri).join(', ')}` };
}

// The two code-signing profiles must reach every device a remediation is assigned to, or enforceSignatureCheck fails there.
// Given a profile's current assignments and the remediation's target ({kind:'group'|'groups'|'allDevices'}), returns what is
// missing and the full assignment list to POST to .../assign (Intune replaces the whole list, so existing ones are kept as is).
// Additive only: nothing is ever removed. A target group that the profile excludes is reported, never overridden.
const OD_GROUP = '#microsoft.graph.groupAssignmentTarget';
const OD_EXCL = '#microsoft.graph.exclusionGroupAssignmentTarget';
const OD_ALL = '#microsoft.graph.allDevicesAssignmentTarget';
export function widenProfileAssignments(assignments, target) {
  const targets = (assignments || []).map(a => a?.target).filter(t => t && typeof t === 'object');
  const type = t => String(t['@odata.type'] || '');
  const gid = t => String(t.groupId || '').toLowerCase();
  const hasAll = targets.some(t => type(t) === OD_ALL);
  const included = new Set(targets.filter(t => type(t) === OD_GROUP).map(gid));
  const excluded = new Set(targets.filter(t => type(t) === OD_EXCL).map(gid));
  const want = target?.kind === 'allDevices' ? [] : target?.kind === 'group' ? [String(target.groupId).toLowerCase()] : target?.kind === 'groups' ? target.groupIds.map(g => String(g).toLowerCase()) : null;
  if (!want) throw new Error('widenProfileAssignments: unknown target');
  const blocked = want.filter(g => excluded.has(g));
  if (target.kind === 'allDevices') {
    if (hasAll) return { covered: true, added: [], blocked, next: null };
    return { covered: false, added: ['allDevices'], blocked, next: [...targets, { '@odata.type': OD_ALL }].map(t => ({ target: t })) };
  }
  const missing = hasAll ? [] : want.filter(g => !included.has(g));
  if (!missing.length) return { covered: blocked.length === 0, added: [], blocked, next: null };
  return { covered: false, added: missing, blocked, next: [...targets, ...missing.map(groupId => ({ '@odata.type': OD_GROUP, groupId }))].map(t => ({ target: t })) };
}

const OK = ['compliant', 'remediated', 'succeeded'];
export function certDeviceRows(profileLabel, statuses) {
  return statuses.map(s => ({
    device: s.deviceDisplayName || s.id, user: s.userPrincipalName || null, profile: profileLabel,
    status: s.status || 'unknown', deployed: OK.includes(String(s.status || '').toLowerCase()), lastReported: s.lastReportedDateTime || null,
  }));
}
