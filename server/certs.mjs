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

const OK = ['compliant', 'remediated', 'succeeded'];
export function certDeviceRows(profileLabel, statuses) {
  return statuses.map(s => ({
    device: s.deviceDisplayName || s.id, user: s.userPrincipalName || null, profile: profileLabel,
    status: s.status || 'unknown', deployed: OK.includes(String(s.status || '').toLowerCase()), lastReported: s.lastReportedDateTime || null,
  }));
}
