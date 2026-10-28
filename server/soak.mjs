import { runOutcome } from './catalog.mjs';

// The canary soak gate as one pure function, so the rule is tested in one place and cannot drift between the Changes tab and
// the publish route. No clock, no network: the caller passes `now` and the evidence it read.
//
// A promotion needs ALL of these:
//   published  r360 recorded a real publish of this exact commit to the canary group (the soak clock starts there)
//   newer      main holds no newer, unpublished change to this remediation
//   drift      Intune still holds exactly the signed canary content, assigned to the canary group only
//   soak       at least `soakDays` whole days since that publish
//   devices    every canary device that reported has a CLEAN state written after the publish (and the named canary device reported)
//   errors     the Intune run summary shows no script errors and no recurring issue
// Only `soak` can be overridden (with a written reason, audited and bannered). Everything else is a hard stop.
export const DAY_MS = 86400000;
export const DEFAULT_SOAK_DAYS = 7;
export const MIN_REASON = 10;
export const MAX_REASON = 500;
const CLEAN = new Set(['Without issues', 'Issue fixed']);

export const cleanReason = v => String(v ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, MAX_REASON);
export const validReason = v => cleanReason(v).length >= MIN_REASON;

export function evaluateSoak({ now, soakDays = DEFAULT_SOAK_DAYS, publishedAt = null, newerOnMain = false, driftProblems = [], alreadyPromoted = false, promotedLabel = 'the production target', runStates = null, summary = null, canaryDevice = '' }) {
  const checks = [];
  const add = (id, label, ok, detail) => checks.push({ id, label, ok: Boolean(ok), detail: detail || '' });
  const start = publishedAt == null ? NaN : Date.parse(publishedAt);
  const published = Number.isFinite(start);
  add('published', 'Published to the canary group by r360', published, published ? `Published ${new Date(start).toISOString()}.` : 'r360 has no record of a canary publish of the current version.');
  add('newer', 'No newer unpublished change on main', !newerOnMain, newerOnMain ? 'main holds a newer change to this remediation that has not been published to canary.' : '');
  add('drift', 'Intune matches the signed canary version (In sync)', !driftProblems.length && !alreadyPromoted,
    alreadyPromoted ? `Already assigned to ${promotedLabel}.` : driftProblems.join('; '));
  const elapsed = published ? Math.max(0, now - start) : 0;
  const daysSoaked = Math.floor(elapsed / DAY_MS);
  const soakMet = published && elapsed >= soakDays * DAY_MS;
  add('soak', `At least ${soakDays} canary days`, soakMet, published ? `Day ${daysSoaked} of ${soakDays}${soakMet ? '' : `, ${soakDays - daysSoaked} to go`}.` : 'The soak clock has not started.');

  // Devices: the latest state per canary device must be clean and newer than the publish.
  const states = Array.isArray(runStates) ? runStates : null;
  let devOk = false, devDetail = 'No device run states could be read.';
  if (states) {
    const rows = states.map(st => ({ device: String(st.managedDevice?.deviceName || st.managedDeviceId || st.id || 'unknown'), outcome: runOutcome(st), at: Date.parse(st.lastStateUpdateDateTime || '') }));
    const bad = rows.filter(r => !CLEAN.has(r.outcome) || (published && !(r.at >= start))).map(r => `${r.device}: ${CLEAN.has(r.outcome) ? 'last report is older than the publish' : r.outcome}`);
    const named = String(canaryDevice || '').toLowerCase();
    const missing = named && !rows.some(r => r.device.toLowerCase() === named);
    devOk = rows.length > 0 && !bad.length && !missing;
    devDetail = !rows.length ? 'No canary device has reported a run yet.' : missing ? `The canary device ${canaryDevice} has not reported.` : bad.length ? bad.slice(0, 5).join('; ') : `${rows.length} canary device(s) report clean after the publish.`;
  }
  add('devices', 'Every canary device is healthy and reported after the publish', devOk, devDetail);

  let errOk = false, errDetail = 'The Intune run summary could not be read.';
  if (summary && typeof summary === 'object') {
    const errors = (Number(summary.detectionScriptErrorDeviceCount) || 0) + (Number(summary.remediationScriptErrorDeviceCount) || 0);
    const recurred = Number(summary.issueReoccurredDeviceCount) || 0;
    errOk = errors === 0 && recurred === 0;
    errDetail = errOk ? 'No script errors and no recurring issues.' : [errors ? `${errors} device(s) with script errors` : '', recurred ? `${recurred} device(s) with a recurring issue` : ''].filter(Boolean).join('; ');
  }
  add('errors', 'Intune run summary shows 0 errors', errOk, errDetail);

  const failing = checks.filter(c => !c.ok).map(c => c.id);
  return { ready: failing.length === 0, soakMet, daysSoaked: published ? daysSoaked : 0, daysRequired: soakDays, startedAt: published ? new Date(start).toISOString() : null,
    alreadyPromoted: Boolean(alreadyPromoted), checks, failing, overridable: failing.length === 1 && failing[0] === 'soak' };
}

// Cheap, time-only view for the list (no Graph): where the clock stands for a canary publish.
export function soakClock({ now, soakDays = DEFAULT_SOAK_DAYS, publishedAt }) {
  const start = Date.parse(publishedAt || '');
  if (!Number.isFinite(start)) return null;
  const elapsed = Math.max(0, now - start);
  const days = Math.floor(elapsed / DAY_MS);
  return { startedAt: new Date(start).toISOString(), days, required: soakDays, met: elapsed >= soakDays * DAY_MS, label: elapsed >= soakDays * DAY_MS ? `Day ${days}, soak complete` : `Day ${days} of ${soakDays}` };
}
