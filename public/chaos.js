// Chaos Monkey templates. HeatMap 360's Chaos Monkey page links here with #new/chaos-<ID>?from=heatmap-360,
// one link per hardening test, and the New remediation form opens filled in from the template below. r360 still does
// every write itself: you review the form and press Create pull request, and the usual approve, sign, publish path follows.
// detect.ps1 is the real test (chaos/tests/<ID>.ps1 plus the helpers it needs from chaos/lib.ps1, built into
// chaos-scripts.js, loaded only when a Chaos Monkey link is opened). It only reads: PASS exits 0; FAIL and COULD NOT TEST exit 1, so a machine is never shown as hardened
// unless the test proved it. remediate.ps1 never changes anything and "Run remediation script" stays off.
import { CHAOS_TESTS } from './chaos-list.js';
export { CHAOS_TESTS };
const TIER = { probe: "Active probe", local: "Configuration check: this machine", ad: "Configuration check: AD objects" };
const ps = s => String(s).replace(/'/g, "''"); // inside a single-quoted PowerShell string

// "chaos-N1?from=heatmap-360" -> the filled-in form for test N1, or null when the link names no known test.
export async function chaosPreset(arg) {
  const m = /^chaos-([A-Z]\d{1,2})(?:\?(.*))?$/.exec(String(arg || ""));
  if (!m) return null;
  const t = CHAOS_TESTS.find(x => x[0] === m[1]);
  if (!t) return null;
  const [id, tier, group, name, proves] = t;
  const from = new URLSearchParams(m[2] || "").get("from") === "heatmap-360" ? "HeatMap 360" : null;
  const displayName = `STT - Chaos - ${id} ${name}`;
  const { CHAOS_DETECT } = await import('./chaos-scripts.js');
  const detect = CHAOS_DETECT[id] || [
    `# ${displayName}`,
    "# The test script for this id is missing from chaos-scripts.js. It exits 1 so it can never report a machine as hardened.",
    `Write-Output 'NOT BUILT: ${ps(id)} ${ps(name)}'`,
    "exit 1",
    "",
  ].join("\n");
  const remediate = [
    `# ${displayName}`,
    "# Chaos Monkey tests never remediate. 'Run remediation script' is off, and this script changes nothing.",
    "Write-Output 'Chaos Monkey tests never change anything.'",
    "exit 0",
    "",
  ].join("\n");
  return {
    id, from, folder: `Chaos-${id}`,
    meta: {
      displayName, description: `Chaos Monkey test ${id} (${TIER[tier]}, ${group}). Proves: ${proves} Test only, never remediates.`,
      publisher: "SecTechTalk", runAs: "system", runAs32Bit: false, enforceSignatureCheck: true,
      schedule: { type: "daily", interval: 1, time: "02:00:00" }, assignment: { runRemediationScript: false },
    },
    detect, remediate,
  };
}

// Pressing "Create r360 change" in HeatMap creates the change without a second press here. r360 only does that when the
// link really came from HeatMap's Chaos Monkey page on this computer (the browser's referrer, which another site cannot
// fake), so a link from anywhere else just opens the filled-in form. The go-ahead is kept for this tab only, for 15
// minutes, so it survives sign-in and Elevate to write, and is used once. The create itself is the normal one: your
// write session, the CSRF token, the audit trail and the canary group.
export const CHAOS_SOURCES = ['http://localhost:3460', 'http://127.0.0.1:3460'];
export const CHAOS_AUTO_KEY = 'r360:chaos-auto';
const AUTO_MS = 15 * 60 * 1000;
export function markChaosAuto(hash, referrer, storage, now = Date.now()) {
  const m = /^#new\/chaos-([A-Z]\d{1,2})\?(.*)$/.exec(String(hash || ''));
  if (!m || new URLSearchParams(m[2]).get('from') !== 'heatmap-360' || !CHAOS_TESTS.some(t => t[0] === m[1])) return false;
  let origin = null;
  try { origin = new URL(referrer).origin; } catch { return false; }
  if (!CHAOS_SOURCES.includes(origin)) return false;
  storage.setItem(CHAOS_AUTO_KEY, JSON.stringify({ id: m[1], at: now }));
  return true;
}
// True once, when the go-ahead for this test is there and fresh. Any other go-ahead is dropped.
export function takeChaosAuto(id, storage, now = Date.now()) {
  let v = null;
  try { v = JSON.parse(storage.getItem(CHAOS_AUTO_KEY) || 'null'); } catch { /* bad value: treated as none */ }
  storage.removeItem(CHAOS_AUTO_KEY);
  return !!v && v.id === id && typeof v.at === 'number' && now - v.at >= 0 && now - v.at < AUTO_MS;
}
