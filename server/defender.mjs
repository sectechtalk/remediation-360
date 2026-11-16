// Microsoft Defender for Endpoint, delegated: every call uses the signed-in approver's own r360-write token for the
// Defender resource (no application permission, no secret). r360-write already carries the WindowsDefenderATP delegated
// scopes with admin consent (New-R360AppRegistration.ps1). The user also needs a Defender role that allows the action
// ("Active remediation actions") and access to the device's device group; Defender enforces both.
//
// Token audience is the legacy resource api.securitycenter.microsoft.com (Microsoft: a token for any other audience gets
// 403 even on the new host); calls go to api.security.microsoft.com.
export const DEFENDER_RESOURCE = 'https://api.securitycenter.microsoft.com';
export const DEFENDER_API = 'https://api.security.microsoft.com/api';
export const DEFENDER_SCOPES = ['Machine.Read', 'Machine.Isolate', 'Machine.Scan', 'Machine.CollectForensics', 'Machine.RestrictExecution', 'Machine.StopAndQuarantine']
  .map(s => `${DEFENDER_RESOURCE}/${s}`);

// The actions r360 offers. `plan` is the lowest Defender plan that includes the action (Microsoft Learn,
// respond-machine-alerts): P1 = Defender for Endpoint Plan 1, MDB = Defender for Business, P2 = Plan 2.
// `release` names the action that undoes this one, so the page can offer it once this one has run.
export const ACTIONS = Object.freeze({
  isolate: { label: 'Isolate from the network', path: 'isolate', plans: ['P1', 'MDB', 'P2'], release: 'unisolate',
    params: { isolationType: { values: ['Full', 'Selective'], default: 'Full', field: 'IsolationType' } },
    about: 'Cuts the PC off the network except for Defender itself. Full blocks everything; Selective keeps Outlook, Teams and Skype working.' },
  unisolate: { label: 'Release from isolation', path: 'unisolate', plans: ['P1', 'MDB', 'P2'], releases: 'isolate',
    about: 'Gives the PC its network back.' },
  scan: { label: 'Run antivirus scan', path: 'runAntiVirusScan', plans: ['P1', 'MDB', 'P2'],
    params: { scanType: { values: ['Quick', 'Full'], default: 'Quick', field: 'ScanType' } },
    about: 'Starts a Microsoft Defender Antivirus scan. Quick takes minutes; Full can take hours.' },
  quarantine: { label: 'Stop and quarantine a file', path: 'StopAndQuarantineFile', plans: ['P1', 'P2'],
    params: { sha1: { pattern: /^[0-9a-f]{40}$/i, field: 'Sha1', required: true } },
    about: 'Stops the file if it is running and deletes it, by SHA-1. Not in Defender for Business. Microsoft-signed files are refused.' },
  collect: { label: 'Collect investigation package', path: 'collectInvestigationPackage', plans: ['P2'],
    about: 'Gathers logs, processes, network connections and more from the PC into a package you download from the Defender portal.' },
  restrict: { label: 'Restrict app execution', path: 'restrictCodeExecution', plans: ['P2'], release: 'unrestrict',
    about: 'Lets only Microsoft-signed programs run on the PC.' },
  unrestrict: { label: 'Remove app restriction', path: 'unrestrictCodeExecution', plans: ['P2'], releases: 'restrict',
    about: 'Lets all programs run again.' },
});
export const ACTION_IDS = Object.keys(ACTIONS);

// Validates the operator's choices and returns the exact Defender request body. Throws a message a person can act on.
export function actionBody(actionId, params = {}, comment = '') {
  const a = ACTIONS[actionId];
  if (!a) throw Object.assign(new Error('Choose one of the listed actions.'), { expose: true, status: 400 });
  const text = String(comment || '').trim();
  if (text.length < 10) throw Object.assign(new Error('Give a reason of at least 10 characters. It goes into Defender and the audit trail.'), { expose: true, status: 400 });
  const body = { Comment: text.slice(0, 900) };
  const clean = {};
  for (const [key, spec] of Object.entries(a.params || {})) {
    let v = params?.[key];
    if (v === undefined || v === null || v === '') v = spec.default;
    if (v === undefined) { if (spec.required) throw Object.assign(new Error(`${key} is required for ${a.label}.`), { expose: true, status: 400 }); continue; }
    v = String(v).trim();
    if (spec.values && !spec.values.includes(v)) throw Object.assign(new Error(`${key} must be ${spec.values.join(' or ')}.`), { expose: true, status: 400 });
    if (spec.pattern && !spec.pattern.test(v)) throw Object.assign(new Error(`${key} is not valid (expected a 40-character SHA-1).`), { expose: true, status: 400 });
    body[spec.field] = spec.pattern ? v.toLowerCase() : v;
    clean[key] = body[spec.field];
  }
  return { body, params: clean };
}

const MACHINE_ID = /^[0-9a-f]{40}$/i;
const ACTION_GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const isMachineId = v => MACHINE_ID.test(String(v || ''));
export const pickMachine = m => ({ id: m.id, name: m.computerDnsName || m.id, os: [m.osPlatform, m.version].filter(Boolean).join(' '), health: m.healthStatus || '',
  onboarding: m.onboardingStatus || '', lastSeen: m.lastSeen || null, group: m.rbacGroupName || '', aadDeviceId: m.aadDeviceId || null, riskScore: m.riskScore || '', exposureLevel: m.exposureLevel || '' });
export const pickAction = a => ({ id: a.id, type: a.type, status: a.status, machineId: a.machineId, computerDnsName: a.computerDnsName || '', requestor: a.requestor || '',
  created: a.creationDateTimeUtc || null, updated: a.lastUpdateDateTimeUtc || null, comment: a.requestorComment || '', error: a.errorHResult || 0 });
export const FINAL_STATUSES = ['Succeeded', 'Failed', 'TimeOut', 'Cancelled'];

export function createDefender({ fetcher = fetch } = {}) {
  const call = async (token, method, path, body) => {
    let res;
    try {
      res = await fetcher(`${DEFENDER_API}${path}`, { method, redirect: 'error', signal: AbortSignal.timeout(30000),
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/json', ...(body ? { 'Content-Type': 'application/json' } : {}) }, body: body ? JSON.stringify(body) : undefined });
    } catch (e) { throw Object.assign(new Error(`Defender could not be reached: ${e.message}`), { expose: true, status: 502 }); }
    const text = await res.text();
    let json = {};
    try { json = text ? JSON.parse(text) : {}; } catch { /* not JSON */ }
    if (!res.ok) {
      const msg = json?.error?.message || text.slice(0, 200).replace(/\s+/g, ' ') || `HTTP ${res.status}`;
      const hint = res.status === 401 ? ' Your Defender sign-in was refused. End the write session and elevate again.'
        : res.status === 403 ? ' Defender refused: you need a Defender role with "Active remediation actions" (and "View data") that covers this device\'s device group, and the tenant needs a Defender for Endpoint or Defender for Business license.'
          : res.status === 404 ? ' Defender does not know this device or action.' : '';
      throw Object.assign(new Error(`Defender: ${msg}.${hint}`.replace('..', '.')), { expose: true, status: res.status === 400 || res.status === 404 ? res.status : 502, defenderStatus: res.status, requestId: res.headers.get('request-id') || undefined });
    }
    return json;
  };
  return {
    async findMachines(token, q) {
      const name = String(q || '').trim();
      if (!/^[A-Za-z0-9][A-Za-z0-9._-]{1,62}$/.test(name)) throw Object.assign(new Error('Type at least 2 letters of the device name (letters, digits, dot, dash, underscore).'), { expose: true, status: 400 });
      const filter = encodeURIComponent(`startswith(computerDnsName,'${name.toLowerCase()}')`);
      const j = await call(token, 'GET', `/machines?$filter=${filter}&$top=10`);
      return (j.value || []).map(pickMachine);
    },
    async machine(token, id) {
      if (!isMachineId(id)) throw Object.assign(new Error('That is not a Defender device id.'), { expose: true, status: 400 });
      return pickMachine(await call(token, 'GET', `/machines/${id}`));
    },
    async run(token, machineId, actionId, body) {
      if (!isMachineId(machineId)) throw Object.assign(new Error('That is not a Defender device id.'), { expose: true, status: 400 });
      const a = ACTIONS[actionId];
      if (!a) throw Object.assign(new Error('Unknown action.'), { expose: true, status: 400 });
      return pickAction(await call(token, 'POST', `/machines/${machineId}/${a.path}`, body));
    },
    async action(token, id) {
      if (!ACTION_GUID.test(String(id || ''))) throw Object.assign(new Error('That is not a Defender action id.'), { expose: true, status: 400 });
      return pickAction(await call(token, 'GET', `/machineactions/${id}`));
    },
    // Readiness: one cheap read that proves the token, the consent, the license and the View data role at once.
    async probe(token) { await call(token, 'GET', '/machines?$top=1'); return true; },
  };
}
