import { createHash } from 'node:crypto';
import { gitStamp } from './catalog.mjs';
import { ALL_DEVICES, graphTargets, groupsOf, isGuid, targetOfAssignments, targetOfGraph, targetKey, cleanName } from './target.mjs';

// Intune Remediations (deviceHealthScripts) writes, as the signed-in user: the caller passes the delegated r360-write token.
// There is no app-only path in this file. Graph beta, same endpoints and bodies as tools/Publish-Remediation.ps1 in the
// remediations repo, so the CLI and r360 produce the same object.
export const GRAPH_HOST = 'https://graph.microsoft.com';
export const HS = '/beta/deviceManagement/deviceHealthScripts';
const GROUP_SELECT = 'id,displayName,description,securityEnabled,mailEnabled,groupTypes,membershipRule';

export const sha256Hex = buf => createHash('sha256').update(buf).digest('hex');
const b64 = buf => Buffer.from(buf).toString('base64');
const clean = m => String(m ?? '').replace(/https?:\/\/\S+/g, '').replace(/Bearer\s+\S+/gi, '').replace(/\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]*/g, '').replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 200);

export class GraphWriteError extends Error {
  constructor(message, { status, code, requestId, what } = {}) { super(message); this.status = status; this.code = code; this.graphRequestId = requestId; this.what = what; }
}

// The description Intune shows. "[git <sha8>" first so the Remediations page can read the published commit back.
const bit = s => String(s ?? '').replace(/[\[\];\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 80) || 'unknown';
export function descriptionStamp({ description, mergeSha, authorUpn, approverUpn, publisherUpn, selfApproved, provenanceNone, mode, soakOverride = null, target = null, targetName = null }) {
  const base = `${description} [git ${String(mergeSha).slice(0, 8)} by ${bit(authorUpn)}; approved by ${bit(approverUpn)}; published by ${bit(publisherUpn)} via r360]`;
  // A promotion also records where it went, so the Intune page says it without opening r360.
  // targetName: one name for a single group, or an array (same order as the group ids) for several.
  const names = Array.isArray(targetName) ? targetName : [targetName];
  const to = !target ? '' : target.kind === ALL_DEVICES ? ' [promoted to All devices]'
    : target.kind === 'groups' ? ` [promoted to ${target.groupIds.length} groups: ${target.groupIds.map((id, i) => `${bit(names[i] || id)} ${id}`).join(', ')}]`
    : ` [promoted to group ${bit(names[0] || target.groupId)} ${target.groupId}]`;
  const ov = soakOverride ? ` [SOAK OVERRIDE: ${Number(soakOverride.days) || 0} of ${Number(soakOverride.required) || 0} days, reason in the r360 audit trail]` : '';
  return base + to + ov + (selfApproved ? ` [self-approved, ${mode || 'testing'} mode]` : '') + (provenanceNone ? ` [provenance: none, admin override, ${mode || 'testing'} mode]` : '');
}

// Same mapping as the CLI: hourly, daily, once.
export function scheduleOf(s) {
  const type = s?.type;
  if (type === 'hourly') return { '@odata.type': '#microsoft.graph.deviceHealthScriptHourlySchedule', interval: Number(s.interval) };
  if (type === 'daily') return { '@odata.type': '#microsoft.graph.deviceHealthScriptDailySchedule', interval: Number(s.interval), time: s.time || '02:00:00', useUtc: Boolean(s.useUtc) };
  if (type === 'once') return { '@odata.type': '#microsoft.graph.deviceHealthScriptRunOnceSchedule', interval: 1, date: s.date, time: s.time || '02:00:00', useUtc: Boolean(s.useUtc) };
  throw new Error(`Unknown schedule type "${type}"`);
}

// Everything that goes to Graph, from the verified artifact bytes only. detect/remediate are Buffers (signed scripts, byte for byte).
// The target is { kind: 'group', groupId }, { kind: 'groups', groupIds } or { kind: 'allDevices' }; a bare groupId is still accepted.
// One assignment per group (same schedule and settings), all sent in a single assign call.
export function buildDesired({ meta, detect, remediate, description, groupId, target = null }) {
  const t = target || { kind: 'group', groupId };
  if (t.kind === ALL_DEVICES) { /* the built-in All devices target has no group */ }
  else if (!['group', 'groups'].includes(t.kind) || !groupsOf(t).length || !groupsOf(t).every(isGuid)) throw new Error('assignment.groupId is not a real group');
  return {
    script: {
      displayName: meta.displayName, description, publisher: meta.publisher, runAsAccount: meta.runAs === 'user' ? 'user' : 'system', runAs32Bit: Boolean(meta.runAs32Bit),
      enforceSignatureCheck: true, detectionScriptContent: b64(detect), remediationScriptContent: b64(remediate),
    },
    assign: { deviceHealthScriptAssignments: graphTargets(t).map(target => ({
      target,
      runRemediationScript: meta.assignment?.runRemediationScript !== false,
      runSchedule: scheduleOf(meta.schedule),
    })) },
    hashes: { detect: sha256Hex(detect), remediate: sha256Hex(remediate) },
  };
}

const t8 = t => String(t ?? '').slice(0, 8);
const normSched = s => s && ({ type: String(s['@odata.type'] || '').replace('#microsoft.graph.deviceHealthScript', '').replace('Schedule', '').toLowerCase(), interval: Number(s.interval), time: s.time == null ? null : t8(s.time), date: s.date == null ? null : String(s.date).slice(0, 10), useUtc: s.useUtc == null ? null : Boolean(s.useUtc) });
const decode = c => (c ? Buffer.from(c, 'base64') : null);

// What differs between what Intune holds and what we would publish. [] means identical (so a second publish does nothing).
export function intuneDiff({ existing, assignments, desired, mergeSha, groupLabel = 'canary' }) {
  const p = [];
  if (!existing) return ['not in Intune'];
  const want = desired.script;
  const stamp = gitStamp(existing.description);
  if (!stamp || stamp.length < 8 || !String(mergeSha).startsWith(stamp)) p.push('the published git commit differs');
  if (existing.description !== want.description) p.push('the description differs');
  if (existing.publisher !== want.publisher) p.push('publisher differs');
  if (String(existing.runAsAccount || '').toLowerCase() !== want.runAsAccount) p.push('runAs differs');
  if (Boolean(existing.runAs32Bit) !== want.runAs32Bit) p.push('runAs32Bit differs');
  if (existing.enforceSignatureCheck !== true) p.push('enforceSignatureCheck is not true');
  const d = decode(existing.detectionScriptContent), r = decode(existing.remediationScriptContent);
  if (!d || sha256Hex(d) !== desired.hashes.detect) p.push('detect.ps1 is not the signed artifact');
  if (!r || sha256Hex(r) !== desired.hashes.remediate) p.push('remediate.ps1 is not the signed artifact');
  // The assignments must be exactly the desired target set: same targets, no more, no fewer, each with the desired schedule.
  const wantList = desired.assign.deviceHealthScriptAssignments;
  const wantT = targetOfAssignments(wantList);
  const list = assignments || [];
  const have = targetOfAssignments(list);
  if (list.length !== wantList.length) p.push(`${list.length} assignments instead of exactly ${wantList.length === 1 ? 'one' : wantList.length}`);
  else if (!have || targetKey(have) !== targetKey(wantT)) {
    p.push(wantT?.kind === ALL_DEVICES ? 'not assigned to All devices only'
      : wantT?.kind === 'groups' ? `not assigned to exactly the ${wantT.groupIds.length} chosen groups`
      : `not assigned to the ${groupLabel} group only`);
  }
  // Intune reads runRemediationScript back as false even when written true (seen live Oct 27, 2026), so it is not compared.
  const wantSched = JSON.stringify(normSched(wantList[0]?.runSchedule));
  if (list.some(a => JSON.stringify(normSched(a.runSchedule)) !== wantSched)) p.push('the schedule differs');
  return p;
}

export function createIntune({ fetcher = fetch, sleep = ms => new Promise(r => setTimeout(r, ms)), maxRetries = 4 } = {}) {
  // headers: extra request headers; they may override the default Accept ($count only answers text/plain, HTTP 415 otherwise).
  // retryOn: statuses that are safe to repeat for this call. 429 means "not processed", so it is safe for every method;
  // 503/504 only for calls that are idempotent (reads, PATCH, assign), never for create.
  async function request(token, method, path, body, { retryOn = [429, 503, 504], what = 'Graph call', headers = {} } = {}) {
    const url = path.startsWith('https://') ? path : `${GRAPH_HOST}${path}`;
    if (new URL(url).origin !== GRAPH_HOST) throw new GraphWriteError('Refusing a non-Graph URL', { what });
    for (let attempt = 0; ; attempt++) {
      const res = await fetcher(url, { method, headers: { Accept: 'application/json', ...headers, Authorization: `Bearer ${token}`, ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}), redirect: 'error', signal: AbortSignal.timeout(30000) });
      const requestId = res.headers?.get?.('request-id') || res.headers?.get?.('client-request-id') || undefined;
      if (retryOn.includes(res.status) && attempt < maxRetries) {
        const ra = Number(res.headers?.get?.('retry-after'));
        await sleep(Math.min(Number.isFinite(ra) && ra > 0 ? ra * 1000 : 2 ** attempt * 1000, 30000));
        continue;
      }
      let json = null;
      const text = res.status === 204 ? '' : await res.text().catch(() => '');
      if (text) { try { json = JSON.parse(text); } catch { json = null; } }
      if (!res.ok) {
        const code = json?.error?.code ? String(json.error.code).replace(/[^\w.]/g, '').slice(0, 60) : undefined;
        const msg = clean(json?.error?.message);
        throw new GraphWriteError(`${what} failed: HTTP ${res.status}${code ? ` ${code}` : ''}${msg ? `: ${msg}` : ''}`, { status: res.status, code, requestId, what });
      }
      return { json, requestId, status: res.status };
    }
  }
  // One scope per publish, so Graph request ids of concurrent publishes never mix.
  const scope = () => {
  const ids = [];
  const track = r => { if (r.requestId) { ids.push(r.requestId); if (ids.length > 50) ids.shift(); } return r; };
  return {
    requestIds: () => ids.slice(),
    // All scripts with this name (case-insensitive), paged through the whole list like the CLI does.
    async findByName(token, displayName) {
      const out = [];
      let next = `${HS}?$select=id,displayName,version`;
      for (let pages = 0; next && pages < 50; pages++) {
        const r = track(await request(token, 'GET', next, undefined, { what: 'Read Intune remediations' }));
        out.push(...(r.json?.value || []));
        next = r.json?.['@odata.nextLink'] || null;
        if (next && !next.startsWith(`${GRAPH_HOST}/`)) throw new GraphWriteError('Unexpected nextLink host', { what: 'Read Intune remediations' });
      }
      return out.filter(s => String(s.displayName || '').toLowerCase() === String(displayName).toLowerCase());
    },
    async read(token, id) {
      const [s, a] = await Promise.all([
        request(token, 'GET', `${HS}/${encodeURIComponent(id)}`, undefined, { what: 'Read the Intune remediation' }),
        request(token, 'GET', `${HS}/${encodeURIComponent(id)}/assignments`, undefined, { what: 'Read the Intune assignment' }),
      ]);
      track(s); track(a);
      return { script: s.json, assignments: a.json?.value || [], requestId: s.requestId };
    },
    // Run evidence for the soak gate (reads only). Same shapes the Fleet page reads.
    async runSummary(token, id) {
      const r = track(await request(token, 'GET', `${HS}/${encodeURIComponent(id)}/runSummary`, undefined, { what: 'Read the Intune run summary' }));
      return r.json || null;
    },
    async runStates(token, id) {
      const out = [];
      let next = `${HS}/${encodeURIComponent(id)}/deviceRunStates?$expand=managedDevice($select=deviceName,userPrincipalName,osVersion)&$top=200`;
      for (let pages = 0; next && pages < 50; pages++) {
        const r = track(await request(token, 'GET', next, undefined, { what: 'Read the Intune device run states' }));
        out.push(...(r.json?.value || []));
        next = r.json?.['@odata.nextLink'] || null;
        if (next && !next.startsWith(`${GRAPH_HOST}/`)) throw new GraphWriteError('Unexpected nextLink host', { what: 'Read the Intune device run states' });
      }
      return out;
    },
    // Entra groups, read as the signed-in user (delegated, GroupMember.Read.All). Reads only. Counts are best effort: null when Graph will not say.
    async getGroup(token, id) {
      if (!isGuid(id)) throw new GraphWriteError('Invalid group id', { what: 'Read the Entra group' });
      try {
        const r = track(await request(token, 'GET', `/v1.0/groups/${id}?$select=${GROUP_SELECT}`, undefined, { what: 'Read the Entra group' }));
        return r.json || null;
      } catch (e) { if (e instanceof GraphWriteError && e.status === 404) return null; throw e; }
    },
    async searchGroups(token, text, { top = 10 } = {}) {
      const q = cleanName(String(text ?? '').replace(/["\\]/g, ' '), 64);
      if (q.length < 2) return [];
      const url = `/v1.0/groups?$search=${encodeURIComponent(`"displayName:${q}"`)}&$select=${GROUP_SELECT}&$top=${Math.min(Math.max(1, top), 25)}`;
      const r = track(await request(token, 'GET', url, undefined, { what: 'Search Entra groups', headers: { ConsistencyLevel: 'eventual' } }));
      return Array.isArray(r.json?.value) ? r.json.value : [];
    },
    async groupCounts(token, id) {
      if (!isGuid(id)) return { deviceCount: null, memberCount: null };
      const one = async path => {
        try { const r = track(await request(token, 'GET', `/v1.0/groups/${id}/transitiveMembers${path}/$count`, undefined, { what: 'Count the Entra group members', headers: { ConsistencyLevel: 'eventual', Accept: 'text/plain' } })); const n = Number(r.json); return Number.isFinite(n) ? n : null; }
        catch { return null; }
      };
      const [deviceCount, memberCount] = await Promise.all([one('/microsoft.graph.device'), one('')]);
      return { deviceCount, memberCount };
    },
    async create(token, body) { const r = track(await request(token, 'POST', HS, body, { retryOn: [429], what: 'Create the Intune remediation' })); return { id: r.json?.id, requestId: r.requestId }; },
    async update(token, id, body) { const r = track(await request(token, 'PATCH', `${HS}/${encodeURIComponent(id)}`, body, { what: 'Update the Intune remediation' })); return { requestId: r.requestId }; },
    async assign(token, id, body) { const r = track(await request(token, 'POST', `${HS}/${encodeURIComponent(id)}/assign`, body, { what: 'Assign the Intune remediation' })); return { requestId: r.requestId }; },
  };
  };
  return { ...scope(), scope };
}