// The assignment target of a remediation, in one place: one Entra group (assignment.groupId), several Entra groups
// (assignment.groupIds, 1..20) or Intune's built-in "All devices" (assignment.target = "allDevices"). The groupId form is the
// original one and stays valid unchanged. All devices is exclusive: it is never combined with groups.
// In memory a target is { kind: 'group', groupId } (exactly one group), { kind: 'groups', groupIds } (two or more, sorted, unique)
// or { kind: 'allDevices' }. A set of one group is always the 'group' kind, so the same set always has the same key.
// Pure functions only. Nothing here reads Graph; the server validates that each group exists before it relies on one.
export const ALL_DEVICES = 'allDevices';
export const ALL_DEVICES_LABEL = 'All devices';
export const ODATA_GROUP = '#microsoft.graph.groupAssignmentTarget';
export const ODATA_ALL_DEVICES = '#microsoft.graph.allDevicesAssignmentTarget';
export const NULL_GUID = '00000000-0000-0000-0000-000000000000';
export const MAX_GROUPS = 20;
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const isGuid = v => typeof v === 'string' && GUID.test(v) && v.toLowerCase() !== NULL_GUID;
export const ALL_DEVICES_EXCLUSIVE = 'All devices already includes every group, so it cannot be combined with groups. Choose All devices alone, or only groups.';

// A list of group ids -> a target (one group: 'group', more: 'groups'), or null if any id is invalid, duplicated, or the count is out of range.
export function groupsTarget(ids) {
  if (!Array.isArray(ids) || ids.length < 1 || ids.length > MAX_GROUPS || !ids.every(isGuid)) return null;
  const low = ids.map(x => x.toLowerCase());
  if (new Set(low).size !== low.length) return null;
  const sorted = [...low].sort();
  return sorted.length === 1 ? { kind: 'group', groupId: sorted[0] } : { kind: 'groups', groupIds: sorted };
}
// The group ids of a target ([] for All devices or nothing).
export const groupsOf = t => (t?.kind === 'group' ? [t.groupId] : t?.kind === 'groups' ? [...t.groupIds] : []);

// remediation.json assignment -> a target, or null (not exactly one valid form).
export function targetOf(assignment) {
  const a = assignment && typeof assignment === 'object' ? assignment : {};
  const forms = ['groupId', 'groupIds', 'target'].filter(k => a[k] !== undefined);
  if (forms.length !== 1) return null;
  if (forms[0] === 'groupId') return isGuid(a.groupId) ? { kind: 'group', groupId: a.groupId.toLowerCase() } : null;
  if (forms[0] === 'groupIds') return groupsTarget(a.groupIds);
  return a.target === ALL_DEVICES ? { kind: ALL_DEVICES } : null;
}

// A request body target -> a target, or { error }. Strict: no other keys.
//   { type: 'group', groupId } | { type: 'groups', groupIds: [..] } | { type: 'allDevices' }
export function parseTargetRequest(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return { error: 'Choose a target: one or more groups, or All devices.' };
  const extra = Object.keys(raw).filter(k => !['type', 'groupId', 'groupIds'].includes(k));
  if (extra.length) return { error: `Unknown field(s) in target: ${extra.join(', ')}` };
  if (raw.type === ALL_DEVICES) return raw.groupId !== undefined || raw.groupIds !== undefined ? { error: `The All devices target takes no groups. ${ALL_DEVICES_EXCLUSIVE}` } : { target: { kind: ALL_DEVICES } };
  if (raw.type === 'group') {
    if (raw.groupIds !== undefined) return { error: 'A "group" target takes groupId only. Use type "groups" for several.' };
    return isGuid(raw.groupId) ? { target: { kind: 'group', groupId: raw.groupId.toLowerCase() } } : { error: 'The target group id must be a real group GUID.' };
  }
  if (raw.type === 'groups') {
    if (raw.groupId !== undefined) return { error: 'A "groups" target takes groupIds only.' };
    const ids = raw.groupIds;
    if (!Array.isArray(ids) || ids.length < 1) return { error: 'Choose at least one group.' };
    if (ids.length > MAX_GROUPS) return { error: `Choose at most ${MAX_GROUPS} groups.` };
    if (ids.some(x => typeof x === 'string' && x.toLowerCase() === ALL_DEVICES.toLowerCase())) return { error: ALL_DEVICES_EXCLUSIVE };
    if (!ids.every(isGuid)) return { error: 'Every target group id must be a real group GUID.' };
    if (new Set(ids.map(x => x.toLowerCase())).size !== ids.length) return { error: 'A group is listed more than once.' };
    return { target: groupsTarget(ids) };
  }
  return { error: 'The target type must be "group", "groups" or "allDevices".' };
}

// A Graph assignment target -> a single target, or null for anything else (exclusion groups, all licensed users, and so on).
export function targetOfGraph(t) {
  const type = String(t?.['@odata.type'] || '').toLowerCase();
  if (type === ODATA_ALL_DEVICES.toLowerCase()) return { kind: ALL_DEVICES };
  if (type === ODATA_GROUP.toLowerCase() && isGuid(t?.groupId)) return { kind: 'group', groupId: t.groupId.toLowerCase() };
  return null;
}
// A list of Graph assignments -> the target set they form, or null when it is not a clean set: empty, an unknown target type,
// a duplicate, or All devices mixed with anything else.
export function targetOfAssignments(list) {
  const ts = (Array.isArray(list) ? list : []).map(a => targetOfGraph(a?.target));
  if (!ts.length || ts.some(t => !t)) return null;
  if (ts.some(t => t.kind === ALL_DEVICES)) return ts.length === 1 ? { kind: ALL_DEVICES } : null;
  return groupsTarget(ts.map(t => t.groupId));
}
export const graphTarget = t => (t.kind === ALL_DEVICES ? { '@odata.type': ODATA_ALL_DEVICES } : { '@odata.type': ODATA_GROUP, groupId: t.groupId });
// One Graph assignment target per group (or the single All devices target).
export const graphTargets = t => (t.kind === ALL_DEVICES ? [graphTarget(t)] : groupsOf(t).map(groupId => graphTarget({ kind: 'group', groupId })));

// The assignment object for remediation.json. Other assignment settings (runRemediationScript) are kept; the target form is replaced.
// One group is written as groupId (the original form), two or more as groupIds.
export function assignmentFor(t, previous = {}) {
  const { groupId: _g, groupIds: _gs, target: _t, ...rest } = previous && typeof previous === 'object' ? previous : {};
  if (t.kind === ALL_DEVICES) return { target: ALL_DEVICES, ...rest };
  if (t.kind === 'groups') return { groupIds: [...t.groupIds], ...rest };
  return { groupId: t.groupId, ...rest };
}
// Leaves of remediation.json that a promotion from the canary group (assignment.groupId) to this target changes, and nothing else.
export const promotionDiff = t => (t.kind === ALL_DEVICES ? 'assignment.groupId,assignment.target' : t.kind === 'groups' ? 'assignment.groupId,assignment.groupIds' : 'assignment.groupId');

export const targetKey = t => (t?.kind === ALL_DEVICES ? ALL_DEVICES : t?.kind === 'group' ? `group:${t.groupId}` : t?.kind === 'groups' ? `groups:${t.groupIds.join(',')}` : null);
export const sameTarget = (a, b) => Boolean(a && b && targetKey(a) === targetKey(b));
// True when the canary group is anywhere in the target set.
export const isCanaryTarget = (t, canaryGroupId) => Boolean(canaryGroupId && groupsOf(t).includes(String(canaryGroupId).toLowerCase()));
// True only when the target is exactly the canary group, alone (what an ordinary change may publish to).
export const isCanaryOnly = (t, canaryGroupId) => t?.kind === 'group' && isCanaryTarget(t, canaryGroupId);
// An audit/commit key back to a target ("allDevices", "group:<id>", "groups:<id>,<id>"), or null.
export function targetFromKey(key) {
  const k = String(key ?? '');
  if (k === ALL_DEVICES) return { kind: ALL_DEVICES };
  if (k.startsWith('group:')) { const t = groupsTarget([k.slice(6)]); return t; }
  if (k.startsWith('groups:')) { const t = groupsTarget(k.slice(7).split(',')); return t && targetKey(t) === k ? t : null; }
  return null;
}

// Single-line, bracket-free text that is safe in a commit message, a description stamp and a Markdown table cell.
export const cleanName = (s, max = 80) => String(s ?? '').replace(/[\[\]<>|`;\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
// name: a string for one group, or an array of names (same order as groupsOf) for several.
export function targetText(t, name) {
  if (t?.kind === ALL_DEVICES) return ALL_DEVICES_LABEL;
  if (t?.kind === 'groups') {
    const names = Array.isArray(name) ? name : [];
    return `${t.groupIds.length} groups: ${t.groupIds.map((id, i) => { const n = cleanName(names[i]); return n ? `"${n}" (${id})` : id; }).join(', ')}`;
  }
  const n = cleanName(Array.isArray(name) ? name[0] : name);
  return n ? `group "${n}" (${t.groupId})` : `group ${t?.groupId}`;
}
