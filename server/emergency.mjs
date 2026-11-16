import { randomBytes } from 'node:crypto';
import { ChangeError } from './changes.mjs';
import { fourEyes } from './foureyes.mjs';
import { ACTIONS, actionBody, isMachineId, FINAL_STATUSES } from './defender.mjs';

// The fast path (design section 8, Track 1): a Defender response action on ONE device, requested by one person and
// approved by a second within the emergency window, then run immediately AS THE APPROVER with their own delegated
// Defender token. Every step is written to the audit trail before anything happens ("no audit, no action"), and the
// audit trail is also where the state lives: there is no other store to drift from it.
//
//   emergency.requested  requester, device, action, reason, expiry          (state: pending)
//   emergency.cancelled  the requester withdrew it                          (state: cancelled)
//   emergency.rejected   an approver said no                                (state: rejected)
//   emergency.approved   intent row, written before Defender is called      (state: approved)
//   emergency.executed   Defender accepted it; machine action id + status   (state: running)
//   emergency.failed     Defender refused or could not be reached           (state: failed)
//   emergency.result     the machine action reached a final status          (state: succeeded / failed / timed out / cancelled)
//   emergency.denied     a refused attempt (four-eyes, expired, wrong state); recorded, changes nothing
export const EMERGENCY_ACTIONS = ['emergency.requested', 'emergency.cancelled', 'emergency.rejected', 'emergency.approved', 'emergency.executed',
  'emergency.failed', 'emergency.result', 'emergency.denied'];
export const REQUEST_ROLES = ['author', 'emergencyApprover', 'admin'];
export const APPROVE_ROLES = ['emergencyApprover'];
export const LIST_DAYS = 14;
const ID = /^EMG-[0-9a-f]{8}$/;

const parse = v => { if (!v) return {}; if (typeof v === 'object') return v; try { return JSON.parse(v); } catch { return {}; } };

// Pure: audit rows (any order) -> one record per emergency, newest first.
export function foldEmergencies(rows, { now = Date.now() } = {}) {
  const byId = new Map();
  const sorted = [...rows].filter(r => ID.test(r.requestId || '')).sort((a, b) => Date.parse(a.at) - Date.parse(b.at));
  for (const r of sorted) {
    const d = parse(r.detail);
    let e = byId.get(r.requestId);
    if (r.action === 'emergency.requested') {
      if (e) continue; // first request row wins
      e = { id: r.requestId, state: 'pending', requestedAt: r.at, requesterOid: r.actorOid, requesterUpn: r.actorUpn, reason: r.reason || '',
        machineId: d.machineId, device: d.device, action: d.action, actionLabel: ACTIONS[d.action]?.label || d.action, params: d.params || {},
        expiresAt: d.expiresAt, events: [] };
      byId.set(r.requestId, e);
    }
    if (!e) continue;
    e.events.push({ at: r.at, action: r.action, actorUpn: r.actorUpn, result: r.result, reason: r.reason || '', detail: d });
    const step = { 'emergency.cancelled': 'cancelled', 'emergency.rejected': 'rejected', 'emergency.approved': 'approved', 'emergency.executed': 'running', 'emergency.failed': 'failed' }[r.action];
    if (step && (e.state === 'pending' || (e.state === 'approved' && ['running', 'failed'].includes(step)))) {
      e.state = step;
      if (r.action === 'emergency.approved') { e.approverOid = r.approverOid || r.actorOid; e.approverUpn = r.actorUpn; e.approvedAt = r.at; e.selfApproved = r.selfApproved === true; }
      if (r.action === 'emergency.executed') { e.machineActionId = d.machineActionId; e.defenderStatus = d.status; }
      if (r.action === 'emergency.failed') e.error = r.reason || d.error || '';
      if (r.action === 'emergency.rejected' || r.action === 'emergency.cancelled') { e.closedBy = r.actorUpn; e.closedReason = r.reason || ''; }
    }
    if (r.action === 'emergency.result' && e.state === 'running') {
      e.defenderStatus = d.status;
      e.state = d.status === 'Succeeded' ? 'succeeded' : d.status === 'TimeOut' ? 'timed out' : d.status === 'Cancelled' ? 'cancelled in Defender' : 'failed';
    }
  }
  const out = [...byId.values()];
  for (const e of out) if (e.state === 'pending' && Date.parse(e.expiresAt) <= now) e.state = 'expired';
  return out.sort((a, b) => Date.parse(b.requestedAt) - Date.parse(a.requestedAt));
}

export function createEmergency({ config, audit, defender, now = () => Date.now(), log = console }) {
  const windowMin = Number.isInteger(config.emergencyWindowMinutes) && config.emergencyWindowMinutes >= 5 && config.emergencyWindowMinutes <= 1440 ? config.emergencyWindowMinutes : 240;
  const who = u => ({ actorOid: u.oid, actorUpn: u.upn });
  const inflight = new Set();
  const intent = async event => {
    try { return await audit.record(event); }
    catch (e) { log.error?.(`${event.action}: audit failed: ${e.message}`); throw new ChangeError(503, 'The audit trail is unavailable, so nothing was done.'); }
  };
  const after = async event => { try { await audit.record(event); } catch (e) { log.error?.(`${event.action}: audit failed after the fact: ${e.message}`); } };
  const deny = async (user, e, reason, message, status = 409) => {
    await after({ ...who(user), action: 'emergency.denied', result: 'denied', requestId: e?.id, target: e ? `device:${e.device}` : undefined, reason });
    throw new ChangeError(status, message);
  };
  const all = async () => {
    let rows;
    try { rows = (await audit.list({ from: now() - LIST_DAYS * 86400000, to: now(), actions: EMERGENCY_ACTIONS, limit: 2000 })).rows; }
    catch (e) { log.error?.(`emergency list: ${e.message}`); throw new ChangeError(503, 'The audit trail could not be read, so emergency requests cannot be shown or acted on.'); }
    return foldEmergencies(rows, { now: now() });
  };
  const one = async id => {
    if (!ID.test(String(id || ''))) throw new ChangeError(404, 'No such emergency request.');
    const e = (await all()).find(x => x.id === id);
    if (!e) throw new ChangeError(404, `No emergency request ${id} in the last ${LIST_DAYS} days.`);
    return e;
  };
  const view = e => ({ ...e, events: e.events.map(({ detail, ...rest }) => rest) });

  return {
    windowMinutes: windowMin,
    async list() {
      const items = await all();
      return { items: items.map(view), windowMinutes: windowMin, maxDevices: 1, fourEyes: config.fourEyes, actions: Object.fromEntries(Object.entries(ACTIONS).map(([k, a]) => [k, { label: a.label, about: a.about, plans: a.plans, release: a.release || null, releases: a.releases || null, params: Object.fromEntries(Object.entries(a.params || {}).map(([p, s]) => [p, { values: s.values || null, default: s.default || null, required: Boolean(s.required) }])) }])) };
    },
    async readiness(token) {
      try { await defender.probe(await token()); return { ok: true, text: 'Defender answered with your sign-in. You can search devices and act on them.' }; }
      catch (e) { return { ok: false, text: e.message }; }
    },
    async machines(token, q) { return { items: await defender.findMachines(await token(), q) }; },

    // One device per request (R360_EMERGENCY_MAX_DEVICES is 1 by design; the API takes exactly one machine id).
    async request(user, body, { token }) {
      const { machineId, action, params, reason } = body || {};
      if (!isMachineId(machineId)) throw new ChangeError(400, 'Pick one device from the search results.');
      let built;
      try { built = actionBody(action, params, reason); } catch (e) { throw new ChangeError(400, e.message); }
      const machine = await defender.machine(await token(), machineId).catch(e => { throw new ChangeError(e.status === 400 || e.status === 404 ? 400 : 502, e.message); });
      const open = (await all()).find(x => x.machineId === machineId && x.action === action && ['pending', 'approved'].includes(x.state));
      if (open) throw new ChangeError(409, `${open.id} already asks for "${open.actionLabel}" on ${open.device}. Approve, reject or cancel that one first.`);
      const id = `EMG-${randomBytes(4).toString('hex')}`;
      const at = now();
      const expiresAt = new Date(at + windowMin * 60000).toISOString();
      await intent({ ...who(user), action: 'emergency.requested', result: 'ok', requestId: id, target: `device:${machine.name}`, reason: built.body.Comment,
        detail: { machineId, device: machine.name, action, params: built.params, expiresAt, health: machine.health, group: machine.group } });
      return { id, state: 'pending', device: machine.name, action, actionLabel: ACTIONS[action].label, expiresAt };
    },

    async approve(user, id, { token }) {
      if (inflight.has(id)) throw new ChangeError(409, 'This request is being approved right now.');
      inflight.add(id);
      try {
        const e = await one(id);
        if (e.state === 'expired') await deny(user, e, 'expired', `${id} expired at ${e.expiresAt}. Ask for it again if it is still needed.`);
        if (e.state !== 'pending') await deny(user, e, 'not-pending', `${id} is ${e.state}, so it cannot be approved.`);
        const fe = fourEyes({ mode: config.fourEyes, step: 'approve', authorOid: e.requesterOid, actorOid: user.oid });
        if (!fe.allowed) await deny(user, e, fe.reason, fe.message.replace('this change', 'this emergency request'), 403);
        const built = actionBody(e.action, e.params, e.reason);
        const defToken = await token();
        await intent({ ...who(user), action: 'emergency.approved', result: 'ok', requestId: id, target: `device:${e.device}`, approverOid: user.oid, selfApproved: fe.selfApproved,
          mode: config.fourEyes, reason: fe.selfApproved ? 'self-approval-testing' : 'ok', detail: { action: e.action, machineId: e.machineId, requesterOid: e.requesterOid } });
        let result;
        try { result = await defender.run(defToken, e.machineId, e.action, built.body); }
        catch (err) {
          await after({ ...who(user), action: 'emergency.failed', result: 'failed', requestId: id, target: `device:${e.device}`, reason: String(err.message).slice(0, 500), detail: { defenderStatus: err.defenderStatus, requestId: err.requestId } });
          throw new ChangeError(502, `Approved and recorded, but Defender did not run it: ${err.message}`);
        }
        await after({ ...who(user), action: 'emergency.executed', result: 'ok', requestId: id, target: `device:${e.device}`, detail: { machineActionId: result.id, status: result.status, type: result.type } });
        return { id, state: 'running', machineActionId: result.id, defenderStatus: result.status, selfApproved: fe.selfApproved };
      } finally { inflight.delete(id); }
    },

    // An approver rejects; the requester cancels. Either closes the request.
    async close(user, roles, id, body) {
      const e = await one(id);
      const mine = e.requesterOid === user.oid;
      if (!mine && !roles.includes('emergencyApprover')) throw new ChangeError(403, 'Only the requester can cancel this, and only an emergency approver can reject it.');
      if (!['pending', 'expired'].includes(e.state)) throw new ChangeError(409, `${id} is ${e.state}, so it cannot be closed.`);
      const action = mine ? 'emergency.cancelled' : 'emergency.rejected';
      await intent({ ...who(user), action, result: 'ok', requestId: id, target: `device:${e.device}`, reason: String(body?.reason || '').trim().slice(0, 500) || (mine ? 'withdrawn by the requester' : 'rejected') });
      return { id, state: mine ? 'cancelled' : 'rejected' };
    },

    // Reads the machine action from Defender and records the final status once.
    async refresh(user, id, { token }) {
      const e = await one(id);
      if (!e.machineActionId) throw new ChangeError(409, `${id} has not run in Defender.`);
      const a = await defender.action(await token(), e.machineActionId).catch(err => { throw new ChangeError(502, err.message); });
      if (e.state === 'running' && FINAL_STATUSES.includes(a.status)) {
        await after({ ...who(user), action: 'emergency.result', result: a.status === 'Succeeded' ? 'ok' : 'failed', requestId: id, target: `device:${e.device}`, detail: { machineActionId: a.id, status: a.status, error: a.error } });
      }
      return { id, defenderStatus: a.status, updated: a.updated, final: FINAL_STATUSES.includes(a.status) };
    },
  };
}
