import { randomBytes } from 'node:crypto';
import { ChangeError } from './changes.mjs';

// Offboard requests: end one person's access in Entra and push it to their SCIM apps now, instead of waiting for the next
// provisioning cycle (about 40 minutes). Federation 360 (f-360) finds what the person can reach and opens this page with
// the request filled in; r360 does the writes, as the signed-in operator, with the operator's own delegated token from the
// write session. f-360 stays read-only and verifies afterwards.
//
// Two request types:
//   disable  Disable user everywhere: disable the account, revoke sign-in sessions, Provision on demand in every SCIM app
//            the person is assigned to (the app receives active=false), then re-read the account to verify.
//   remove   Remove from one app: delete the person's direct assignment to that app, Provision on demand in that app (the
//            app disables or deletes them, per its scoping), then re-read the assignments to verify.
//
// Four-eyes is off by default (R360_OFFBOARD_FOUR_EYES=off): the requester runs the request at once. With "on", the
// request waits for a different person with the emergencyApprover role, who runs it.
//
// The audit trail is the only store, as for Emergency. "No audit, no action": each write is preceded by an audit row.
//   offboard.requested  requester, type, user, apps, reason                 (state: pending)
//   offboard.approved   who runs it (the requester when four-eyes is off)    (state: running)
//   offboard.step       one step's result (ok / failed / skipped / action needed)
//   offboard.completed  overall result: ok, partial or failed                (state: done / partial / failed)
//   offboard.cancelled  the requester withdrew it, or an approver rejected it
//   offboard.denied     a refused attempt; changes nothing
export const OFFBOARD_ACTIONS = ['offboard.requested', 'offboard.approved', 'offboard.step', 'offboard.completed', 'offboard.cancelled', 'offboard.denied'];
export const RUN_ROLES = ['emergencyApprover', 'admin'];
export const APPROVE_ROLES = ['emergencyApprover'];
export const TYPES = Object.freeze({
  disable: { label: 'Disable user everywhere', about: 'Disables the account, revokes every sign-in session (refresh tokens stop working at once), then runs Provision on demand in each SCIM app the person is assigned to so the app disables them now. Access tokens already issued keep working until they expire (up to 90 minutes), except in Microsoft 365 apps that support CAE.' },
  remove: { label: 'Remove from one app', about: 'Removes the person\'s direct assignment to one app, then runs Provision on demand in that app so it disables or deletes them now. Access through a group is reported, not changed: remove them from the group in Entra.' },
});
export const LIST_DAYS = 30;
const ID = /^OFB-[0-9a-f]{8}$/;
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const UPN = /^[A-Za-z0-9._%+'#-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;
const MAX_APPS = 50;
export const GRAPH = 'https://graph.microsoft.com/v1.0';
// Delegated Microsoft Graph scopes on r360-write for this page. The signed-in operator also needs an Entra role:
// User Administrator for ordinary users, Privileged Authentication Administrator to disable an admin account, and
// Application Administrator (or Cloud Application Administrator) for Provision on demand and assignment removal.
export const OFFBOARD_SCOPES = ['User.Read.All', 'User.EnableDisableAccount.All', 'User.RevokeSessions.All', 'Synchronization.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All']
  .map(s => `https://graph.microsoft.com/${s}`);

const parse = v => { if (!v) return {}; if (typeof v === 'object') return v; try { return JSON.parse(v); } catch { return {}; } };
export const isUserRef = v => UPN.test(String(v || '')) || GUID.test(String(v || ''));

// Validates a request body. Returns the clean request; throws a message a person can act on.
export function checkRequest(body) {
  const type = String(body?.type || '');
  if (!TYPES[type]) throw new ChangeError(400, 'Choose Disable user everywhere or Remove from one app.');
  const user = String(body?.user || '').trim();
  if (!isUserRef(user)) throw new ChangeError(400, 'Give the person\'s full sign-in name (for example someone@contoso.com) or their object ID.');
  const reason = String(body?.reason || '').trim();
  if (reason.length < 10) throw new ChangeError(400, 'Give a reason of at least 10 characters. It goes into the audit trail.');
  const apps = [];
  for (const a of Array.isArray(body?.apps) ? body.apps : []) {
    const spId = String(a?.spId || '').trim();
    if (!GUID.test(spId)) throw new ChangeError(400, 'Each app needs its service principal (enterprise application) object ID.');
    if (!apps.some(x => x.spId.toLowerCase() === spId.toLowerCase())) apps.push({ spId: spId.toLowerCase(), name: String(a?.name || '').trim().slice(0, 120) });
  }
  if (apps.length > MAX_APPS) throw new ChangeError(400, `At most ${MAX_APPS} apps per request.`);
  if (type === 'remove' && apps.length !== 1) throw new ChangeError(400, 'Remove from one app needs exactly one app.');
  return { type, user, reason: reason.slice(0, 900), apps, source: String(body?.source || '').slice(0, 40) };
}

// Pure: audit rows (any order) -> one record per request, newest first.
export function foldOffboards(rows) {
  const byId = new Map();
  const sorted = [...rows].filter(r => ID.test(r.requestId || '')).sort((a, b) => Date.parse(a.at) - Date.parse(b.at));
  for (const r of sorted) {
    const d = parse(r.detail);
    let o = byId.get(r.requestId);
    if (r.action === 'offboard.requested') {
      if (o) continue;
      o = { id: r.requestId, state: 'pending', requestedAt: r.at, requesterOid: r.actorOid, requesterUpn: r.actorUpn, reason: r.reason || '', type: d.type,
        typeLabel: TYPES[d.type]?.label || d.type, user: d.user, apps: d.apps || [], source: d.source || '', steps: [], events: [] };
      byId.set(r.requestId, o);
    }
    if (!o) continue;
    o.events.push({ at: r.at, action: r.action, actorUpn: r.actorUpn, result: r.result, reason: r.reason || '' });
    if (r.action === 'offboard.approved' && o.state === 'pending') { o.state = 'running'; o.runBy = r.actorUpn; o.runAt = r.at; o.selfApproved = r.selfApproved === true; }
    if (r.action === 'offboard.step') o.steps.push({ at: r.at, step: d.step, app: d.app || '', result: r.result, text: r.reason || '' });
    if (r.action === 'offboard.completed' && o.state === 'running') { o.state = r.result === 'ok' ? 'done' : r.result === 'partial' ? 'partial' : 'failed'; o.finishedAt = r.at; o.summary = r.reason || ''; o.userId = d.userId || o.userId; }
    if (r.action === 'offboard.cancelled' && o.state === 'pending') { o.state = 'cancelled'; o.closedBy = r.actorUpn; o.closedReason = r.reason || ''; }
  }
  return [...byId.values()].sort((a, b) => Date.parse(b.requestedAt) - Date.parse(a.requestedAt));
}

// Microsoft Graph writes as the operator. Every error explains what to fix.
export function createEntraWriter({ fetcher = fetch } = {}) {
  const call = async (token, method, path, body) => {
    let res;
    try {
      res = await fetcher(`${GRAPH}${path}`, { method, redirect: 'error', signal: AbortSignal.timeout(60000),
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/json', ...(body ? { 'Content-Type': 'application/json' } : {}) }, body: body ? JSON.stringify(body) : undefined });
    } catch (e) { throw Object.assign(new Error(`Microsoft Graph could not be reached: ${e.message}`), { status: 502 }); }
    if (res.status === 204) return {};
    const text = await res.text();
    let json = {};
    try { json = text ? JSON.parse(text) : {}; } catch { /* not JSON */ }
    if (!res.ok) {
      const code = json?.error?.code || '';
      const msg = json?.error?.message || `HTTP ${res.status}`;
      const hint = res.status === 403 ? (method === 'PATCH' ? ' To disable an admin account you need Privileged Authentication Administrator; for other users, User Administrator.' : ' Your Entra role or r360-write\'s consent does not allow this. Check the permissions on the Offboard page.')
        : res.status === 404 ? ' Entra does not know this object.' : '';
      throw Object.assign(new Error(`Graph ${res.status}${code ? ` ${code}` : ''}: ${msg}.${hint}`.replace('..', '.')), { status: res.status, code });
    }
    return json;
  };
  const all = async (token, path) => {
    const out = [];
    let next = path;
    while (next) {
      const j = await call(token, 'GET', next);
      out.push(...(j.value || []));
      const link = j['@odata.nextLink'];
      next = link && link.startsWith(`${GRAPH}/`) ? link.slice(GRAPH.length) : null;
    }
    return out;
  };
  return {
    user: (t, ref) => call(t, 'GET', `/users/${encodeURIComponent(ref)}?$select=id,displayName,userPrincipalName,accountEnabled,signInSessionsValidFromDateTime`),
    disable: (t, id) => call(t, 'PATCH', `/users/${id}`, { accountEnabled: false }),
    revoke: (t, id) => call(t, 'POST', `/users/${id}/revokeSignInSessions`),
    assignments: (t, id) => all(t, `/users/${id}/appRoleAssignments?$top=999`),
    removeAssignment: (t, userId, assignmentId) => call(t, 'DELETE', `/users/${userId}/appRoleAssignments/${encodeURIComponent(assignmentId)}`),
    servicePrincipal: (t, spId) => call(t, 'GET', `/servicePrincipals/${spId}?$select=id,appId,displayName`),
    jobs: (t, spId) => all(t, `/servicePrincipals/${spId}/synchronization/jobs`),
    schema: (t, spId, jobId) => call(t, 'GET', `/servicePrincipals/${spId}/synchronization/jobs/${encodeURIComponent(jobId)}/schema`),
    provisionOnDemand: (t, spId, jobId, ruleId, userId) => call(t, 'POST', `/servicePrincipals/${spId}/synchronization/jobs/${encodeURIComponent(jobId)}/provisionOnDemand`,
      { parameters: [{ ruleId, subjects: [{ objectId: userId, objectTypeName: 'User' }] }] }),
  };
}

// The synchronization rule that provisions Entra users (Provision on demand needs its id).
export function userRuleId(schema) {
  const rules = schema?.synchronizationRules || [];
  const r = rules.find(x => (x.objectMappings || []).some(m => /^user$/i.test(m.sourceObjectName || '') && m.enabled !== false)) || rules[0];
  return r?.id || '';
}

// Provision on demand answers with a JSON string per step; reduce it to success or the first failure.
export function onDemandOutcome(resp) {
  const values = Array.isArray(resp?.value) ? resp.value : [resp];
  const steps = [];
  for (const v of values) {
    const body = parse(v?.value);
    for (const s of body?.provisioningSteps || body?.steps || []) steps.push({ name: s.name || s.stepName || '', status: String(s.status || s.result || ''), description: s.description || '' });
    if (body?.result || body?.status) steps.push({ name: 'result', status: String(body.result || body.status), description: body.details || body.description || '' });
  }
  const failed = steps.find(s => /fail|error/i.test(s.status));
  if (failed) return { ok: false, text: `${failed.name || 'A step'} failed${failed.description ? `: ${String(failed.description).slice(0, 300)}` : ''}` };
  const skipped = steps.find(s => /skip/i.test(s.status));
  return { ok: true, text: skipped ? `Done; Entra skipped a step (${skipped.name}${skipped.description ? `: ${String(skipped.description).slice(0, 200)}` : ''})` : 'Provision on demand finished without errors' };
}

// The operator's token, with the reason shown to them when Entra refuses it (no consent, session gone).
const tokenOf = async token => { try { return await token(); } catch (e) { throw new ChangeError(e.status === 403 ? 403 : 502, e.message); } };

export function createOffboard({ config, audit, entra, now = () => Date.now(), log = console }) {
  const fourEyesOn = config.offboardFourEyes === 'on';
  const who = u => ({ actorOid: u.oid, actorUpn: u.upn });
  const inflight = new Set();
  const intent = async event => {
    try { return await audit.record(event); }
    catch (e) { log.error?.(`${event.action}: audit failed: ${e.message}`); throw new ChangeError(503, 'The audit trail is unavailable, so nothing was done.'); }
  };
  const after = async event => { try { await audit.record(event); } catch (e) { log.error?.(`${event.action}: audit failed after the fact: ${e.message}`); } };
  const all = async () => {
    let rows;
    try { rows = (await audit.list({ from: now() - LIST_DAYS * 86400000, to: now(), actions: OFFBOARD_ACTIONS, limit: 3000 })).rows; }
    catch (e) { log.error?.(`offboard list: ${e.message}`); throw new ChangeError(503, 'The audit trail could not be read, so offboard requests cannot be shown or run.'); }
    return foldOffboards(rows);
  };
  const one = async id => {
    if (!ID.test(String(id || ''))) throw new ChangeError(404, 'No such offboard request.');
    const o = (await all()).find(x => x.id === id);
    if (!o) throw new ChangeError(404, `No offboard request ${id} in the last ${LIST_DAYS} days.`);
    return o;
  };

  // Provision on demand for one app: every job on the service principal, with its user rule.
  async function pushToApp(t, o, userId, app) {
    const name = app.name || app.spId;
    let jobs;
    try { jobs = await entra.jobs(t, app.spId); }
    catch (e) { return { result: 'failed', text: `Could not read the provisioning job: ${e.message}` }; }
    if (!jobs.length) return { result: 'skipped', text: 'This app has no SCIM provisioning job, so nothing can be pushed. Its own session decides when access ends.' };
    const texts = [];
    let failed = false;
    for (const j of jobs) {
      if (j.status?.code === 'Paused' || j.schedule?.state === 'Disabled') { texts.push(`job ${j.templateId || j.id} is stopped (Provision on demand still runs)`); }
      try {
        const rule = userRuleId(await entra.schema(t, app.spId, j.id));
        if (!rule) { failed = true; texts.push(`job ${j.templateId || j.id}: no user rule in its schema`); continue; }
        const out = onDemandOutcome(await entra.provisionOnDemand(t, app.spId, j.id, rule, userId));
        if (!out.ok) failed = true;
        texts.push(out.text);
      } catch (e) { failed = true; texts.push(e.message); }
    }
    return { result: failed ? 'failed' : 'ok', text: `${name}: ${texts.join('; ')}` };
  }

  async function execute(user, o, t) {
    const step = async (stepName, res, app = '') => {
      await after({ ...who(user), action: 'offboard.step', result: res.result, requestId: o.id, target: `user:${o.user}`, reason: res.text, detail: { step: stepName, app } });
      return { step: stepName, app, ...res };
    };
    const results = [];
    let account;
    try { account = await entra.user(t, o.user); }
    catch (e) {
      results.push(await step('find-user', { result: 'failed', text: e.message }));
      await after({ ...who(user), action: 'offboard.completed', result: 'failed', requestId: o.id, target: `user:${o.user}`, reason: 'The person could not be found, so nothing was changed.' });
      return { state: 'failed', steps: results };
    }
    const uid = account.id;
    const startedAt = now();
    let apps = o.apps;

    if (o.type === 'disable') {
      try { await entra.disable(t, uid); results.push(await step('disable', { result: 'ok', text: account.accountEnabled === false ? 'The account was already disabled; set again.' : 'Account disabled.' })); }
      catch (e) { results.push(await step('disable', { result: 'failed', text: e.message })); }
      try { await entra.revoke(t, uid); results.push(await step('revoke', { result: 'ok', text: 'Sign-in sessions revoked: refresh tokens no longer work.' })); }
      catch (e) { results.push(await step('revoke', { result: 'failed', text: e.message })); }
      // Every app the person is assigned to directly; f-360's list adds apps reached through groups.
      try {
        for (const a of await entra.assignments(t, uid)) {
          if (!apps.some(x => x.spId === String(a.resourceId).toLowerCase())) apps = [...apps, { spId: String(a.resourceId).toLowerCase(), name: a.resourceDisplayName || '' }];
        }
      } catch (e) { results.push(await step('list-apps', { result: 'failed', text: `Direct assignments could not be read: ${e.message}` })); }
      for (const app of apps) results.push(await step('provision', await pushToApp(t, o, uid, app), app.name || app.spId));
      try {
        const after2 = await entra.user(t, uid);
        const revoked = after2.signInSessionsValidFromDateTime && Date.parse(after2.signInSessionsValidFromDateTime) >= startedAt - 5 * 60000;
        const ok = after2.accountEnabled === false && revoked;
        results.push(await step('verify', { result: ok ? 'ok' : 'failed', text: `Re-read: account ${after2.accountEnabled === false ? 'disabled' : 'STILL ENABLED'}, sessions valid from ${after2.signInSessionsValidFromDateTime || 'unknown'}${revoked ? '' : ' (not revoked yet)'}.` }));
      } catch (e) { results.push(await step('verify', { result: 'failed', text: `Could not re-read the account: ${e.message}` })); }
    } else {
      const app = apps[0];
      let direct = [];
      try {
        direct = (await entra.assignments(t, uid)).filter(a => String(a.resourceId).toLowerCase() === app.spId);
        if (!direct.length) results.push(await step('remove', { result: 'action', text: `${app.name || app.spId}: no direct assignment. Access comes through a group: remove them from that group in Entra (Groups > the group > Members).` }, app.name));
        for (const a of direct) {
          await entra.removeAssignment(t, uid, a.id);
          results.push(await step('remove', { result: 'ok', text: `Removed the direct assignment to ${a.resourceDisplayName || app.name || app.spId}.` }, app.name));
        }
      } catch (e) { results.push(await step('remove', { result: 'failed', text: e.message }, app.name)); }
      results.push(await step('provision', await pushToApp(t, o, uid, app), app.name || app.spId));
      try {
        const left = (await entra.assignments(t, uid)).filter(a => String(a.resourceId).toLowerCase() === app.spId);
        results.push(await step('verify', { result: left.length ? 'failed' : 'ok', text: left.length ? `Re-read: still ${left.length} direct assignment(s) to ${app.name || app.spId}.` : `Re-read: no direct assignment to ${app.name || app.spId} remains.` }, app.name));
      } catch (e) { results.push(await step('verify', { result: 'failed', text: `Could not re-read the assignments: ${e.message}` }, app.name)); }
    }

    const failed = results.filter(r => r.result === 'failed').length;
    const action = results.filter(r => r.result === 'action').length;
    const overall = failed === results.length ? 'failed' : failed || action ? 'partial' : 'ok';
    const summary = overall === 'ok' ? 'Every step finished and the re-read confirms it.' : `${failed} step(s) failed${action ? `, ${action} need you to act` : ''}. See the steps.`;
    await after({ ...who(user), action: 'offboard.completed', result: overall, requestId: o.id, target: `user:${o.user}`, reason: summary, detail: { userId: uid } });
    return { state: overall === 'ok' ? 'done' : overall, steps: results, summary };
  }

  async function run(user, o, token) {
    if (inflight.has(o.id)) throw new ChangeError(409, 'This request is running right now.');
    inflight.add(o.id);
    try {
      const t = await tokenOf(token);
      const self = o.requesterOid === user.oid;
      await intent({ ...who(user), action: 'offboard.approved', result: 'ok', requestId: o.id, target: `user:${o.user}`, approverOid: user.oid, selfApproved: fourEyesOn ? false : self,
        mode: fourEyesOn ? 'on' : 'off', reason: fourEyesOn ? 'approved by a second person' : 'four-eyes off: run by the requester' });
      return { id: o.id, ...(await execute(user, { ...o }, t)) };
    } finally { inflight.delete(o.id); }
  }

  return {
    fourEyes: fourEyesOn ? 'on' : 'off',
    async list() {
      return { items: await all(), fourEyes: fourEyesOn ? 'on' : 'off', types: TYPES, scopes: OFFBOARD_SCOPES.map(s => s.replace('https://graph.microsoft.com/', '')) };
    },
    // Reads the person as the operator: proves the token, the consent and that the person exists, before anything is asked.
    async preview(token, ref) {
      if (!isUserRef(ref)) throw new ChangeError(400, 'Give the person\'s full sign-in name or object ID.');
      const t = await tokenOf(token);
      const u = await entra.user(t, ref).catch(e => { throw new ChangeError(e.status === 404 ? 404 : 502, e.status === 404 ? `No user ${ref} in this tenant.` : e.message); });
      const assigned = await entra.assignments(t, u.id).catch(() => null);
      return { user: { id: u.id, upn: u.userPrincipalName, name: u.displayName, enabled: u.accountEnabled !== false, sessionsValidFrom: u.signInSessionsValidFromDateTime || null },
        assignments: assigned ? assigned.map(a => ({ spId: String(a.resourceId).toLowerCase(), name: a.resourceDisplayName || '' })) : null };
    },
    async request(user, body, { token }) {
      const req = checkRequest(body);
      const open = (await all()).find(x => x.user.toLowerCase() === req.user.toLowerCase() && x.type === req.type && ['pending', 'running'].includes(x.state));
      if (open) throw new ChangeError(409, `${open.id} already asks to ${open.typeLabel.toLowerCase()} for ${open.user}. Run or cancel that one first.`);
      const id = `OFB-${randomBytes(4).toString('hex')}`;
      await intent({ ...who(user), action: 'offboard.requested', result: 'ok', requestId: id, target: `user:${req.user}`, reason: req.reason, detail: { type: req.type, user: req.user, apps: req.apps, source: req.source } });
      const o = { id, state: 'pending', requesterOid: user.oid, requesterUpn: user.upn, ...req };
      if (fourEyesOn) return { id, state: 'pending', fourEyes: 'on', message: `${id} is waiting for a second person with the emergencyApprover role.` };
      return run(user, o, token);
    },
    async approve(user, roles, id, { token }) {
      const o = await one(id);
      if (o.state !== 'pending') throw new ChangeError(409, `${id} is ${o.state}, so it cannot be run.`);
      if (fourEyesOn) {
        if (!roles.some(r => APPROVE_ROLES.includes(r))) throw new ChangeError(403, 'Only an emergencyApprover can run someone else\'s offboard request.');
        if (o.requesterOid === user.oid) {
          await after({ ...who(user), action: 'offboard.denied', result: 'denied', requestId: id, target: `user:${o.user}`, reason: 'four-eyes on: requester cannot run their own request' });
          throw new ChangeError(403, 'Four-eyes is on for offboarding: a different person must run this request.');
        }
      }
      return run(user, o, token);
    },
    async cancel(user, roles, id, body) {
      const o = await one(id);
      if (o.state !== 'pending') throw new ChangeError(409, `${id} is ${o.state}, so it cannot be cancelled.`);
      if (o.requesterOid !== user.oid && !roles.some(r => APPROVE_ROLES.includes(r))) throw new ChangeError(403, 'Only the requester or an emergencyApprover can cancel this.');
      await intent({ ...who(user), action: 'offboard.cancelled', result: 'ok', requestId: id, target: `user:${o.user}`, reason: String(body?.reason || '').trim().slice(0, 500) || 'cancelled' });
      return { id, state: 'cancelled' };
    },
  };
}
