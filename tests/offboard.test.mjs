import test from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { createApp } from '../server/app.mjs';
import { SessionStore, SESSION_COOKIE } from '../server/auth.mjs';
import { loadConfig } from '../server/config.mjs';
import { checkRequest, createEntraWriter, createOffboard, foldOffboards, onDemandOutcome, userRuleId, OFFBOARD_SCOPES, GRAPH } from '../server/offboard.mjs';
import { ENV } from './fixtures.mjs';

// Offboard: Disable user everywhere / Remove from one app, run as the operator, every step audited.
const AARON = { oid: '94540000-0000-4000-8000-0000000000c3', upn: 'admin@contoso.com' };
const USER1 = { oid: '0d000000-0000-4000-8000-0000000000c4', upn: 'user1@contoso.com' };
const LEAVER = 'e1a2b3c4-0000-4000-8000-100000000002';
const SP_HR = 'e1a2b3c4-0000-4000-8000-000000000007';
const SP_AWS = 'e1a2b3c4-0000-4000-8000-000000000002';
const SP_NOTES = 'e1a2b3c4-0000-4000-8000-000000000005';

function world({ fourEyes = 'off' } = {}) {
  const w = { t: Date.parse('2026-11-24T17:00:00Z'), seq: 0, events: [], calls: [] };
  w.config = loadConfig({ ...ENV, R360_OFFBOARD_FOUR_EYES: fourEyes });
  w.audit = {
    record: async e => { if (w.auditDown) throw new Error('down'); w.events.push({ ...e, at: new Date(w.t + (++w.seq) * 1000).toISOString() }); return e; },
    list: async ({ actions } = {}) => ({ rows: w.events.filter(e => !actions || actions.includes(e.action)).reverse() }),
  };
  w.user = { id: LEAVER, userPrincipalName: 'sam.leaver@contoso.example', displayName: 'Sam Leaver', accountEnabled: true, signInSessionsValidFromDateTime: '2026-01-01T00:00:00Z' };
  w.assignments = [{ id: 'as-aws', resourceId: SP_AWS, resourceDisplayName: 'AWS IAM Identity Center' }];
  w.jobs = { [SP_HR]: [{ id: 'scim.hr', templateId: 'scim' }], [SP_AWS]: [{ id: 'aws.job', templateId: 'aws' }], [SP_NOTES]: [] };
  w.entra = {
    user: async (t, ref) => { w.calls.push(['user', t, ref]); return { ...w.user }; },
    disable: async (t, id) => { w.calls.push(['disable', t, id]); if (w.disableFails) throw Object.assign(new Error('Graph 403 Authorization_RequestDenied: Insufficient privileges. To disable an admin account you need Privileged Authentication Administrator'), { status: 403 }); w.user.accountEnabled = false; },
    revoke: async (t, id) => { w.calls.push(['revoke', t, id]); w.user.signInSessionsValidFromDateTime = new Date(w.t).toISOString(); },
    assignments: async (t, id) => { w.calls.push(['assignments', t, id]); return [...w.assignments]; },
    removeAssignment: async (t, uid, aid) => { w.calls.push(['remove', t, uid, aid]); w.assignments = w.assignments.filter(a => a.id !== aid); },
    jobs: async (t, sp) => { w.calls.push(['jobs', t, sp]); return w.jobs[sp] || []; },
    schema: async (t, sp, job) => { w.calls.push(['schema', t, sp, job]); return { synchronizationRules: [{ id: `rule-${job}`, objectMappings: [{ sourceObjectName: 'User', enabled: true }] }] }; },
    provisionOnDemand: async (t, sp, job, rule, uid) => {
      w.calls.push(['pod', t, sp, job, rule, uid]);
      const result = sp === SP_HR && w.hrFails ? 'Failure' : 'Success';
      return { key: 'x', value: JSON.stringify({ result, details: result === 'Failure' ? '401 from the SCIM endpoint' : '' }) };
    },
  };
  return w;
}
const ob = w => createOffboard({ config: w.config, audit: w.audit, entra: w.entra, now: () => w.t, log: { error() {} } });
const tok = name => ({ token: async () => name });
const acts = w => w.events.map(e => e.action);

test('checkRequest: known types, a real person and reason, GUID app ids, exactly one app for remove', () => {
  const ok = checkRequest({ type: 'disable', user: 'sam.leaver@contoso.example', reason: 'Left the company today', apps: [{ spId: SP_HR.toUpperCase(), name: 'HR Hub' }, { spId: SP_HR, name: 'dup' }] });
  assert.deepEqual(ok.apps, [{ spId: SP_HR, name: 'HR Hub' }]);
  assert.throws(() => checkRequest({ type: 'delete', user: 'a@b.com', reason: 'long enough reason' }), /Disable user everywhere or Remove/);
  assert.throws(() => checkRequest({ type: 'disable', user: 'not a user', reason: 'long enough reason' }), /full sign-in name/);
  assert.throws(() => checkRequest({ type: 'disable', user: 'a@b.com', reason: 'short' }), /at least 10/);
  assert.throws(() => checkRequest({ type: 'disable', user: 'a@b.com', reason: 'long enough reason', apps: [{ spId: 'x' }] }), /object ID/);
  assert.throws(() => checkRequest({ type: 'remove', user: 'a@b.com', reason: 'long enough reason', apps: [] }), /exactly one app/);
  assert.equal(OFFBOARD_SCOPES.length, 5);
  assert.ok(OFFBOARD_SCOPES.every(s => s.startsWith('https://graph.microsoft.com/')));
});

test('Disable user everywhere (four-eyes off): runs at once, disables, revokes, provisions every SCIM app, verifies, audits each step', async () => {
  const w = world();
  const r = await ob(w).request(AARON, { type: 'disable', user: 'sam.leaver@contoso.example', reason: 'Left the company today', apps: [{ spId: SP_HR, name: 'HR Hub' }, { spId: SP_NOTES, name: 'Notes' }], source: 'federation-360' }, tok('OT'));
  assert.equal(r.state, 'done', JSON.stringify(r.steps));
  assert.deepEqual(r.steps.map(s => `${s.step}:${s.result}`), ['disable:ok', 'revoke:ok', 'provision:ok', 'provision:skipped', 'provision:ok', 'verify:ok']);
  // AWS was added from the direct assignments; each SCIM job got Provision on demand with its user rule.
  assert.deepEqual(w.calls.filter(c => c[0] === 'pod').map(c => [c[2], c[3], c[4], c[5]]), [[SP_HR, 'scim.hr', 'rule-scim.hr', LEAVER], [SP_AWS, 'aws.job', 'rule-aws.job', LEAVER]]);
  assert.ok(w.calls.every(c => c[1] === 'OT'), 'every Graph call uses the operator token');
  assert.deepEqual(acts(w).slice(0, 2), ['offboard.requested', 'offboard.approved']);
  assert.equal(acts(w).at(-1), 'offboard.completed');
  assert.equal(w.events.find(e => e.action === 'offboard.approved').selfApproved, true);
  const [item] = (await ob(w).list()).items;
  assert.equal(item.state, 'done');
  assert.equal(item.steps.length, 6);
  assert.equal(item.source, 'federation-360');
});

test('a failed SCIM push or a refused disable makes the request partial, with the reason', async () => {
  const w = world();
  w.hrFails = true;
  w.disableFails = true;
  const r = await ob(w).request(AARON, { type: 'disable', user: 'sam.leaver@contoso.example', reason: 'Left the company today', apps: [{ spId: SP_HR, name: 'HR Hub' }] }, tok('OT'));
  assert.equal(r.state, 'partial');
  assert.match(r.steps.find(s => s.step === 'disable').text, /Privileged Authentication Administrator/);
  assert.match(r.steps.find(s => s.app === 'HR Hub').text, /401 from the SCIM endpoint/);
  assert.equal(r.steps.find(s => s.step === 'verify').result, 'failed', 'the re-read shows the account is still enabled');
});

test('Remove from one app: deletes the direct assignment, provisions that app, verifies; group-only access needs the operator', async () => {
  const w = world();
  const r = await ob(w).request(AARON, { type: 'remove', user: 'sam.leaver@contoso.example', reason: 'Moved to another team', apps: [{ spId: SP_AWS, name: 'AWS IAM Identity Center' }] }, tok('OT'));
  assert.equal(r.state, 'done');
  assert.deepEqual(w.calls.find(c => c[0] === 'remove'), ['remove', 'OT', LEAVER, 'as-aws']);
  assert.equal(w.calls.some(c => c[0] === 'disable' || c[0] === 'revoke'), false, 'remove never disables the account');
  const g = await ob(w).request(AARON, { type: 'remove', user: 'sam.leaver@contoso.example', reason: 'Moved to another team', apps: [{ spId: SP_HR, name: 'HR Hub' }] }, tok('OT'));
  assert.equal(g.state, 'partial');
  assert.match(g.steps[0].text, /through a group/);
});

test('four-eyes on: the request waits; the requester cannot run it; a second emergencyApprover can; cancel works', async () => {
  const w = world({ fourEyes: 'on' });
  const o = ob(w);
  const r = await o.request(AARON, { type: 'disable', user: 'sam.leaver@contoso.example', reason: 'Left the company today' }, tok('A'));
  assert.equal(r.state, 'pending');
  assert.equal(w.calls.length, 0, 'nothing touched Entra yet');
  await assert.rejects(o.request(AARON, { type: 'disable', user: 'SAM.LEAVER@contoso.example', reason: 'Asking a second time' }, tok('A')), /already asks/);
  await assert.rejects(o.approve(AARON, ['emergencyApprover'], r.id, tok('A')), /different person/);
  assert.ok(acts(w).includes('offboard.denied'));
  await assert.rejects(o.approve(USER1, ['admin'], r.id, tok('U')), /Only an emergencyApprover/);
  const ran = await o.approve(USER1, ['emergencyApprover'], r.id, tok('U'));
  assert.equal(ran.state, 'done');
  assert.ok(w.calls.every(c => c[1] === 'U'), 'run with the approver\'s token');
  await assert.rejects(o.approve(USER1, ['emergencyApprover'], r.id, tok('U')), /is done/);
  const c = await o.request(AARON, { type: 'remove', user: 'kai@contoso.example', reason: 'Moved to another team', apps: [{ spId: SP_AWS }] }, tok('A'));
  assert.equal((await o.cancel(AARON, [], c.id, {})).state, 'cancelled');
});

test('no audit, no action; an unknown person changes nothing', async () => {
  const w = world();
  w.auditDown = true;
  await assert.rejects(ob(w).request(AARON, { type: 'disable', user: 'sam.leaver@contoso.example', reason: 'Left the company today' }, tok('OT')), /audit trail is unavailable/);
  assert.equal(w.calls.length, 0);
  const w2 = world();
  w2.entra.user = async () => { throw Object.assign(new Error('Graph 404'), { status: 404 }); };
  const r = await ob(w2).request(AARON, { type: 'disable', user: 'ghost@contoso.example', reason: 'Left the company today' }, tok('OT'));
  assert.equal(r.state, 'failed');
  assert.equal(w2.calls.length, 0);
  const w3 = world();
  await assert.rejects(ob(w3).request(AARON, { type: 'disable', user: 'sam.leaver@contoso.example', reason: 'Left the company today' }, { token: async () => { throw Object.assign(new Error('r360-write has no admin consent for the offboard permissions yet.'), { status: 403 }); } }), err => err.status === 403 && /admin consent/.test(err.message));
});

test('Entra writer: exact Graph calls and bodies, 403 explains the role', async () => {
  const seen = [];
  const e = createEntraWriter({ fetcher: async (url, init) => {
    seen.push({ url, method: init.method, body: init.body && JSON.parse(init.body), auth: init.headers.Authorization });
    if (init.method === 'PATCH' && url.includes('admin')) return new Response('{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges"}}', { status: 403 });
    return init.method === 'GET' ? new Response('{"value":[]}', { status: 200 }) : new Response(null, { status: 204 });
  } });
  await e.disable('T', LEAVER);
  await e.revoke('T', LEAVER);
  await e.removeAssignment('T', LEAVER, 'as-1');
  await e.provisionOnDemand('T', SP_HR, 'scim.hr', 'rule1', LEAVER);
  assert.deepEqual(seen.map(s => `${s.method} ${s.url.replace(GRAPH, '')}`), [
    `PATCH /users/${LEAVER}`, `POST /users/${LEAVER}/revokeSignInSessions`, `DELETE /users/${LEAVER}/appRoleAssignments/as-1`, `POST /servicePrincipals/${SP_HR}/synchronization/jobs/scim.hr/provisionOnDemand`]);
  assert.deepEqual(seen[0].body, { accountEnabled: false });
  assert.deepEqual(seen[3].body, { parameters: [{ ruleId: 'rule1', subjects: [{ objectId: LEAVER, objectTypeName: 'User' }] }] });
  assert.equal(seen[0].auth, 'Bearer T');
  await assert.rejects(e.disable('T', 'admin'), /Privileged Authentication Administrator/);
});

test('userRuleId and onDemandOutcome read Entra\'s shapes', () => {
  assert.equal(userRuleId({ synchronizationRules: [{ id: 'g', objectMappings: [{ sourceObjectName: 'Group' }] }, { id: 'u', objectMappings: [{ sourceObjectName: 'User' }] }] }), 'u');
  assert.equal(userRuleId({}), '');
  assert.equal(onDemandOutcome({ value: JSON.stringify({ provisioningSteps: [{ name: 'Import', status: 'success' }, { name: 'Export', status: 'failure', description: '401' }] }) }).ok, false);
  assert.equal(onDemandOutcome({ value: JSON.stringify({ result: 'Success' }) }).ok, true);
});

test('foldOffboards keeps the first request row and ignores bad ids', () => {
  const at = s => new Date(Date.parse('2026-11-24T17:00:00Z') + s * 1000).toISOString();
  const req = { action: 'offboard.requested', requestId: 'OFB-0000000a', actorOid: AARON.oid, actorUpn: AARON.upn, at: at(1), detail: JSON.stringify({ type: 'disable', user: 'a@b.com', apps: [] }) };
  const out = foldOffboards([req, { ...req, at: at(2), detail: JSON.stringify({ type: 'remove', user: 'x@b.com' }) }, { action: 'offboard.approved', requestId: 'bogus', at: at(3) }]);
  assert.equal(out.length, 1);
  assert.equal(out[0].user, 'a@b.com');
  assert.equal(out[0].state, 'pending');
});

test('page: reads the Federation 360 link, keeps only GUID apps, and shows the request before a write session', async () => {
  const dom = new JSDOM('<!doctype html><main id="view"></main>', { url: `http://localhost:3660/#offboard/disable?user=sam.leaver%40contoso.example&app=${SP_HR}:HR%20Hub&app=bad:Nope&from=federation-360` });
  globalThis.window = dom.window; globalThis.document = dom.window.document; globalThis.location = dom.window.location; globalThis.sessionStorage = dom.window.sessionStorage;
  for (const k of ['HTMLElement', 'Node', 'Event']) globalThis[k] = dom.window[k];
  const { presetFrom, createOffboardUi, RETURN_KEY } = await import('../public/offboard.js');
  assert.deepEqual(presetFrom(dom.window.location.hash), { type: 'disable', user: 'sam.leaver@contoso.example', apps: [{ spId: SP_HR, name: 'HR Hub' }], from: 'federation-360' });
  assert.equal(presetFrom('#offboard/explode?user=x'), null);
  const el = (tag, props = {}, ...kids) => { const e = Object.assign(document.createElement(tag), props); e.append(...kids.filter(k => k != null)); return e; };
  const pill = (t, c) => el('span', { className: `pill ${c}`, textContent: t });
  const api = async () => ({ items: [], fourEyes: 'off', types: { disable: { label: 'Disable user everywhere', about: 'x' }, remove: { label: 'Remove from one app', about: 'y' } }, scopes: ['User.Read.All'] });
  const ui = createOffboardUi({ el, pill, api, view: () => document.getElementById('view'), fmtTime: v => v, session: { me: { roles: ['admin'], write: { active: false }, user: { oid: AARON.oid } } } });
  await ui.page();
  await new Promise(r => setTimeout(r, 0));
  const text = document.getElementById('view').textContent;
  assert.match(text, /Federation 360 sent a request: Disable user everywhere for sam\.leaver@contoso\.example \(1 app\)/);
  assert.match(text, /Elevate to write/);
  assert.equal(dom.window.sessionStorage.getItem(RETURN_KEY), dom.window.location.hash, 'the link survives sign-in and Elevate');
  const elevate = [...document.querySelectorAll('#view button')].find(x => x.textContent === 'Elevate to write');
  assert.ok(elevate, 'Elevate to write is on the page itself');
  assert.equal(elevate.disabled, true, 'greyed out when the session cannot elevate');
});

test('page: Elevate to write on the Offboard page keeps the request and comes back to it', async () => {
  const dom = new JSDOM('<!doctype html><main id="view"></main>', { url: 'http://localhost:3660/#offboard' });
  globalThis.window = dom.window; globalThis.document = dom.window.document; globalThis.location = dom.window.location; globalThis.sessionStorage = dom.window.sessionStorage;
  for (const k of ['HTMLElement', 'Node', 'Event']) globalThis[k] = dom.window[k];
  const { createOffboardUi, RETURN_KEY } = await import('../public/offboard.js');
  const el = (tag, props = {}, ...kids) => { const e = Object.assign(document.createElement(tag), props); e.append(...kids.filter(k => k != null)); return e; };
  const api = async () => ({ items: [], fourEyes: 'off', types: { disable: { label: 'Disable user everywhere', about: 'x' }, remove: { label: 'Remove from one app', about: 'y' } }, scopes: ['User.Read.All'] });
  const ui = createOffboardUi({ el, pill: t => el('span', { textContent: t }), api, view: () => document.getElementById('view'), fmtTime: v => v, session: { me: { roles: ['admin'], write: { active: false, canElevate: true }, user: { oid: AARON.oid } } } });
  await ui.page();
  await new Promise(r => setTimeout(r, 0));
  const b = [...document.querySelectorAll('#view button')].find(x => x.textContent === 'Elevate to write');
  assert.equal(b.disabled, false);
  try { b.click(); } catch { /* jsdom does not navigate */ }
  assert.equal(dom.window.sessionStorage.getItem(RETURN_KEY), '#offboard');
  assert.equal(b.textContent, 'Opening sign-in…');
});

test('HTTP: offboard routes need a write session and an emergencyApprover/admin role, and use the operator\'s offboard token', async () => {
  const w = world();
  const roles = { [AARON.oid]: ['admin'], [USER1.oid]: ['author'] };
  const tokens = [];
  const auth = {
    writeConfigured: true, beginSignIn: async () => 'https://login.microsoftonline.com/x', completeSignIn: async () => {}, graphToken: async () => 'GT',
    beginElevate: async s => { s.writePending = { state: 'ws', nonce: 'n', verifier: 'v', created: w.t }; return 'https://login.microsoftonline.com/write'; },
    completeElevate: async s => ({ oid: s.user.oid, upn: s.user.upn, homeAccountId: `ha.${s.user.oid}`, acrs: [], accessToken: 'WT' }), endWrite: async () => {}, signOut: async () => {},
    offboardToken: async ha => { tokens.push(ha); return `OFF.${ha}`; },
  };
  const github = { catalog: async () => ({ sha: 'm', items: [], approvers: Object.entries(roles).map(([entraObjectId, r]) => ({ entraObjectId, roles: r })) }) };
  const data = { pim: async () => ({ gate: { ok: true, text: 'active' } }) };
  const sessions = new SessionStore({ now: () => w.t });
  const app = createApp({ config: w.config, sessions, auth, data, github, audit: w.audit, entra: w.entra, fetcher: async () => new Response('{}'), now: () => w.t, log: { error() {} } });
  const srv = app.listen(0); await new Promise(r => srv.once('listening', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  const client = user => {
    const s = sessions.create(); s.user = user;
    const headers = { cookie: `${SESSION_COOKIE}=${s.id}` };
    const get = p => fetch(base + p, { redirect: 'manual', headers });
    const post = (p, body = {}) => fetch(base + p, { method: 'POST', redirect: 'manual', body: JSON.stringify(body), headers: { ...headers, origin: w.config.publicUrl, 'x-r360-csrf': s.csrf, 'content-type': 'application/json' } });
    const elevate = async () => { await get('/auth/write/start'); return get('/auth/write/callback?code=0123456789&state=ws'); };
    return { get, post, elevate };
  };
  try {
    const aaron = client(AARON), user1 = client(USER1);
    assert.equal((await fetch(`${base}/api/offboard`)).status, 401);
    assert.equal((await aaron.get('/api/offboard')).status, 200);
    const body = { type: 'disable', user: 'sam.leaver@contoso.example', reason: 'Left the company today' };
    assert.equal((await aaron.post('/api/offboard', body)).status, 403, 'no write session');
    await user1.elevate();
    assert.equal((await user1.post('/api/offboard', body)).status, 403, 'author role cannot offboard');
    await aaron.elevate();
    const preview = await (await aaron.get('/api/offboard/preview?user=sam.leaver%40contoso.example')).json();
    assert.equal(preview.user.upn, 'sam.leaver@contoso.example');
    const res = await aaron.post('/api/offboard', body);
    assert.equal(res.status, 200);
    assert.equal((await res.json()).state, 'done');
    assert.ok(tokens.every(t => t === `ha.${AARON.oid}`));
    assert.ok(w.calls.every(c => c[1] === `OFF.ha.${AARON.oid}`));
    const list = await (await aaron.get('/api/offboard')).json();
    assert.equal(list.items[0].state, 'done');
    assert.equal(list.fourEyes, 'off');
  } finally { srv.close(); }
});
