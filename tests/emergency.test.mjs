import test from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../server/app.mjs';
import { SessionStore, SESSION_COOKIE } from '../server/auth.mjs';
import { loadConfig } from '../server/config.mjs';
import { actionBody, ACTIONS, createDefender, DEFENDER_SCOPES, DEFENDER_API } from '../server/defender.mjs';
import { createEmergency, foldEmergencies } from '../server/emergency.mjs';
import { ENV } from './fixtures.mjs';

// The fast path: one Defender action on one device, second-person approval, run as the approver, all audited.
const AARON = { oid: '94540000-0000-4000-8000-0000000000c3', upn: 'admin@contoso.com', name: 'Aaron' };
const USER1 = { oid: '0d000000-0000-4000-8000-0000000000c4', upn: 'user1@contoso.com', name: 'User One' };
const MID = 'ab'.repeat(20);
const ACTION_ID = 'aaaabbbb-0000-cccc-1111-dddd2222eeee';

function world({ mode = 'testing', roles = { [AARON.oid]: ['author', 'emergencyApprover'], [USER1.oid]: ['emergencyApprover'] }, auditDown = false } = {}) {
  const w = { t: Date.parse('2026-11-16T17:00:00Z'), seq: 0, events: [], calls: [], roles, mode };
  w.config = loadConfig({ ...ENV, R360_FOUR_EYES: mode });
  w.audit = {
    record: async e => { if (w.auditDown) throw Object.assign(new Error('down'), { audit: true }); w.events.push({ ...e, at: new Date(w.t + (++w.seq) * 1000).toISOString() }); return e; },
    list: async ({ actions } = {}) => ({ rows: w.events.filter(e => !actions || actions.includes(e.action)).reverse(), truncated: false }),
  };
  w.auditDown = auditDown;
  w.defender = {
    probe: async t => { w.calls.push(['probe', t]); return true; },
    findMachines: async (t, q) => { w.calls.push(['find', t, q]); return [{ id: MID, name: 'DEVICE01.contoso.example', health: 'Active' }]; },
    machine: async (t, id) => { w.calls.push(['machine', t, id]); return { id, name: 'DEVICE01.contoso.example', health: 'Active', group: 'Canary' }; },
    run: async (t, id, action, body) => { w.calls.push(['run', t, id, action, body]); if (w.runFails) throw Object.assign(new Error('Defender: Forbidden.'), { defenderStatus: 403 }); return { id: ACTION_ID, status: 'Pending', type: 'Isolate' }; },
    action: async (t, id) => { w.calls.push(['action', t, id]); return { id, status: w.finalStatus || 'InProgress' }; },
  };
  return w;
}
const em = w => createEmergency({ config: w.config, audit: w.audit, defender: w.defender, now: () => w.t, log: { error() {} } });
const tok = name => ({ token: async () => name });
const acts = w => w.events.map(e => e.action);

test('actionBody: known actions only, a real reason, validated parameters, exact Defender body', () => {
  assert.deepEqual(actionBody('isolate', {}, 'Ransomware alert 1234 on this PC').body, { Comment: 'Ransomware alert 1234 on this PC', IsolationType: 'Full' });
  assert.deepEqual(actionBody('scan', { scanType: 'Full' }, 'Suspicious download reported').body, { Comment: 'Suspicious download reported', ScanType: 'Full' });
  assert.equal(actionBody('quarantine', { sha1: 'A'.repeat(40) }, 'Known bad file from alert').body.Sha1, 'a'.repeat(40));
  assert.throws(() => actionBody('offboard', {}, 'long enough reason'), /listed actions/);
  assert.throws(() => actionBody('isolate', {}, 'short'), /at least 10/);
  assert.throws(() => actionBody('isolate', { isolationType: 'Partial' }, 'long enough reason'), /Full or Selective/);
  assert.throws(() => actionBody('quarantine', { sha1: 'xyz' }, 'long enough reason'), /SHA-1/);
  assert.throws(() => actionBody('quarantine', {}, 'long enough reason'), /required/);
  // Plans come from Microsoft Learn: Defender for Business has no stop and quarantine; investigation package and app restriction are Plan 2.
  assert.deepEqual(ACTIONS.quarantine.plans, ['P1', 'P2']);
  assert.deepEqual(ACTIONS.collect.plans, ['P2']);
  assert.equal(ACTIONS.isolate.release, 'unisolate');
});

test('Defender client: legacy token audience, new API host, startswith device search, errors explain the role', async () => {
  assert.ok(DEFENDER_SCOPES.every(s => s.startsWith('https://api.securitycenter.microsoft.com/Machine.')));
  const seen = [];
  const d = createDefender({ fetcher: async (url, init) => { seen.push({ url, init }); return url.includes('/isolate') ? new Response('{"error":{"message":"Forbidden"}}', { status: 403 }) : new Response(JSON.stringify({ value: [{ id: MID, computerDnsName: 'DEVICE01', healthStatus: 'Active' }] }), { status: 200 }); } });
  const found = await d.findMachines('DT', 'ABLAP');
  assert.equal(found[0].name, 'DEVICE01');
  assert.equal(seen[0].url, `${DEFENDER_API}/machines?$filter=${encodeURIComponent("startswith(computerDnsName,'ablap')")}&$top=10`);
  assert.equal(seen[0].init.headers.Authorization, 'Bearer DT');
  await assert.rejects(d.findMachines('DT', "x' or 1 eq 1"), /at least 2 letters/);
  await assert.rejects(d.run('DT', MID, 'isolate', { Comment: 'c' }), /Active remediation actions/);
  await assert.rejects(d.run('DT', 'not-an-id', 'isolate', {}), /device id/);
});

test('request then a second person approves: audit intent first, Defender runs once with the APPROVER token', async () => {
  const w = world({ mode: 'enforced' });
  const e = em(w);
  const r = await e.request(AARON, { machineId: MID, action: 'isolate', params: { isolationType: 'Selective' }, reason: 'Active ransomware alert on DEVICE01' }, tok('AARON-DEF'));
  assert.match(r.id, /^EMG-[0-9a-f]{8}$/);
  assert.equal((await e.list()).items[0].state, 'pending');
  await assert.rejects(e.request(AARON, { machineId: MID, action: 'isolate', reason: 'Second identical ask here' }, tok('AARON-DEF')), /already asks/);
  await assert.rejects(e.approve(AARON, r.id, tok('AARON-DEF')), /different approver/);
  assert.equal(w.calls.filter(c => c[0] === 'run').length, 0, 'a refused self-approval never reaches Defender');
  const ok = await e.approve(USER1, r.id, tok('USER1-DEF'));
  assert.equal(ok.state, 'running');
  const run = w.calls.find(c => c[0] === 'run');
  assert.deepEqual(run, ['run', 'USER1-DEF', MID, 'isolate', { Comment: 'Active ransomware alert on DEVICE01', IsolationType: 'Selective' }]);
  assert.deepEqual(acts(w), ['emergency.requested', 'emergency.denied', 'emergency.approved', 'emergency.executed'], 'the duplicate ask is refused before any row is written');
  await assert.rejects(e.approve(USER1, r.id, tok('USER1-DEF')), /is running/);
  w.finalStatus = 'Succeeded';
  assert.equal((await e.refresh(USER1, r.id, tok('USER1-DEF'))).final, true);
  await e.refresh(USER1, r.id, tok('USER1-DEF'));
  assert.equal(acts(w).filter(a => a === 'emergency.result').length, 1, 'the final status is recorded once');
  const item = (await e.list()).items[0];
  assert.equal(item.state, 'succeeded');
  assert.equal(item.approverUpn, USER1.upn);
});

test('testing mode allows self-approval and flags it; the window expires requests; a dead audit trail stops everything', async () => {
  const w = world({ mode: 'testing' });
  const e = em(w);
  const r = await e.request(AARON, { machineId: MID, action: 'scan', reason: 'Testing the fast path on canary' }, tok('A'));
  const ok = await e.approve(AARON, r.id, tok('A'));
  assert.equal(ok.selfApproved, true);
  assert.equal(w.events.find(x => x.action === 'emergency.approved').selfApproved, true);

  const r2 = await e.request(AARON, { machineId: MID, action: 'collect', reason: 'Needs evidence before reimage' }, tok('A'));
  w.t += 241 * 60000;
  assert.equal((await e.list()).items.find(x => x.id === r2.id).state, 'expired');
  await assert.rejects(e.approve(USER1, r2.id, tok('U')), /expired/);

  w.auditDown = true;
  await assert.rejects(e.request(AARON, { machineId: MID, action: 'scan', reason: 'Audit is down right now' }, tok('A')), /audit trail is unavailable/);
});

test('Defender refusing the action is recorded as failed; requester cancels, approver rejects', async () => {
  const w = world();
  const e = em(w);
  w.runFails = true;
  const r = await e.request(AARON, { machineId: MID, action: 'isolate', reason: 'Isolate after phishing click' }, tok('A'));
  await assert.rejects(e.approve(USER1, r.id, tok('U')), /did not run it/);
  assert.equal((await e.list()).items[0].state, 'failed');

  const c = await e.request(AARON, { machineId: MID, action: 'scan', reason: 'Scan after phishing click' }, tok('A'));
  assert.equal((await e.close(AARON, ['author'], c.id, {})).state, 'cancelled');
  const j = await e.request(AARON, { machineId: MID, action: 'scan', reason: 'Scan again for the record' }, tok('A'));
  await assert.rejects(e.close({ oid: '00000000-0000-4000-8000-000000000009', upn: 'x@contoso.com' }, ['author'], j.id, {}), /Only the requester/);
  assert.equal((await e.close(USER1, ['emergencyApprover'], j.id, { reason: 'not needed' })).state, 'rejected');
});

test('foldEmergencies ignores rows without a valid id and a second request row with the same id', () => {
  const at = s => new Date(Date.parse('2026-11-16T17:00:00Z') + s * 1000).toISOString();
  const req = { action: 'emergency.requested', requestId: 'EMG-0000000a', actorOid: AARON.oid, actorUpn: AARON.upn, at: at(1), detail: JSON.stringify({ machineId: MID, device: 'd', action: 'scan', expiresAt: at(9999) }) };
  const out = foldEmergencies([req, { ...req, at: at(2), detail: JSON.stringify({ machineId: MID, device: 'other', action: 'isolate', expiresAt: at(9999) }) }, { action: 'emergency.approved', requestId: 'bogus', at: at(3) }], { now: Date.parse(at(5)) });
  assert.equal(out.length, 1);
  assert.equal(out[0].device, 'd');
});

// HTTP: the routes need a session, a live write session, the right approvers.json role, and CSRF.
test('HTTP: emergency routes are gated by write session and role; approve uses the approver\'s Defender token', async () => {
  const w = world({ mode: 'enforced', roles: { [AARON.oid]: ['author'], [USER1.oid]: ['emergencyApprover'] } });
  const defTokens = [];
  const auth = {
    writeConfigured: true, beginSignIn: async () => 'https://login.microsoftonline.com/x', completeSignIn: async () => {}, graphToken: async () => 'GT',
    beginElevate: async s => { s.writePending = { state: 'ws', nonce: 'n', verifier: 'v', created: w.t }; return 'https://login.microsoftonline.com/write'; },
    completeElevate: async s => ({ oid: s.user.oid, upn: s.user.upn, homeAccountId: `ha.${s.user.oid}`, acrs: [], accessToken: 'WT' }), endWrite: async () => {}, signOut: async () => {},
    defenderToken: async ha => { defTokens.push(ha); return `DEF.${ha}`; },
  };
  const github = { catalog: async () => ({ sha: 'm', items: [], approvers: Object.entries(w.roles).map(([entraObjectId, roles]) => ({ entraObjectId, roles })) }) };
  const data = { pim: async () => ({ gate: { ok: true, text: 'active' } }) };
  const sessions = new SessionStore({ now: () => w.t });
  const app = createApp({ config: w.config, sessions, auth, data, github, audit: w.audit, defender: w.defender, fetcher: async () => new Response('{}'), now: () => w.t, log: { error() {} } });
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
    assert.equal((await fetch(`${base}/api/emergency`)).status, 401);
    assert.equal((await aaron.get('/api/emergency')).status, 200, 'anyone signed in can read the list');
    assert.equal((await aaron.get('/api/emergency/machines?q=ablap')).status, 403, 'no write session');
    await aaron.elevate();
    const found = await (await aaron.get('/api/emergency/machines?q=ablap')).json();
    assert.equal(found.items[0].id, MID);
    const made = await (await aaron.post('/api/emergency', { machineId: MID, action: 'isolate', reason: 'Isolate DEVICE01 now please' })).json();
    assert.match(made.id, /^EMG-/);
    assert.equal((await aaron.post(`/api/emergency/${made.id}/approve`)).status, 403, 'author role cannot approve');
    await user1.elevate();
    const ok = await user1.post(`/api/emergency/${made.id}/approve`);
    assert.equal(ok.status, 200);
    assert.equal(w.calls.find(c => c[0] === 'run')[1], `DEF.ha.${USER1.oid}`);
    const list = await (await aaron.get('/api/emergency')).json();
    assert.equal(list.items[0].state, 'running');
    assert.equal(list.items[0].events.every(ev => !('detail' in ev)), true, 'raw audit detail is not sent to the browser');
  } finally { srv.close(); }
});
