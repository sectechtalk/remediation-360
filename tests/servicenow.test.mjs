import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { servicenowSettings, validateQuery, textClause, encodedQuery, loadPreconfigured, issueIndex, createServiceNowSearch, memoryQueryStore, keyVaultSecret, createQueryStore } from '../server/servicenow.mjs';
import { createRequests, CHANGE_LABEL } from '../server/requests.mjs';
import { createApp } from '../server/app.mjs';
import { SessionStore, SESSION_COOKIE } from '../server/auth.mjs';
import { loadConfig } from '../server/config.mjs';
import { ACTIONS } from '../server/audit.mjs';
import { ENV } from './fixtures.mjs';

const OID = '94540000-0000-4000-8000-0000000000c3';
const USER = { oid: OID, upn: 'admin@contoso.com', name: 'Aaron' };
const INSTANCE = 'https://contoso.service-now.com';
const SYS = 'a'.repeat(32), SYS2 = 'b'.repeat(32);
const config = loadConfig({ ...ENV, R360_CHANGE_MAILBOX: 'changes@contoso.example' });
const settings = servicenowSettings({ SERVICENOW_INSTANCE: INSTANCE, SERVICENOW_USER: 'svc.r360', SERVICENOW_PASSWORD: 'pw' });
const item = (sysId, number, extra = {}) => ({ sys_id: sysId, number, short_description: `Renew cert ${number}`, state: 'Open', assignment_group: 'PKI Team', opened_at: '2026-11-10 09:00:00', sys_updated_on: '2026-11-14 10:00:00', priority: '3 - Moderate', ...extra });

function world({ roles = ['author'], items = [item(SYS, 'RITM0010001'), item(SYS2, 'RITM0010002')] } = {}) {
  const w = { t: Date.parse('2026-11-15T16:00:00Z'), events: [], calls: [], issues: new Map(), next: 50, items };
  w.audit = { record: async e => { w.events.push(e); }, list: async () => ({ rows: [] }) };
  w.github = {
    listIssues: async ({ label, state }) => [...w.issues.values()].filter(i => i.labels.includes(label) && (state === 'all' || i.state === state)).reverse(),
    createIssue: async ({ title, body, labels }) => { const n = w.next++; const i = { number: n, title, body, labels, state: 'open', createdAt: new Date(w.t).toISOString(), url: `https://github.com/your-org/r360/issues/${n}`, comments: 0, isPull: false }; w.issues.set(n, i); return { ...i, githubRequestId: 'G' }; },
    updateIssue: async ({ number, title, body }) => { const i = w.issues.get(number); Object.assign(i, { title, body }); return i; },
  };
  w.fetcher = async (url, init) => {
    w.calls.push({ url: String(url), auth: init.headers.Authorization });
    const u = new URL(url);
    const one = /\/api\/now\/table\/(\w+)\/([0-9a-f]{32})$/.exec(u.pathname);
    if (one) { const it = w.items.find(i => i.sys_id === one[2]); return it ? Response.json({ result: it }) : new Response('{}', { status: 404 }); }
    return Response.json({ result: w.items }, { headers: { 'X-Total-Count': String(w.items.length) } });
  };
  w.requests = createRequests({ config, github: w.github, audit: w.audit, mailbox: {}, llm: { configured: false }, now: () => w.t, log: { error() {} } });
  w.store = memoryQueryStore();
  w.sn = createServiceNowSearch({ settings, store: w.store, github: w.github, requests: w.requests, audit: w.audit, preconfigured: loadPreconfigured(), fetcher: w.fetcher, now: () => w.t, log: { error() {} } });
  w.roles = roles;
  return w;
}

test('settings: off until instance, user and a password (or Key Vault secret name) are set; only service-now.com over https', () => {
  assert.equal(servicenowSettings({}).configured, false);
  assert.equal(servicenowSettings({ SERVICENOW_INSTANCE: INSTANCE, SERVICENOW_USER: 'u' }).configured, false);
  assert.equal(servicenowSettings({ SERVICENOW_INSTANCE: INSTANCE, SERVICENOW_USER: 'u', SERVICENOW_PASSWORD_SECRET: 'servicenow-r360-password' }).configured, true);
  assert.throws(() => servicenowSettings({ SERVICENOW_INSTANCE: 'http://contoso.service-now.com' }), /https/);
  assert.throws(() => servicenowSettings({ SERVICENOW_INSTANCE: 'https://evil.example.com' }), /service-now/);
  assert.throws(() => servicenowSettings({ SERVICENOW_PASSWORD_SECRET: 'bad/name' }), /secret name/);
  assert.equal(settings.queryTable, 'r360snqueries');
});

test('queries: known tables only, one line, no ORDERBY; free text cannot add conditions', () => {
  assert.deepEqual(validateQuery({ table: 'incident', query: 'active=true' }), { table: 'incident', query: 'active=true', name: '' });
  assert.throws(() => validateQuery({ table: 'sys_user', query: '' }), /Table must be/);
  assert.throws(() => validateQuery({ table: 'incident', query: 'a=1\nb=2' }), /one line/);
  assert.throws(() => validateQuery({ table: 'incident', query: 'active=true^ORDERBYnumber' }), /ORDERBY/);
  assert.throws(() => validateQuery({ table: 'incident', query: '' }, { requireName: true }), /name/);
  assert.equal(textClause('cert^NQsys_id!=x'), 'numberLIKEcert NQsys_id!=x^ORshort_descriptionLIKEcert NQsys_id!=x^ORdescriptionLIKEcert NQsys_id!=x');
  assert.equal(textClause('  '), '');
  assert.equal(encodedQuery({ query: 'active=true', text: 'web' }), 'active=true^numberLIKEweb^ORshort_descriptionLIKEweb^ORdescriptionLIKEweb^ORDERBYDESCsys_updated_on');
});

test('preconfigured queries: the repo file loads and starts with Certificate revocations; bad files are refused', () => {
  const pre = loadPreconfigured();
  assert.equal(pre[0].id, 'pre:certificate-revocations');
  assert.equal(pre[0].name, 'Certificate revocations');
  assert.equal(pre[0].table, 'sc_req_item');
  assert.equal(pre[0].query, 'cat_item.name=Certificate Revocation^active=true');
  assert.deepEqual(pre[0].actionTemplates, []);
  assert.throws(() => loadPreconfigured({ read: () => '{' }), /not valid JSON/);
  assert.throws(() => loadPreconfigured({ read: () => JSON.stringify({ version: 1, queries: [{ id: 'aa', name: 'A1', table: 'incident', query: '' }, { id: 'aa', name: 'A2', table: 'incident', query: '' }] }) }), /unique/);
  assert.throws(() => loadPreconfigured({ read: () => JSON.stringify({ version: 1, queries: [{ id: 'xx', name: 'X1', table: 'cmdb_ci', query: '' }] }) }), /Table must be/);
  assert.match(readFileSync(new URL('../Dockerfile', import.meta.url), 'utf8'), /COPY config \.\/config/);
});

test('issue index: every ServiceNow number in a title or body, open issues win over closed ones', () => {
  const m = issueIndex([
    { number: 3, title: 'RITM0010001: old', body: '', state: 'closed', url: 'u3' },
    { number: 7, title: 'x', body: 'See INC0012345 and RITM0010001', state: 'open', url: 'u7' },
    { number: 9, title: 'RITM00100011 is not RITM0010001x', body: '', state: 'open', url: 'u9' },
  ]);
  assert.equal(m.get('RITM0010001').number, 7);
  assert.equal(m.get('INC0012345').changeNumber, 'R360-CHG-7');
  assert.equal(m.has('RITM00100011'), true);
});

test('search: runs the preconfigured query read-only with basic auth and marks which items already have an issue', async () => {
  const w = world();
  await w.github.createIssue({ title: '[R360-CHG-50] RITM0010001: Renew cert', body: '', labels: [CHANGE_LABEL] });
  const r = await w.sn.search(USER, { queryId: 'pre:certificate-revocations', text: 'web^x' });
  const u = new URL(w.calls[0].url);
  assert.equal(u.origin + u.pathname, `${INSTANCE}/api/now/table/sc_req_item`);
  assert.equal(u.searchParams.get('sysparm_query'), 'cat_item.name=Certificate Revocation^active=true^numberLIKEweb x^ORshort_descriptionLIKEweb x^ORdescriptionLIKEweb x^ORDERBYDESCsys_updated_on');
  assert.equal(w.calls[0].auth, `Basic ${Buffer.from('svc.r360:pw').toString('base64')}`);
  assert.equal(r.rows.length, 2);
  assert.equal(r.rows[0].issue.changeNumber, 'R360-CHG-50');
  assert.equal(r.rows[1].issue, null);
  assert.equal(r.rows[0].link, `${INSTANCE}/sc_req_item.do?sys_id=${SYS}`);
  assert.equal(JSON.stringify(r).includes('pw'), false);
  await assert.rejects(w.sn.search(USER, { table: 'incident', query: '', text: '' }), /Enter search text/);
  await assert.rejects(w.sn.search(USER, { queryId: 'pre:gone' }), /no longer exists/);
});

test('search: ServiceNow errors become clear messages; unconfigured says how to set it up', async () => {
  const w = world();
  const sn = createServiceNowSearch({ ...w, settings, preconfigured: [], fetcher: async () => new Response('', { status: 401 }), log: { error() {} } });
  await assert.rejects(sn.search(USER, { table: 'incident', text: 'x' }), /refused the r360 service account/);
  const off = createServiceNowSearch({ settings: { configured: false }, store: null, github: w.github, requests: w.requests, audit: w.audit });
  await assert.rejects(off.search(USER, { table: 'incident', text: 'x' }), e => e.status === 503 && /Set-R360ServiceNow/.test(e.message));
  assert.equal((await off.queries(USER, ['author'])).configured, false);
});

test('Create issue re-reads the item from ServiceNow, opens a change request named after it, and refuses a second open one', async () => {
  const w = world();
  const c = await w.sn.createIssue(USER, ['author'], { table: 'sc_req_item', sysId: SYS });
  assert.equal(c.changeNumber, 'R360-CHG-50');
  assert.equal(c.servicenowNumber, 'RITM0010001');
  const issue = w.issues.get(50);
  assert.match(issue.title, /^\[R360-CHG-50\] RITM0010001: Renew cert RITM0010001$/);
  assert.match(issue.body, new RegExp(`${INSTANCE}/sc_req_item\\.do\\?sys_id=${SYS}`));
  assert.match(issue.body, /PKI Team/);
  assert.deepEqual(w.events.map(e => `${e.action}:${e.result}`), ['request.created:intent', 'request.created:ok']);
  await assert.rejects(w.sn.createIssue(USER, ['author'], { table: 'sc_req_item', sysId: SYS }), e => e.status === 409 && /already has R360-CHG-50/.test(e.message));
  await assert.rejects(w.sn.createIssue(USER, [], { table: 'sc_req_item', sysId: SYS2 }), e => e.status === 403);
  await assert.rejects(w.sn.createIssue(USER, ['author'], { table: 'sc_req_item', sysId: 'c'.repeat(32) }), e => e.status === 404);
  await assert.rejects(w.sn.createIssue(USER, ['author'], { table: 'sys_user', sysId: SYS }), e => e.status === 400);
});

test('saved queries: role required, names unique, save and delete audited intent-first; audit down means no change', async () => {
  const w = world();
  await assert.rejects(w.sn.saveQuery(USER, [], { name: 'Mine', table: 'incident', query: 'active=true' }), e => e.status === 403);
  const q = await w.sn.saveQuery(USER, ['author'], { name: 'Open PKI incidents', table: 'incident', query: 'assignment_group.name=PKI Team^active=true' });
  assert.match(q.id, /^saved:[0-9a-f]{16}$/);
  await assert.rejects(w.sn.saveQuery(USER, ['author'], { name: 'open pki incidents', table: 'incident', query: 'active=true' }), e => e.status === 409);
  const list = await w.sn.queries(USER, ['author']);
  assert.equal(list.saved[0].name, 'Open PKI incidents');
  assert.equal(list.preconfigured[0].name, 'Certificate revocations');
  assert.equal(list.canSave, true);
  const r = await w.sn.search(USER, { queryId: q.id });
  assert.equal(new URL(w.calls.at(-1).url).pathname, '/api/now/table/incident');
  assert.equal(r.query.name, 'Open PKI incidents');
  await w.sn.deleteQuery(USER, ['author'], q.id);
  assert.equal((await w.sn.queries(USER, ['author'])).saved.length, 0);
  assert.deepEqual(w.events.map(e => `${e.action}:${e.result}`), ['servicenow.query.saved:intent', 'servicenow.query.saved:ok', 'servicenow.query.deleted:intent', 'servicenow.query.deleted:ok']);
  w.audit.record = async () => { throw new Error('down'); };
  await assert.rejects(w.sn.saveQuery(USER, ['author'], { name: 'X1', table: 'incident', query: 'active=true' }), e => e.status === 503);
  assert.equal(w.store.rows.size, 0);
  for (const a of ['servicenow.query.saved', 'servicenow.query.deleted']) assert.ok(ACTIONS.includes(a));
});

test('Key Vault password: read once with the managed identity, retried after a failure, never returned', async () => {
  let reads = 0;
  const kv = keyVaultSecret({ vaultUri: 'https://kv-r360-test.vault.azure.net', name: 'servicenow-r360-password', miToken: async r => { assert.equal(r, 'https://vault.azure.net'); return 'MI'; },
    fetcher: async (url, init) => { reads++; assert.equal(String(url), 'https://kv-r360-test.vault.azure.net/secrets/servicenow-r360-password?api-version=7.4'); assert.equal(init.headers.Authorization, 'Bearer MI'); return reads === 1 ? new Response('', { status: 403 }) : Response.json({ value: 'kvpw' }); } });
  const w = world();
  const sn = createServiceNowSearch({ ...w, settings: { ...settings, password: '', passwordSecret: 'servicenow-r360-password' }, preconfigured: [], password: kv, fetcher: w.fetcher, log: { error() {} } });
  await assert.rejects(sn.search(USER, { table: 'incident', text: 'x' }), /Key Vault/);
  await sn.search(USER, { table: 'incident', text: 'x' });
  await sn.search(USER, { table: 'incident', text: 'y' });
  assert.equal(reads, 2);
  assert.equal(w.calls.at(-1).auth, `Basic ${Buffer.from('svc.r360:kvpw').toString('base64')}`);
});

test('query store: Azure Table list, insert and delete with the managed identity', async () => {
  const calls = [];
  const store = createQueryStore({ account: 'str360test', table: 'r360snqueries', miToken: async () => 'MI', fetcher: async (url, init = {}) => {
    calls.push(`${init.method || 'GET'} ${url}`);
    if (!init.method) return Response.json({ value: [{ RowKey: '0123456789abcdef', name: 'A', table: 'incident', query: 'q' }] });
    return new Response(null, { status: 204 });
  } });
  assert.equal((await store.list())[0].name, 'A');
  await store.insert({ PartitionKey: 'queries', RowKey: '0123456789abcdef' });
  assert.equal(await store.remove('0123456789abcdef'), true);
  assert.match(calls[0], /^GET https:\/\/str360test\.table\.core\.windows\.net\/r360snqueries\(\)\?\$filter=PartitionKey%20eq%20'queries'/);
  assert.equal(calls[2], "DELETE https://str360test.table.core.windows.net/r360snqueries(PartitionKey='queries',RowKey='0123456789abcdef')");
});

test('http: ServiceNow routes need a session and CSRF', async () => {
  const w = world();
  const sessions = new SessionStore({ now: () => w.t });
  const github = { ...w.github, catalog: async () => ({ sha: 'm', items: [], approvers: [{ entraObjectId: OID, roles: ['author'] }] }) };
  const auth = { writeConfigured: false, graphToken: async () => 'GT', beginSignIn: async () => 'x', completeSignIn: async () => {}, endWrite: async () => {}, signOut: async () => {} };
  const app = createApp({ config, sessions, auth, data: {}, github, audit: w.audit, now: () => w.t, log: { error() {} },
    servicenow: deps => createServiceNowSearch({ ...deps, settings, store: w.store, preconfigured: loadPreconfigured(), fetcher: w.fetcher, now: () => w.t, log: { error() {} } }) });
  const srv = app.listen(0); await new Promise(r => srv.once('listening', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    assert.equal((await fetch(`${base}/api/servicenow/queries`)).status, 401);
    const s = sessions.create(); s.user = USER;
    const headers = { cookie: `${SESSION_COOKIE}=${s.id}` };
    const post = (p, b, extra = {}) => fetch(base + p, { method: 'POST', body: JSON.stringify(b), headers: { ...headers, origin: config.publicUrl, 'x-r360-csrf': s.csrf, 'content-type': 'application/json', ...extra } });
    const q = await (await fetch(`${base}/api/servicenow/queries`, { headers })).json();
    assert.equal(q.configured, true);
    assert.equal(q.preconfigured[0].id, 'pre:certificate-revocations');
    assert.equal((await post('/api/servicenow/search', { queryId: 'pre:certificate-revocations' }, { 'x-r360-csrf': 'bad' })).status, 403);
    const r = await (await post('/api/servicenow/search', { queryId: 'pre:certificate-revocations' })).json();
    assert.equal(r.rows.length, 2);
    assert.equal((await post('/api/servicenow/search', { table: 'sys_user', query: 'x' })).status, 400);
    const c = await (await post('/api/servicenow/issue', { table: 'sc_req_item', sysId: SYS2 })).json();
    assert.equal(c.servicenowNumber, 'RITM0010002');
  } finally { srv.close(); }
});
