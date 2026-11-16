import { readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { STORAGE_RESOURCE } from './audit.mjs';
import { VAULT_RESOURCE } from './identity.mjs';
import { ChangeError } from './changes.mjs';
import { CHANGE_LABEL, ROLES } from './requests.mjs';
import { changeNumber } from './mailbox.mjs';

// ServiceNow search. Read-only against ServiceNow: r360 runs a query (free text, a preconfigured query, a saved query or a
// pasted ServiceNow encoded query) and shows, for each item, the r360 change request (GitHub issue) that mentions its
// number. "Create issue" opens a change request for an item through the normal Change requests path.
//
//   - Preconfigured queries: config/servicenow-queries.json in this repo, reviewed through pull requests. Each may later
//     name Action Templates (actionTemplates), which r360 does not act on yet.
//   - Saved queries: operators save their own named queries in an Azure Table (R360_SERVICENOW_QUERY_TABLE, default
//     r360snqueries) in the audit storage account. Saving and deleting are audited.
//
// Credentials: SERVICENOW_INSTANCE, SERVICENOW_USER, and the password either as SERVICENOW_PASSWORD (a Container Apps
// secret reference) or as SERVICENOW_PASSWORD_SECRET, the name of a Key Vault secret read with the managed identity (local
// hosting). The password lives only in this module's closure and is never logged, returned, audited or shown.
export const SN_TABLES = Object.freeze({ sc_req_item: 'Requested items', incident: 'Incidents', change_request: 'Change requests', sc_task: 'Catalog tasks' });
export const SN_ACTIONS = ['servicenow.query.saved', 'servicenow.query.deleted'];
const FIELDS = ['sys_id', 'number', 'short_description', 'state', 'assignment_group', 'opened_at', 'sys_updated_on', 'priority'];
const MAX_ROWS = 100;
const MAX_QUERY = 2000;
const MAX_TEXT = 100;
const MAX_SAVED = 200;
const ISSUE_TTL_MS = 60000;
const TABLE_VERSION = '2020-12-06';
const PARTITION = 'queries';
const SYS_ID = /^[0-9a-f]{32}$/;
const ID = /^[a-z0-9][a-z0-9-]{1,62}$/;
// ServiceNow record numbers as they appear in GitHub issue titles and bodies.
export const SN_NUMBER = /\b(?:RITM|REQ|INC|CHG|SCTASK|CTASK|PRB|TASK)\d{7,10}\b/g;
export const PRECONFIGURED_FILE = new URL('../config/servicenow-queries.json', import.meta.url);

const expose = (status, message) => new ChangeError(status, message);
const cleanLine = (v, max) => String(v ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max);
const text = (v, max = 400) => cleanLine(v && typeof v === 'object' ? v.display_value ?? v.value ?? '' : v, max);

// Returns { configured: false } when not set up. Throws only when a value is present but invalid.
export function servicenowSettings(env = process.env) {
  const instance = String(env.SERVICENOW_INSTANCE || '').trim();
  const user = String(env.SERVICENOW_USER || '').trim();
  const password = String(env.SERVICENOW_PASSWORD || '');
  const passwordSecret = String(env.SERVICENOW_PASSWORD_SECRET || '').trim();
  const queryTable = String(env.R360_SERVICENOW_QUERY_TABLE || 'r360snqueries').trim();
  if (!/^[A-Za-z][A-Za-z0-9]{2,62}$/.test(queryTable)) throw new Error('R360_SERVICENOW_QUERY_TABLE is not a valid table name');
  if (passwordSecret && !/^[A-Za-z0-9-]{1,127}$/.test(passwordSecret)) throw new Error('SERVICENOW_PASSWORD_SECRET is not a valid Key Vault secret name');
  let origin = null;
  if (instance) {
    const u = new URL(instance);
    if (u.protocol !== 'https:' || !/^[a-z0-9-]+\.service-now\.com$/i.test(u.hostname)) throw new Error('SERVICENOW_INSTANCE must be https://<name>.service-now.com');
    origin = u.origin;
  }
  const configured = Boolean(origin && user && (password || passwordSecret));
  return { configured, instance: origin, user, password, passwordSecret, queryTable };
}

// A query is a ServiceNow table plus an encoded query (what ServiceNow's list view gives with "Copy query").
export function validateQuery(q, { requireName = false } = {}) {
  const b = q && typeof q === 'object' ? q : {};
  const table = String(b.table ?? '').trim();
  const query = String(b.query ?? '').trim();
  const name = cleanLine(b.name, 80);
  const bad = [];
  if (!Object.hasOwn(SN_TABLES, table)) bad.push(`Table must be one of ${Object.keys(SN_TABLES).join(', ')}.`);
  if (query.length > MAX_QUERY) bad.push(`The encoded query must be at most ${MAX_QUERY} characters.`);
  if (/[\u0000-\u001f\u007f]/.test(query)) bad.push('The encoded query must be one line.');
  if (/(^|\^)(ORDERBY|ORDERBYDESC|GROUPBY)/i.test(query)) bad.push('Leave ORDERBY and GROUPBY out of the query; r360 sorts by last update.');
  if (requireName && (name.length < 2)) bad.push('Give the query a name of 2 to 80 characters.');
  if (bad.length) throw new ChangeError(400, bad.join(' '), bad);
  return { table, query, name };
}

// Free text matches the number, short description or description. ^ would start a new condition, so it is removed.
export function textClause(raw) {
  const t = cleanLine(raw, MAX_TEXT).replace(/\^/g, ' ').replace(/\s+/g, ' ').trim();
  if (!t) return '';
  return `numberLIKE${t}^ORshort_descriptionLIKE${t}^ORdescriptionLIKE${t}`;
}

export function encodedQuery({ query, text: free }) {
  return [query, textClause(free), 'ORDERBYDESCsys_updated_on'].filter(Boolean).join('^');
}

export function loadPreconfigured({ read = () => readFileSync(PRECONFIGURED_FILE, 'utf8') } = {}) {
  let doc;
  try { doc = JSON.parse(read()); } catch (e) { throw new Error(`config/servicenow-queries.json is not valid JSON: ${e.message}`); }
  if (!doc || doc.version !== 1 || !Array.isArray(doc.queries)) throw new Error('config/servicenow-queries.json must be { "version": 1, "queries": [...] }');
  const seen = new Set();
  return doc.queries.map((q, i) => {
    const id = String(q?.id ?? '');
    if (!ID.test(id) || seen.has(id)) throw new Error(`config/servicenow-queries.json query ${i + 1}: id must be unique, lowercase letters, digits and dashes`);
    seen.add(id);
    let v;
    try { v = validateQuery(q, { requireName: true }); } catch (e) { throw new Error(`config/servicenow-queries.json query ${id}: ${e.message}`); }
    const templates = Array.isArray(q.actionTemplates) ? q.actionTemplates.map(t => cleanLine(t, 80)).filter(Boolean).slice(0, 20) : [];
    return Object.freeze({ id: `pre:${id}`, kind: 'preconfigured', name: v.name, table: v.table, query: v.query, description: cleanLine(q.description, 400), actionTemplates: templates });
  });
}

// GitHub issues (r360 change requests, open and closed) indexed by every ServiceNow number in their title or body.
export function issueIndex(issues) {
  const map = new Map();
  for (const i of issues) {
    const found = new Set(`${i.title}\n${i.body}`.match(SN_NUMBER) || []);
    for (const n of found) {
      const prev = map.get(n);
      // An open issue wins over a closed one; otherwise the newest.
      if (!prev || (prev.state !== 'open' && i.state === 'open') || (prev.state === i.state && i.number > prev.number))
        map.set(n, { number: i.number, changeNumber: changeNumber(i.number), url: i.url, state: i.state });
    }
  }
  return map;
}

export function toRow(item, instance, table) {
  const sysId = text(item.sys_id, 64).toLowerCase();
  if (!SYS_ID.test(sysId)) return null;
  return {
    sysId, table, number: text(item.number, 40), shortDescription: text(item.short_description, 400), state: text(item.state, 80),
    assignmentGroup: text(item.assignment_group, 200), priority: text(item.priority, 80), openedAt: text(item.opened_at, 40), updatedAt: text(item.sys_updated_on, 40),
    link: `${instance}/${table}.do?sys_id=${sysId}`,
  };
}

// Saved queries: Azure Table with read, add and delete (Storage Table Data Contributor on this one table only).
export function createQueryStore({ account, table, miToken, fetcher = fetch, now = () => Date.now() }) {
  const base = `https://${account}.table.core.windows.net`;
  const headers = async extra => ({ Authorization: `Bearer ${await miToken(STORAGE_RESOURCE)}`, 'x-ms-version': TABLE_VERSION, 'x-ms-date': new Date(now()).toUTCString(),
    Accept: 'application/json;odata=nometadata', DataServiceVersion: '3.0;', MaxDataServiceVersion: '3.0;NetFx', ...extra });
  const call = (url, init) => fetcher(url, { ...init, redirect: 'error', signal: AbortSignal.timeout(15000) });
  const fail = async (res, what) => new Error(`saved query ${what} failed: HTTP ${res.status} ${(await res.text().catch(() => '')).slice(0, 200).replace(/\s+/g, ' ')}`);
  return {
    async list() {
      const res = await call(`${base}/${table}()?$filter=${encodeURIComponent(`PartitionKey eq '${PARTITION}'`)}&$top=${MAX_SAVED}`, { headers: await headers() });
      if (res.status === 404) return [];
      if (!res.ok) throw await fail(res, 'list');
      return (await res.json()).value || [];
    },
    async insert(row) {
      const res = await call(`${base}/${table}`, { method: 'POST', headers: await headers({ 'Content-Type': 'application/json', Prefer: 'return-no-content' }), body: JSON.stringify(row) });
      if (!res.ok) throw await fail(res, 'save');
    },
    async remove(rowKey) {
      const res = await call(`${base}/${table}(PartitionKey='${PARTITION}',RowKey='${rowKey}')`, { method: 'DELETE', headers: await headers({ 'If-Match': '*' }) });
      if (res.status === 404) return false;
      if (!res.ok) throw await fail(res, 'delete');
      return true;
    },
  };
}

export function memoryQueryStore() {
  const rows = new Map();
  return { rows, list: async () => [...rows.values()], insert: async r => { rows.set(r.RowKey, { ...r }); }, remove: async k => rows.delete(k) };
}

// Reads a Key Vault secret with the managed identity token. Used for the ServiceNow password in local hosting.
export function keyVaultSecret({ vaultUri, name, miToken, fetcher = fetch }) {
  return async () => {
    const res = await fetcher(`${vaultUri.replace(/\/$/, '')}/secrets/${encodeURIComponent(name)}?api-version=7.4`, {
      headers: { Authorization: `Bearer ${await miToken(VAULT_RESOURCE)}` }, redirect: 'error', signal: AbortSignal.timeout(15000) });
    if (!res.ok) throw new Error(`Key Vault secret ${name} could not be read: HTTP ${res.status}`);
    const value = (await res.json())?.value;
    if (!value) throw new Error(`Key Vault secret ${name} is empty`);
    return value;
  };
}

export function createServiceNowSearch({ settings, store, github, requests, audit, password, preconfigured = [], fetcher = fetch, now = () => Date.now(), log = console }) {
  const configured = Boolean(settings?.configured);
  let secret = settings?.password ? Promise.resolve(settings.password) : null;
  const getPassword = () => {
    if (!secret) secret = Promise.resolve().then(password).catch(e => { secret = null; log.error?.(`servicenow password: ${e.message}`); throw expose(503, 'The ServiceNow password could not be read from Key Vault. Run tools/Set-R360ServiceNow.ps1.'); });
    return secret;
  };
  const must = (cond, status, msg) => { if (!cond) throw expose(status, msg); };
  const canWrite = roles => roles.some(r => ROLES.includes(r));

  async function snGet(path, params) {
    const qs = new URLSearchParams({ sysparm_display_value: 'true', sysparm_exclude_reference_link: 'true', sysparm_fields: FIELDS.join(','), ...params });
    let res;
    try {
      res = await fetcher(`${settings.instance}/api/now/table/${path}?${qs}`, { redirect: 'error', signal: AbortSignal.timeout(30000),
        headers: { Accept: 'application/json', Authorization: `Basic ${Buffer.from(`${settings.user}:${await getPassword()}`).toString('base64')}` } });
    } catch (e) {
      if (e.expose) throw e;
      throw expose(502, `ServiceNow could not be reached (${e.name === 'TimeoutError' ? 'timed out' : 'network error'}).`);
    }
    if (res.status === 401 || res.status === 403) throw expose(502, `ServiceNow refused the r360 service account (HTTP ${res.status}). Check SERVICENOW_USER and the password in Key Vault.`);
    if (res.status === 400) throw expose(400, 'ServiceNow rejected the query. Check the encoded query and the table.');
    if (res.status === 404) return null;
    if (!res.ok) throw expose(502, `ServiceNow returned HTTP ${res.status}.`);
    const body = await res.json().catch(() => null);
    if (!body || body.result === undefined) throw expose(502, 'ServiceNow returned an unexpected response.');
    return { result: body.result, total: Number(res.headers.get('x-total-count')) || null };
  }

  let issues = { at: 0, map: null };
  async function linkedIssues() {
    if (issues.map && now() - issues.at < ISSUE_TTL_MS) return issues.map;
    try {
      const rows = await github.listIssues({ label: CHANGE_LABEL, state: 'all', max: 100 });
      issues = { at: now(), map: issueIndex(rows) };
    } catch (e) {
      log.error?.(`servicenow issue lookup: ${e.message}`);
      return null;
    }
    return issues.map;
  }

  async function savedQueries() {
    if (!store) return [];
    const rows = await store.list();
    return rows.map(r => ({ id: `saved:${r.RowKey}`, kind: 'saved', name: r.name, table: r.table, query: r.query || '', createdBy: r.createdBy, createdAt: r.createdAt }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }

  async function queries(user, roles) {
    let saved = [], savedError = null;
    try { saved = await savedQueries(); } catch (e) { log.error?.(`servicenow saved queries: ${e.message}`); savedError = 'Saved queries could not be read.'; }
    return { configured, instance: settings?.instance || null, tables: SN_TABLES, preconfigured, saved, savedError, canSave: Boolean(store) && canWrite(roles), canCreateIssue: canWrite(roles) };
  }

  async function resolve(body) {
    const b = body && typeof body === 'object' ? body : {};
    const id = typeof b.queryId === 'string' ? b.queryId : '';
    if (id.startsWith('pre:')) { const q = preconfigured.find(p => p.id === id); must(q, 404, 'That preconfigured query no longer exists.'); return q; }
    if (id.startsWith('saved:')) { const q = (await savedQueries()).find(p => p.id === id); must(q, 404, 'That saved query no longer exists.'); return q; }
    return { id: null, kind: 'adhoc', name: '', ...validateQuery(b) };
  }

  async function search(user, body) {
    must(configured, 503, 'ServiceNow is not configured. Run tools/Set-R360ServiceNow.ps1 -Apply.');
    const q = await resolve(body);
    const free = cleanLine(body?.text, MAX_TEXT);
    must(q.query || free, 400, 'Enter search text, pick a query, or paste an encoded query.');
    const r = await snGet(q.table, { sysparm_query: encodedQuery({ query: q.query, text: free }), sysparm_limit: String(MAX_ROWS) });
    const items = Array.isArray(r?.result) ? r.result : [];
    const index = await linkedIssues();
    const rows = items.map(i => toRow(i, settings.instance, q.table)).filter(Boolean).map(row => ({ ...row, issue: index ? index.get(row.number) || null : undefined }));
    return { query: { id: q.id, kind: q.kind, name: q.name, table: q.table, query: q.query, actionTemplates: q.actionTemplates || [] }, text: free, rows,
      truncated: rows.length >= MAX_ROWS || (r?.total || 0) > rows.length, total: r?.total ?? rows.length, issueLookup: index ? 'ok' : 'GitHub issues could not be read, so the GitHub column is unknown.' };
  }

  async function saveQuery(user, roles, body) {
    must(store, 503, 'Saved queries are not set up. Run tools/Set-R360ServiceNow.ps1 -Apply.');
    must(canWrite(roles), 403, 'Your approvers.json role does not allow saving queries.');
    const v = validateQuery(body, { requireName: true });
    must(v.query, 400, 'Paste the encoded query to save.');
    const existing = await savedQueries();
    must(existing.length < MAX_SAVED, 409, `There are already ${MAX_SAVED} saved queries. Delete one first.`);
    must(!existing.some(q => q.name.toLowerCase() === v.name.toLowerCase()), 409, `A saved query named "${v.name}" already exists.`);
    const rowKey = randomBytes(8).toString('hex');
    await audit.record({ actorOid: user.oid, actorUpn: user.upn, action: 'servicenow.query.saved', target: v.name, result: 'intent', detail: { table: v.table, query: v.query } })
      .catch(e => { log.error?.(`servicenow.query.saved: audit failed: ${e.message}`); throw expose(503, 'The audit trail is unavailable, so the query was not saved.'); });
    await store.insert({ PartitionKey: PARTITION, RowKey: rowKey, name: v.name, table: v.table, query: v.query, createdBy: user.upn, createdAt: new Date(now()).toISOString() });
    await audit.record({ actorOid: user.oid, actorUpn: user.upn, action: 'servicenow.query.saved', target: v.name, result: 'ok' }).catch(e => log.error?.(`servicenow.query.saved: audit failed: ${e.message}`));
    return { id: `saved:${rowKey}`, kind: 'saved', name: v.name, table: v.table, query: v.query };
  }

  async function deleteQuery(user, roles, id) {
    must(store, 503, 'Saved queries are not set up.');
    must(canWrite(roles), 403, 'Your approvers.json role does not allow deleting queries.');
    must(/^saved:[0-9a-f]{16}$/.test(String(id)), 404, 'No such saved query.');
    const q = (await savedQueries()).find(p => p.id === id);
    must(q, 404, 'No such saved query.');
    await audit.record({ actorOid: user.oid, actorUpn: user.upn, action: 'servicenow.query.deleted', target: q.name, result: 'intent', detail: { table: q.table, query: q.query } })
      .catch(e => { log.error?.(`servicenow.query.deleted: audit failed: ${e.message}`); throw expose(503, 'The audit trail is unavailable, so the query was not deleted.'); });
    await store.remove(id.slice(6));
    await audit.record({ actorOid: user.oid, actorUpn: user.upn, action: 'servicenow.query.deleted', target: q.name, result: 'ok' }).catch(e => log.error?.(`servicenow.query.deleted: audit failed: ${e.message}`));
    return { deleted: id };
  }

  // Opens an r360 change request for one ServiceNow item. The item is read again from ServiceNow by sys_id, so the
  // browser cannot make r360 write arbitrary text; the title carries the ServiceNow number, which links them from then on.
  async function createIssue(user, roles, body) {
    must(configured, 503, 'ServiceNow is not configured.');
    must(canWrite(roles), 403, 'Your approvers.json role does not allow creating change requests.');
    const table = String(body?.table ?? ''), sysId = String(body?.sysId ?? '').toLowerCase();
    must(Object.hasOwn(SN_TABLES, table) && SYS_ID.test(sysId), 400, 'Pick a ServiceNow item.');
    const r = await snGet(`${table}/${sysId}`, {});
    const row = r?.result && !Array.isArray(r.result) ? toRow(r.result, settings.instance, table) : null;
    must(row && row.number, 404, 'That ServiceNow item was not found.');
    issues = { at: 0, map: null };
    const index = await linkedIssues();
    const linked = index?.get(row.number);
    must(!linked || linked.state !== 'open', 409, `${row.number} already has ${linked?.changeNumber}.`);
    const created = await requests.create(user, roles, {
      title: `${row.number}: ${row.shortDescription || 'ServiceNow item'}`.slice(0, 200),
      organization: row.assignmentGroup.length >= 2 ? row.assignmentGroup.slice(0, 120) : 'ServiceNow',
      description: `ServiceNow ${SN_TABLES[table].replace(/s$/, '').toLowerCase()} ${row.number}: ${row.link}\nState: ${row.state || 'unknown'}${row.assignmentGroup ? `\nAssignment group: ${row.assignmentGroup}` : ''}`,
    });
    issues = { at: 0, map: null };
    return { ...created, servicenowNumber: row.number };
  }

  return { configured, queries, search, saveQuery, deleteQuery, createIssue };
}
