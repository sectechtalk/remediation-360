import { randomUUID } from 'node:crypto';

// Append-only audit trail. Every event is written twice, and an action is only allowed to proceed when BOTH writes succeed:
//   1. Azure Table (query + Audit page). The managed identity holds a custom role with read + add only (no update/delete).
//   2. A JSON blob in an immutable container (365-day WORM policy), one blob per event, for evidence export.
// Authentication is the managed identity (resource https://storage.azure.com/). No account key or SAS exists.
export const STORAGE_RESOURCE = 'https://storage.azure.com/';
const TABLE_VERSION = '2020-12-06';
const BLOB_VERSION = '2022-11-02';
const MAX_FIELD = 4000;
const MAX_EPOCH = 9999999999999;

export const ACTIONS = ['session.signin', 'session.elevate', 'session.elevate.denied', 'session.end', 'change.proposed', 'change.updated', 'change.discarded',
  'change.approved', 'change.approval.denied', 'change.rejected', 'change.branchupdated', 'change.merged', 'sign.verified', 'sign.verify.failed', 'publish.canary', 'publish.denied', 'promote.proposed', 'promote.denied', 'publish.production'];

// Only these fields are ever persisted. Anything else on an event is dropped, so a token or secret that ends up on an
// event object by mistake cannot reach the audit store.
const FIELDS = ['actorOid', 'actorUpn', 'approverOid', 'selfApproved', 'action', 'target', 'gitSha', 'prNumber', 'requestId',
  'graphRequestId', 'githubRequestId', 'pimInstance', 'pimState', 'acrs', 'result', 'reason', 'soakDays', 'mode', 'sessionUntil', 'toTarget', 'detail'];
const BOOLEAN_FIELDS = new Set(['selfApproved']);
const NUMBER_FIELDS = new Set(['prNumber', 'soakDays']);
const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g;

const clean = v => String(v).replace(JWT, '[redacted]').replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, MAX_FIELD);

export function rowKeyFor(epochMs, id = randomUUID()) {
  if (!Number.isInteger(epochMs) || epochMs < 0 || epochMs > MAX_EPOCH) throw new Error('Invalid audit timestamp');
  // Newest first: a table scan of one partition returns the latest event first.
  return `${String(MAX_EPOCH - epochMs).padStart(13, '0')}-${id}`;
}
export const partitionFor = epochMs => { const d = new Date(epochMs); return `${d.getUTCFullYear()}${String(d.getUTCMonth() + 1).padStart(2, '0')}`; };
export const blobPathFor = (epochMs, rowKey) => { const d = new Date(epochMs); return `${d.getUTCFullYear()}/${String(d.getUTCMonth() + 1).padStart(2, '0')}/${String(d.getUTCDate()).padStart(2, '0')}/${rowKey}.json`; };

export function buildAuditRow(event, { now = Date.now(), id } = {}) {
  if (!event || typeof event.action !== 'string' || !/^[a-z0-9]+(\.[a-z0-9]+)*$/.test(event.action)) throw new Error('Audit event needs a valid action');
  if (!event.actorOid) throw new Error('Audit event needs an actor');
  const row = { PartitionKey: partitionFor(now), RowKey: rowKeyFor(now, id), at: new Date(now).toISOString() };
  for (const k of FIELDS) {
    let v = event[k];
    if (v === undefined || v === null || v === '') continue;
    if (BOOLEAN_FIELDS.has(k)) row[k] = v === true;
    else if (NUMBER_FIELDS.has(k)) { if (Number.isFinite(Number(v))) row[k] = Number(v); }
    else if (typeof v === 'object') row[k] = clean(JSON.stringify(v));
    else row[k] = clean(v);
  }
  return row;
}

export function createAudit({ config, miToken, fetcher = fetch, now = () => Date.now(), log = console }) {
  const tableBase = `https://${config.auditAccount}.table.core.windows.net`;
  const blobBase = `https://${config.auditAccount}.blob.core.windows.net`;
  const headers = async (version, extra = {}) => ({ Authorization: `Bearer ${await miToken(STORAGE_RESOURCE)}`, 'x-ms-version': version, 'x-ms-date': new Date(now()).toUTCString(), ...extra });
  const call = async (url, init, what) => {
    let res;
    try { res = await fetcher(url, { ...init, redirect: 'error', signal: AbortSignal.timeout(15000) }); }
    catch (e) { throw Object.assign(new Error(`audit ${what} unreachable: ${e.message}`), { audit: true }); }
    return res;
  };
  const fail = async (res, what) => {
    const detail = (await res.text().catch(() => '')).slice(0, 200).replace(/\s+/g, ' ');
    return Object.assign(new Error(`audit ${what} failed: HTTP ${res.status} ${detail}`), { audit: true });
  };

  return {
    // Writes one event to the table and to an immutable blob. Throws (error.audit = true) when either fails; callers must
    // treat that as "the action did not happen".
    async record(event) {
      const t = now();
      const row = buildAuditRow(event, { now: t });
      const tbl = await call(`${tableBase}/${config.auditTable}`, {
        method: 'POST',
        headers: await headers(TABLE_VERSION, { 'Content-Type': 'application/json', Accept: 'application/json;odata=nometadata', Prefer: 'return-no-content', DataServiceVersion: '3.0;', MaxDataServiceVersion: '3.0;NetFx' }),
        body: JSON.stringify(row),
      }, 'table insert');
      if (!tbl.ok) throw await fail(tbl, 'table insert');
      const body = JSON.stringify(row);
      const blob = await call(`${blobBase}/${config.auditContainer}/${blobPathFor(t, row.RowKey)}`, {
        method: 'PUT',
        headers: await headers(BLOB_VERSION, { 'x-ms-blob-type': 'BlockBlob', 'Content-Type': 'application/json', 'If-None-Match': '*' }),
        body,
      }, 'blob export');
      if (!blob.ok) throw await fail(blob, 'blob export');
      return row;
    },

    // Newest-first query. Time range, action list and actor are applied by the table; target by substring here.
    async list({ from, to, actions, actor, target, limit = 500 } = {}) {
      const toMs = Number.isFinite(to) ? to : now();
      const fromMs = Number.isFinite(from) ? from : toMs - 30 * 86400000;
      if (fromMs > toMs) return { rows: [], truncated: false };
      const cap = Math.min(Math.max(1, Math.trunc(limit) || 500), 2000);
      const months = [];
      for (let d = new Date(Date.UTC(new Date(toMs).getUTCFullYear(), new Date(toMs).getUTCMonth(), 1)); d.getTime() >= Date.UTC(new Date(fromMs).getUTCFullYear(), new Date(fromMs).getUTCMonth(), 1) && months.length < 24; d.setUTCMonth(d.getUTCMonth() - 1)) months.push(partitionFor(d.getTime()));
      const rows = [];
      let truncated = false;
      const lo = rowKeyFor(Math.min(toMs, MAX_EPOCH)).slice(0, 13);
      const hi = rowKeyFor(Math.max(fromMs, 0)).slice(0, 13);
      for (const pk of months) {
        const parts = [`PartitionKey eq '${pk}'`, `RowKey ge '${lo}'`, `RowKey le '${hi}~'`];
        if (actions?.length) parts.push(`(${actions.map(a => { if (!/^[a-z0-9.]+$/.test(a)) throw new Error('Invalid action filter'); return `action eq '${a}'`; }).join(' or ')})`);
        if (actor) { if (!/^[\w.@+'-]{1,200}$/.test(actor)) throw new Error('Invalid actor filter'); parts.push(`actorUpn eq '${actor.replace(/'/g, "''")}'`); }
        let next = '';
        do {
          const url = `${tableBase}/${config.auditTable}()?$filter=${encodeURIComponent(parts.join(' and '))}&$top=${Math.min(1000, cap)}${next}`;
          const res = await call(url, { headers: await headers(TABLE_VERSION, { Accept: 'application/json;odata=nometadata', DataServiceVersion: '3.0;', MaxDataServiceVersion: '3.0;NetFx' }) }, 'table query');
          if (!res.ok) throw await fail(res, 'table query');
          for (const r of (await res.json()).value || []) {
            if (target && !String(r.target || '').toLowerCase().includes(String(target).toLowerCase())) continue;
            rows.push(r);
            if (rows.length >= cap) { truncated = true; break; }
          }
          const npk = res.headers.get('x-ms-continuation-NextPartitionKey'), nrk = res.headers.get('x-ms-continuation-NextRowKey');
          next = npk ? `&NextPartitionKey=${encodeURIComponent(npk)}${nrk ? `&NextRowKey=${encodeURIComponent(nrk)}` : ''}` : '';
        } while (next && !truncated);
        if (truncated) break;
      }
      return { rows, truncated };
    },
  };
}

const CSV_COLUMNS = ['at', 'action', 'result', 'actorUpn', 'actorOid', 'target', 'reason', 'approverOid', 'selfApproved', 'gitSha', 'prNumber', 'requestId',
  'graphRequestId', 'githubRequestId', 'pimInstance', 'pimState', 'acrs', 'soakDays', 'mode', 'sessionUntil', 'toTarget', 'detail', 'RowKey'];
export const csvCell = v => {
  let s = v === undefined || v === null ? '' : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`; // spreadsheet formula guard
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};
export const toCsv = rows => [CSV_COLUMNS.join(','), ...rows.map(r => CSV_COLUMNS.map(c => csvCell(r[c])).join(','))].join('\r\n') + '\r\n';
