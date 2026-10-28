import test from 'node:test';
import assert from 'node:assert/strict';
import { buildAuditRow, rowKeyFor, createAudit, toCsv, csvCell, blobPathFor, partitionFor } from '../server/audit.mjs';
import { loadConfig } from '../server/config.mjs';
import { ENV } from './fixtures.mjs';

const config = loadConfig(ENV);
const OID = '94540000-0000-4000-8000-0000000000c3';
const T0 = Date.parse('2026-10-26T18:30:00Z');

test('audit row: newest-first RowKey, UTC month partition, whitelisted fields only', () => {
  const a = buildAuditRow({ actorOid: OID, action: 'session.elevate' }, { now: T0 });
  const b = buildAuditRow({ actorOid: OID, action: 'session.elevate' }, { now: T0 + 1000 });
  assert.equal(a.PartitionKey, '202610');
  assert.ok(b.RowKey < a.RowKey, 'a later event sorts first');
  assert.match(a.RowKey, /^\d{13}-[0-9a-f-]{36}$/);
  assert.equal(partitionFor(Date.parse('2026-11-01T00:00:00Z')), '202611');
  assert.equal(blobPathFor(T0, 'k'), '2026/10/26/k.json');
  const row = buildAuditRow({ actorOid: OID, actorUpn: 'a@b', action: 'x.y', selfApproved: true, prNumber: '12', soakDays: 7, detail: { roles: ['author'] },
    accessToken: 'SECRET', refresh_token: 'SECRET', password: 'SECRET', secret: 'SECRET' }, { now: T0 });
  assert.equal(row.selfApproved, true); assert.equal(row.prNumber, 12); assert.equal(row.soakDays, 7); assert.equal(row.detail, '{"roles":["author"]}');
  assert.ok(!JSON.stringify(row).includes('SECRET'), 'unknown fields never reach the store');
});

test('audit row: JWT-looking values are redacted; bad events are refused', () => {
  const jwt = 'eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2ln';
  const row = buildAuditRow({ actorOid: OID, action: 'x', reason: `leaked ${jwt} here`, detail: `t=${jwt}` }, { now: T0 });
  assert.ok(!row.reason.includes('eyJ') && !row.detail.includes('eyJ'));
  assert.throws(() => buildAuditRow({ action: 'x' }), /actor/);
  assert.throws(() => buildAuditRow({ actorOid: OID, action: 'Bad Action' }), /action/);
  assert.throws(() => rowKeyFor(-1), /timestamp/);
  assert.ok(buildAuditRow({ actorOid: OID, action: 'x', reason: 'a'.repeat(9000) }, { now: T0 }).reason.length <= 4000);
});

const miToken = async r => { assert.equal(r, 'https://storage.azure.com/'); return 'ST'; };

test('record writes the table row, then an immutable-container blob; both with the managed identity token', async () => {
  const calls = [];
  const fetcher = async (url, init) => { calls.push({ url: String(url), init }); return new Response(null, { status: init.method === 'POST' ? 204 : 201 }); };
  const audit = createAudit({ config, miToken, fetcher, now: () => T0 });
  const row = await audit.record({ actorOid: OID, actorUpn: 'a@b', action: 'session.elevate', result: 'ok' });
  assert.equal(calls.length, 2);
  assert.equal(calls[0].url, 'https://str360test01.table.core.windows.net/r360audit');
  assert.equal(calls[0].init.headers.Authorization, 'Bearer ST');
  assert.equal(calls[0].init.headers['x-ms-version'], '2020-12-06');
  assert.equal(JSON.parse(calls[0].init.body).RowKey, row.RowKey);
  assert.equal(calls[1].url, `https://str360test01.blob.core.windows.net/r360audit-export/2026/10/26/${row.RowKey}.json`);
  assert.equal(calls[1].init.method, 'PUT');
  assert.equal(calls[1].init.headers['If-None-Match'], '*', 'never overwrites');
  assert.equal(calls[1].init.headers['x-ms-blob-type'], 'BlockBlob');
  assert.deepEqual(JSON.parse(calls[1].init.body), row);
  assert.ok(!('x-ms-blob-public-access' in calls[1].init.headers));
});

test('audit fails closed: a failed table insert or blob export throws (and the table insert failing skips the blob)', async () => {
  let calls = [];
  const tableDown = createAudit({ config, miToken, now: () => T0, fetcher: async (url, init) => { calls.push(String(url)); return new Response('denied', { status: 403 }); } });
  await assert.rejects(tableDown.record({ actorOid: OID, action: 'x' }), e => e.audit === true && /table insert failed: HTTP 403/.test(e.message));
  assert.equal(calls.length, 1);
  calls = [];
  const blobDown = createAudit({ config, miToken, now: () => T0, fetcher: async (url, init) => { calls.push(init.method); return init.method === 'POST' ? new Response(null, { status: 204 }) : new Response('conflict', { status: 409 }); } });
  await assert.rejects(blobDown.record({ actorOid: OID, action: 'x' }), e => e.audit === true && /blob export failed: HTTP 409/.test(e.message));
  const unreachable = createAudit({ config, miToken, now: () => T0, fetcher: async () => { throw new Error('ECONNRESET'); } });
  await assert.rejects(unreachable.record({ actorOid: OID, action: 'x' }), e => e.audit === true && /unreachable/.test(e.message));
});

test('list: month partitions, server-side filters, continuation, target substring, cap', async () => {
  const urls = [];
  const mk = (n, extra = {}) => Array.from({ length: n }, (_, i) => ({ action: 'session.end', target: `t${i}`, ...extra }));
  const fetcher = async url => {
    urls.push(decodeURIComponent(String(url)));
    if (urls.length === 1) return new Response(JSON.stringify({ value: mk(2) }), { status: 200, headers: { 'x-ms-continuation-NextPartitionKey': 'PK', 'x-ms-continuation-NextRowKey': 'RK' } });
    return new Response(JSON.stringify({ value: [{ action: 'session.end', target: 'WRITE-session' }] }), { status: 200 });
  };
  const audit = createAudit({ config, miToken, fetcher, now: () => T0 });
  const { rows, truncated } = await audit.list({ from: Date.parse('2026-09-15T00:00:00Z'), to: T0, actions: ['session.end', 'session.elevate'], actor: "o'brien@x.com", target: 't1' });
  assert.equal(truncated, false);
  assert.equal(urls.length, 3, 'two partitions (Oct, Sep) plus one continuation page');
  assert.match(urls[0], /PartitionKey eq '202610'/); assert.match(urls[2], /PartitionKey eq '202609'/);
  assert.match(urls[0], /\(action eq 'session\.end' or action eq 'session\.elevate'\)/);
  assert.match(urls[0], /actorUpn eq 'o''brien@x\.com'/);
  assert.match(urls[1], /NextPartitionKey=PK&NextRowKey=RK/);
  assert.deepEqual(rows.map(r => r.target), ['t1'], 'target filter is a case-insensitive substring');
  const capped = await createAudit({ config, miToken, now: () => T0, fetcher: async () => new Response(JSON.stringify({ value: mk(5) }), { status: 200 }) }).list({ limit: 3 });
  assert.equal(capped.rows.length, 3); assert.equal(capped.truncated, true);
  await assert.rejects(audit.list({ actions: ["x' or 1 eq 1 or action eq 'y"] }), /Invalid action/);
  await assert.rejects(audit.list({ actor: "a' or 'b" }), /Invalid actor/);
  await assert.rejects(createAudit({ config, miToken, now: () => T0, fetcher: async () => new Response('x', { status: 500 }) }).list({}), e => e.audit === true);
});

test('csv export guards spreadsheet formulas and quotes', () => {
  assert.equal(csvCell('=HYPERLINK("x")'), '"\'=HYPERLINK(""x"")"');
  assert.equal(csvCell('a,b'), '"a,b"'); assert.equal(csvCell(undefined), ''); assert.equal(csvCell('@x'), "'@x");
  const csv = toCsv([{ at: 'now', action: 'session.end', actorUpn: 'a@b', reason: '+1' }]);
  assert.match(csv, /^at,action,result,actorUpn/); assert.match(csv, /now,session\.end,,a@b,,,'\+1/);
});
