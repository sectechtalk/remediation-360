import test from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

// Drives public/servicenow.js in jsdom with a fake API: query picker, search results with the GitHub column, Create issue, save.
const dom = new JSDOM('<!doctype html><main id="view"></main>', { url: 'http://localhost:3660/' });
globalThis.window = dom.window; globalThis.document = dom.window.document;
for (const k of ['HTMLElement', 'Node', 'Event', 'KeyboardEvent', 'MouseEvent']) globalThis[k] = dom.window[k];
const { createServiceNowUi } = await import('../public/servicenow.js');
const el = (tag, props = {}, ...kids) => { const e = Object.assign(document.createElement(tag), props); e.append(...kids.filter(k => k != null)); return e; };
const tick = () => new Promise(r => setTimeout(r, 0));
const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];

const META = { configured: true, instance: 'https://contoso.service-now.com', tables: { sc_req_item: 'Requested items', incident: 'Incidents' },
  preconfigured: [{ id: 'pre:certificate-revocations', kind: 'preconfigured', name: 'Certificate revocations', table: 'sc_req_item', query: 'cat_item.name=Certificate Revocation^active=true', description: 'Active revocations.', actionTemplates: [] }],
  saved: [], savedError: null, canSave: true, canCreateIssue: true };
const row = (n, issue) => ({ sysId: String(n).repeat(32), table: 'sc_req_item', number: `RITM001000${n}`, shortDescription: `Item ${n}`, state: 'Open', assignmentGroup: 'PKI', updatedAt: '2026-11-14', link: `https://contoso.service-now.com/sc_req_item.do?sys_id=${n}`, issue });

test('picker lists preconfigured and saved queries; results link existing issues and Create issue opens one', async () => {
  const calls = [];
  const api = async (path, refresh, init = {}) => {
    calls.push({ path, body: init.body });
    if (path === '/api/servicenow/queries' && !init.method) return META;
    if (path === '/api/servicenow/search') return { query: { ...META.preconfigured[0] }, text: '', rows: [row(1, { number: 50, changeNumber: 'R360-CHG-50', url: 'https://github.com/your-org/r360/issues/50', state: 'open' }), row(2, null)], truncated: false, total: 2, issueLookup: 'ok' };
    if (path === '/api/servicenow/issue') return { number: 51, changeNumber: 'R360-CHG-51', url: 'https://github.com/your-org/r360/issues/51' };
    if (path === '/api/servicenow/queries') return { id: 'saved:0123456789abcdef', kind: 'saved', name: init.body.name, table: init.body.table, query: init.body.query, createdBy: 'admin@contoso.com', createdAt: '2026-11-15T16:00:00Z' };
    throw new Error(`unexpected ${path}`);
  };
  const ui = createServiceNowUi({ el, api, view: () => $('#view'), fmtTime: v => v });
  await ui.page();
  const sel = $('#view select');
  assert.deepEqual([...sel.querySelectorAll('optgroup')].map(g => g.label), ['Preconfigured', 'Saved']);
  assert.ok([...sel.options].some(o => o.textContent === 'Certificate revocations'));
  sel.value = 'pre:certificate-revocations'; sel.dispatchEvent(new Event('change'));
  const query = $('input[title="Encoded query"]');
  assert.equal(query.value, 'cat_item.name=Certificate Revocation^active=true');
  assert.equal(query.readOnly, true);
  $$('button').find(b => b.textContent === 'Search').click(); await tick(); await tick();
  assert.deepEqual(calls.at(-1), { path: '/api/servicenow/search', body: { queryId: 'pre:certificate-revocations', text: '' } });
  assert.ok($$('a').some(a => a.textContent === 'R360-CHG-50' && a.href === 'https://github.com/your-org/r360/issues/50'));
  assert.ok($$('a').some(a => a.textContent === 'RITM0010001' && a.href.startsWith('https://contoso.service-now.com/')));
  assert.match($('#view').textContent, /No action templates for this query yet/);
  $$('button').find(b => b.textContent === 'Create issue').click(); await tick(); await tick();
  assert.deepEqual(calls.at(-1).body, { table: 'sc_req_item', sysId: '2'.repeat(32) });
  assert.ok($$('a').some(a => a.textContent === 'R360-CHG-51'));

  sel.value = ''; sel.dispatchEvent(new Event('change'));
  assert.equal(query.readOnly, false);
  query.value = 'active=true';
  $('input[placeholder="Name for this query"]').value = 'All active';
  $$('button').find(b => b.textContent === 'Save query').click(); await tick(); await tick();
  assert.equal(calls.at(-1).body.name, 'All active');
  assert.equal(sel.value, 'saved:0123456789abcdef');
  assert.ok(!$$('button').find(b => b.textContent === 'Delete saved query').hidden);
});

test('not configured: the page says which script to run', async () => {
  const ui = createServiceNowUi({ el, api: async () => ({ ...META, configured: false }), view: () => $('#view'), fmtTime: v => v });
  await ui.page();
  assert.match($('#view').textContent, /Set-R360ServiceNow\.ps1 -Apply/);
});
