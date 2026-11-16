import { renderTable } from './table.js';

// ServiceNow search: pick a preconfigured or saved query, or paste ServiceNow's encoded query, add free text, and see for
// each item the r360 change request (GitHub issue) that mentions its number. The server decides and enforces everything.
const GITHUB = 'https://github.com/';

export function createServiceNowUi({ el, api, view, fmtTime }) {
  let meta = null;

  const safeLink = (u, prefix, text) => (typeof u === 'string' && prefix && u.startsWith(prefix) ? el('a', { href: u, target: '_blank', rel: 'noopener', textContent: text }) : el('span', { textContent: text }));
  const busy = async (b, msg, fn) => {
    b.disabled = true; msg.replaceChildren(el('span', { className: 'muted', textContent: 'Working...' }));
    try { await fn(); } catch (e) { msg.replaceChildren(el('span', { className: 'error', textContent: e.message })); } finally { b.disabled = false; }
  };
  const allQueries = () => [...(meta?.preconfigured || []), ...(meta?.saved || [])];

  function picker() {
    const sel = el('select', {}, el('option', { value: '', textContent: 'Custom: free text or a pasted encoded query' }));
    const group = (label, rows) => {
      const g = el('optgroup', { label });
      if (!rows.length) g.append(el('option', { disabled: true, textContent: label === 'Saved' ? 'None saved yet' : 'None yet' }));
      for (const q of rows) g.append(el('option', { value: q.id, textContent: q.name }));
      return g;
    };
    sel.append(group('Preconfigured', meta.preconfigured || []), group('Saved', meta.saved || []));
    return sel;
  }

  function results(host, d) {
    const instance = meta.instance ? `${meta.instance}/` : null;
    const msg = el('div', { role: 'status' });
    const head = el('p', { className: 'muted', textContent: `${d.rows.length} item(s)${d.truncated ? ` of ${d.total || 'more'}; showing the ${d.rows.length} most recently updated. Narrow the query to see the rest.` : ''}${d.query.name ? ` from "${d.query.name}"` : ''}.` });
    const templates = d.query.kind === 'preconfigured' ? el('p', { className: 'muted', textContent: d.query.actionTemplates.length ? `Action templates for this query: ${d.query.actionTemplates.join(', ')} (coming soon).` : 'No action templates for this query yet.' }) : null;
    const issueCell = r => {
      if (r.issue === undefined) return el('span', { className: 'muted', textContent: 'unknown' });
      if (r.issue) return el('span', {}, safeLink(r.issue.url, GITHUB, r.issue.changeNumber), el('span', { className: 'muted', textContent: r.issue.state === 'open' ? '' : ' (closed)' }));
      const b = el('button', { className: 'btn', type: 'button', textContent: 'Create issue', disabled: !meta.canCreateIssue, title: meta.canCreateIssue ? `Open an r360 change request for ${r.number}` : 'Your approvers.json role does not allow this.' });
      b.onclick = () => busy(b, msg, async () => {
        const c = await api('/api/servicenow/issue', false, { method: 'POST', body: { table: r.table, sysId: r.sysId } });
        r.issue = { number: c.number, changeNumber: c.changeNumber, url: c.url, state: 'open' };
        b.replaceWith(safeLink(c.url, GITHUB, c.changeNumber));
        msg.replaceChildren(el('span', { className: 'ok', textContent: `${c.changeNumber} opened for ${r.number}.${c.warning ? ` ${c.warning}` : ''}` }));
      });
      return b;
    };
    const table = el('div');
    host.replaceChildren(head, templates, d.issueLookup !== 'ok' ? el('p', { className: 'error', textContent: d.issueLookup }) : null, msg, table);
    renderTable(table, { rows: d.rows, empty: 'Nothing in ServiceNow matches.', columns: [
      { key: 'number', label: 'Number', width: 130, render: r => safeLink(r.link, instance, r.number) },
      { key: 'shortDescription', label: 'Short description', width: 320 },
      { key: 'state', label: 'State', width: 120 },
      { key: 'assignmentGroup', label: 'Assignment group', width: 180 },
      { key: 'updatedAt', label: 'Updated', width: 150 },
      { key: 'issue', label: 'GitHub issue', width: 160, render: issueCell },
    ] });
  }

  async function page() {
    const host = view();
    host.replaceChildren(el('h1', { textContent: 'ServiceNow' }), el('p', { className: 'muted', textContent: 'Loading...' }));
    try { meta = await api('/api/servicenow/queries'); } catch (e) { host.replaceChildren(el('h1', { textContent: 'ServiceNow' }), el('p', { className: 'error', textContent: e.message })); return; }
    const intro = el('p', { className: 'muted', textContent: 'Search ServiceNow and see whether each item already has an r360 change request on GitHub. Read-only: nothing changes in ServiceNow.' });
    if (!meta.configured) {
      host.replaceChildren(el('h1', { textContent: 'ServiceNow' }), intro, el('p', { className: 'error', textContent: 'ServiceNow is not configured. On DEVICE02 run tools\\Set-R360ServiceNow.ps1 -Apply, then tools\\Install-R360Local.ps1 -Update -Apply.' }));
      return;
    }
    const sel = picker();
    const table = el('select', {}, ...Object.entries(meta.tables).map(([k, v]) => el('option', { value: k, textContent: v })));
    const query = el('input', { type: 'text', title: 'Encoded query', size: 60, maxLength: 2000, placeholder: 'Encoded query (optional): in ServiceNow, right-click the filter breadcrumb, Copy query' });
    const text = el('input', { type: 'search', title: 'Free text', size: 30, maxLength: 100, placeholder: 'Free text: number or description' });
    const go = el('button', { className: 'btn', type: 'button', textContent: 'Search' });
    const name = el('input', { type: 'text', size: 30, maxLength: 80, placeholder: 'Name for this query' });
    const save = el('button', { className: 'btn', type: 'button', textContent: 'Save query' });
    const del = el('button', { className: 'btn', type: 'button', textContent: 'Delete saved query' });
    const about = el('p', { className: 'muted' });
    const msg = el('div', { role: 'status' });
    const out = el('div');
    const saveRow = el('div', { className: 'toolbar' }, name, save);
    const sync = () => {
      const q = allQueries().find(x => x.id === sel.value);
      table.disabled = Boolean(q); query.readOnly = Boolean(q);
      if (q) { table.value = q.table; query.value = q.query; }
      about.textContent = q ? (q.kind === 'preconfigured' ? `${q.description || 'Preconfigured query'} Kept in config/servicenow-queries.json.` : `Saved by ${q.createdBy} ${fmtTime(q.createdAt)}.`) : '';
      saveRow.hidden = Boolean(q) || !meta.canSave;
      del.hidden = !(q && q.kind === 'saved' && meta.canSave);
    };
    sel.onchange = () => { if (!sel.value) query.value = ''; sync(); };
    const run = () => busy(go, msg, async () => {
      const body = sel.value ? { queryId: sel.value, text: text.value } : { table: table.value, query: query.value, text: text.value };
      const d = await api('/api/servicenow/search', false, { method: 'POST', body });
      msg.replaceChildren();
      results(out, d);
    });
    go.onclick = run;
    text.onkeydown = e => { if (e.key === 'Enter') run(); };
    save.onclick = () => busy(save, msg, async () => {
      const q = await api('/api/servicenow/queries', false, { method: 'POST', body: { name: name.value, table: table.value, query: query.value } });
      meta.saved = [...meta.saved, q].sort((a, b) => a.name.localeCompare(b.name));
      const keep = q.id; const fresh = picker(); sel.replaceChildren(...fresh.childNodes); sel.value = keep; name.value = ''; sync();
      msg.replaceChildren(el('span', { className: 'ok', textContent: `Saved "${q.name}".` }));
    });
    del.onclick = () => busy(del, msg, async () => {
      const q = allQueries().find(x => x.id === sel.value);
      await api('/api/servicenow/queries/delete', false, { method: 'POST', body: { id: sel.value } });
      meta.saved = meta.saved.filter(x => x.id !== q.id);
      const fresh = picker(); sel.replaceChildren(...fresh.childNodes); sel.value = ''; query.value = ''; sync();
      msg.replaceChildren(el('span', { className: 'ok', textContent: `Deleted "${q.name}".` }));
    });
    host.replaceChildren(el('h1', { textContent: 'ServiceNow' }), intro,
      el('div', { className: 'toolbar' }, el('label', { className: 'field' }, el('span', { textContent: 'Query' }), sel), el('label', { className: 'field' }, el('span', { textContent: 'Table' }), table)),
      el('div', { className: 'toolbar' }, query), about,
      el('div', { className: 'toolbar' }, text, go, del), saveRow,
      meta.savedError ? el('p', { className: 'error', textContent: meta.savedError }) : null, msg, out);
    sync();
  }

  return { page };
}
