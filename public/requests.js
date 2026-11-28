import { renderTable } from './table.js';
import { busy as busyButton, busyStatus, flash } from './busy.js';

// Change requests: get a change number, see open changes with their email counts, summarize, make actionable and close.
// The server decides and enforces everything. Summaries are shown as plain text (never as HTML). Links go only to github.com.
const GITHUB = 'https://github.com/';
const safeUrl = u => (typeof u === 'string' && u.startsWith(GITHUB) ? u : null);

// Paragraphs, "- " bullets and **bold** only, built as DOM text nodes: model output is never parsed as HTML.
export function renderSummary(el, text) {
  const inlineNodes = line => String(line).split(/(\*\*[^*]+\*\*)/).filter(Boolean).map(part => (/^\*\*[^*]+\*\*$/.test(part) ? el('strong', { textContent: part.slice(2, -2) }) : document.createTextNode(part)));
  const out = [];
  let list = null;
  for (const raw of String(text || '').split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) { list = null; continue; }
    if (/^[-*] /.test(line)) { if (!list) { list = el('ul'); out.push(list); } list.append(el('li', {}, ...inlineNodes(line.slice(2)))); continue; }
    list = null;
    out.push(el('p', {}, ...inlineNodes(line.replace(/^#{1,6}\s+/, ''))));
  }
  return out;
}

export function createRequestsUi({ el, pill, api, view, fmtTime }) {
  const link = (u, text) => (safeUrl(u) ? el('a', { href: u, target: '_blank', rel: 'noopener', textContent: text }) : el('span', { textContent: text }));
  const copyBtn = (text, label = 'Copy') => {
    const b = el('button', { className: 'btn', textContent: label, type: 'button' });
    b.onclick = async () => { try { await navigator.clipboard.writeText(text); flash(b, 'Copied'); } catch { flash(b, 'Copy failed: select the text and press Ctrl+C', 3000); } };
    return b;
  };
  const busy = (b, text, msg, fn) => busyStatus(b, text, msg, fn, el);

  function newForm(d, reload) {
    const title = el('input', { type: 'text', size: 60, maxLength: 200, placeholder: 'What is changing' });
    const org = el('input', { type: 'text', size: 40, maxLength: 120, placeholder: 'Who asked for it' });
    const desc = el('textarea', { rows: 3, cols: 80, maxLength: 4000, placeholder: 'Optional details' });
    const go = el('button', { className: 'btn', textContent: 'Get change number', type: 'button', disabled: !d.canWrite, title: d.canWrite ? '' : 'Your approvers.json role does not allow this.' });
    const msg = el('div', { role: 'status' });
    go.onclick = () => busy(go, 'Getting a change number…', msg, async () => {
      const r = await api('/api/requests', false, { method: 'POST', body: { title: title.value, organization: org.value, description: desc.value } });
      title.value = ''; org.value = ''; desc.value = '';
      msg.replaceChildren(el('div', { className: 'card request-new' },
        el('h2', { textContent: `${r.changeNumber} ` }, copyBtn(r.changeNumber, 'Copy number')),
        el('dl', { className: 'kv' }, ...[['Send emails to', el('span', {}, `${r.mailbox} `, copyBtn(r.mailbox))], ['Subject line', el('span', {}, `${r.subject} `, copyBtn(r.subject))], ['Tracked on', link(r.url, r.url)]]
          .flatMap(([k, v]) => [el('dt', { textContent: k }), el('dd', {}, v)])),
        el('p', { className: 'muted', textContent: `Any email to ${r.mailbox} with ${r.changeNumber} in the subject or body is tracked on this change.` }),
        r.warning ? el('p', { className: 'error', textContent: r.warning }) : null));
      reload();
    });
    return el('details', { className: 'request-form' }, // closed by default, like every section
      el('summary', { textContent: 'Get a change number' }),
      el('div', { className: 'form' },
        el('label', { className: 'field' }, el('span', { textContent: 'Title' }), title),
        el('label', { className: 'field' }, el('span', { textContent: 'Requesting organization' }), org),
        el('label', { className: 'field' }, el('span', { textContent: 'Description' }), desc)),
      el('div', { className: 'toolbar' }, go), msg);
  }

  function closePanel(row, panel, reload) {
    const reason = el('select', {}, el('option', { value: 'completed', textContent: 'Completed' }), el('option', { value: 'cancelled', textContent: 'Cancelled' }));
    const note = el('textarea', { rows: 2, cols: 70, maxLength: 2000, placeholder: 'Closing note (optional, posted on the issue)' });
    const go = el('button', { className: 'btn', textContent: `Close ${row.changeNumber}`, type: 'button' });
    const cancel = el('button', { className: 'btn', textContent: 'Keep open', type: 'button' });
    const msg = el('span', { role: 'status' });
    cancel.onclick = () => panel.replaceChildren();
    go.onclick = () => busy(go, `Closing ${row.changeNumber}…`, msg, async () => {
      await api(`/api/requests/${row.number}/close`, false, { method: 'POST', body: { reason: reason.value, note: note.value } });
      panel.replaceChildren(el('p', { className: 'ok', textContent: `${row.changeNumber} is closed.` }));
      reload();
    });
    panel.replaceChildren(el('div', { className: 'card' }, el('h2', { textContent: `Close ${row.changeNumber}: ${row.title}` }), el('div', { className: 'toolbar' }, reason), note, el('div', { className: 'toolbar' }, go, cancel, msg)));
  }

  function summaryPanel(row, panel, text, meta) {
    panel.replaceChildren(el('div', { className: 'card' },
      el('h2', { textContent: `${row.changeNumber}: ${row.title} ` }, meta?.url ? link(meta.url, 'on GitHub') : null),
      el('p', { className: 'muted', textContent: meta?.line || '' }),
      el('div', { className: 'summary-text' }, ...renderSummary(el, text))));
  }

  function table(d, holder, panel, reload) {
    const msg = el('div', { role: 'status' });
    const act = (row, label, busyText, path, after, extraBlock = null) => {
      const block = !d.canWrite ? 'Your approvers.json role does not allow this.' : !d.llmConfigured ? 'Needs an AI provider API key. Summarize now works without one.' : extraBlock;
      const b = el('button', { className: 'btn', textContent: label, type: 'button', disabled: Boolean(block), title: block || '' });
      b.onclick = () => busy(b, busyText, msg, async () => { const r = await api(`/api/requests/${row.number}/${path}`, false, { method: 'POST', body: {} }); msg.replaceChildren(); after(r); reload(false); });
      return b;
    };
    const rows = d.rows;
    holder.replaceChildren(msg, el('div'));
    renderTable(holder.lastChild, { rows, columns: [
      { key: 'changeNumber', label: 'Change', width: 130, render: r => link(r.url, r.changeNumber) },
      { key: 'title', label: 'Title', width: 260 },
      { key: 'organization', label: 'Organization', width: 160 },
      { key: 'emails', label: 'Emails', width: 70 },
      { key: 'lastEmailAt', label: 'Last email', width: 170, render: r => fmtTime(r.lastEmailAt) || 'none yet' },
      { key: 'summary', label: 'Summary', width: 190, render: r => {
        if (!r.summary) return el('span', { className: 'muted', textContent: 'none' });
        const b = el('button', { className: 'btn', type: 'button', textContent: `View (${fmtTime(r.summary.at)})` });
        b.onclick = () => { flash(b, 'Shown below'); summaryPanel(r, panel, r.summary.text, { url: r.summary.url, line: `Summary of ${r.summary.emails} email(s) by ${r.summary.model}, ${fmtTime(r.summary.at)}.${r.summary.emails < r.emails ? ' Newer emails arrived since: summarize again.' : ''}` }); };
        return b;
      } },
      { key: 'actions', label: 'Action items', width: 110, render: r => (r.actions ? link(r.actions.url, `${r.actions.count} item(s)`) : el('span', { className: 'muted', textContent: 'none' })) },
      { key: 'do', label: '', width: 400, render: r => el('span', { className: 'row-actions' },
        d.llmConfigured ? act(r, 'Summarize now', 'Summarizing…', 'summarize', x => summaryPanel(r, panel, x.summary, { url: x.url, line: `Summary of ${x.emails} email(s) by ${x.provider} ${x.model}, just now.${x.warning ? ` ${x.warning}` : ''}` }), r.emails ? null : 'No emails have arrived for this change yet.')
          // No API key yet: Summarize now labels the issue and the summary watcher posts the summary there within a minute.
          : r.summaryRequested ? el('span', { className: 'pill warn', textContent: 'Summary requested', title: 'The summary watcher posts it on the issue within about a minute.' })
            : (() => {
              const block = !d.canWrite ? 'Your approvers.json role does not allow this.' : !r.emails ? 'No emails have arrived for this change yet.' : null;
              const b = el('button', { className: 'btn', type: 'button', textContent: 'Summarize now', disabled: Boolean(block), title: block || 'Hands the change to Claude, which posts the summary on the issue within about a minute.' });
              b.onclick = () => busy(b, 'Requesting a summary…', msg, async () => { await api(`/api/requests/${r.number}/request-summary`, false, { method: 'POST', body: {} }); msg.replaceChildren(el('span', { className: 'ok', textContent: `Summary of ${r.changeNumber} requested. It appears here within about a minute.` })); reload(false); });
              return b;
            })(),
        act(r, 'Make actionable', 'Finding action items…', 'actions', x => panel.replaceChildren(el('div', { className: 'card' }, el('h2', { textContent: `${r.changeNumber}: action items ` }, link(x.url, 'on GitHub')),
          x.actions.length ? el('ul', {}, ...x.actions.map(a => el('li', { textContent: `${a.title}${a.owner ? ` (owner: ${a.owner})` : ''}${a.due ? ` (due ${a.due})` : ''}` }))) : el('p', { textContent: 'Nothing actionable in the emails.' }))), r.summary ? null : 'Summarize first.'),
        (() => { const b = el('button', { className: 'btn', type: 'button', textContent: 'Close', disabled: !d.canWrite }); b.onclick = () => { flash(b, 'Shown below'); closePanel(r, panel, reload); }; return b; })()) },
      { key: 'subject', label: 'Subject line to use', width: 300 },
      { key: 'createdAt', label: 'Opened', width: 170, render: r => fmtTime(r.createdAt) },
    ], empty: 'No open change requests.' });
  }

  let timer = null;
  function requests() {
    const body = el('div');
    const refresh = el('button', { className: 'btn', textContent: 'Refresh', type: 'button' });
    const check = el('button', { className: 'btn', textContent: 'Check mailbox now', type: 'button' });
    const stamp = el('span', { className: 'muted' });
    const panel = el('div', { className: 'request-panel' });
    // A reload after an action runs even while Refresh is busy; Refresh shows it is reading.
    const load = (clearPanel = true) => busyButton(refresh, 'Reading the mailbox…', async () => {
      if (clearPanel) panel.replaceChildren();
      body.replaceChildren(el('p', { className: 'muted', textContent: 'Reading the mailbox and GitHub...' }));
      try {
        const d = await api('/api/requests');
        stamp.textContent = d.fetchedAt ? `Loaded ${fmtTime(d.fetchedAt)}` : '';
        if (!d.enabled) { body.replaceChildren(el('p', { className: 'muted', textContent: 'Change requests are off. Run tools/Set-R360ChangeRequests.ps1 -Apply to turn them on.' })); return; }
        const info = d.syncError ? el('p', { className: 'error', textContent: d.syncError })
          : el('p', { className: 'muted', textContent: `Mailbox ${d.mailbox}${d.sync ? `: checked ${fmtTime(d.sync.at)}, ${d.sync.scanned} email(s) scanned${d.sync.added ? `, ${d.sync.added} new logged` : ''}${d.sync.truncated ? ' (scan limit reached)' : ''}` : ''}. Tracker: ${d.repo} issues labeled r360-change. ${d.llmConfigured ? `Summaries: ${d.provider} ${d.model || ''}.` : 'Summaries: handed to Claude (no API key yet). Summarize now marks the change and the summary appears here within about a minute. Make actionable turns on when the API key is added.'}` });
        const holder = el('div');
        body.replaceChildren(...[newForm(d, () => load(false)), info, d.sync?.error ? el('p', { className: 'error', textContent: d.sync.error }) : null, holder].filter(Boolean));
        table(d, holder, panel, load);
        // While a handed-off summary is pending, check again every 20 seconds so it shows up without a manual refresh.
        clearTimeout(timer);
        if (d.rows.some(r => r.summaryRequested)) timer = setTimeout(() => { if (body.isConnected) load(false); }, 20000);
      } catch (e) { body.replaceChildren(el('p', { className: 'error', textContent: e.message })); }
    }, { always: true });
    refresh.onclick = () => load();
    check.onclick = () => busyButton(check, 'Checking the mailbox…', async () => { try { await api('/api/requests/sync', false, { method: 'POST', body: {} }); await load(false); } catch (e) { stamp.textContent = e.message; } });
    view().replaceChildren(el('h1', { textContent: 'Change requests' }),
      el('p', { className: 'muted', textContent: 'Open changes tracked by email. Each change number is a GitHub issue; emails that carry the number are logged on it, summarized on request, and the change is closed here.' }),
      el('div', { className: 'toolbar' }, refresh, check, stamp), body, panel);
    load();
  }
  return { requests, stop: () => clearTimeout(timer) };
}
