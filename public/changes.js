import { renderTable } from './table.js';

// Authoring UI (S3): the New/Edit form, the diff preview, and the Changes tab. The server enforces everything; this only
// collects input and shows state. No inline script or style (CSP), one button style (.btn).
export const GITHUB = 'https://github.com/';
const POLL_MS = 10000;
// Node.replaceChildren turns a null argument into the text "null", so drop empty entries first.
const nodes = list => list.filter(k => k != null && k !== false);
const safeUrl = u => (typeof u === 'string' && u.startsWith(GITHUB) ? u : null);

// Line diff. Common head and tail are trimmed first; very large middles fall back to "replaced".
export function diffLines(a, b) {
  const x = a.split('\n'), y = b.split('\n');
  let s = 0;
  while (s < x.length && s < y.length && x[s] === y[s]) s++;
  let ex = x.length, ey = y.length;
  while (ex > s && ey > s && x[ex - 1] === y[ey - 1]) { ex--; ey--; }
  const mid = [];
  const mx = x.slice(s, ex), my = y.slice(s, ey);
  if (mx.length * my.length > 4e6) { mx.forEach(t => mid.push(['-', t])); my.forEach(t => mid.push(['+', t])); }
  else {
    const L = Array.from({ length: mx.length + 1 }, () => new Uint32Array(my.length + 1));
    for (let i = mx.length - 1; i >= 0; i--) for (let j = my.length - 1; j >= 0; j--) L[i][j] = mx[i] === my[j] ? L[i + 1][j + 1] + 1 : Math.max(L[i + 1][j], L[i][j + 1]);
    let i = 0, j = 0;
    while (i < mx.length && j < my.length) {
      if (mx[i] === my[j]) { mid.push([' ', mx[i]]); i++; j++; }
      else if (L[i + 1][j] >= L[i][j + 1]) mid.push(['-', mx[i++]]);
      else mid.push(['+', my[j++]]);
    }
    while (i < mx.length) mid.push(['-', mx[i++]]);
    while (j < my.length) mid.push(['+', my[j++]]);
  }
  return [...x.slice(0, s).map(t => [' ', t]), ...mid, ...x.slice(ex).map(t => [' ', t])];
}

const DEFAULT_META = { displayName: '', description: '', publisher: 'SecTechTalk', runAs: 'system', runAs32Bit: false, enforceSignatureCheck: true,
  schedule: { type: 'daily', interval: 1, time: '02:00:00' }, assignment: { runRemediationScript: true } };

export function createChangesUi({ el, pill, api, view, fmtTime, session }) {
  let poll = null;
  const stop = () => { clearInterval(poll); poll = null; };
  const go = hash => { location.hash = hash; };
  const canAuthor = () => session.me?.write?.active && session.me.roles.some(r => r === 'author' || r === 'admin');
  const authorBlock = () => !session.me?.write?.active ? 'Start a write session first (Elevate to write).' : !session.me.roles.some(r => r === 'author' || r === 'admin') ? 'Your role does not allow authoring.' : null;

  // A link styled as a button that is inert (greyed, with the reason) when the user may not author.
  const authorLink = (href, text) => {
    const block = authorBlock();
    const a = el('a', { className: 'btn', href, textContent: text, title: block || '' });
    if (block) { a.setAttribute('aria-disabled', 'true'); a.onclick = ev => ev.preventDefault(); }
    return a;
  };
  const field = (label, input, hint) => el('label', { className: 'field' }, el('span', { textContent: label }), input, hint ? el('small', { className: 'muted', textContent: hint }) : null);
  const check = (checked) => el('input', { type: 'checkbox', checked: !!checked });

  function diffView(path, before, after) {
    const rows = diffLines(before ?? '', after).filter(([k]) => k !== ' ');
    const pre = el('pre', { className: 'diff' });
    if (!rows.length) { pre.textContent = '(no changes)'; return el('div', {}, el('h3', { textContent: path }), pre); }
    const full = diffLines(before ?? '', after);
    const shown = full.length > 600 ? full.filter(([k]) => k !== ' ') : full;
    for (const [k, t] of shown.slice(0, 600)) pre.append(el('div', { className: k === '+' ? 'add' : k === '-' ? 'del' : 'ctx', textContent: `${k} ${t}` }));
    if (shown.length > 600) pre.append(el('div', { className: 'muted', textContent: `... ${shown.length - 600} more lines not shown` }));
    return el('div', {}, el('h3', { textContent: path }), pre);
  }

  // mode: 'new' | 'edit' (a remediation on main) | 'update' (an open change)
  async function form(mode, key) {
    stop();
    const title = mode === 'new' ? 'New remediation' : mode === 'edit' ? `Edit remediation ${key}` : `Update change #${key}`;
    view().replaceChildren(el('h1', { textContent: title }), el('p', { className: 'muted', textContent: 'Loading...' }));
    const block = authorBlock();
    let src = null, headSha = null, folder = mode === 'new' ? '' : key;
    try {
      if (mode === 'edit') src = await api(`/api/changes/source/${encodeURIComponent(key)}`);
      if (mode === 'update') { src = await api(`/api/changes/${Number(key)}/source`); folder = src.folder; headSha = src.headSha; }
    } catch (e) { view().replaceChildren(el('h1', { textContent: title }), el('p', { className: 'error', textContent: e.message })); return; }
    const m = src?.meta || DEFAULT_META;
    const sch = m.schedule || {};
    const f = {
      folder: el('input', { type: 'text', value: folder, size: 30, disabled: mode !== 'new', placeholder: 'My-Remediation' }),
      displayName: el('input', { type: 'text', value: m.displayName || '', size: 50 }),
      description: el('textarea', { value: m.description || '', rows: 3, cols: 70 }),
      publisher: el('input', { type: 'text', value: m.publisher || '', size: 30 }),
      runAs: el('select', {}, ...['system', 'user'].map(v => el('option', { value: v, textContent: v }))),
      runAs32Bit: check(m.runAs32Bit), enforce: check(m.enforceSignatureCheck), enforceHad: m.enforceSignatureCheck !== undefined,
      stype: el('select', {}, ...['hourly', 'daily', 'once'].map(v => el('option', { value: v, textContent: v }))),
      interval: el('input', { type: 'number', value: String(sch.interval ?? 1), min: 1, max: 23 }),
      time: el('input', { type: 'text', value: sch.time || '', size: 10, placeholder: 'HH:MM:SS' }),
      date: el('input', { type: 'text', value: sch.date || '', size: 12, placeholder: 'YYYY-MM-DD' }),
      useUtc: check(sch.useUtc), useUtcHad: sch.useUtc !== undefined,
      runScript: check(m.assignment?.runRemediationScript), runScriptHad: m.assignment?.runRemediationScript !== undefined,
      detect: el('textarea', { value: src?.detect || '', rows: 14, cols: 100, spellcheck: false, className: 'code' }),
      remediate: el('textarea', { value: src?.remediate || '', rows: 14, cols: 100, spellcheck: false, className: 'code' }),
    };
    f.runAs.value = m.runAs || 'system'; f.stype.value = sch.type || 'daily';
    const upload = (target, label) => {
      const inp = el('input', { type: 'file', accept: '.ps1,text/plain' });
      inp.onchange = async () => { const file = inp.files[0]; if (file) { if (file.size > 150 * 1024) { status.textContent = `${label}: the file is larger than 150 KB.`; status.className = 'error'; return; } target.value = await file.text(); } };
      return el('div', {}, el('span', { className: 'muted', textContent: `Or upload ${label}: ` }), inp);
    };
    const body = () => {
      const schedule = { type: f.stype.value, interval: Number(f.interval.value) };
      if (f.time.value.trim()) schedule.time = f.time.value.trim();
      if (f.date.value.trim()) schedule.date = f.date.value.trim();
      if (f.useUtc.checked || f.useUtcHad) schedule.useUtc = f.useUtc.checked;
      const assignment = {};
      if (f.runScript.checked || f.runScriptHad) assignment.runRemediationScript = f.runScript.checked;
      const meta = { displayName: f.displayName.value, description: f.description.value.trim() || f.displayName.value.trim(), publisher: f.publisher.value, runAs: f.runAs.value, runAs32Bit: f.runAs32Bit.checked, schedule, assignment };
      if (f.enforce.checked || f.enforceHad) meta.enforceSignatureCheck = f.enforce.checked;
      const base = { meta, detect: f.detect.value, remediate: f.remediate.value };
      return mode === 'update' ? { ...base, expectHeadSha: headSha } : { ...base, kind: mode, folder: f.folder.value.trim() };
    };
    const status = el('p', { role: 'status', className: 'muted' });
    const preview = el('div');
    const outcome = el('div');
    const previewBtn = el('button', { className: 'btn', textContent: 'Validate and preview', disabled: !!block, title: block || 'Check the files and show what will be committed.' });
    const submit = el('button', { className: 'btn', textContent: mode === 'update' ? 'Push update to the pull request' : 'Create pull request', disabled: !!block, title: block || 'Creates a branch and a pull request as the r360 GitHub App. Audited.' });
    const fail = e => { status.className = 'error'; status.textContent = e.message; if (e.details) status.append(el('ul', {}, ...e.details.map(d => el('li', { textContent: d })))); };
    const call = async dry => {
      status.className = 'muted'; status.textContent = dry ? 'Validating...' : 'Working...'; preview.replaceChildren(); outcome.replaceChildren();
      previewBtn.disabled = submit.disabled = true;
      try {
        const b = body();
        const path = mode === 'update' ? `/api/changes/${Number(key)}/update` : '/api/changes';
        const r = await postJson(path, dry && mode !== 'update' ? { ...b, dryRun: true } : b, dry && mode === 'update');
        return r;
      } catch (e) { fail(e); return null; }
      finally { previewBtn.disabled = submit.disabled = !!block; }
    };
    // Updates have no server dry run, so the preview of an update is the client diff only.
    const postJson = async (path, b, clientOnly) => {
      if (clientOnly) return { clientOnly: true };
      return api(path, false, { method: 'POST', body: b });
    };
    const showDiff = r => {
      const b = body();
      const meta = JSON.stringify(b.meta, null, 2) + '\n';
      const beforeMeta = src?.meta ? JSON.stringify(src.meta, null, 2) + '\n' : '';
      preview.replaceChildren(el('h2', { textContent: 'Preview' }),
        r && !r.clientOnly ? el('p', { className: 'muted', textContent: `${r.files.map(x => `${x.path.split('/').pop()}: ${x.status}`).join(', ')}. Assignment group ${r.groupId} (decided by the server). Open changes: ${r.openChanges} of ${r.maxOpenChanges}.` }) : null,
        diffView('remediation.json (as entered; the server writes it in canonical order)', beforeMeta, meta), diffView('detect.ps1', src?.detect || '', b.detect), diffView('remediate.ps1', src?.remediate || '', b.remediate));
    };
    previewBtn.onclick = async () => { const r = await call(true); if (r) { status.className = 'ok'; status.textContent = 'Valid. Nothing has been written yet.'; showDiff(r); } };
    submit.onclick = async () => {
      const r = await call(false);
      if (!r) return;
      status.className = 'ok'; status.textContent = mode === 'update' ? `Pushed an update to change #${r.number}.` : `Created change #${r.number}.`;
      const link = safeUrl(r.url);
      outcome.replaceChildren(...nodes([el('p', {}, link ? el('a', { href: link, target: '_blank', rel: 'noopener', textContent: `Open pull request #${r.number} on GitHub` }) : `Pull request #${r.number}`),
        r.warning ? el('p', { className: 'warn', textContent: r.warning }) : null, r.pimWarning ? el('p', { className: 'muted', textContent: r.pimWarning }) : null,
        el('a', { className: 'btn', href: '#changes', textContent: 'View in Changes' })]));
      previewBtn.disabled = submit.disabled = true;
    };
    view().replaceChildren(...nodes([el('h1', { textContent: title }),
      el('p', { className: 'muted', textContent: mode === 'new' ? 'New remediations are assigned to the canary group only. The scripts go in unsigned; CI signs them after merge.' : 'The assignment group cannot be changed here. The scripts go in unsigned; CI signs them after merge.' }),
      block ? el('p', { className: 'warn', textContent: block }) : null,
      el('div', { className: 'form' },
        field('Folder name', f.folder, mode === 'new' ? 'Letters, digits, dot, underscore, hyphen. Becomes remediations/<folder>.' : null),
        field('Display name', f.displayName), field('Description', f.description, 'Optional. Left empty, it is the display name.'), field('Publisher', f.publisher),
        field('Run as', f.runAs), field('Run in 32-bit PowerShell', f.runAs32Bit), field('Enforce signature check', f.enforce),
        field('Schedule type', f.stype), field('Interval (1 to 23)', f.interval), field('Time (daily)', f.time), field('Date (once)', f.date), field('Use UTC', f.useUtc),
        field('Run remediation script', f.runScript)),
      el('h2', { textContent: 'detect.ps1' }), f.detect, upload(f.detect, 'detect.ps1'),
      el('h2', { textContent: 'remediate.ps1' }), f.remediate, upload(f.remediate, 'remediate.ps1'),
      el('div', { className: 'toolbar' }, previewBtn, submit, el('a', { className: 'btn', href: '#remediations', textContent: 'Cancel' })), status, outcome, preview]));
  }

  const stepper = steps => el('span', { className: 'stepper' }, ...steps.map(s => el('span', { className: `step ${s.state}`, textContent: s.label, title: s.state })));
  const stageCls = s => ({ 'ci-passed': 'ok', approved: 'ok', merged: 'ok', signing: 'warn', signed: 'ok', published: 'ok', 'sign-failed': 'bad', 'ci-failed': 'bad', discarded: 'muted' }[s] || 'warn');
  const writeBlock = () => (!session.me?.write?.active ? 'Start a write session first (Elevate to write).' : null);
  const signText = s => (!s ? '' : { verified: 'Signed and verified', ready: 'Signed by CI, not yet verified here', running: 'Signing is running', waiting: 'Waiting for the signing run', missing: 'No signing run found', 'workflow-failed': 'Signing failed', 'verify-failed': 'Verification failed', unknown: 'Unknown' }[s.state] || s.state);
  const signCls = s => ({ verified: 'ok', ready: 'warn', running: 'warn', waiting: 'muted', 'workflow-failed': 'bad', 'verify-failed': 'bad' }[s?.state] || 'muted');

  async function changesView() {
    stop();
    const out = el('div'), msg = el('p', { role: 'status', className: 'muted' }), note = el('p', { role: 'status', className: 'muted' }), panel = el('div', { className: 'promote-panel' });
    const newBtn = authorLink('#new', 'New remediation');
    view().replaceChildren(el('h1', { textContent: 'Changes' }),
      el('p', { className: 'muted', textContent: 'Remediation changes proposed through r360, from pull requests in your-org/remediations. Refreshes every 10 seconds.' }),
      el('div', { className: 'toolbar' }, newBtn), msg, note, panel, out);
    let last = '';
    // The target picker in the Promote panel: search Entra groups by name (delegated Graph, server side) and add as many as needed (up to 20),
    // or choose Intune's built-in All devices on its own. Each chosen group is a removable chip under "Selected targets", which stays put
    // when the search box loses focus or a new search runs. The canary group is never listed or accepted. The server checks everything again.
    // el() assigns properties; aria-* must be real attributes, so ael() sets those with setAttribute.
    const ael = (tag, props = {}, ...kids) => {
      const aria = Object.entries(props).filter(([k]) => k.startsWith('aria-'));
      const e = el(tag, Object.fromEntries(Object.entries(props).filter(([k]) => !k.startsWith('aria-'))), ...kids);
      for (const [k, v] of aria) e.setAttribute(k, String(v));
      return e;
    };
    const MAX_GROUPS = 20;
    const targetPicker = (d, onChange) => {
      const state = { groups: new Map(), all: false };
      const canary = String(d.canaryGroupId || '').toLowerCase();
      const n = v => (v == null ? 'count unavailable' : String(v));
      const cnt = (v, what) => (v == null ? `${what}: count unavailable` : `${v} ${what}`);
      const chosen = el('p', { role: 'status', className: 'muted' });
      const status = el('p', { role: 'status', className: 'muted' });
      const note = el('p', { className: 'muted target-note', role: 'status' });
      const chips = ael('div', { className: 'chips', 'aria-live': 'polite' });
      const selected = el('div', { className: 'selected-targets' }, el('h4', { textContent: 'Selected targets' }), chips);
      const list = el('ul', { className: 'group-results' });
      const input = ael('input', { type: 'search', className: 'group-search', placeholder: 'Search groups by name (2 or more characters), or paste a group id', maxLength: 64, 'aria-label': 'Search Entra groups by name' });
      const buttons = [];
      const count = () => (state.all ? 1 : state.groups.size);
      const label = () => (state.all ? 'All devices' : state.groups.size === 1 ? '1 group' : `${state.groups.size} groups`);
      const chip = (text, title, onRemove) => el('span', { className: 'chip', title }, el('span', { textContent: text }),
        ael('button', { type: 'button', className: 'chip-remove', 'aria-label': `Remove ${text}`, title: `Remove ${text}`, textContent: '\u00d7', onclick: onRemove }));
      const update = () => {
        for (const b of buttons) b.setAttribute('aria-pressed', String(b.dataset.key === 'allDevices' ? state.all : state.groups.has(b.dataset.key)));
        if (state.all) chips.replaceChildren(chip('All devices', "Intune's built-in All devices target", () => { state.all = false; note.textContent = ''; update(); }));
        else if (state.groups.size) chips.replaceChildren(...[...state.groups.values()].map(g => chip(g.name, `${g.id} | ${n(g.deviceCount)} devices | ${n(g.memberCount)} members`, () => { state.groups.delete(g.id); update(); input.focus(); })));
        else chips.replaceChildren(el('span', { className: 'muted', textContent: 'None yet. Click a search result to add it here.' }));
        if (state.all) { chosen.className = 'warn'; chosen.textContent = 'Target: All devices. Every Intune-managed device would run this remediation. Make sure that is what you want.'; }
        else if (state.groups.size === 1) { const [g] = state.groups.values(); chosen.className = 'ok'; chosen.textContent = `Target: ${g.name} (${g.id}), ${cnt(g.deviceCount, 'devices')}, ${cnt(g.memberCount, 'members')}.`; }
        else if (state.groups.size > 1) {
          const gs = [...state.groups.values()], sum = k => (gs.some(g => g[k] == null) ? null : gs.reduce((t, g) => t + g[k], 0));
          chosen.className = 'ok'; chosen.textContent = `Targets: ${gs.length} groups, ${cnt(sum('deviceCount'), 'devices')}, ${cnt(sum('memberCount'), 'members')} in total (a device in several groups is counted once per group, and runs the remediation once).`;
        } else { chosen.className = 'muted'; chosen.textContent = 'No target chosen yet. Search for groups, or choose All devices.'; }
        onChange(count());
      };
      const addGroup = g => {
        if (g.id === canary) { note.className = 'error target-note'; note.textContent = 'The canary group cannot be a promotion target.'; return; }
        if (state.groups.has(g.id)) { state.groups.delete(g.id); note.textContent = ''; update(); return; }
        if (state.groups.size >= MAX_GROUPS) { note.className = 'error target-note'; note.textContent = `At most ${MAX_GROUPS} groups per promotion.`; return; }
        if (state.all) { state.all = false; note.className = 'warn target-note'; note.textContent = 'All devices was removed: it already includes every group, so it cannot be combined with groups.'; } else note.textContent = '';
        state.groups.set(g.id, g); update();
      };
      const toggleAll = () => {
        if (state.all) { state.all = false; note.textContent = ''; }
        else {
          const had = state.groups.size; state.groups.clear(); state.all = true;
          note.className = 'warn target-note';
          note.textContent = had ? `All devices replaces the ${had === 1 ? 'group' : `${had} groups`} you had selected: it already includes every device in them, so it is always chosen on its own.` : 'All devices is always chosen on its own: it already includes every device in every group.';
        }
        update();
      };
      const option = (key, labelText, detail, onclick) => {
        const b = ael('button', { type: 'button', className: 'btn group-pick', 'aria-pressed': 'false', onclick: () => { onclick(); input.focus(); } }, el('strong', { textContent: labelText }), ` ${detail}`);
        b.dataset.key = key; buttons.push(b);
        return el('li', {}, b);
      };
      const allDevices = option('allDevices', 'All devices', "Intune's built-in target for every managed device. Widest possible blast radius. Cannot be combined with groups.", toggleAll);
      const groupOf = g => ({ id: g.id, name: g.displayName, deviceCount: g.deviceCount, memberCount: g.memberCount });
      const render = r => {
        buttons.length = 1; // keep the All devices button
        const gs = r.groups.filter(g => g.id !== canary);
        list.replaceChildren(allDevices, ...gs.map(g => option(g.id, g.displayName, `${g.id} | ${n(g.deviceCount)} devices | ${n(g.memberCount)} members${g.dynamic ? ' | dynamic' : ''}${g.kind === 'Microsoft 365' ? ' | Microsoft 365' : ''}`, () => addGroup(groupOf(g)))));
        update();
        status.className = 'muted';
        status.textContent = gs.length ? `${gs.length} group${gs.length === 1 ? '' : 's'} found${r.more ? ' (showing the first 10, refine the search)' : ''}. Click to add or remove.` : 'No matching groups.';
        if (r.canaryHidden) status.textContent += ' The canary group is not offered.';
      };
      let seq = 0, timer = null;
      const search = async () => {
        const q = input.value.trim(), mine = ++seq;
        if (q.length < 2) { status.className = 'muted'; status.textContent = 'Type at least 2 characters.'; return; }
        status.className = 'muted'; status.textContent = 'Searching...';
        try { const r = await api(`/api/changes/promote-groups?q=${encodeURIComponent(q)}`); if (mine === seq) render(r); }
        catch (e) { if (mine === seq) { status.className = 'error'; status.textContent = e.message; } }
      };
      input.oninput = () => { clearTimeout(timer); timer = setTimeout(search, 300); };
      input.onkeydown = ev => { if (ev.key === 'Enter') { ev.preventDefault(); clearTimeout(timer); search(); } };
      list.replaceChildren(allDevices);
      const searchBtn = el('button', { type: 'button', className: 'btn', textContent: 'Search', onclick: () => { clearTimeout(timer); search(); } });
      if (d.defaultTarget?.groupId) {
        // The optional R360_PROD_GROUP_ID default: preselect it, if it still exists.
        api(`/api/changes/promote-groups?q=${encodeURIComponent(d.defaultTarget.groupId)}`).then(r => {
          const g = r.groups?.[0];
          if (g && !count()) { render(r); addGroup(groupOf(g)); }
        }).catch(() => {});
      }
      update();
      const body = () => {
        if (state.all) return { type: 'allDevices' };
        const ids = [...state.groups.keys()];
        return !ids.length ? null : ids.length === 1 ? { type: 'group', groupId: ids[0] } : { type: 'groups', groupIds: ids };
      };
      return { node: el('div', { className: 'target-picker' }, el('div', { className: 'toolbar' }, input, searchBtn), status, list, selected, note, chosen), state, body, count, label };
    };
    // S6: the Promote panel. It reads the canary evidence, shows each check, and only offers what the server says is allowed.
    // The steps are numbered: 1 choose targets, 2 (only if the soak is not met) write the override reason, then create the pull request.
    const promotePanel = (c, d) => {
      const ev = d.evidence;
      const result = el('p', { role: 'status', className: 'muted' });
      const close = ael('button', { className: 'btn', textContent: 'Close (changes nothing)', title: 'Only hides this panel. Nothing is created, changed or assigned.', 'aria-label': 'Close this panel. It only hides the panel; nothing is created, changed or assigned.', onclick: () => panel.replaceChildren() });
      const send = async (btn, body) => {
        btn.disabled = true; result.className = 'muted'; result.textContent = 'Creating the promotion pull request...';
        try {
          const r = await api('/api/changes/promote', false, { method: 'POST', body });
          const u = safeUrl(r.url);
          result.className = r.warning ? 'warn' : 'ok';
          result.replaceChildren(...nodes([`Promotion pull request #${r.number} created${r.soakOverride ? ` with a SOAK OVERRIDE (${r.soakDays} of ${r.soakRequired} days)` : ''}. Approve, merge and publish it like any change. `, u ? el('a', { href: u, target: '_blank', rel: 'noopener', textContent: 'Open on GitHub' }) : null, r.warning ? ` ${r.warning}` : null]));
          last = ''; await load();
        } catch (e) { result.className = 'error'; result.textContent = e.message; btn.disabled = false; }
      };
      const items = ev.checks.map(k => el('li', {}, pill(k.ok ? 'pass' : 'FAIL', k.ok ? 'ok' : 'bad'), ` ${k.label}: ${k.detail}`));
      const kids = [el('h2', { textContent: `Promote ${c.folder}` }),
        el('p', { className: 'muted', textContent: `Canary version ${String(d.canarySha || '').slice(0, 12)}. Soak: ${ev.daysSoaked} of ${ev.daysRequired} days. This creates a pull request that changes only the assignment, from the canary group to the targets you choose below. Nothing is assigned to them until that pull request is approved, merged, signed and published.` }),
        el('ul', { className: 'checks' }, ...items)];
      if (d.block) kids.push(el('p', { className: 'error', textContent: d.block }));
      if (d.selfPromote) kids.push(el('p', { className: 'warn', textContent: 'You authored this canary change. Testing mode allows you to promote it; this is recorded as a self-promotion. Enforced mode would refuse.' }));
      const step = (num, title, ...body) => el('li', { className: 'promote-step' }, el('h3', { textContent: `Step ${num}. ${title}` }), ...body);
      if (d.canPromote || d.canOverride) {
        const override = !d.canPromote;
        const go = el('button', { className: 'btn', disabled: true });
        const why = override ? ael('textarea', { className: 'override-reason', rows: 3, maxLength: 500, 'aria-label': 'Override reason', placeholder: `Why is it safe to promote after ${ev.daysSoaked} of ${ev.daysRequired} days? At least ${d.requiredReasonLength} characters. This is recorded in the audit trail and on the pull request.` }) : null;
        let pk = null;
        const sync = () => {
          const k = pk ? pk.count() : 0;
          const what = k ? ` for ${pk.label()}` : '';
          go.textContent = `${override ? 'Override soak and create promotion PR' : 'Create promotion PR'}${what}`;
          go.disabled = !k || (override && why.value.trim().length < d.requiredReasonLength);
          go.title = !k ? 'Select at least one target in step 1.' : override && why.value.trim().length < d.requiredReasonLength ? `Write the override reason in step 2 (at least ${d.requiredReasonLength} characters).` : '';
        };
        pk = targetPicker(d, sync);
        if (why) why.oninput = sync;
        sync();
        go.onclick = () => send(go, { folder: c.folder, canarySha: d.canarySha, ...(override ? { overrideReason: why.value } : {}), target: pk.body() });
        const steps = [step(1, 'Search and select targets', pk.node)];
        // The reason box always sits below the red banner, full width (see .override-block in style.css).
        if (override) steps.push(step(2, 'Write the override reason', el('div', { className: 'override-block' },
          el('p', { className: 'soak-banner', role: 'alert', textContent: `SOAK OVERRIDE: only ${ev.daysSoaked} of ${ev.daysRequired} canary days have passed. Every other check passed. An override is audited and bannered on the change.` }), why)));
        steps.push(step(steps.length + 1, 'Create the promotion pull request', el('div', { className: 'toolbar' }, go, close)));
        kids.push(el('ol', { className: 'promote-steps' }, ...steps));
      } else kids.push(el('div', { className: 'toolbar' }, close));
      kids.push(result);
      return el('div', {}, ...kids);
    };
    const openPromote = async c => {
      panel.replaceChildren(el('p', { className: 'muted', textContent: `Reading the canary evidence for ${c.folder} from Intune...` }));
      try { panel.replaceChildren(promotePanel(c, await api(`/api/changes/promote-evidence/${encodeURIComponent(c.folder)}`))); }
      catch (e) { panel.replaceChildren(el('p', { className: 'error', textContent: e.message })); }
    };
    const load = async () => {
      try {
        const d = await api('/api/changes');
        const sig = JSON.stringify(d.changes);
        msg.className = 'muted'; msg.textContent = `Loaded ${fmtTime(d.fetchedAt)}. Open changes: ${d.openCount} of ${d.maxOpenChanges}.`;
        if (sig === last) return;
        last = sig;
        const block = authorBlock();
        const wblock = writeBlock();
        // One server-side action (approve, reject, merge, verify). Two clicks, like Discard; the server decides everything.
        const act = (label, path, getBody, { can, why, confirm, busy, ask, done }) => {
          const b = el('button', { className: 'btn', textContent: label, disabled: !!wblock || !can, title: wblock || (can ? confirm : why) || '' });
          let reasonBox = null;
          b.onclick = async () => {
            if (b.dataset.armed !== '1') {
              b.dataset.armed = '1'; b.textContent = `Confirm ${label.toLowerCase()}`;
              if (ask) { reasonBox = el('input', { type: 'text', size: 28, placeholder: ask }); b.after(reasonBox); }
              return;
            }
            const body = getBody(reasonBox?.value || '');
            if (ask && String(body.reason || '').trim().length < 3) { note.className = 'error'; note.textContent = 'Enter a reason of at least 3 characters.'; return; }
            b.disabled = true; b.textContent = busy;
            try {
              const r = await api(path, false, { method: 'POST', body });
              note.className = r.warning ? 'warn' : 'ok'; note.textContent = [done(r), r.warning].filter(Boolean).join(' ');
              last = ''; await load();
            } catch (e) { note.className = 'error'; note.textContent = e.message; b.disabled = false; b.textContent = label; delete b.dataset.armed; reasonBox?.remove(); }
          };
          return b;
        };
        out.replaceChildren(el('div'));
        renderTable(out.firstChild, { rows: d.changes.map(c => ({ ...c, who: c.authorUpn || c.authorOid })), columns: [
          { key: 'number', label: 'PR', width: 70, render: c => { const u = safeUrl(c.url); return u ? el('a', { href: u, target: '_blank', rel: 'noopener', textContent: `#${c.number}` }) : `#${c.number}`; } },
          { key: 'folder', label: 'Remediation', width: 220 },
          { key: 'who', label: 'Author', width: 200 },
          { key: 'stage', label: 'Stage', width: 110, render: c => pill(c.stage, stageCls(c.stage)) },
          { key: 'steps', label: 'Progress', width: 560, render: c => stepper(c.steps) },
          { key: 'approval', label: 'Approval', width: 230, render: c => {
            if (c.published) return el('span', {}, c.published.selfApproved ? pill('self-published', 'warn') : pill(c.promote ? `published to ${c.promoteInfo?.target?.name || 'target'}` : 'published to canary', 'ok'), ` ${c.published.byUpn || c.published.byOid || ''} ${c.published.at ? fmtTime(c.published.at) : ''}`);
            if (c.approval) return el('span', {}, c.approval.selfApproved ? pill('self-approved', 'warn') : pill('approved', 'ok'), ` ${c.approval.approverUpn || c.approval.approverOid}`);
            if (c.ignoredSelfApproval) return pill('self-approval ignored', 'bad');
            if (c.signing) {
              const run = safeUrl(c.signing.runUrl);
              return el('span', {}, pill(signText(c.signing), signCls(c.signing)), run ? el('a', { href: run, target: '_blank', rel: 'noopener', textContent: ' run' }) : null, c.signing.problems?.length ? el('small', { className: 'error', textContent: ` ${c.signing.problems[0]}` }) : null);
            }
            return c.provenanceError ? el('small', { className: 'muted', textContent: c.provenanceError, title: c.provenanceError }) : '';
          } },
          { key: 'soak', label: 'Soak', width: 220, render: c => {
            if (c.promoteInfo?.soakOverride) return el('span', { className: 'soak-banner', title: c.promoteInfo.overrideReason || '', textContent: `SOAK OVERRIDE: ${c.promoteInfo.soakDays} of ${c.promoteInfo.soakRequired} days. Reason: ${c.promoteInfo.overrideReason || ''}` });
            if (c.promote) return el('span', { className: 'muted', textContent: c.promoteInfo?.target ? `promotion to ${c.promoteInfo.target.kind === 'allDevices' ? 'All devices' : c.promoteInfo.target.kind === 'groups' ? `${c.promoteInfo.target.groupIds.length} groups` : (c.promoteInfo.target.name || c.promoteInfo.target.groupId)}` : 'promotion' });
            return c.soak ? pill(c.soak.label, c.soak.met ? 'ok' : 'warn') : '';
          } },
          { key: 'failingChecks', label: 'Failing checks', width: 160, render: c => c.failingChecks.join(', ') },
          { key: 'updatedAt', label: 'Updated', width: 170, render: c => fmtTime(c.updatedAt) },
          { key: 'actions', label: 'Actions', width: 520, render: c => {
            if (c.merged) {
              const dest = c.promote ? (c.promoteInfo?.target ? (c.promoteInfo.target.kind === 'allDevices' ? 'All devices' : c.promoteInfo.target.kind === 'groups' ? `${c.promoteInfo.target.groupIds.length} groups` : (c.promoteInfo.target.name || 'the chosen group')) : 'the chosen target') : 'canary';
              const publish = act(`Publish to ${dest}`, `/api/changes/${c.number}/publish`, () => ({ mergeSha: c.mergeSha }), { can: c.canPublish, why: c.publishBlock, confirm: `Publish the CI-signed artifact for this commit to Intune, assigned to ${c.promote ? dest : 'the canary group'} only, as you. ${c.promote ? 'The canary evidence is checked again first. ' : ''}Audited.`, busy: 'Publishing...',
                done: r => (r.already ? 'Intune already holds this signed version. Nothing changed.' : `${r.created ? 'Created' : 'Updated'} in Intune and assigned to the ${dest} group.${r.selfApproved ? ' Self-published (testing mode).' : ''}`) });
              const promote = c.published && !c.promote && !c.supersededBy ? el('button', { className: 'btn', textContent: 'Promote', disabled: !!wblock || !c.canPromote, title: wblock || (c.canPromote ? 'Check the canary evidence, then create a promotion pull request.' : c.promoteBlock) || '', onclick: () => openPromote(c) }) : null;
              const verify = c.canVerify ? act('Verify signing', `/api/changes/${c.number}/verify-signing`, () => ({}), { can: true, confirm: 'Download the signed artifact and verify it against the merged files.', busy: 'Verifying...', done: r => (r.ok ? (r.already ? 'Signing was already verified.' : 'Signing verified.') : `Verification failed: ${(r.problems || []).join('; ')}`) }) : null;
              return el('span', {}, ...nodes([verify, verify && publish ? ' ' : null, publish, promote ? ' ' : null, promote]));
            }
            if (c.state !== 'open') return '';
            const edit = authorLink(`#update/${c.number}`, 'Edit');
            const discard = el('button', { className: 'btn', textContent: 'Discard', disabled: !!block || !c.canEdit, title: block || (c.canEdit ? 'Close the pull request and delete its branch.' : 'Only the author or an admin can discard this change.') });
            discard.onclick = async () => {
              if (discard.dataset.armed !== '1') { discard.dataset.armed = '1'; discard.textContent = 'Confirm discard'; return; }
              discard.disabled = true; discard.textContent = 'Discarding...';
              try { await api(`/api/changes/${c.number}/discard`, false, { method: 'POST', body: {} }); last = ''; await load(); }
              catch (e) { msg.className = 'error'; msg.textContent = e.message; discard.disabled = false; discard.textContent = 'Discard'; delete discard.dataset.armed; }
            };
            if (c.promote) { edit.setAttribute('aria-disabled', 'true'); edit.title = 'A promotion pull request cannot be edited. Discard it and promote again.'; edit.onclick = ev => ev.preventDefault(); }
    else if (!block && !c.canEdit) { edit.setAttribute('aria-disabled', 'true'); edit.title = 'Only the author or an admin can edit this change.'; edit.onclick = ev => ev.preventDefault(); }
            const sha = { headSha: c.headSha };
            const approve = act('Approve', `/api/changes/${c.number}/approve`, () => sha, { can: c.canApprove, why: c.approveBlock, confirm: c.authorOid === session.me?.user?.oid ? 'You are the author: this is a self-approval, allowed only while four-eyes is in testing mode. Audited.' : 'Approve exactly this commit. A new commit voids the approval.', busy: 'Approving...', done: r => (r.already ? 'You already approved this commit.' : r.selfApproved ? 'Approved (self-approved, testing mode).' : 'Approved.') });
            const reject = act('Reject', `/api/changes/${c.number}/reject`, reason => ({ headSha: c.headSha, reason }), { can: c.canReject, why: c.rejectBlock, confirm: 'Close the pull request with a reason. Audited.', busy: 'Rejecting...', ask: 'Reason', done: () => 'Rejected.' });
            const merge = act('Merge', `/api/changes/${c.number}/merge`, () => sha, { can: c.canMerge, why: c.mergeBlock, confirm: 'Squash merge this exact commit into main. CI then signs it. Audited.', busy: 'Merging...', done: r => (r.branchUpdated ? r.message : r.already ? 'Already merged.' : `Merged. ${r.selfApproved ? 'Self-approved (testing mode). ' : ''}Signing starts now; use Verify signing when it finishes.`) });
            return el('span', {}, edit, ' ', discard, ' ', approve, ' ', reject, ' ', merge);
          } },
        ], empty: 'No changes have been proposed through r360 yet.' });
      } catch (e) { msg.className = 'error'; msg.textContent = e.message; }
    };
    await load();
    poll = setInterval(() => { if (!document.hidden) load(); }, POLL_MS);
  }

  return { new: () => form('new'), edit: key => form('edit', key), update: key => form('update', key), changes: changesView, stop, canAuthor, authorBlock, authorLink };
}
