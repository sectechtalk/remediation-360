import { renderTable } from './table.js';

// r360 Phase 1: read-only. Each dataset has exactly one home page (no duplicated data).
const STUBS = { rollouts: ['Rollouts', 3, 'Canary run on DEVICE01, widen, retire, certificate profile management.'],
  emergency: ['Emergency', 4, 'Two-person Defender and Intune actions, 4 hours, 1 device.'],
  audit: ['Audit', 2, 'Audit viewer and export (table r360audit).'] };
const PT = { timeZone: 'America/Los_Angeles', dateStyle: 'medium', timeStyle: 'short' };
export const fmtTime = v => v ? `${new Date(v).toLocaleString('en-US', PT)} PT` : '';
const el = (tag, props = {}, ...kids) => { const e = Object.assign(document.createElement(tag), props); e.append(...kids.filter(k => k != null)); return e; };
const pill = (text, cls) => el('span', { className: `pill ${cls}`, textContent: text });
const view = () => document.getElementById('view');

async function api(path, refresh) {
  const r = await fetch(path + (refresh ? '?refresh=1' : ''), { headers: { Accept: 'application/json' } });
  if (r.status === 401) { location.href = '/auth/signin'; throw new Error('Sign in required'); }
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
  return j;
}
function page(title, subtitle, loader) {
  const body = el('div');
  const btn = el('button', { className: 'btn', textContent: 'Refresh' });
  const stamp = el('span', { className: 'muted' });
  const run = async refresh => {
    btn.disabled = true; btn.title = 'Loading';
    body.replaceChildren(el('p', { className: 'muted', textContent: 'Loading...' }));
    try { const d = await loader(refresh, body); stamp.textContent = d?.fetchedAt ? `Loaded ${fmtTime(d.fetchedAt)}` : ''; }
    catch (e) { body.replaceChildren(el('p', { className: 'error', textContent: e.message })); }
    finally { btn.disabled = false; btn.title = ''; }
  };
  btn.onclick = () => run(true);
  view().replaceChildren(el('h1', { textContent: title }), el('p', { className: 'muted', textContent: subtitle }), el('div', { className: 'toolbar' }, btn, stamp), body);
  run(false);
}
const statusCls = s => ({ 'In sync': 'ok', 'Drift': 'bad', 'Not in Intune': 'warn', 'Intune only': 'warn' }[s] || 'bad');
const outcomeCls = s => ({ 'Without issues': 'ok', 'Issue fixed': 'ok', 'Failed': 'bad', 'Issue detected': 'warn', 'Pending': 'warn' }[s] || 'muted');

const VIEWS = {
  remediations: () => page('Remediations', 'Catalog from your-org/remediations main and Intune Remediations, with drift between them and run summary counts.', async (refresh, body) => {
    const d = await api('/api/remediations', refresh);
    body.replaceChildren(el('p', { className: 'muted', textContent: `Repo main ${d.repoSha.slice(0, 8)} (${fmtTime(d.repoDate)}): ${d.repoMessage}` }), el('div'));
    renderTable(body.lastChild, { rows: d.rows.map(r => ({ ...r, source: r.inRepo ? (r.intuneId ? 'Repo + Intune' : 'Repo') : 'Intune' })), columns: [
      { key: 'name', label: 'Remediation', width: 240 },
      { key: 'status', label: 'Drift', width: 130, render: r => pill(r.status, statusCls(r.status)) },
      { key: 'reasons', label: 'Differences', width: 260 },
      { key: 'source', label: 'Source', width: 110 },
      { key: 'folder', label: 'Repo folder', width: 200 },
      { key: 'publishedGit', label: 'Published git', width: 110 },
      { key: 'enforceSignatureCheck', label: 'Signature check', width: 120 },
      { key: 'runAs', label: 'Run as', width: 80 },
      { key: 'publisher', label: 'Publisher', width: 120 },
      { key: 'withoutIssues', label: 'Without issues', width: 110 },
      { key: 'issueFixed', label: 'Issue fixed', width: 100 },
      { key: 'issueRecurred', label: 'Recurred', width: 90 },
      { key: 'errors', label: 'Errors', width: 80 },
      { key: 'pending', label: 'Pending', width: 80 },
      { key: 'lastRun', label: 'Last run', width: 170, render: r => fmtTime(r.lastRun) },
      { key: 'lastModified', label: 'Intune modified', width: 170, render: r => fmtTime(r.lastModified) },
      { key: 'intuneId', label: 'Intune id', width: 280 },
    ], empty: 'No remediations in the repo or Intune.' });
    return d;
  }),
  fleet: () => page('Fleet', 'Run state of every remediation on every device (Intune deviceRunStates).', async (refresh, body) => {
    const d = await api('/api/fleet', refresh);
    renderTable(body, { rows: d.rows, columns: [
      { key: 'device', label: 'Device', width: 140 },
      { key: 'remediation', label: 'Remediation', width: 220 },
      { key: 'outcome', label: 'Outcome', width: 120, render: r => pill(r.outcome, outcomeCls(r.outcome)) },
      { key: 'detection', label: 'Detection', width: 100 },
      { key: 'remediationState', label: 'Remediation', width: 120 },
      { key: 'lastUpdate', label: 'Last update', width: 170, render: r => fmtTime(r.lastUpdate) },
      { key: 'lastSync', label: 'Last sync', width: 170, render: r => fmtTime(r.lastSync) },
      { key: 'user', label: 'User', width: 180 },
      { key: 'os', label: 'OS version', width: 120 },
      { key: 'output', label: 'Output', width: 260 },
      { key: 'error', label: 'Error', width: 260 },
    ], empty: 'No device run states yet.' });
    return d;
  }),
  certificates: () => page('Certificates', 'r360 code-signing certificate deployment through the Intune Trusted Root and Trusted Publisher profiles.', async (refresh, body) => {
    const d = await api('/api/certificates', refresh);
    const cards = el('div', { className: 'cards' }, ...d.profiles.map(p => el('div', { className: 'card' },
      el('h2', { textContent: `${p.label}: ` }, p.found ? pill(p.matches ? 'Thumbprint matches' : 'Thumbprint mismatch', p.matches ? 'ok' : 'bad') : pill('Profile missing', 'bad')),
      el('dl', { className: 'kv' }, ...[['Profile', p.name], ['Check', p.detail], ['Assigned to', (p.assignments || []).join(', ') || 'not assigned'], ['Modified', fmtTime(p.lastModified)]]
        .flatMap(([k, v]) => [el('dt', { textContent: k }), el('dd', { textContent: v || '' })])))));
    const canary = d.devices.filter(x => x.device.toUpperCase() === d.canaryDevice.toUpperCase());
    const canaryOk = canary.length === d.profiles.length && canary.every(x => x.deployed);
    const tbl = el('div');
    body.replaceChildren(el('p', {}, `Expected thumbprint ${d.thumbprint}. Canary ${d.canaryDevice}: `, pill(canaryOk ? 'both profiles deployed' : 'not confirmed by Intune', canaryOk ? 'ok' : 'warn')), cards, el('h2', { textContent: 'Device status' }), tbl);
    renderTable(tbl, { rows: d.devices, columns: [
      { key: 'device', label: 'Device', width: 160 }, { key: 'profile', label: 'Profile', width: 140 },
      { key: 'status', label: 'Status', width: 120, render: r => pill(r.status, r.deployed ? 'ok' : (r.status === 'error' || r.status === 'conflict' ? 'bad' : 'warn')) },
      { key: 'lastReported', label: 'Last reported', width: 170, render: r => fmtTime(r.lastReported) }, { key: 'user', label: 'User', width: 200 },
    ], empty: 'Intune has not reported any device for these profiles yet.' });
    return d;
  }),
  settings: () => page('Settings', 'Read-only view of r360 configuration and your access. Change settings with the tools scripts.', async (refresh, body) => {
    const [s, pim, me] = await Promise.all([api('/api/settings'), api('/api/pim', refresh), api('/api/me')]);
    const kv = obj => el('dl', { className: 'kv' }, ...Object.entries(obj).flatMap(([k, v]) => [el('dt', { textContent: k }), el('dd', { textContent: String(v) })]));
    const pimTbl = el('div');
    body.replaceChildren(
      el('h2', { textContent: 'Your access' }),
      kv({ 'Signed in as': `${me.user.name} (${me.user.upn})`, 'Object id': me.user.oid, 'r360 roles (approvers.json)': me.approversError ? `ERROR: ${me.approversError}` : (me.roles.join(', ') || 'none') }),
      el('h2', { textContent: 'PIM status' }),
      el('p', {}, pill(pim.gate.ok ? 'Ready' : (s.settings.pimMode === 'enforce' ? 'Blocked' : 'Warning'), pim.gate.ok ? 'ok' : 'warn'), ` ${pim.gate.text} `, el('a', { className: 'btn', href: pim.activateUrl, target: '_blank', rel: 'noopener', textContent: 'Open PIM activation' })),
      pimTbl,
      el('h2', { textContent: 'Configuration' }), kv(s.settings));
    renderTable(pimTbl, { rows: pim.rows, columns: [
      { key: 'role', label: 'Role', width: 240 }, { key: 'state', label: 'State', width: 120 },
      { key: 'start', label: 'Start', width: 170, render: r => fmtTime(r.start) }, { key: 'end', label: 'End', width: 170, render: r => r.end ? fmtTime(r.end) : 'permanent' }, { key: 'scope', label: 'Scope', width: 100 },
    ], empty: 'No directory roles.' });
    return pim;
  }),
};
for (const [k, [title, phase, what]] of Object.entries(STUBS)) VIEWS[k] = () => view().replaceChildren(el('h1', { textContent: title }), el('p', { className: 'muted', textContent: `Coming in phase ${phase}. ${what}` }));

function route() {
  const name = (location.hash || '#remediations').slice(1);
  const v = VIEWS[name] ? name : 'remediations';
  document.querySelectorAll('#nav a').forEach(a => a.classList.toggle('active', a.dataset.view === v));
  VIEWS[v]();
}
async function boot() {
  const me = await api('/api/me');
  document.getElementById('who').textContent = me.user.upn;
  const b = document.getElementById('banners');
  if (me.fourEyes === 'testing') b.append(el('div', { className: 'banner testing', textContent: 'TESTING MODE: four-eyes is not enforced (self-approval allowed and audited).' }));
  if (me.approversError) b.append(el('div', { className: 'banner warn', textContent: `approvers.json problem: ${me.approversError}. Writes fail closed.` }));
  addEventListener('hashchange', route);
  route();
}
if (typeof document !== 'undefined' && document.getElementById('view')) boot().catch(e => { view().textContent = e.message; });
