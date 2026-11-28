import { busyStatus, leaving } from './busy.js';
// Offboard: end one person's access now. Disable user everywhere, or Remove from one app, then push it to the SCIM apps with
// Provision on demand and re-read to verify. Federation 360 opens this page with the request filled in:
//   #offboard/disable?user=<upn>&app=<spId>:<name>&app=...&from=federation-360
//   #offboard/remove?user=<upn>&app=<spId>:<name>&from=federation-360
// The server decides and enforces everything; this page only shows state and sends requests.
const STATE_CLS = { pending: 'warn', running: 'warn', done: 'ok', partial: 'bad', failed: 'bad', cancelled: 'muted' };
const STEP_CLS = { ok: 'ok', failed: 'bad', skipped: 'muted', action: 'warn' };
const STEP_LABEL = { 'find-user': 'Find the person', disable: 'Disable the account', revoke: 'Revoke sessions', 'list-apps': 'List their apps', remove: 'Remove the assignment', provision: 'Provision on demand', verify: 'Verify' };
const RUN_ROLES = ['emergencyApprover', 'admin'];
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const RETURN_KEY = 'r360:return';

// Reads the request Federation 360 put in the address. Unknown or malformed values are dropped, never trusted.
export function presetFrom(hash) {
  const m = /^#offboard\/(disable|remove)(?:\?(.*))?$/.exec(String(hash || ''));
  if (!m) return null;
  const q = new URLSearchParams(m[2] || '');
  const apps = [];
  for (const v of q.getAll('app')) {
    const spId = v.slice(0, 36);
    if (GUID.test(spId) && !apps.some(a => a.spId === spId.toLowerCase())) apps.push({ spId: spId.toLowerCase(), name: v.slice(37).slice(0, 120) });
  }
  return { type: m[1], user: (q.get('user') || '').trim().slice(0, 200), apps: apps.slice(0, 50), from: (q.get('from') || '').slice(0, 40) };
}

export function createOffboardUi({ el, pill, api, view, fmtTime, session }) {
  const busy = (b, text, msg, fn) => busyStatus(b, text, msg, fn, el);
  const roles = () => session.me?.roles || [];
  const writing = () => Boolean(session.me?.write?.active);
  // Elevate from this page: the same sign-in as the menu's Elevate to write, but it comes back here (with the request).
  const elevateButton = () => {
    const w = session.me?.write || {};
    const b = el('button', { className: 'btn', type: 'button', textContent: 'Elevate to write', disabled: !w.canElevate });
    b.title = w.canElevate ? 'Sign in again to start your audited write session, then come back to this page.' : (w.blockedReason || 'Elevate to write is not available.');
    b.onclick = () => {
      try { sessionStorage.setItem(RETURN_KEY, /^#offboard\//.test(location.hash) ? location.hash : '#offboard'); } catch { /* storage blocked: you land on the home page */ }
      leaving(b, 'Opening sign-in…');
      location.href = '/auth/write/start';
    };
    const row = el('p', { className: 'row-actions' }, b);
    if (!w.canElevate && w.blockedReason) row.append(el('span', { className: 'muted', textContent: ` ${w.blockedReason}` }));
    return row;
  };
  const me = () => session.me?.user?.oid;

  const stepList = steps => el('ol', { className: 'offboard-steps' }, ...steps.map(s => el('li', {},
    pill(s.result === 'action' ? 'you need to act' : s.result, STEP_CLS[s.result] || 'muted'), ' ', el('strong', { textContent: STEP_LABEL[s.step] || s.step || '' }),
    s.app ? ` (${s.app})` : '', el('div', { className: 'muted', textContent: s.text || '' }))));

  function permissions(d) {
    return el('details', { className: 'card' },
      el('summary', { textContent: 'Permissions this page needs' }),
      el('p', {}, 'r360-write needs these delegated Microsoft Graph permissions with admin consent: ', el('strong', { textContent: d.scopes.join(', ') }), '.'),
      el('p', { textContent: 'The person signed in to r360 also needs an Entra role: User Administrator to disable ordinary users, Privileged Authentication Administrator to disable an admin, and Application Administrator or Cloud Application Administrator for Provision on demand and removing app assignments. Entra checks the role on every call; r360 cannot do more than you can.' }),
      el('p', { className: 'muted' }, 'To add them: run ', el('code', { textContent: 'tools\\Add-R360OffboardPermissions.ps1' }), ' (it also grants the admin consent), then end the write session and elevate again.'));
  }

  function form(d, preset, reload) {
    const type = el('select', {}, ...Object.entries(d.types).map(([k, t]) => el('option', { value: k, textContent: t.label })));
    type.value = preset?.type || 'disable';
    const about = el('p', { className: 'muted' });
    const user = el('input', { type: 'text', size: 40, maxLength: 200, placeholder: 'someone@contoso.com', value: preset?.user || '' });
    const read = el('button', { className: 'btn', type: 'button', textContent: 'Read from Entra' });
    const who = el('div', { className: 'muted', textContent: 'Not read yet. Read the person to see their account and direct app assignments.' });
    const appsBox = el('div', { className: 'form' });
    const reason = el('textarea', { rows: 3, cols: 70, maxLength: 900, placeholder: 'Why, in a sentence or two. This goes into the audit trail.' });
    if (preset?.from) reason.value = `Offboarding requested from ${preset.from === 'federation-360' ? 'Federation 360' : preset.from} User lookup.`;
    const go = el('button', { className: 'btn', type: 'button', textContent: d.fourEyes === 'on' ? 'Ask for approval' : 'Run request' });
    const msg = el('div', { role: 'status' });
    const result = el('div');
    let apps = [...(preset?.apps || [])];
    const checks = new Map();
    const drawApps = () => {
      const single = type.value === 'remove';
      checks.clear();
      appsBox.replaceChildren(el('p', { textContent: single ? 'The one app to remove them from:' : 'SCIM apps to push the disable to now (r360 also adds every app they are assigned to directly):' }),
        ...(apps.length ? apps.map((a, i) => {
          const c = el('input', { type: single ? 'radio' : 'checkbox', name: 'offboard-app', checked: single ? i === 0 : true });
          checks.set(a.spId, c);
          return el('label', { className: 'field' }, c, ` ${a.name || '(no name)'} `, el('code', { textContent: a.spId }));
        }) : [el('p', { className: 'muted', textContent: single ? 'No app chosen. Open this page from Federation 360 User lookup, or read the person and pick an app.' : 'None listed yet.' })]));
      about.textContent = d.types[type.value].about;
    };
    type.onchange = drawApps;
    drawApps();
    read.onclick = () => busy(read, 'Reading the person from Entra…', msg, async () => {
      const r = await api(`/api/offboard/preview?user=${encodeURIComponent(user.value.trim())}`);
      msg.replaceChildren();
      who.className = '';
      who.replaceChildren(el('strong', { textContent: r.user.name || r.user.upn }), ` ${r.user.upn} · `, pill(r.user.enabled ? 'enabled' : 'disabled', r.user.enabled ? 'warn' : 'ok'),
        r.user.sessionsValidFrom ? ` · sessions valid from ${fmtTime(r.user.sessionsValidFrom)}` : '',
        r.assignments === null ? el('div', { className: 'muted', textContent: 'Direct assignments could not be read.' }) : el('div', { className: 'muted', textContent: `${r.assignments.length} direct app assignment(s).` }));
      for (const a of r.assignments || []) if (!apps.some(x => x.spId === a.spId)) apps.push(a);
      drawApps();
    });
    go.onclick = () => busy(go, d.fourEyes === 'on' ? 'Sending the request…' : 'Running: disable, revoke, provision, verify…', msg, async () => {
      const chosen = apps.filter(a => checks.get(a.spId)?.checked);
      const r = await api('/api/offboard', false, { method: 'POST', body: { type: type.value, user: user.value.trim(), apps: chosen, reason: reason.value, source: preset?.from || '' } });
      msg.replaceChildren(el('p', { className: r.state === 'done' ? 'ok' : r.state === 'pending' ? 'muted' : 'error', textContent: r.message || `${r.id}: ${r.state}. ${r.summary || ''}` }));
      result.replaceChildren(...(r.steps ? [stepList(r.steps)] : []));
      reload();
    });
    return el('div', { className: 'card offboard-form' },
      el('h2', { textContent: preset ? 'Request from Federation 360' : 'New offboard request' }),
      el('ol', { className: 'promote-steps' },
        el('li', { className: 'promote-step' }, el('h3', { textContent: '1. What to do' }), type, about),
        el('li', { className: 'promote-step' }, el('h3', { textContent: '2. Who' }), el('div', { className: 'toolbar' }, user, read), who),
        el('li', { className: 'promote-step' }, el('h3', { textContent: '3. Which apps' }), appsBox),
        el('li', { className: 'promote-step' }, el('h3', { textContent: '4. Say why' }), reason)),
      el('div', { className: 'toolbar' }, go), msg, result);
  }

  function card(o, d, reload) {
    const msg = el('div', { role: 'status' });
    const buttons = [];
    const canRun = writing() && o.state === 'pending' && roles().some(r => RUN_ROLES.includes(r)) && (d.fourEyes === 'off' || o.requesterOid !== me());
    if (canRun) {
      const b = el('button', { className: 'btn', type: 'button', textContent: 'Run now' });
      b.onclick = () => busy(b, 'Running the request…', msg, async () => { const r = await api(`/api/offboard/${o.id}/run`, false, { method: 'POST' }); msg.replaceChildren(el('p', { className: r.state === 'done' ? 'ok' : 'error', textContent: `${r.state}. ${r.summary || ''}` })); reload(); });
      buttons.push(b);
    }
    if (writing() && o.state === 'pending' && (o.requesterOid === me() || roles().includes('emergencyApprover'))) {
      const b = el('button', { className: 'btn', type: 'button', textContent: 'Cancel request' });
      b.onclick = () => busy(b, 'Cancelling…', msg, async () => { await api(`/api/offboard/${o.id}/cancel`, false, { method: 'POST', body: { reason: 'cancelled on the Offboard page' } }); reload(); });
      buttons.push(b);
    }
    return el('div', { className: `card offboard-item state-${o.state}` },
      el('h3', {}, `${o.id}  `, pill(o.state, STATE_CLS[o.state] || 'muted'), o.selfApproved ? pill('run by the requester', 'muted') : null),
      el('dl', { className: 'kv' }, ...[
        ['Request', o.typeLabel],
        ['Person', o.user],
        o.apps?.length ? ['Apps', o.apps.map(a => a.name || a.spId).join(', ')] : null,
        ['Reason', o.reason],
        ['Asked by', `${o.requesterUpn}, ${fmtTime(o.requestedAt)}${o.source ? ` (from ${o.source})` : ''}`],
        o.runBy ? ['Run by', `${o.runBy}, ${fmtTime(o.runAt)}`] : null,
        o.summary ? ['Result', o.summary] : null,
        o.closedBy ? ['Cancelled by', `${o.closedBy}: ${o.closedReason}`] : null,
      ].filter(Boolean).flatMap(([k, v]) => [el('dt', { textContent: k }), el('dd', {}, v)])),
      o.steps?.length ? stepList(o.steps) : null,
      buttons.length ? el('div', { className: 'toolbar' }, ...buttons) : null, msg);
  }

  async function page() {
    const preset = presetFrom(location.hash);
    if (preset) { try { sessionStorage.setItem(RETURN_KEY, location.hash); } catch { /* storage blocked */ } }
    const top = el('div');
    const body = el('div', {}, el('p', { className: 'muted', textContent: 'Loading...' }));
    view().replaceChildren(
      el('h1', { textContent: 'Offboard' }),
      el('p', { className: 'guide-lead', textContent: 'End one person\'s access now: disable them everywhere, or remove them from one app, then push it to their SCIM apps with Provision on demand instead of waiting for the next cycle (about 40 minutes). Federation 360 User lookup fills this in for you and verifies the result afterwards.' }),
      top, body);
    const load = async () => {
      let d;
      try { d = await api('/api/offboard'); } catch (e) { body.replaceChildren(el('p', { className: 'error', textContent: e.message })); return; }
      const open = d.items.filter(o => ['pending', 'running'].includes(o.state));
      const done = d.items.filter(o => !open.includes(o));
      body.replaceChildren(
        el('h2', { textContent: `Open (${open.length})` }),
        open.length ? el('div', { className: 'cards offboard-list' }, ...open.map(o => card(o, d, load))) : el('p', { className: 'muted', textContent: 'Nothing is waiting.' }),
        el('h2', { textContent: `Last 30 days (${done.length})` }),
        done.length ? el('div', { className: 'cards offboard-list' }, ...done.map(o => card(o, d, load))) : el('p', { className: 'muted', textContent: 'No finished offboard requests.' }),
        el('p', { className: 'muted', textContent: `Four-eyes for offboarding is ${d.fourEyes === 'on' ? 'on: a different person with the emergencyApprover role runs each request' : 'off: the requester runs the request (setting R360_OFFBOARD_FOUR_EYES=on turns it on)'}. Every step is in Audit.` }));
      if (!top.dataset.ready) {
        top.dataset.ready = '1';
        const parts = [permissions(d)];
        if (!writing()) {
          parts.unshift(el('div', { className: 'card' },
            preset ? el('p', {}, 'Federation 360 sent a request: ', el('strong', { textContent: `${d.types[preset.type].label} for ${preset.user || 'someone'}` }), preset.apps.length ? ` (${preset.apps.length} app${preset.apps.length === 1 ? '' : 's'}).` : '.') : null,
            el('p', {}, 'To run it, start a write session first. You sign in again, and this page comes back', preset ? ' with the request filled in.' : '.'),
            elevateButton()));
        } else if (!roles().some(r => RUN_ROLES.includes(r))) {
          parts.unshift(el('div', { className: 'card' }, el('p', { className: 'error', textContent: 'Your approvers.json roles do not include emergencyApprover or admin, so you cannot run offboard requests.' })));
        } else parts.unshift(form(d, preset, load));
        top.replaceChildren(...parts);
      }
    };
    load();
  }
  return { page };
}
