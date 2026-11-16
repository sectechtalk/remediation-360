// Emergency (the fast path): ask for one Defender action on one device, a second person approves, r360 runs it in
// Defender as the approver. The server decides and enforces everything; this page only shows state and sends requests.
const DEFENDER_DEVICES = 'https://security.microsoft.com/machines';
const STATE_CLS = { pending: 'warn', approved: 'warn', running: 'warn', succeeded: 'ok', failed: 'bad', 'timed out': 'bad', expired: 'muted', rejected: 'muted', cancelled: 'muted', 'cancelled in Defender': 'muted' };
const REQUEST_ROLES = ['author', 'emergencyApprover', 'admin'];
const POLL_MS = 20000;

export function createEmergencyUi({ el, pill, api, view, fmtTime, session }) {
  let timer = null;
  const stop = () => { clearTimeout(timer); timer = null; };
  const busy = async (b, msg, fn) => {
    b.disabled = true; msg.replaceChildren(el('span', { className: 'muted', textContent: 'Working...' }));
    try { await fn(); } catch (e) { msg.replaceChildren(el('span', { className: 'error', textContent: e.message })); } finally { b.disabled = false; }
  };
  const roles = () => session.me?.roles || [];
  const writing = () => Boolean(session.me?.write?.active);
  const me = () => session.me?.user?.oid;

  function requestForm(d, reload, preset = null) {
    const q = el('input', { type: 'text', size: 24, maxLength: 63, placeholder: 'Device name, e.g. DEVICE01', value: preset?.device || '' });
    const find = el('button', { className: 'btn', type: 'button', textContent: 'Search Defender' });
    const results = el('ul', { className: 'group-results' });
    const chosen = el('p', { className: 'muted', textContent: 'No device chosen yet.' });
    let machine = preset ? { id: preset.machineId, name: preset.device } : null;
    if (machine) chosen.replaceChildren('Device: ', el('strong', { textContent: machine.name }));
    const action = el('select', {}, ...Object.entries(d.actions).map(([k, a]) => el('option', { value: k, textContent: `${a.label} (${a.plans.join(', ')})` })));
    if (preset?.action) action.value = preset.action;
    const about = el('p', { className: 'muted' });
    const params = el('div', { className: 'form' });
    const reason = el('textarea', { rows: 3, cols: 70, maxLength: 900, placeholder: 'Why, in a sentence or two. This goes to Defender and the audit trail.' });
    const go = el('button', { className: 'btn', type: 'button', textContent: 'Ask for approval' });
    const msg = el('div', { role: 'status' });
    const inputs = {};
    const drawParams = () => {
      const a = d.actions[action.value];
      about.textContent = `${a.about} Needs: ${a.plans.map(p => ({ P1: 'Defender for Endpoint Plan 1', P2: 'Defender for Endpoint Plan 2', MDB: 'Defender for Business' }[p])).join(' or ')}.`;
      params.replaceChildren();
      for (const k of Object.keys(inputs)) delete inputs[k];
      for (const [k, spec] of Object.entries(a.params)) {
        const input = spec.values ? el('select', {}, ...spec.values.map(v => el('option', { value: v, textContent: v }))) : el('input', { type: 'text', size: 44, maxLength: 40, placeholder: 'SHA-1 of the file (40 hex characters)' });
        if (spec.default) input.value = spec.default;
        inputs[k] = input;
        params.append(el('label', { className: 'field' }, el('span', { textContent: { isolationType: 'Isolation type', scanType: 'Scan type', sha1: 'File SHA-1' }[k] || k }), input));
      }
    };
    action.onchange = drawParams;
    drawParams();
    find.onclick = () => busy(find, msg, async () => {
      const r = await api(`/api/emergency/machines?q=${encodeURIComponent(q.value.trim())}`);
      msg.replaceChildren();
      results.replaceChildren(...(r.items.length ? r.items.map(m => {
        const b = el('button', { className: 'btn group-pick', type: 'button', textContent: `${m.name}  ·  ${m.health || 'unknown health'}  ·  ${m.os || ''}  ·  last seen ${fmtTime(m.lastSeen) || 'unknown'}${m.group ? `  ·  ${m.group}` : ''}` });
        b.onclick = () => { machine = m; chosen.replaceChildren('Device: ', el('strong', { textContent: m.name }), ` (${m.health || 'unknown health'})`); results.querySelectorAll('.group-pick').forEach(x => x.setAttribute('aria-pressed', String(x === b))); };
        return el('li', {}, b);
      }) : [el('li', { className: 'muted', textContent: 'Defender knows no device whose name starts with that.' })]));
    });
    go.onclick = () => busy(go, msg, async () => {
      if (!machine) throw new Error('Search for the device and pick it first.');
      const p = Object.fromEntries(Object.entries(inputs).map(([k, i]) => [k, i.value]));
      const r = await api('/api/emergency', false, { method: 'POST', body: { machineId: machine.id, action: action.value, params: p, reason: reason.value } });
      msg.replaceChildren(el('p', { className: 'ok', textContent: `${r.id}: ${r.actionLabel} on ${r.device} is waiting for a second person. It expires ${fmtTime(r.expiresAt)}.` }));
      reason.value = '';
      reload();
    });
    return el('div', { className: 'card emergency-form' },
      el('h2', { textContent: preset ? 'Ask for the release' : 'Ask for an emergency action' }),
      el('ol', { className: 'promote-steps' },
        el('li', { className: 'promote-step' }, el('h3', { textContent: '1. Find the device in Defender' }), el('div', { className: 'toolbar' }, q, find), results, chosen),
        el('li', { className: 'promote-step' }, el('h3', { textContent: '2. Choose the action' }), action, about, params),
        el('li', { className: 'promote-step' }, el('h3', { textContent: '3. Say why' }), reason)),
      el('div', { className: 'toolbar' }, go), msg);
  }

  function card(e, d, reload) {
    const msg = el('div', { role: 'status' });
    const buttons = [];
    const canApprove = writing() && roles().includes('emergencyApprover') && e.state === 'pending' && (e.requesterOid !== me() || d.fourEyes === 'testing');
    if (canApprove) {
      const b = el('button', { className: 'btn', type: 'button', textContent: e.requesterOid === me() ? 'Approve my own request and run (testing mode)' : 'Approve and run now' });
      b.onclick = () => busy(b, msg, async () => {
        const r = await api(`/api/emergency/${e.id}/approve`, false, { method: 'POST' });
        msg.replaceChildren(el('p', { className: 'ok', textContent: `Defender accepted it (${r.defenderStatus}).${r.selfApproved ? ' Self-approved in testing mode; recorded in the audit trail.' : ''}` }));
        reload();
      });
      buttons.push(b);
    }
    if (writing() && ['pending', 'expired'].includes(e.state) && (e.requesterOid === me() || roles().includes('emergencyApprover'))) {
      const mine = e.requesterOid === me();
      const b = el('button', { className: 'btn', type: 'button', textContent: mine ? 'Cancel my request' : 'Reject' });
      b.onclick = () => busy(b, msg, async () => { await api(`/api/emergency/${e.id}/close`, false, { method: 'POST', body: { reason: mine ? 'withdrawn by the requester' : 'rejected by an emergency approver' } }); reload(); });
      buttons.push(b);
    }
    if (writing() && e.machineActionId) {
      const b = el('button', { className: 'btn', type: 'button', textContent: 'Check status in Defender' });
      b.onclick = () => busy(b, msg, async () => { const r = await api(`/api/emergency/${e.id}/refresh`, false, { method: 'POST' }); msg.replaceChildren(el('span', { textContent: `Defender says: ${r.defenderStatus}` })); if (r.final) reload(); });
      buttons.push(b);
    }
    const release = d.actions[e.action]?.release;
    if (writing() && release && e.state === 'succeeded' && roles().some(r => REQUEST_ROLES.includes(r))) {
      const b = el('button', { className: 'btn', type: 'button', textContent: d.actions[release].label });
      b.onclick = () => { b.replaceWith(requestForm(d, reload, { machineId: e.machineId, device: e.device, action: release })); };
      buttons.push(b);
    }
    const params = Object.entries(e.params || {}).map(([k, v]) => `${k} ${v}`).join(', ');
    return el('div', { className: `card emergency-item state-${e.state.replace(/\s+/g, '-')}` },
      el('h3', {}, `${e.id}  `, pill(e.state, STATE_CLS[e.state] || 'muted'), e.selfApproved ? pill('self-approved', 'bad') : null),
      el('dl', { className: 'kv' }, ...[
        ['Action', `${e.actionLabel}${params ? ` (${params})` : ''}`],
        ['Device', el('span', {}, `${e.device} `, el('a', { href: DEFENDER_DEVICES, target: '_blank', rel: 'noopener', textContent: 'Defender devices' }))],
        ['Reason', e.reason],
        ['Asked by', `${e.requesterUpn}, ${fmtTime(e.requestedAt)}`],
        e.state === 'pending' ? ['Expires', fmtTime(e.expiresAt)] : null,
        e.approverUpn ? ['Approved by', `${e.approverUpn}, ${fmtTime(e.approvedAt)}`] : null,
        e.defenderStatus ? ['Defender status', e.defenderStatus] : null,
        e.error ? ['Error', e.error] : null,
        e.closedBy ? ['Closed by', `${e.closedBy}: ${e.closedReason}`] : null,
      ].filter(Boolean).flatMap(([k, v]) => [el('dt', { textContent: k }), el('dd', {}, v)])),
      buttons.length ? el('div', { className: 'toolbar' }, ...buttons) : null, msg);
  }

  async function page() {
    stop();
    const top = el('div');
    const body = el('div', {}, el('p', { className: 'muted', textContent: 'Loading...' }));
    view().replaceChildren(
      el('h1', { textContent: 'Emergency' }),
      el('p', { className: 'guide-lead', textContent: 'The fast path: one Microsoft Defender action on one PC, approved by a second person, running in minutes. For anything that should last or reach more than one PC, use the slow path (Remediations).' }),
      el('p', { className: 'muted' }, 'Not sure which path? Read ', el('a', { href: '#paths', textContent: 'Fast or slow path' }), '.'),
      top, body);
    const load = async () => {
      stop();
      let d;
      try { d = await api('/api/emergency'); } catch (e) { body.replaceChildren(el('p', { className: 'error', textContent: e.message })); return; }
      const open = d.items.filter(e => ['pending', 'approved', 'running'].includes(e.state));
      const done = d.items.filter(e => !open.includes(e));
      body.replaceChildren(
        el('h2', { textContent: `Open (${open.length})` }),
        open.length ? el('div', { className: 'cards emergency-list' }, ...open.map(e => card(e, d, load))) : el('p', { className: 'muted', textContent: 'Nothing is waiting.' }),
        el('h2', { textContent: `Last 14 days (${done.length})` }),
        done.length ? el('div', { className: 'cards emergency-list' }, ...done.map(e => card(e, d, load))) : el('p', { className: 'muted', textContent: 'No finished emergency actions.' }),
        el('p', { className: 'muted', textContent: `Rules: one device per request; a second person with the emergencyApprover role approves within ${d.windowMinutes / 60} hours; r360 runs it in Defender as the approver. Four-eyes is ${d.fourEyes === 'testing' ? 'in testing mode, so self-approval is allowed and flagged' : 'enforced'}. Every step is in Audit.` }));
      if (!top.dataset.ready) {
        top.dataset.ready = '1';
        if (!writing()) top.replaceChildren(el('div', { className: 'card' }, el('p', {}, 'To ask for or approve an emergency action, start a write session first (', el('strong', { textContent: 'Elevate to write' }), ' in the menu). Anyone signed in can read this page.')));
        else {
          const ready = el('p', { className: 'muted', textContent: 'Checking Defender with your sign-in...' });
          top.replaceChildren(el('div', { className: 'card' }, el('h2', { textContent: 'Defender connection' }), ready));
          api('/api/emergency/readiness').then(r => {
            ready.className = r.ok ? 'ok' : 'error'; ready.textContent = r.text;
            if (r.ok && roles().some(x => REQUEST_ROLES.includes(x))) top.append(requestForm(d, load));
          }).catch(e => { ready.className = 'error'; ready.textContent = e.message; });
        }
      }
      if (writing() && d.items.some(e => e.state === 'running')) timer = setTimeout(async () => {
        for (const e of d.items.filter(x => x.state === 'running')) await api(`/api/emergency/${e.id}/refresh`, false, { method: 'POST' }).catch(() => {});
        load();
      }, POLL_MS);
    };
    load();
  }
  return { page, stop };
}
