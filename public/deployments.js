import { renderTable } from './table.js';

// Deployments lane UI. The server decides and enforces everything; this shows targets, open changes with their plan, and
// runs, and offers Merge and apply, Run plan and Check drift. Links go only to github.com. No inline script or style (CSP).
const GITHUB = 'https://github.com/';
const safeUrl = u => (typeof u === 'string' && u.startsWith(GITHUB) ? u : null);
const POLL_MS = 15000;

export const outcomeCls = s => ({ succeeded: 'ok', clean: 'ok', failed: 'bad', error: 'bad', drift: 'bad', running: 'warn', waiting: 'warn', cancelled: 'muted', skipped: 'muted' }[s] || 'muted');
export const driftLabel = s => ({ clean: 'No drift', drift: 'DRIFT', error: 'Check failed', running: 'Checking', cancelled: 'Cancelled', never: 'Never checked', unknown: 'Unknown' }[s] || s);
export const planText = p => {
  if (!p?.counts) return p?.state === 'none' ? 'No plan yet' : p?.state === 'running' ? 'Planning...' : p?.state === 'failed' ? 'Plan failed' : 'Plan not posted';
  if (p.counts.noChanges) return 'No changes';
  return `+${p.counts.add ?? '?'} ~${p.counts.change ?? '?'} -${p.counts.destroy ?? '?'}`;
};

export function createDeploymentsUi({ el, pill, api, view, fmtTime, session }) {
  let poll = null;
  const stop = () => { clearInterval(poll); poll = null; };
  const link = (u, text) => (safeUrl(u) ? el('a', { href: u, target: '_blank', rel: 'noopener', textContent: text }) : el('span', { textContent: text }));
  const roles = () => session.me?.roles || [];
  const writeBlock = allowed => !session.me?.write?.active ? 'Start a write session first (Elevate to write).' : !roles().some(r => allowed.includes(r)) ? 'Your role does not allow this.' : null;

  function actionButton(text, allowed, extraBlock, onClick, msg) {
    const block = writeBlock(allowed) || extraBlock || null;
    const b = el('button', { className: 'btn', textContent: text, disabled: !!block, title: block || '' });
    b.onclick = async () => {
      b.disabled = true; msg.textContent = '';
      try { msg.replaceChildren(await onClick()); }
      catch (e) { msg.replaceChildren(el('span', { className: 'error', textContent: e.message })); }
      finally { b.disabled = false; }
    };
    return b;
  }

  function targetCard(t, reload) {
    const msg = el('span', { role: 'status' });
    const head = el('h2', { textContent: `${t.name} ` }, link(t.repoUrl, t.repo));
    if (t.error) return el('div', { className: 'card deploy' }, head, el('p', { className: 'error', textContent: t.error }));
    const dispatch = mode => actionButton(mode === 'plan' ? 'Run plan' : 'Check drift now', ['author', 'approver', 'admin'], null, async () => {
      const r = await api(`/api/deployments/${encodeURIComponent(t.id)}/dispatch`, false, { method: 'POST', body: { mode } });
      setTimeout(reload, 4000);
      return el('span', {}, `${mode === 'plan' ? 'Plan' : 'Drift check'} started. `, link(r.runsUrl, 'Watch it in GitHub'), r.warning ? el('span', { className: 'error', textContent: ` ${r.warning}` }) : null);
    }, msg);
    const kv = el('dl', { className: 'kv' }, ...[
      ['Branch', t.branch], ['Workflow', link(t.workflowUrl, t.workflow)], ['Environment', t.environment], ['Tenant', t.tenantId || 'not set'], ['Path', t.path || '(whole repo)'],
      ['Last apply', t.lastApply ? el('span', {}, pill(t.lastApply.state, outcomeCls(t.lastApply.state)), ` ${fmtTime(t.lastApply.at)} `, link(t.lastApply.url, 'logs')) : 'never'],
      ['Drift', el('span', {}, pill(driftLabel(t.drift.state), outcomeCls(t.drift.state)), t.drift.at ? ` ${fmtTime(t.drift.at)} ` : ' ', t.drift.url ? link(t.drift.url, 'logs') : null)],
    ].flatMap(([k, v]) => [el('dt', { textContent: k }), el('dd', {}, v)]));

    const changes = el('div');
    renderTable(changes, { rows: t.changes, columns: [
      { key: 'merge', label: '', width: 130, render: c => actionButton('Merge and apply', ['approver', 'admin'], c.blockedReason, async () => {
        const r = await api(`/api/deployments/${encodeURIComponent(t.id)}/pulls/${c.number}/merge`, false, { method: 'POST', body: { headSha: c.headSha } });
        setTimeout(reload, 4000);
        return el('span', {}, `#${c.number} merged (${r.mergeSha.slice(0, 8)}). The apply runs next. `, link(r.applyUrl, 'Watch the apply'), r.warning ? el('span', { className: 'error', textContent: ` ${r.warning}` }) : null);
      }, msg) },
      { key: 'number', label: 'PR', width: 60, render: c => link(c.url, `#${c.number}`) },
      { key: 'title', label: 'Change', width: 260 },
      { key: 'plan', label: 'Plan (+add ~change -destroy)', width: 190, render: c => el('span', {}, pill(planText(c.plan), c.plan.counts?.destroy ? 'bad' : outcomeCls(c.plan.state)), ' ', c.plan.commentUrl ? link(c.plan.commentUrl, 'plan') : null, ' ', c.plan.runUrl ? link(c.plan.runUrl, 'logs') : null) },
      { key: 'blockedReason', label: 'Ready to merge', width: 260, render: c => (c.canMerge ? pill('Ready', 'ok') : el('span', { className: 'muted', textContent: c.blockedReason })) },
      { key: 'author', label: 'Author', width: 120 },
      { key: 'headSha', label: 'Commit', width: 90, render: c => c.headSha?.slice(0, 8) || '' },
      { key: 'updatedAt', label: 'Updated', width: 170, render: c => fmtTime(c.updatedAt) },
    ], empty: 'No open deployment changes. Open a pull request on the target repository; the plan is posted on it.' });

    const runs = el('div');
    renderTable(runs, { rows: t.runs, columns: [
      { key: 'kind', label: 'Run', width: 80 },
      { key: 'outcome', label: 'Result', width: 110, render: r => pill(r.outcome, outcomeCls(r.outcome)) },
      { key: 'url', label: 'Logs', width: 70, render: r => link(r.url, 'logs') },
      { key: 'event', label: 'Trigger', width: 130 },
      { key: 'actor', label: 'Started by', width: 130 },
      { key: 'pullNumbers', label: 'PR', width: 60, render: r => (r.pullNumbers?.length ? `#${r.pullNumbers[0]}` : '') },
      { key: 'headSha', label: 'Commit', width: 90, render: r => r.headSha?.slice(0, 8) || '' },
      { key: 'startedAt', label: 'Started', width: 170, render: r => fmtTime(r.startedAt) },
      { key: 'updatedAt', label: 'Updated', width: 170, render: r => fmtTime(r.updatedAt) },
    ], empty: 'No runs of this workflow yet.' });

    return el('div', { className: 'card deploy' }, head, kv,
      el('div', { className: 'toolbar' }, dispatch('plan'), dispatch('drift'), msg),
      t.auditNote ? el('p', { className: 'error', textContent: t.auditNote }) : null,
      el('h3', { textContent: 'Open changes' }), changes, el('h3', { textContent: 'Recent runs' }), runs);
  }

  function deployments() {
    stop();
    const body = el('div');
    const btn = el('button', { className: 'btn', textContent: 'Refresh' });
    const stamp = el('span', { className: 'muted' });
    const load = async (quiet = false) => {
      btn.disabled = true;
      if (!quiet) body.replaceChildren(el('p', { className: 'muted', textContent: 'Loading...' }));
      try {
        const d = await api('/api/deployments');
        stamp.textContent = `Loaded ${fmtTime(d.fetchedAt)}`;
        body.replaceChildren(...(d.targets.length ? d.targets.map(t => targetCard(t, () => load(true)))
          : [el('p', { className: 'muted', textContent: 'No deployment targets yet. Set them with tools/Set-R360DeployTargets.ps1 (see docs/deployments.md).' })]));
        const busy = d.targets.some(t => t.runs.some(r => r.outcome === 'running' || r.outcome === 'waiting'));
        stop();
        if (busy) poll = setInterval(() => load(true), POLL_MS);
      } catch (e) { body.replaceChildren(el('p', { className: 'error', textContent: e.message })); }
      finally { btn.disabled = false; }
    };
    btn.onclick = () => load(false);
    view().replaceChildren(el('h1', { textContent: 'Deployments' }),
      el('p', { className: 'muted', textContent: 'Terraform changes run by GitHub Actions. A change is a pull request with its plan posted on it; merging starts the apply behind the target\'s GitHub environment; a scheduled plan flags drift. Every finished run is recorded in Audit. Four-eyes is off for this lane.' }),
      el('div', { className: 'toolbar' }, btn, stamp), body);
    load(false);
  }
  return { deployments, stop };
}
