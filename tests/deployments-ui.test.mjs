import test from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

// Renders public/deployments.js in jsdom with a fake api: target card, plan pill, merge and dispatch buttons and their gates.
const HEAD = 'a'.repeat(40);
const DATA = { fetchedAt: '2026-11-12T06:00:00Z', fourEyes: 'off', targets: [{
  id: 'f360-lab', name: 'Federation 360 lab', repo: 'your-org/f-360', repoUrl: 'https://github.com/your-org/f-360', branch: 'main', workflow: 'lab.yml',
  workflowUrl: 'https://github.com/your-org/f-360/actions/workflows/lab.yml', environment: 'lab', tenantId: null, path: 'lab/terraform', error: null, auditNote: null,
  lastApply: { state: 'succeeded', at: '2026-11-12T05:00:00Z', url: 'https://github.com/your-org/f-360/actions/runs/9' },
  drift: { state: 'drift', at: '2026-11-12T04:00:00Z', url: 'https://github.com/your-org/f-360/actions/runs/10' },
  changes: [{ number: 5, title: 'Add SCIM app', url: 'https://github.com/your-org/f-360/pull/5', author: 'your-org', headSha: HEAD, updatedAt: '2026-11-12T05:30:00Z',
    plan: { state: 'succeeded', counts: { add: 3, change: 1, destroy: 0, noChanges: false }, commentUrl: 'https://github.com/c', runUrl: 'javascript:alert(1)' }, canMerge: true, blockedReason: null }],
  runs: [{ id: 11, kind: 'plan', outcome: 'succeeded', event: 'pull_request', actor: 'your-org', headSha: HEAD, url: 'https://github.com/r/11', startedAt: '2026-11-12T05:30:00Z', updatedAt: '2026-11-12T05:31:00Z', pullNumbers: [5] }],
}] };

async function render(me) {
  const dom = new JSDOM('<main id="view"></main>');
  globalThis.document = dom.window.document; globalThis.Node = dom.window.Node; globalThis.window ??= dom.window;
  const { createDeploymentsUi, planText } = await import('../public/deployments.js');
  const calls = [];
  const el = (tag, props = {}, ...kids) => { const e = Object.assign(document.createElement(tag), props); e.append(...kids.filter(k => k != null)); return e; };
  const pill = (text, cls) => el('span', { className: `pill ${cls}`, textContent: text });
  const api = async (path, refresh, init = {}) => { calls.push({ path, init }); return path === '/api/deployments' ? DATA : { ok: true, mergeSha: 'c'.repeat(40), applyUrl: 'https://github.com/x', runsUrl: 'https://github.com/x' }; };
  const ui = createDeploymentsUi({ el, pill, api, view: () => document.getElementById('view'), fmtTime: v => v || '', session: { me } });
  ui.deployments();
  await new Promise(r => setTimeout(r, 20));
  return { doc: document, calls, ui, planText };
}
const button = (doc, text) => [...doc.querySelectorAll('button')].find(b => b.textContent === text);

test('Deployments page: card, drift, plan counts, and unsafe links are not rendered as links', async () => {
  const { doc, ui, planText } = await render({ roles: ['approver'], write: { active: true } });
  const text = doc.getElementById('view').textContent;
  assert.match(text, /Federation 360 lab/); assert.match(text, /DRIFT/); assert.match(text, /\+3 ~1 -0/); assert.match(text, /Four-eyes is off/);
  assert.ok([...doc.querySelectorAll('a')].every(a => a.href.startsWith('https://github.com/')), 'only github.com links');
  assert.equal(planText({ state: 'none' }), 'No plan yet');
  assert.equal(planText({ counts: { noChanges: true } }), 'No changes');
  ui.stop();
});

test('Deployments page: merge posts the head sha; buttons are gated by write session and role', async () => {
  const a = await render({ roles: ['approver'], write: { active: true } });
  const m = button(a.doc, 'Merge and apply'); assert.equal(m.disabled, false);
  m.click(); await new Promise(r => setTimeout(r, 20));
  const post = a.calls.find(c => c.init.method === 'POST');
  assert.equal(post.path, '/api/deployments/f360-lab/pulls/5/merge'); assert.deepEqual(post.init.body, { headSha: HEAD });
  a.ui.stop();
  const b = await render({ roles: ['author'], write: { active: true } });
  assert.equal(button(b.doc, 'Merge and apply').disabled, true); assert.equal(button(b.doc, 'Run plan').disabled, false);
  b.ui.stop();
  const c = await render({ roles: ['admin'], write: { active: false } });
  assert.equal(button(c.doc, 'Merge and apply').disabled, true); assert.match(button(c.doc, 'Check drift now').title, /write session/);
  c.ui.stop();
});
