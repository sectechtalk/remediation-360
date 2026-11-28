// Aaron's rule for every 360 app: every button shows it is doing something. A button that starts work shows a spinner and a
// specific busy label at once, cannot be clicked twice, counts seconds after 3 s, then the page shows the result or the
// exact error. Instant buttons say what they did. A busy button must not look like a disabled one.
import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!doctype html><main id="view"></main>', { url: 'http://localhost:3660/' });
globalThis.window = dom.window; globalThis.document = dom.window.document;
for (const k of ['HTMLElement', 'Node', 'Event', 'KeyboardEvent', 'MouseEvent']) globalThis[k] = dom.window[k];
const { busy, busyStatus, flash, leaving, installPressFeedback } = await import('../public/busy.js');
const { createServiceNowUi } = await import('../public/servicenow.js');
const { createDeploymentsUi } = await import('../public/deployments.js');

const read = file => readFileSync(new URL(`../public/${file}`, import.meta.url), 'utf8');
const el = (tag, props = {}, ...kids) => { const e = Object.assign(document.createElement(tag), props); e.append(...kids.filter(k => k != null)); return e; };
const tick = () => new Promise(r => setTimeout(r, 0));
const $ = s => document.querySelector(s);
const button = text => [...document.querySelectorAll('button')].find(b => b.textContent === text);
const deferred = () => { let resolve, reject; const p = new Promise((a, b) => { resolve = a; reject = b; }); return { p, resolve, reject }; };

test('busy() shows the busy label and spinner class at once, ignores a second click, and always restores the button', async () => {
  const b = el('button', { className: 'btn', textContent: 'Search' });
  const d = deferred();
  let runs = 0;
  const first = busy(b, 'Searching…', () => { runs++; return d.p; });
  assert.deepEqual([b.textContent, b.disabled, b.getAttribute('aria-busy'), b.classList.contains('is-busy')], ['Searching…', true, 'true', true]);
  assert.equal(await busy(b, 'Searching…', () => { runs++; }), undefined, 'a second click while busy does nothing');
  d.resolve(7);
  assert.equal(await first, 7);
  assert.equal(runs, 1);
  assert.deepEqual([b.textContent, b.disabled, b.hasAttribute('aria-busy'), b.classList.contains('is-busy')], ['Search', false, false, false]);
  await assert.rejects(busy(b, 'Searching…', async () => { throw new Error('boom'); }));
  assert.deepEqual([b.textContent, b.disabled], ['Search', false], 'an error never leaves the button stuck');
  // { always: true } still runs the work when the button is already busy (background reloads).
  b.disabled = true;
  assert.equal(await busy(b, 'x', async () => 'ran', { always: true }), 'ran');
});

test('busy() adds a seconds counter after 3 seconds', async () => {
  mock.timers.enable({ apis: ['setInterval', 'Date'] });
  try {
    const b = el('button', { textContent: 'Merge and apply' });
    const d = deferred();
    const p = busy(b, 'Merging…', () => d.p);
    mock.timers.tick(2000); assert.equal(b.textContent, 'Merging…');
    mock.timers.tick(1000); assert.equal(b.textContent, 'Merging… 3 s');
    mock.timers.tick(5000); assert.equal(b.textContent, 'Merging… 8 s');
    d.resolve(); await p;
    assert.equal(b.textContent, 'Merge and apply');
  } finally { mock.timers.reset(); }
});

test('busyStatus() writes what is happening, then the exact error, and leaves the button usable', async () => {
  const b = el('button', { textContent: 'Search Defender' });
  const msg = el('div');
  const d = deferred();
  const p = busyStatus(b, 'Searching Defender…', msg, () => d.p, el);
  assert.equal(msg.textContent, 'Searching Defender…');
  d.reject(new Error('Defender returned 403: the signed-in user lacks Machine.Read.All'));
  await p;
  assert.equal(msg.textContent, 'Defender returned 403: the signed-in user lacks Machine.Read.All');
  assert.equal(msg.querySelector('.error')?.textContent, msg.textContent);
  assert.deepEqual([b.textContent, b.disabled], ['Search Defender', false]);
});

test('flash() and leaving() and the press safety net', async () => {
  const b = el('button', { textContent: 'Copy' });
  flash(b, 'Copied', 10);
  assert.ok(b.textContent === 'Copied' && b.classList.contains('is-done'));
  await new Promise(r => setTimeout(r, 30));
  assert.ok(b.textContent === 'Copy' && !b.classList.contains('is-done'));
  const s = el('button', { textContent: 'Sign out' });
  leaving(s, 'Signing out…');
  assert.deepEqual([s.textContent, s.disabled, s.classList.contains('is-busy')], ['Signing out…', true, true]);
  const host = el('div');
  document.body.append(host);
  installPressFeedback(host);
  const dl = el('a', { className: 'btn', textContent: 'Download CSV', target: '_blank', href: '#x' }); dl.dataset.done = 'Download started';
  const out = el('a', { className: 'btn', textContent: 'Open PIM activation', target: '_blank', href: '#y' });
  const inert = el('a', { className: 'btn', textContent: 'New remediation', href: '#new', title: 'Start a write session first' }); inert.setAttribute('aria-disabled', 'true'); inert.onclick = e => e.preventDefault();
  const plain = el('button', { textContent: 'Menu' });
  host.append(dl, out, inert, plain);
  for (const a of [dl, out]) a.addEventListener('click', e => e.preventDefault());
  dl.click(); out.click(); inert.click(); plain.click();
  assert.equal(dl.textContent, 'Download started');
  assert.equal(out.textContent, 'Opened in a new tab');
  assert.match(inert.textContent, /Not available/);
  assert.ok(plain.classList.contains('pressed'), 'instant buttons get a visible press');
  host.remove();
});

test('ServiceNow: Search shows "Searching ServiceNow…" while it runs, then the result', async () => {
  const d = deferred();
  const META = { configured: true, instance: 'https://contoso.service-now.com', tables: { incident: 'Incidents' }, preconfigured: [], saved: [], canSave: false, canCreateIssue: false };
  const api = async (path, refresh, init = {}) => (path === '/api/servicenow/queries' && !init.method ? META : d.p);
  await createServiceNowUi({ el, api, view: () => $('#view'), fmtTime: v => v }).page();
  const go = button('Search');
  go.click(); await tick();
  assert.equal(go.textContent, 'Searching ServiceNow…');
  assert.ok(go.disabled && go.classList.contains('is-busy'));
  assert.match($('#view [role=status]').textContent, /Searching ServiceNow…/);
  d.resolve({ query: { kind: 'custom' }, rows: [], truncated: false, issueLookup: 'ok' });
  await tick(); await tick();
  assert.equal(go.textContent, 'Search');
  assert.equal(go.disabled, false);
  assert.match($('#view').textContent, /0 item\(s\)/);
});

test('Deployments: Merge and apply shows "Merging…", then the exact error from the server', async () => {
  const d = deferred();
  const target = { id: 'f360-lab', name: 'Lab', repo: 'your-org/f-360', repoUrl: 'https://github.com/your-org/f-360', branch: 'main', workflow: 'lab.yml', environment: 'lab', drift: { state: 'clean' }, runs: [],
    changes: [{ number: 7, title: 'Add app', headSha: 'abcdef0123456789', canMerge: true, plan: { state: 'succeeded', counts: { add: 1, change: 0, destroy: 0 } }, url: 'https://github.com/your-org/f-360/pull/7' }] };
  const api = async (path, refresh, init = {}) => (init.method ? d.p : { fetchedAt: '2026-11-21T00:00:00Z', targets: [target] });
  const session = { me: { roles: ['admin'], write: { active: true } } };
  const ui = createDeploymentsUi({ el, pill: (t, c) => el('span', { className: `pill ${c}`, textContent: t }), api, view: () => $('#view'), fmtTime: v => v, session });
  ui.deployments(); await tick(); await tick();
  const m = button('Merge and apply');
  m.click(); await tick();
  assert.deepEqual([m.textContent, m.disabled, m.classList.contains('is-busy')], ['Merging…', true, true]);
  d.reject(new Error('GitHub refused the merge: required check "plan" has not passed'));
  await tick(); await tick();
  assert.deepEqual([m.textContent, m.disabled], ['Merge and apply', false]);
  assert.match($('#view').textContent, /GitHub refused the merge: required check "plan" has not passed/);
  ui.stop();
});

// Every <button> in r360, by file, with the feedback it gives. A new button fails here until it gets busy() (work),
// flash() (instant result), leaving() (leaves the page) or an immediate visible redraw, and is added below.
const BUTTONS = {
  'app.js': { count: 4, labels: ['Refreshing…', 'Loading…', 'Searching the audit log…', 'Ending the write session…', 'Opening sign-in…', 'Signing out…'] },
  'changes.js': { count: 10, labels: ['Validating…', 'Creating the pull request…', 'Pushing the update…', 'Searching groups…', 'Creating the promotion PR…', 'Reading canary evidence…', 'Publishing to Intune…', 'Verifying signing…', 'Discarding…', 'Approving…', 'Rejecting…', 'Merging…'] },
  'deployments.js': { count: 2, labels: ['Starting the plan…', 'Starting the drift check…', 'Merging…', 'Refreshing…'] },
  'emergency.js': { count: 7, labels: ['Searching Defender…', 'Sending the request…', 'Approving and running in Defender…', 'Cancelling…', 'Rejecting…', 'Checking Defender…'] },
  'offboard.js': { count: 5, labels: ['Opening sign-in…', 'Reading the person from Entra…', 'Sending the request…', 'Running: disable, revoke, provision, verify…', 'Running the request…', 'Cancelling…'] },
  'requests.js': { count: 10, labels: ['Copied', 'Getting a change number…', 'Summarizing…', 'Requesting a summary…', 'Finding action items…', 'Shown below', 'Reading the mailbox…', 'Checking the mailbox…'] },
  'servicenow.js': { count: 4, labels: ['Creating the issue…', 'Searching ServiceNow…', 'Saving…', 'Deleting…'] },
  'page-sections.js': { count: 1, labels: ['Expand all', 'Collapse all'] }, // relabels itself and opens or closes every section at once
  'table.js': { count: 2, labels: [] }, // sort and filter: the table redraws, or the filter menu opens, at once
  'index.html': { count: 7, labels: [] }, // section headers, theme, Menu: instant; Sign out: leaving() from app.js
};
const BUTTON_RE = /el\('button'|ael\('button'|createElement\('button'\)|<button/g;

test('every button in r360 is registered with its feedback, and nothing uses the old silent "Working..." pattern', () => {
  const files = readdirSync(new URL('../public/', import.meta.url)).filter(f => /\.(js|html)$/.test(f));
  for (const f of files) {
    const src = read(f);
    const n = (src.match(BUTTON_RE) || []).length;
    if (!n) continue;
    assert.ok(BUTTONS[f], `${f} has ${n} button(s) but is not in BUTTONS: give each busy(), flash(), leaving() or an immediate redraw, then register the file`);
    assert.equal(n, BUTTONS[f].count, `${f}: a button was added or removed. Give a new one busy(), flash(), leaving() or an immediate redraw, then update the count`);
    for (const label of BUTTONS[f].labels) assert.ok(src.includes(`'${label}'`) || src.includes(`${label}\``) || src.includes(`'${label}`), `${f}: missing feedback label "${label}"`);
    assert.doesNotMatch(src, /Working\.\.\./, `${f}: use busy()/busyStatus() with a specific label, not "Working..."`);
    assert.doesNotMatch(src, /\.textContent = '[A-Z][a-z]+ing\.\.\.'/, `${f}: set busy labels through busy(), which also adds the spinner and counter`);
  }
  assert.match(read('app.js'), /installPressFeedback\(document\)/);
});

test('a busy button looks different from a disabled one, and buttons are filled', () => {
  const css = read('style.css');
  const rule = sel => css.split('\n').find(l => l.startsWith(sel))?.split('{')[1] || '';
  assert.match(rule('.btn {'), /background: var\(--accent-soft\)/, 'buttons are filled, never the page colour');
  assert.doesNotMatch(rule('.btn {'), /transparent/);
  const disabled = rule('.btn:disabled');
  const isBusy = rule('.btn.is-busy, .btn.is-busy:disabled');
  assert.match(disabled, /dashed/); assert.match(disabled, /var\(--surface-2\)/);
  assert.match(isBusy, /var\(--accent-strong\)/); assert.match(isBusy, /cursor: progress/);
  assert.doesNotMatch(isBusy, /dashed|--muted/);
  assert.match(css, /\.btn\.is-busy::before \{[^}]*animation: r360-spin/);
  assert.match(css, /prefers-reduced-motion[^\n]*\.btn\.is-busy::before/);
});
