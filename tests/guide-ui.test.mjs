import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

// New hire pages (public/guide.js): Overview is the default page, every page renders, every in-app link goes to a
// real page, and the copy keeps the house style (no em dashes) and the facts the license guide depends on.
const dom = new JSDOM('<!doctype html><main id="view"></main>', { url: 'http://localhost:3660/' });
globalThis.window = dom.window; globalThis.document = dom.window.document;
for (const k of ['HTMLElement', 'Node', 'Event']) globalThis[k] = dom.window[k];
const { createGuideUi, rich, MATRIX, LICENSES, FEATURE_LICENSES, FEATURE_COSTS, PRICES_CHECKED, DEFENDER_ACTION_PLANS } = await import('../public/guide.js');
const el = (tag, props = {}, ...kids) => { const e = Object.assign(document.createElement(tag), props); e.append(...kids.filter(k => k != null)); return e; };
const pill = (text, cls) => el('span', { className: `pill ${cls}`, textContent: text });
const view = () => document.getElementById('view');
const ui = createGuideUi({ el, pill, view });

const html = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
const app = readFileSync(new URL('../public/app.js', import.meta.url), 'utf8');
const navViews = new Set([...html.matchAll(/data-view="([a-z]+)"/g)].map(m => m[1]));

test('New hire is the first rail section, above Change, with Overview first', () => {
  const sections = [...html.matchAll(/data-section="([a-z-]+)"/g)].map(m => m[1]);
  assert.deepEqual(sections, ['new-hire', 'change', 'roll-out', 'govern']);
  const first = [...html.matchAll(/data-view="([a-z]+)"/g)].slice(0, 4).map(m => m[1]);
  assert.deepEqual(first, ['overview', 'paths', 'support', 'licenses']);
});

test('r360 opens on Overview: no hash and unknown pages both route to it', () => {
  assert.match(app, /export const DEFAULT_VIEW = 'overview';/);
  assert.match(app, /location\.hash \|\| `#\$\{DEFAULT_VIEW\}`/);
  assert.match(app, /Object\.hasOwn\(VIEWS, name\) \? name : DEFAULT_VIEW/);
});

for (const [page, heading] of [['overview', 'Welcome to Remediation 360'], ['paths', 'Fast or slow path'], ['support', 'What works where'], ['licenses', 'Licenses by feature']]) {
  test(`${page}: renders, links only to real pages, no em dashes`, () => {
    ui[page]();
    assert.equal(view().querySelector('h1').textContent, heading);
    for (const a of view().querySelectorAll('a[href^="#"]')) assert.ok(navViews.has(a.getAttribute('href').slice(1)), `${a.textContent} -> ${a.getAttribute('href')}`);
    for (const a of view().querySelectorAll('a[href^="https:"]')) { assert.equal(a.target, '_blank'); assert.equal(a.rel, 'noopener'); }
    assert.doesNotMatch(view().textContent, /—/, 'house style: no em dashes');
    assert.doesNotMatch(view().textContent, /\*\*|\]\(/, 'all inline markup was rendered');
  });
}

test('Overview explains the seven pipeline steps and the words a new owner hears', () => {
  ui.overview();
  assert.equal(view().querySelectorAll('.guide-flow-step').length, 7);
  const terms = [...view().querySelectorAll('.guide-terms dt')].map(d => d.textContent);
  for (const t of ['CI/CD', 'GitHub', 'Intune', 'Defender', 'Entra ID', 'Canary']) assert.ok(terms.includes(t), t);
});

test('What works where: the slow path needs a joined PC and an E3-class license; Business Premium and Office 365 do not get it', () => {
  const row = name => MATRIX.find(([lic]) => lic.startsWith(name))[1];
  assert.deepEqual(row('M365 E3'), ['both', 'both', 'fast', 'fast', 'fast']);
  assert.deepEqual(row('Business Premium'), ['fast', 'fast', 'fast', 'fast', 'fast']);
  assert.ok(row('No license').every(c => c === 'none'));
  assert.match(LICENSES.find(([l]) => l.startsWith('Office 365'))[1], /^No/);
  ui.support();
  assert.equal(view().querySelectorAll('.guide-table')[0].querySelectorAll('tbody tr').length, MATRIX.length);
});

test('rich() renders bold, code and links as nodes, never as HTML', () => {
  const box = el('p', {}, ...rich(el, 'a **b** `c` [d](#overview) <img src=x>'));
  assert.equal(box.querySelector('strong').textContent, 'b');
  assert.equal(box.querySelector('code').textContent, 'c');
  assert.equal(box.querySelector('a').getAttribute('href'), '#overview');
  assert.equal(box.querySelector('img'), null);
});

test('Licenses by feature: one row per feature, the facts operators trip on, and Defender plans that match the Emergency page', async () => {
  const { ACTIONS } = await import('../server/defender.mjs');
  const row = name => FEATURE_LICENSES.find(([f]) => f.startsWith(name));
  assert.match(row('Publish')[1], /Windows Enterprise E3/);
  assert.match(row('Publish')[1], /Business Premium alone is not enough/);
  assert.match(row('Signing')[1], /Key Vault Premium/);
  assert.match(row('Emergency')[2], /Active remediation actions/);
  assert.match(row('Change requests')[1], /no license up to 50 GB/);
  assert.match(row('Settings')[1], /Entra ID P2/);
  const plan = { 'Isolate and release': 'isolate', 'Run antivirus scan': 'scan', 'Stop and quarantine a file': 'quarantine', 'Collect investigation package': 'collect', 'Restrict app execution and remove it': 'restrict' };
  for (const [label, p1, mdb, p2] of DEFENDER_ACTION_PLANS) {
    const plans = ACTIONS[plan[label]].plans;
    assert.deepEqual([p1, mdb, p2], ['P1', 'MDB', 'P2'].map(x => plans.includes(x) ? 'Yes' : 'No'), label);
  }
  ui.licenses();
  assert.equal(view().querySelectorAll('.guide-table')[0].querySelectorAll('tbody tr').length, FEATURE_LICENSES.length);
});

test('Licenses by feature: every row says what to buy, the tiers cheapest first, and a cost; prices are dated', () => {
  assert.equal(FEATURE_COSTS.length, FEATURE_LICENSES.length);
  FEATURE_COSTS.forEach(([key, buy, tiers, cost], i) => {
    assert.ok(FEATURE_LICENSES[i][0].startsWith(key), `${key} lines up with ${FEATURE_LICENSES[i][0]}`);
    assert.ok(buy.length > 10 && cost.length > 3 && tiers.length >= 1, key);
    // Cheapest first: the first dollar figure in each tier never goes down.
    const first = tiers.map(t => t.match(/\$(\d+(?:\.\d+)?)/)).filter(Boolean).map(m => Number(m[1]));
    assert.deepEqual(first, [...first].sort((a, b) => a - b), `${key} tiers are cheapest first`);
  });
  const row = key => FEATURE_COSTS.find(([k]) => k === key);
  assert.match(row('Change requests')[1], /Office 365 or Microsoft 365/);
  assert.match(row('Publish')[2][0], /F3: \$10/);
  assert.match(row('Emergency')[2][0], /Defender for Business: \$3/);
  assert.match(PRICES_CHECKED, /^\d{4}-\d{2}-\d{2}$/);
  ui.licenses();
  const head = [...view().querySelectorAll('.guide-table-wide thead th')].map(t => t.textContent);
  assert.deepEqual(head.slice(1, 4), ['What to buy', 'Tiers, cheapest first', 'Estimated cost per month']);
  assert.match(view().textContent, new RegExp(`pricing pages on ${PRICES_CHECKED}`));
});
