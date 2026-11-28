// Aaron (2026-11-27): "On EVERY page I want the default of collapsible sections to be collapsed. I want every section to be
// collapsible." Every h2/h3 section in #view becomes a closed <details>, and every rail section starts closed.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!doctype html><main id="view"></main>', { url: 'http://localhost:3660/#overview' });
const { window } = dom;
const { document } = window;
const { installPageSections, sectionKey } = await import('../public/page-sections.js');
const { installNavSections } = await import('../public/nav-sections.js');
const tick = () => new Promise(r => setTimeout(r, 0));
const el = (tag, props = {}, ...kids) => { const e = Object.assign(document.createElement(tag), props); e.append(...kids.filter(k => k != null)); return e; };
const view = document.getElementById('view');
const sections = () => [...view.querySelectorAll('details.page-section')];
const head = d => d.querySelector(':scope > summary > h2, :scope > summary > h3').textContent;
installPageSections(view, { win: window });

test('every h2 and h3 section on a page becomes a closed, collapsible section; nested h3s nest', async () => {
  view.replaceChildren(el('h1', { textContent: 'Overview' }), el('p', { className: 'muted', textContent: 'About r360' }),
    el('div', { className: 'card' }, el('h2', { textContent: 'What r360 does' }), el('p', { textContent: 'Fixes PCs' })),
    el('h2', { textContent: 'Targets' }), el('p', { textContent: 'intro' }),
    el('h3', { textContent: 'Open changes' }), el('ul', {}, el('li', { textContent: 'PR 7' })),
    el('h3', { textContent: 'Recent runs' }), el('p', { textContent: 'none' }),
    el('h2', { textContent: 'Lonely' }));
  await tick();
  assert.deepEqual(sections().map(head), ['What r360 does', 'Targets', 'Open changes', 'Recent runs']);
  assert.ok(sections().every(d => !d.open), 'all sections start collapsed');
  const targets = sections()[1];
  assert.deepEqual([...targets.querySelectorAll('details.page-section')].map(head), ['Open changes', 'Recent runs'], 'h3 sections sit inside their h2 section');
  assert.equal(targets.querySelector('.page-section-body > p').textContent, 'intro');
  assert.equal(view.querySelector('h2:not([data-sectioned])').textContent, 'Lonely', 'a heading with nothing under it stays plain');
  assert.equal(view.querySelector('.card > details.page-section > summary > h2').textContent, 'What r360 does', 'a card heading collapses the card body');
});

test('Expand all / Collapse all sits under the page title and opens or closes every section', async () => {
  const all = view.querySelector('button.sections-all');
  assert.equal(all.previousElementSibling.textContent, 'About r360', 'sits under the title and its description');
  assert.equal(all.textContent, 'Expand all');
  all.click();
  assert.ok(sections().every(d => d.open));
  assert.equal(all.textContent, 'Collapse all');
  all.click();
  assert.ok(sections().every(d => !d.open));
  assert.equal(all.textContent, 'Expand all');
});

test('a redraw keeps the state you left; counts in headings do not matter; a new page starts collapsed', async () => {
  const draw = n => view.replaceChildren(el('h1', { textContent: 'Emergency' }), el('h2', { textContent: `Open (${n})` }), el('p', { textContent: 'list' }), el('h2', { textContent: 'Last 14 days (0)' }), el('p', { textContent: 'old' }));
  window.location.hash = '#emergency'; window.dispatchEvent(new window.HashChangeEvent('hashchange'));
  draw(2); await tick();
  sections()[0].open = true; sections()[0].dispatchEvent(new window.Event('toggle'));
  draw(3); await tick(); // background reload with a new count
  assert.deepEqual(sections().map(d => d.open), [true, false]);
  window.location.hash = '#offboard'; window.dispatchEvent(new window.HashChangeEvent('hashchange'));
  window.location.hash = '#emergency'; window.dispatchEvent(new window.HashChangeEvent('hashchange'));
  draw(3); await tick();
  assert.deepEqual(sections().map(d => d.open), [false, false], 'opening the page again starts every section collapsed');
  assert.equal(sectionKey('emergency', 'Open (2)'), sectionKey('emergency', 'Open (3)'));
});

test('a section that appears because you pressed a button opens, so the result is on screen', async () => {
  const panel = el('div');
  const go = el('button', { className: 'btn', type: 'button', textContent: 'Summarize now' });
  go.onclick = () => panel.replaceChildren(el('div', { className: 'card' }, el('h2', { textContent: 'R360-CHG-12: printer swap' }), el('p', { textContent: 'summary text' })));
  view.replaceChildren(el('h1', { textContent: 'Change requests' }), go, panel);
  await tick();
  go.click(); await tick();
  assert.equal(panel.querySelector('details.page-section').open, true);
});

test('every rail section starts collapsed, opens for the current page without being saved, and remembers what you open', () => {
  const store = new Map();
  const storage = { getItem: k => store.get(k) ?? null, setItem: (k, v) => store.set(k, v) };
  const html = '<div id="nav"><div class="nav-group"><button class="nav-label" data-section="a">A</button><a class="nav-item" data-view="one">1</a></div>'
    + '<div class="nav-group"><button class="nav-label" data-section="b">B</button><a class="nav-item" data-view="two">2</a></div></div>';
  const mk = () => { const host = el('div'); host.innerHTML = html; return host; };
  let host = mk();
  let s = installNavSections(host, storage, 'r360.nav.open', { defaultCollapsed: true });
  const labels = () => [...host.querySelectorAll('.nav-label')].map(l => l.getAttribute('aria-expanded'));
  assert.deepEqual(labels(), ['false', 'false']);
  s.expandFor('two');
  assert.deepEqual(labels(), ['false', 'true']);
  assert.equal(store.get('r360.nav.open'), undefined, 'opening for the current page is not saved');
  s.expandFor('one');
  assert.deepEqual(labels(), ['true', 'false'], 'moving to a page in another section closes the one opened for the last page');
  host.querySelector('[data-section="a"]').click(); // you close it
  host.querySelector('[data-section="a"]').click(); // and open it yourself, which is remembered
  assert.deepEqual(JSON.parse(store.get('r360.nav.open')), ['a']);
  host = mk();
  s = installNavSections(host, storage, 'r360.nav.open', { defaultCollapsed: true });
  assert.deepEqual(labels(), ['true', 'false'], 'after a reload only the section you opened is open');
});

test('r360 wires it up: app.js installs page sections, shell.js starts rail sections collapsed, index.html says so', () => {
  const read = f => readFileSync(new URL(`../public/${f}`, import.meta.url), 'utf8');
  assert.match(read('app.js'), /installPageSections\(view\(\)\)/);
  assert.match(read('shell.js'), /defaultCollapsed: true/);
  assert.doesNotMatch(read('index.html'), /class="nav-label" aria-expanded="true"/);
  assert.doesNotMatch(read('requests.js'), /open: !d\.rows\.length/, 'the Get a change number form starts closed too');
});
