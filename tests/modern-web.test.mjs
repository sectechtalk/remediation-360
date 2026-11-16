// Modern Web Guidance fixes modelled on e-360 #50-#54: table headers are real buttons with aria-sort, the filter menu
// works from the keyboard, focus is always visible, and Windows high-contrast (forced colours) keeps every state visible.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const css = readFileSync(new URL('../public/style.css', import.meta.url), 'utf8');

test('table: sort and filter controls are buttons; the sorted header has aria-sort; Escape closes the filter menu', async () => {
  const dom = new JSDOM('<!doctype html><div id="host"></div>');
  Object.assign(globalThis, { document: dom.window.document, Node: dom.window.Node, addEventListener: dom.window.addEventListener.bind(dom.window), removeEventListener: dom.window.removeEventListener.bind(dom.window) });
  const { renderTable } = await import('../public/table.js');
  const host = document.getElementById('host');
  renderTable(host, { rows: [{ name: 'b', n: 2 }, { name: 'a', n: 1 }], columns: [{ key: 'edit', label: '' }, { key: 'name', label: 'Name' }, { key: 'n', label: 'Count' }] });
  const sorts = [...host.querySelectorAll('th button.sort')], flts = [...host.querySelectorAll('th button.flt')];
  assert.equal(sorts.length, 3); assert.equal(flts.length, 3);
  for (const b of [...sorts, ...flts]) assert.equal(b.type, 'button');
  assert.equal(sorts[0].getAttribute('aria-label'), 'Sort by edit', 'an unlabeled column still has an accessible name');
  assert.equal(flts[1].getAttribute('aria-label'), 'Filter Name');
  assert.equal(host.querySelector('th[aria-sort]'), null);
  sorts[1].click();
  assert.equal(sorts[1].closest('th').getAttribute('aria-sort'), 'ascending');
  assert.equal(host.querySelector('tbody td:nth-child(2)').textContent, 'a');
  sorts[1].click();
  assert.equal(sorts[1].closest('th').getAttribute('aria-sort'), 'descending');
  sorts[2].click();
  assert.equal(sorts[1].closest('th').hasAttribute('aria-sort'), false, 'only one sorted column');
  flts[1].click();
  assert.equal(flts[1].getAttribute('aria-expanded'), 'true');
  assert.ok(host.querySelector('.menu[role="group"]'));
  assert.equal(document.activeElement, host.querySelector('.menu input'), 'focus moves into the menu');
  dom.window.dispatchEvent(new dom.window.KeyboardEvent('keydown', { key: 'Escape' }));
  assert.equal(host.querySelector('.menu'), null);
  assert.equal(flts[1].getAttribute('aria-expanded'), 'false');
  assert.equal(document.activeElement, flts[1], 'focus returns to the filter button');
});

test('CSS: header buttons keep the header look, focus is always visible, and forced colours keep states visible', () => {
  assert.match(css, /th button\.sort, th button\.flt \{[^}]*background: none/);
  assert.match(css, /:focus-visible \{[^}]*outline: 2px solid/);
  assert.match(css, /@media \(forced-colors: active\) \{/);
  assert.match(css, /\.btn:disabled[^{]*\{ color: GrayText/);
});
