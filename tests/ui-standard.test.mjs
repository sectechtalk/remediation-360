// 360 look-and-feel standard (2026-11-15): Inter, the shared type scale and colours, the copper Remediation accent,
// the left rail with the 360 app switcher, collapsible sections and a unique icon per page, a theme toggle that follows
// the OS, and a menu drawer at phone width.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import vm from 'node:vm';
import { switcherHtml } from '../public/shell.js';
import { APPS_360 } from '../public/360-apps.js';
import { ICONS_360 } from '../public/360-icons.js';
import { SECURITY_HEADERS } from '../server/app.mjs';

const url = f => new URL(`../public/${f}`, import.meta.url);
const read = f => readFileSync(url(f), 'utf8');
const base = read('360-base.css'), css = read('style.css'), html = read('index.html');
const rail = html.slice(html.indexOf('<nav class="rail"'), html.indexOf('</nav>'));

test('360-base.css: seven-step type scale with a 12px floor, self-hosted Inter, shared colour tokens', () => {
  const steps = { xs: '.75rem', sm: '.8125rem', base: '.875rem', md: '1rem', lg: '1.25rem', xl: '1.5rem', '2xl': '1.875rem' };
  for (const [name, size] of Object.entries(steps)) assert.match(base, new RegExp(`--text-${name}:${size.replace('.', '\\.')};`));
  assert.match(base, /@font-face\{font-family:Inter;/);
  assert.ok(existsSync(url('fonts/InterVariable.woff2')), 'font file is self-hosted');
  for (const t of ['--bg', '--surface', '--surface-2', '--line', '--fg', '--muted', '--ok', '--warn', '--crit']) assert.match(base, new RegExp(`${t}:#`), t);
});

test('style.css imports the base first (the server-rendered sign-in and error pages load only style.css)', () => {
  assert.ok(css.startsWith('@import url("/360-base.css");'));
});

test('style.css has balanced braces (a stray } makes the browser drop the next rule)', () => {
  let depth = 0;
  for (const ch of css.replace(/\/\*[\s\S]*?\*\//g, '')) { if (ch === '{') depth++; if (ch === '}') depth--; assert.ok(depth >= 0, 'closing brace with nothing open'); }
  assert.equal(depth, 0);
});

test('style.css uses only the type tokens, Inter and weights 400/500/600, the shared colour names, and the copper accent', () => {
  assert.deepEqual(css.match(/font(?:-size)?:[^;}]*\d(?:px|pt|rem|em)\b/g) || [], [], 'font sizes outside the scale');
  assert.doesNotMatch(css, /Segoe UI|Consolas|font-weight:\s*(bold|700)/, 'only Inter and the shared mono stack');
  assert.deepEqual((css.match(/font-weight:\s*(\d+)/g) || []).filter(w => !/(400|500|600)$/.test(w)), [], 'weights 400/500/600 only');
  assert.doesNotMatch(css, /var\(--(panel|text|bad)\)/, 'old token names are gone');
  assert.match(css, /--accent: #a14a12;/);
  assert.doesNotMatch(html, /data-theme="dark"/, 'no forced dark mode; theme.js follows the OS');
});

test('index.html: theme script in head, shell and app modules, no inline styles or scripts (CSP)', () => {
  assert.match(html, /<script src="\/theme\.js"><\/script>/);
  assert.match(html, /<script type="module" src="\/shell\.js"><\/script>/);
  assert.match(html, /<script type="module" src="\/app\.js"><\/script>/);
  assert.doesNotMatch(html, /style="|<style|<script>|fonts\.googleapis/);
  assert.match(SECURITY_HEADERS['Content-Security-Policy'], /script-src 'self';/);
  assert.match(SECURITY_HEADERS['Content-Security-Policy'], /style-src 'self';/);
});

test('rail: app switcher under the brand, theme toggle, account controls, and a menu button that controls the rail', () => {
  assert.match(rail, /id="rail" data-rail/);
  assert.ok(rail.indexOf('id="app-switcher"') > rail.indexOf('brand-name'), 'switcher sits under the brand');
  assert.match(rail, /<div id="app-switcher" class="app-switcher" data-app="r-360"><\/div>/);
  assert.match(rail, /<button id="theme-toggle" class="btn" type="button"/);
  for (const id of ['who', 'writectl']) assert.match(rail, new RegExp(`id="${id}"`));
  assert.match(rail, /<form method="post" action="\/auth\/signout">/);
  for (const m of rail.matchAll(/<a class="nav-item" href="#([a-z]+)" data-view="([a-z]+)"/g)) assert.equal(m[1], m[2]);
  assert.match(html, /<button id="nav-toggle" class="btn nav-toggle" type="button" aria-controls="rail" aria-expanded="false">/);
});

test('rail: collapsible section headers and a unique shared icon for every page (360 rail standard)', () => {
  const pages = [...rail.matchAll(/data-view="([a-z]+)"><span data-nav-icon="([a-z0-9-]+)"><\/span>/g)];
  assert.equal(pages.length, [...rail.matchAll(/class="nav-item/g)].length, 'every page link has an icon');
  assert.equal(pages.length, 16);
  const icons = pages.map(m => m[2]);
  assert.deepEqual(icons.filter((n, i) => icons.indexOf(n) !== i), []);
  for (const n of icons) assert.ok(ICONS_360[n], n);
  assert.equal([...rail.matchAll(/<button type="button" class="nav-label" aria-expanded="true" data-section="[a-z-]+"><span>[^<]+<\/span><span class="nav-chevron" aria-hidden="true"><\/span><\/button>/g)].length, 4);
  assert.doesNotMatch(css, /\.nav-(label|item) \{[^}]*font-size/, 'header and link sizes come from 360-base.css');
});

test('app switcher lists every 360 app, marks Remediation 360 as here, and never links an app with no URL', () => {
  const out = switcherHtml('r-360');
  for (const a of APPS_360) assert.ok(out.includes(a.name), a.name);
  assert.match(out, /<span class="app-switch-item" aria-current="page"><strong>Remediation 360<\/strong>/);
  assert.doesNotMatch(out, /href=""/);
});

test('theme: a stored choice wins, otherwise the OS setting; toggling stores the choice under r360-theme', () => {
  const mod = { exports: {} }; vm.runInNewContext(read('theme.js'), { module: mod, window: undefined }); const t = mod.exports;
  const store = m => ({ getItem: k => m[k] ?? null, setItem: (k, v) => { m[k] = v; } });
  const os = dark => ({ matchMedia: () => ({ matches: dark }) });
  assert.equal(t.KEY, 'r360-theme');
  assert.equal(t.initialTheme(store({}), os(true)), 'dark');
  assert.equal(t.initialTheme(store({ 'r360-theme': 'light' }), os(true)), 'light');
  const m = {}, doc = { documentElement: { dataset: { theme: 'light' } }, getElementById: () => null };
  assert.equal(t.toggleTheme(doc, store(m)), 'dark');
  assert.equal(m['r360-theme'], 'dark');
});

test('route marks the current page with aria-current so the rail opens its section', () => {
  assert.match(read('app.js'), /a\.setAttribute\('aria-current', 'page'\)/);
});
