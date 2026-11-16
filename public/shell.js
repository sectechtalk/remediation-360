// 360 shell behaviour shared by every 360 app: the app switcher under the brand, page icons and collapsible sections
// in the rail, and the phone-width menu.
import { APPS_360 } from './360-apps.js';
import { iconSvg } from './360-icons.js';
import { installNavSections } from './nav-sections.js';

const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

export function switcherHtml(current, apps = APPS_360) {
  const items = apps.map(a => {
    const label = `<strong>${esc(a.name)}</strong><small>${esc(a.id === current ? 'You are here' : a.url ? a.about : 'Not linked yet')}</small>`;
    if (a.id === current) return `<li><span class="app-switch-item" aria-current="page">${label}</span></li>`;
    if (!a.url) return `<li><span class="app-switch-item is-unlinked">${label}</span></li>`;
    return `<li><a class="app-switch-item" href="${esc(a.url)}">${label}</a></li>`;
  }).join('');
  return `<details class="app-switcher-menu"><summary class="app-switcher-toggle">360 apps</summary><ul class="app-switch-list">${items}</ul></details>`;
}

export function installShell(doc = document) {
  const host = doc.getElementById('app-switcher');
  if (host) {
    host.innerHTML = switcherHtml(host.dataset.app);
    const menu = host.querySelector('details');
    doc.addEventListener('click', e => { if (menu.open && !host.contains(e.target)) menu.open = false; });
    doc.addEventListener('keydown', e => { if (e.key === 'Escape' && menu.open) { menu.open = false; menu.querySelector('summary').focus(); } });
  }
  const rail = doc.querySelector('[data-rail]');
  // Page icons: <span data-nav-icon="name"></span> becomes the shared inline SVG.
  for (const el of doc.querySelectorAll('[data-nav-icon]')) {
    const tpl = doc.createElement('template'); tpl.innerHTML = iconSvg(el.dataset.navIcon); el.replaceWith(tpl.content);
  }
  // Collapsible sections, unless the app wires them itself (data-sections="app", as e-360 does).
  if (rail && rail.dataset.sections !== 'app' && rail.querySelector('.nav-label')) {
    let storage = null; try { storage = doc.defaultView.localStorage; } catch { /* storage blocked */ }
    const app = host?.dataset.app || 'app';
    const sections = installNavSections(rail, storage, `${app.replace(/-/g, '')}.nav.collapsed`);
    const showCurrent = () => setTimeout(() => sections.expandItem(rail.querySelector('[aria-current="page"]')), 0);
    doc.defaultView.addEventListener('hashchange', showCurrent);
    showCurrent();
  }
  const toggle = doc.getElementById('nav-toggle');
  if (toggle && rail) {
    const set = open => { doc.body.classList.toggle('nav-open', open); toggle.setAttribute('aria-expanded', String(open)); };
    toggle.addEventListener('click', () => set(!doc.body.classList.contains('nav-open')));
    rail.addEventListener('click', e => { if (e.target.closest('a[href], [data-view]')) set(false); });
    doc.addEventListener('click', e => { if (doc.body.classList.contains('nav-open') && !rail.contains(e.target) && !toggle.contains(e.target)) set(false); });
    doc.addEventListener('keydown', e => { if (e.key === 'Escape' && doc.body.classList.contains('nav-open')) { set(false); toggle.focus(); } });
  }
}

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', () => installShell()); else installShell();
}
