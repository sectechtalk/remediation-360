// Collapsible rail sections, shared by every 360 app: copy this file unchanged. Each .nav-label (a native button) heads
// the nav items that follow it until the next label. Which sections are closed is remembered per app under `key`.
export const NAV_COLLAPSE_KEY = 'e360.nav.collapsed';

export function readCollapsed(storage, key = NAV_COLLAPSE_KEY) {
  try {
    const value = JSON.parse(storage?.getItem(key) || '[]');
    return Array.isArray(value) ? value.filter(item => typeof item === 'string') : [];
  } catch { return []; }
}

export function sectionKey(text) {
  return String(text || '').trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

export function installNavSections(nav, storage, storageKey = NAV_COLLAPSE_KEY, { defaultCollapsed = false } = {}) {
  // `remembered` holds closed sections normally, or opened sections when defaultCollapsed.
  const remembered = new Set(readCollapsed(storage, storageKey));
  const shownNow = new Set(); // opened for the current page only (defaultCollapsed), never saved
  const isClosed = key => (defaultCollapsed ? !remembered.has(key) && !shownNow.has(key) : remembered.has(key));
  const setClosed = (key, closed) => {
    shownNow.delete(key);
    if (closed === defaultCollapsed) remembered.delete(key); else remembered.add(key);
  };
  const labels = [...nav.querySelectorAll('.nav-label')];
  const itemsOf = label => {
    const out = [];
    for (let el = label.nextElementSibling; el && !el.classList.contains('nav-label'); el = el.nextElementSibling) out.push(el);
    return out;
  };
  const save = () => { try { storage?.setItem(storageKey, JSON.stringify([...remembered])); } catch { /* storage unavailable */ } };
  const apply = label => {
    const closed = isClosed(label.dataset.section);
    label.setAttribute('aria-expanded', String(!closed));
    label.title = `${closed ? 'Expand' : 'Collapse'} ${label.textContent.trim()}`;
    for (const el of itemsOf(label)) el.classList.toggle('nav-collapsed', closed);
  };
  for (const label of labels) {
    const key = label.dataset.section || sectionKey(label.textContent);
    label.dataset.section = key;
    const native = label.tagName === 'BUTTON';
    if (!native) { label.setAttribute('role', 'button'); label.tabIndex = 0; }
    if (!label.querySelector('.nav-chevron')) label.insertAdjacentHTML('beforeend', '<span class="nav-chevron" aria-hidden="true"></span>');
    const toggle = () => { setClosed(key, !isClosed(key)); apply(label); save(); };
    label.addEventListener('click', toggle);
    // A native button already turns Enter and Space into a click.
    if (!native) label.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); toggle(); } });
    apply(label);
  }
  // Never leave the active page hidden inside a collapsed section.
  const expandItem = item => {
    let el = item?.previousElementSibling;
    while (el && !el.classList.contains('nav-label')) el = el.previousElementSibling;
    if (defaultCollapsed) {
      // Only the current page's section is opened for you: the one opened for the previous page closes again.
      for (const key of [...shownNow]) if (key !== el?.dataset.section) { shownNow.delete(key); const l = labels.find(x => x.dataset.section === key); if (l) apply(l); }
    }
    if (!el || !isClosed(el.dataset.section)) return;
    if (defaultCollapsed) shownNow.add(el.dataset.section); else { remembered.delete(el.dataset.section); save(); }
    apply(el);
  };
  return {
    expandFor: view => expandItem(nav.querySelector(`[data-view="${view}"]`)),
    expandItem,
  };
}
