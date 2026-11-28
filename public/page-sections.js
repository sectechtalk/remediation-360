// Every section on every page is collapsible and starts collapsed (Aaron, 2026-11-27: "On EVERY page I want the default
// of collapsible sections to be collapsed. I want every section to be collapsible.").
//
// A section is a heading (h2 or h3) in the page plus everything after it up to the next heading of the same or a higher
// level. Pages keep building plain headings; this module watches the page and turns each one into a native
// <details class="page-section"> whose <summary> holds the heading, closed by default. Nested h3 sections inside an h2
// section become their own collapsible sections. Find in page (Ctrl+F) still finds text inside a closed section.
//
// Rules on top of "closed by default":
// - A section the page redraws (Refresh, a background reload) keeps the open or closed state you left it in. Counts in
//   the heading do not matter ("Open (2)" and "Open (3)" are the same section).
// - A section that appears because you just pressed a button on the page (a summary, a preview, a promote panel) opens,
//   so the result you asked for is on screen. Opening another page starts every section closed again.
// - A page with two or more sections gets an "Expand all" / "Collapse all" button under its title.
// - A heading with data-no-collapse, or a heading that is alone (nothing under it), is left as it is.
const ACTION_OPENS_MS = 30000;
const HEADINGS = 'h2, h3';
const level = el => Number(el.tagName.slice(1));
const isHeading = el => /^H[1-6]$/.test(el.tagName);

export const sectionKey = (view, text) => `${view}|${String(text || '').replace(/\(\d+\)|\d+/g, '#').replace(/\s+/g, ' ').trim().toLowerCase()}`;

export function installPageSections(root, { win = root.ownerDocument.defaultView, actionWindowMs = ACTION_OPENS_MS } = {}) {
  const doc = root.ownerDocument;
  const state = new Map(); // section key -> open, for the page that is showing now
  let actionAt = 0;
  const view = () => (win.location.hash || '#').slice(1).split('/')[0];
  win.addEventListener('hashchange', () => { state.clear(); actionAt = 0; });
  // A press on a button or button-styled control in the page (not a section header) marks the next new sections as its result.
  const markAction = event => {
    const t = event.target.closest?.('button, a.btn, input[type=submit], input[type=button]');
    if (t && !t.closest('summary') && !t.classList.contains('sections-all')) actionAt = Date.now();
  };
  root.addEventListener('click', markAction, true);
  root.addEventListener('submit', () => { actionAt = Date.now(); }, true);

  const wrap = heading => {
    const body = [];
    // Stop at the next heading, or section an earlier pass built, of the same or a higher level.
    const stops = el => (isHeading(el) && level(el) <= level(heading)) || (el.classList.contains('page-section') && Number(el.dataset.level) <= level(heading));
    for (let el = heading.nextElementSibling; el && !stops(el); el = el.nextElementSibling) body.push(el);
    // A heading with nothing under it yet stays plain and is looked at again when the page changes.
    if (!body.length) return;
    heading.dataset.sectioned = '1';
    const key = sectionKey(view(), heading.textContent);
    const isNew = !state.has(key);
    const open = isNew ? Date.now() - actionAt < actionWindowMs : state.get(key);
    state.set(key, open);
    const details = doc.createElement('details');
    details.className = `page-section level-${level(heading)}`;
    details.dataset.level = String(level(heading));
    details.open = open;
    const summary = doc.createElement('summary');
    summary.className = 'page-section-head';
    summary.title = 'Show or hide this section';
    const content = doc.createElement('div');
    content.className = 'page-section-body';
    heading.before(details);
    summary.append(heading);
    content.append(...body);
    details.append(summary, content);
    details.addEventListener('toggle', () => { state.set(key, details.open); syncAll(); });
  };

  // Expand all / Collapse all, under the page title, when the page has two or more sections.
  let allBtn = null;
  const sections = () => [...root.querySelectorAll('details.page-section')];
  const syncAll = () => {
    if (!allBtn) return;
    const list = sections();
    const text = list.length && list.every(d => d.open) ? 'Collapse all' : 'Expand all';
    // Only write when it changes: every write is a page change, which would run enhance() again.
    if (allBtn.textContent !== text) allBtn.textContent = text;
  };
  const placeAll = () => {
    const list = sections();
    const h1 = root.querySelector('h1');
    if (list.length < 2 || !h1) { allBtn?.remove(); return; }
    if (!allBtn) {
      allBtn = doc.createElement('button');
      allBtn.type = 'button';
      allBtn.className = 'btn sections-all';
      allBtn.onclick = () => {
        const open = allBtn.textContent === 'Expand all';
        for (const d of sections()) d.open = open;
        syncAll();
      };
    }
    // Sits right after the title (and its one-line description, if there is one), or at the end of the page's toolbar
    // there (next to Refresh) so it does not take a line of its own.
    const anchor = h1.nextElementSibling?.matches('p.muted') ? h1.nextElementSibling : h1;
    const bar = anchor.nextElementSibling?.matches('.toolbar') ? anchor.nextElementSibling : null;
    if (bar) { if (allBtn.parentElement !== bar) bar.append(allBtn); }
    else if (anchor.nextElementSibling !== allBtn) anchor.after(allBtn);
    syncAll();
  };

  let queued = false;
  const enhance = () => {
    queued = false;
    // Document order: an h2 is wrapped before the h3s under it, which are then wrapped inside the h2's section.
    for (const h of root.querySelectorAll(HEADINGS)) {
      if (h.dataset.sectioned || h.hasAttribute('data-no-collapse') || h.closest('summary')) continue;
      wrap(h);
    }
    placeAll();
  };
  const schedule = () => { if (!queued) { queued = true; queueMicrotask(enhance); } };
  new win.MutationObserver(schedule).observe(root, { childList: true, subtree: true });
  enhance();
  return { enhance, state };
}
