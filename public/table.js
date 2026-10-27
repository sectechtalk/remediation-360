// Table with sortable headers, multi-select checkbox filters (all values checked by default), resizable columns and
// horizontal scrolling. Pure helpers are exported for unit tests.
export function distinctValues(rows, key) {
  return [...new Set(rows.map(r => cellText(r[key])))].sort((a, b) => a.localeCompare(b));
}
export const cellText = v => v == null || v === '' ? '(blank)' : Array.isArray(v) ? (v.length ? v.join('; ') : '(blank)') : String(v);
export function applyFilters(rows, filters) {
  return rows.filter(r => Object.entries(filters).every(([k, allowed]) => !allowed || allowed.has(cellText(r[k]))));
}
export function sortRows(rows, key, dir) {
  if (!key) return rows;
  const m = dir === 'desc' ? -1 : 1;
  return [...rows].sort((a, b) => {
    const x = a[key], y = b[key];
    if (typeof x === 'number' && typeof y === 'number') return (x - y) * m;
    return cellText(x).localeCompare(cellText(y), undefined, { numeric: true }) * m;
  });
}

export function renderTable(host, { columns, rows, empty = 'No rows.' }) {
  const state = { filters: {}, sort: null, dir: 'asc' };
  const wrap = document.createElement('div');
  wrap.className = 'tablewrap';
  const count = document.createElement('div');
  count.className = 'muted';
  host.replaceChildren(count, wrap);
  const t = document.createElement('table');
  const hr = t.createTHead().insertRow();
  const tb = t.createTBody();
  wrap.append(t);
  const heads = columns.map(c => {
    const th = document.createElement('th');
    th.style.width = (c.width || 140) + 'px';
    const s = document.createElement('span'); s.className = 'sort';
    s.onclick = () => { state.dir = state.sort === c.key && state.dir === 'asc' ? 'desc' : 'asc'; state.sort = c.key; draw(); };
    const f = document.createElement('span'); f.className = 'flt'; f.textContent = '▾'; f.title = 'Filter';
    f.onclick = ev => { ev.stopPropagation(); openMenu(th, c); };
    const g = document.createElement('span'); g.className = 'grip';
    g.onmousedown = ev => { const x0 = ev.clientX, w0 = th.offsetWidth; const mv = e => { th.style.width = Math.max(50, w0 + e.clientX - x0) + 'px'; }; const up = () => { removeEventListener('mousemove', mv); removeEventListener('mouseup', up); }; addEventListener('mousemove', mv); addEventListener('mouseup', up); };
    th.append(s, f, g); hr.append(th);
    return { c, s, f };
  });
  const draw = () => {
    for (const h of heads) {
      h.s.textContent = h.c.label + (state.sort === h.c.key ? (state.dir === 'asc' ? ' ▲' : ' ▼') : '');
      h.f.className = 'flt' + (state.filters[h.c.key] ? ' on' : '');
    }
    const view = sortRows(applyFilters(rows, state.filters), state.sort, state.dir);
    count.textContent = `${view.length} of ${rows.length} row(s)`;
    tb.replaceChildren();
    if (!view.length) { const td = tb.insertRow().insertCell(); td.colSpan = columns.length; td.className = 'muted'; td.textContent = empty; }
    for (const r of view) {
      const tr = tb.insertRow();
      for (const c of columns) {
        const td = tr.insertCell();
        const v = c.render ? c.render(r) : cellText(r[c.key]);
        if (v instanceof Node) td.append(v); else td.textContent = v === '(blank)' ? '' : v;
        td.title = td.textContent;
      }
    }
  };
  const openMenu = (th, c) => {
    document.querySelectorAll('.menu').forEach(m => m.remove());
    const values = distinctValues(rows, c.key);
    const allowed = state.filters[c.key] || new Set(values);
    const m = document.createElement('div'); m.className = 'menu';
    const all = document.createElement('label'); const ac = document.createElement('input'); ac.type = 'checkbox'; ac.checked = allowed.size === values.length; all.append(ac, ' (Select all)'); m.append(all);
    const boxes = values.map(v => { const l = document.createElement('label'); const cb = document.createElement('input'); cb.type = 'checkbox'; cb.checked = allowed.has(v); cb.value = v; l.append(cb, ' ' + v); m.append(l); return cb; });
    const apply = () => { const sel = new Set(boxes.filter(b => b.checked).map(b => b.value)); state.filters[c.key] = sel.size === values.length ? undefined : sel; ac.checked = sel.size === values.length; draw(); };
    ac.onchange = () => { boxes.forEach(b => { b.checked = ac.checked; }); apply(); };
    boxes.forEach(b => { b.onchange = apply; });
    m.onclick = ev => ev.stopPropagation();
    th.append(m);
    setTimeout(() => addEventListener('click', () => m.remove(), { once: true }));
  };
  draw();
}
