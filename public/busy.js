// Every button says it is doing something. Aaron's rule for all 360 apps (same pattern as Exchange 360):
// - A button that starts work shows a busy label at once ("Searching…", "Merging…") with a spinner, is disabled while
//   it works (so a second click does nothing), adds a seconds counter after 3 seconds, and then the page shows the
//   result or the exact error. A busy button looks different from a disabled one (filled with a spinner, not grey).
// - An instant button flashes what it did ("Copied", "Download started", "Opened in a new tab").
// - A button that leaves the page (sign-in, sign-out) says where it is going while the browser loads.
// tests/button-feedback.test.mjs fails when a new button has none of these.

const COUNT_AFTER_S = 3;

// options.always: if the button is already busy (for example a background reload while Refresh is running), run the
// work anyway without touching the button. Without it, a click on a busy button is ignored.
export async function busy(button, text, work, { always = false } = {}) {
  if (!button || button.disabled) return always ? work() : undefined;
  const label = button.textContent;
  button.disabled = true;
  button.setAttribute('aria-busy', 'true');
  button.classList.add('is-busy');
  button.textContent = text;
  const started = Date.now();
  const tick = setInterval(() => {
    const s = Math.floor((Date.now() - started) / 1000);
    if (s >= COUNT_AFTER_S) button.textContent = `${text} ${s} s`;
  }, 1000);
  tick.unref?.();
  try {
    return await work();
  } finally {
    clearInterval(tick);
    button.textContent = label;
    button.disabled = false;
    button.removeAttribute('aria-busy');
    button.classList.remove('is-busy');
  }
}

// busy() plus a status line: shows what is happening under the button, and the exact error if it fails. The error is
// shown, not thrown, so the page never ends up with a stuck button or a silent failure.
export function busyStatus(button, text, status, work, el) {
  status.replaceChildren(el('span', { className: 'muted', textContent: text }));
  return busy(button, text, async () => {
    try { await work(); } catch (e) { status.replaceChildren(el('span', { className: 'error', textContent: e.message })); }
  });
}

export function flash(button, text, ms = 1800) {
  if (!button) return;
  const label = button.dataset.flashLabel || button.textContent;
  button.dataset.flashLabel = label;
  button.textContent = text;
  button.classList.add('is-done');
  clearTimeout(button._flashTimer);
  button._flashTimer = setTimeout(() => {
    button.textContent = label;
    button.classList.remove('is-done');
    delete button.dataset.flashLabel;
  }, ms);
  button._flashTimer.unref?.();
}

// A button that leaves the page (sign-in, sign-out, elevate): say where it is going while the browser loads it.
export function leaving(button, text) {
  if (!button) return;
  button.textContent = text;
  if (button.tagName === 'BUTTON') button.disabled = true;
  button.setAttribute('aria-busy', 'true');
  button.classList.add('is-busy');
}

// The safety net for buttons whose result is instant (sort, filter, collapse, theme): a visible press. Links styled as
// buttons say what they did: data-done="…" if set, "Opened in a new tab" for target=_blank, and an inert link
// (aria-disabled) says it is not available, with the reason in its tooltip.
export function installPressFeedback(doc) {
  doc.addEventListener('click', event => {
    const target = event.target.closest?.('button, a.btn');
    if (!target || target.classList.contains('is-busy')) return;
    target.classList.add('pressed');
    setTimeout(() => target.classList.remove('pressed'), 250);
    if (target.tagName !== 'A') return;
    if (target.getAttribute('aria-disabled') === 'true') flash(target, 'Not available (hover to see why)', 2500);
    else if (target.dataset.done) flash(target, target.dataset.done);
    else if (target.target === '_blank') flash(target, 'Opened in a new tab');
  }, true);
}
