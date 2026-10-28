import test from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { createApp } from '../server/app.mjs';
import { SessionStore, SESSION_COOKIE } from '../server/auth.mjs';
import { world, AARON, ofAction, PROD, PILOT, CAN } from './s6-world.mjs';

// The real public/app.js + public/changes.js in jsdom against the real Express app, with the S6 world behind it.
const dom = new JSDOM('<!doctype html><div id="banners"></div><span id="who"></span><span id="writectl"></span><nav id="nav"><a href="#remediations" data-view="remediations">R</a><a href="#changes" data-view="changes">C</a></nav><main id="view"></main>', { url: 'https://app-r360.example.westus3.azurecontainerapps.io/' });
const target = { base: '', headers: {}, origin: '' };
const realFetch = globalThis.fetch;
const realSetTimeout = globalThis.setTimeout, realSetInterval = globalThis.setInterval;
globalThis.setTimeout = (...a) => { const t = realSetTimeout(...a); t.unref?.(); return t; };
globalThis.setInterval = (...a) => { const t = realSetInterval(...a); t.unref?.(); return t; };
Object.assign(globalThis, { Node: dom.window.Node, FileReader: dom.window.FileReader, document: dom.window.document, location: dom.window.location, addEventListener: dom.window.addEventListener.bind(dom.window), alert: () => { throw new Error('alert must not be used'); } });
globalThis.fetch = (path, init = {}) => String(path).startsWith('/') ? realFetch(target.base + path, { ...init, headers: { ...init.headers, ...target.headers, origin: target.origin } }) : realFetch(path, init);

const until = async (cond, what) => { for (let i = 0; i < 200; i++) { if (await cond()) return; await new Promise(r => realSetTimeout(r, 25)); } assert.fail(`timed out waiting for ${what}; view: ${document.getElementById('view').innerHTML.slice(0, 900)}`); };
const $ = sel => document.querySelector(sel);
const byText = (sel, re) => [...document.querySelectorAll(sel)].find(e => re.test(e.textContent));
const goto = async hash => { location.hash = hash; await new Promise(r => realSetTimeout(r, 30)); };
let app;
async function serve(w) {
  const sessions = new SessionStore({ now: () => w.t });
  const auth = { writeConfigured: true, beginSignIn: async () => 'x', completeSignIn: async () => {}, graphToken: async () => 'GT',
    beginElevate: async s => { s.writePending = { state: 'ws', nonce: 'n', verifier: 'v', created: w.t }; return 'https://login.microsoftonline.com/write'; },
    completeElevate: async s => ({ oid: s.user.oid, upn: s.user.upn, homeAccountId: 'ha', acrs: [], accessToken: 'WT' }), endWrite: async () => {}, signOut: async () => {}, writeToken: async () => 'WT' };
  const data = { pim: async () => ({ gate: { ok: true, text: 'active' } }), remediations: async () => ({ rows: [] }), fleet: async () => ({}), certificates: async () => ({}) };
  const a = createApp({ config: w.config, sessions, auth, data, github: w.github, audit: w.audit, fetcher: w.g.fetcher, now: () => w.t, log: { error() {} } });
  const srv = a.listen(0); await new Promise(r => srv.once('listening', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  const s = sessions.create(); s.user = AARON; const headers = { cookie: `${SESSION_COOKIE}=${s.id}` };
  await fetch(base + '/auth/write/start', { redirect: 'manual', headers }); await fetch(base + '/auth/write/callback?code=0123456789&state=ws', { redirect: 'manual', headers });
  target.base = base; target.headers = headers; target.origin = w.config.publicUrl;
  document.getElementById('banners').replaceChildren(); document.getElementById('view').replaceChildren();
  if (!app) app = await import('../public/app.js'); else app.boot?.();
  await until(() => document.getElementById('who').textContent === AARON.upn, 'the page to load');
  return { close: () => srv.close() };
}
const row = n => [...document.querySelectorAll('#view tr')].find(r => new RegExp(`#${n}(?!\\d)`).test(r.textContent));

test('UI: at day 8 the Soak column says complete and Promote creates the promotion pull request', async () => {
  const w = world({ soakDays: 8 }); const srv = await serve(w);
  try {
    await goto('#changes');
    await until(() => row(3), 'the canary change row');
    assert.match(row(3).textContent, /Day 8, soak complete/);
    const btn = byText('#view button', /^Promote$/);
    assert.ok(btn && !btn.disabled, 'Promote is enabled');
    btn.click();
    await until(() => byText('#view button', /^Create promotion PR/), 'the promote panel');
    // R360_PROD_GROUP_ID is only a default: it is preselected, with its counts, and can be changed.
    await until(() => /Target: Production Devices \(90000000[^)]*\), 41 devices, 58 members\./.test($('.target-picker').textContent), 'the default target');
    // search by name: canary is never offered; a count shows for each group
    const input = $('.group-search');
    input.value = 'canary'; input.dispatchEvent(new dom.window.Event('input'));
    await until(() => /No matching groups\. The canary group is not offered\./.test($('.target-picker').textContent), 'canary hidden');
    assert.equal(byText('.target-picker button', /Remediation Canary/), undefined);
    input.value = 'pilot'; input.dispatchEvent(new dom.window.Event('input'));
    await until(() => byText('.group-pick', /Pilot Devices/), 'the pilot result');
    assert.match(byText('.group-pick', /Pilot Devices/).textContent, new RegExp(`${PILOT} \\| 6 devices \\| 9 members \\| dynamic`));
    assert.ok(byText('.group-pick', /^All devices/), 'All devices is always offered');
    // Clicking a result adds a chip next to the preselected default; removing the default chip leaves Pilot alone.
    byText('.group-pick', /Pilot Devices/).click();
    assert.deepEqual([...document.querySelectorAll('.selected-targets .chip')].map(c => c.firstChild.textContent), ['Production Devices', 'Pilot Devices']);
    assert.match($('.target-picker').textContent, /Targets: 2 groups, 47 devices, 67 members in total/);
    assert.ok(byText('#view button', /^Create promotion PR for 2 groups$/));
    $('.chip-remove[aria-label="Remove Production Devices"]').click();
    assert.match($('.target-picker').textContent, /Target: Pilot Devices \(22222222[^)]*\), 6 devices, 9 members\./);
    assert.ok(byText('#view button', /^Create promotion PR for 1 group$/));
    assert.equal($('.soak-banner'), null, 'no override banner when the gate is met');
    assert.match($('#view').textContent, /Published to the canary group by r360/); assert.match($('#view').textContent, /Intune run summary shows 0 errors/);
    byText('#view button', /^Create promotion PR/).click();
    await until(() => /Promotion pull request #7 created/.test($('#view').textContent), 'the created message');
    assert.equal(w.proposals.length, 1); assert.doesNotMatch(w.proposals[0].title, /OVERRIDE/);
    assert.equal(JSON.parse(w.proposals[0].files[0].content).assignment.groupId, PILOT);
    assert.match(w.proposals[0].title, /to group "Pilot Devices"/);
    assert.equal(w.g.writes().length, 0);
  } finally { srv.close(); }
});

test('UI: with no default group, Create stays disabled until a target is chosen, and All devices carries a warning', async () => {
  const w = world({ soakDays: 8, prod: false }); const srv = await serve(w);
  try {
    await goto('#changes');
    await until(() => row(3), 'the canary change row');
    byText('#view button', /^Promote$/).click();
    await until(() => byText('#view button', /^Create promotion PR/), 'the promote panel');
    const go = byText('#view button', /^Create promotion PR/);
    assert.equal(go.disabled, true); assert.match($('.target-picker').textContent, /No target chosen yet/);
    const input = $('.group-search'); input.value = 'x'; input.dispatchEvent(new dom.window.Event('input'));
    await until(() => /Type at least 2 characters/.test($('.target-picker').textContent), 'the short query hint');
    byText('.group-pick', /^All devices/).click();
    assert.equal(go.disabled, false); assert.match($('.target-picker').textContent, /Target: All devices\. Every Intune-managed device/); assert.match(go.textContent, /for All devices$/);
    go.click();
    await until(() => /Promotion pull request #7 created/.test($('#view').textContent), 'the created message');
    const next = JSON.parse(w.proposals[0].files[0].content); assert.equal(next.assignment.target, 'allDevices'); assert.equal('groupId' in next.assignment, false);
    assert.match(w.proposals[0].title, /to All devices/);
    await goto('#remediations'); await goto('#changes');
    await until(() => row(7) && /promotion to All devices/.test(row(7).textContent), 'the list names the target');
  } finally { srv.close(); }
});

test('UI: at day 3 the override shows a red banner, needs a written reason, and the result is bannered in the list', async () => {
  const w = world({ soakDays: 3 }); const srv = await serve(w);
  try {
    await goto('#changes');
    await until(() => row(3), 'the canary change row');
    assert.match(row(3).textContent, /Day 3 of 7/);
    const btn = byText('#view button', /^Promote$/); assert.ok(btn && !btn.disabled, 'an approver can open the dialog');
    btn.click();
    await until(() => $('.soak-banner'), 'the override banner');
    await until(() => /Target: Production Devices/.test($('.target-picker').textContent), 'the default target');
    const banner = $('.soak-banner'); assert.equal(banner.getAttribute('role'), 'alert'); assert.match(banner.textContent, /SOAK OVERRIDE/); assert.match(banner.textContent, /3 of 7/);
    assert.equal(byText('#view button', /^Create promotion PR/), undefined, 'the plain button is not offered');
    const go = byText('#view button', /Override soak and create promotion PR/); const why = $('#view textarea');
    assert.equal(go.disabled, true);
    why.value = 'too short'; why.dispatchEvent(new dom.window.Event('input')); assert.equal(go.disabled, true);
    why.value = 'Pilot team signed off.'; why.dispatchEvent(new dom.window.Event('input')); assert.equal(go.disabled, false);
    go.click();
    await until(() => /SOAK OVERRIDE \(3 of 7 days\)/.test($('#view').textContent), 'the created message');
    assert.equal(w.proposals.length, 1); assert.match(w.proposals[0].title, /SOAK OVERRIDE/);
    const okRow = ofAction(w, 'promote.proposed').find(r => r.result === 'ok'); assert.equal(okRow.reason, 'Pilot team signed off.');
    await goto('#remediations'); await goto('#changes');
    await until(() => row(7) && /SOAK OVERRIDE/.test(row(7).textContent), 'the bannered promotion row');
    const edit = [...row(7).querySelectorAll('a')].find(a => a.textContent === 'Edit'); assert.equal(edit.getAttribute('aria-disabled'), 'true'); assert.match(edit.title, /cannot be edited/);
  } finally { srv.close(); }
});

test('UI: when a failure is not just the soak days, there is no override, only the reason it is blocked', async () => {
  const w = world({ soakDays: 3 }); w.g.summary.detectionScriptErrorDeviceCount = 2; const srv = await serve(w);
  try {
    await goto('#changes');
    await until(() => row(3), 'the canary change row');
    byText('#view button', /^Promote$/).click();
    await until(() => /Intune run summary shows 0 errors/.test($('#view').textContent), 'the check list');
    assert.equal(byText('#view button', /Override soak/), undefined); assert.equal(byText('#view button', /^Create promotion PR/), undefined);
    assert.match($('#view').textContent, /script errors/);
  } finally { srv.close(); }
});


test('UI: chips persist across a blur and a new search, All devices clears groups with an explanation, and steps and Close are labelled', async () => {
  const w = world({ soakDays: 8 }); const srv = await serve(w);
  try {
    await goto('#changes'); await until(() => row(3), 'the canary change row');
    byText('#view button', /^Promote$/).click();
    await until(() => /Target: Production Devices/.test($('.target-picker')?.textContent), 'the default target');
    assert.equal(document.querySelectorAll('.promote-steps > .promote-step').length, 2);
    assert.match($('.promote-steps').textContent, /Step 1\. Search and select targets/); assert.match($('.promote-steps').textContent, /Step 2\. Create the promotion pull request/);
    const chips = () => [...document.querySelectorAll('.selected-targets .chip')].map(c => c.firstChild.textContent);
    const input = $('.group-search'); const search = q => { input.value = q; input.dispatchEvent(new dom.window.Event('input')); };
    search('pilot'); await until(() => byText('.group-pick', /Pilot Devices/), 'the pilot result');
    byText('.group-pick', /Pilot Devices/).click();
    assert.equal(document.activeElement, input, 'the search keeps focus after a pick');
    input.dispatchEvent(new dom.window.Event('blur')); input.blur(); $('.promote-steps').click();
    assert.deepEqual(chips(), ['Production Devices', 'Pilot Devices'], 'chips survive a blur');
    search('production'); await until(() => byText('.group-pick', /Production Devices/), 'a new search');
    assert.deepEqual(chips(), ['Production Devices', 'Pilot Devices'], 'chips survive a new search');
    assert.ok(byText('#view button', /^Create promotion PR for 2 groups$/));
    byText('.group-pick', /^All devices/).click();
    assert.deepEqual(chips(), ['All devices']); assert.match($('.target-note').textContent, /All devices replaces the 2 groups.*always chosen on its own/);
    assert.ok(byText('#view button', /^Create promotion PR for All devices$/));
    search('pilot'); await until(() => byText('.group-pick', /Pilot Devices/), 'the pilot result again');
    byText('.group-pick', /Pilot Devices/).click();
    assert.deepEqual(chips(), ['Pilot Devices'], 'picking a group replaces All devices');
    const close = byText('#view button', /^Close/);
    assert.equal(close.textContent, 'Close (changes nothing)'); assert.match(close.title, /only hides this panel/i); assert.match(close.getAttribute('aria-label'), /nothing is created, changed or assigned/i);
    assert.equal($('.chip-remove').getAttribute('aria-label'), 'Remove Pilot Devices');
    assert.equal(w.proposals.length, 0); assert.equal(w.g.writes().length, 0);
  } finally { srv.close(); }
});

test('UI: the SOAK OVERRIDE banner sits above the reason, stacked full width, inside step 2', async () => {
  const w = world({ soakDays: 3 }); const srv = await serve(w);
  try {
    await goto('#changes'); await until(() => row(3), 'the canary change row');
    byText('#view button', /^Promote$/).click();
    await until(() => $('.override-block .soak-banner'), 'the override block');
    const block = $('.override-block'), banner = block.querySelector('.soak-banner'), why = block.querySelector('textarea.override-reason');
    assert.ok(why, 'the reason is inside the same block');
    assert.ok(banner.compareDocumentPosition(why) & dom.window.Node.DOCUMENT_POSITION_FOLLOWING, 'the banner comes before the reason in DOM order');
    assert.deepEqual([...block.children].map(e => e.className.split(' ').find(c => c === 'soak-banner' || c === 'override-reason')), ['soak-banner', 'override-reason']);
    assert.match(block.closest('.promote-step').textContent, /Step 2\. Write the override reason/);
    assert.match($('.promote-steps').textContent, /Step 3\. Create the promotion pull request/);
    assert.ok(byText('#view button', /^Override soak and create promotion PR for 1 group$/));
  } finally { srv.close(); }
});

test('CSS: the override block stacks vertically at full width, and there is still exactly one .btn rule', async () => {
  const { readFileSync } = await import('node:fs');
  const css = readFileSync(new URL('../public/style.css', import.meta.url), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');
  const rule = sel => { const m = css.match(new RegExp(`(^|\\})\\s*${sel.replace(/[.]/g, '\\.')}\\s*\\{([^}]*)\\}`)); return m ? m[2].replace(/\s+/g, '') : ''; };
  const block = rule('.override-block');
  assert.match(block, /display:flex/); assert.match(block, /flex-direction:column/); assert.match(block, /align-items:stretch/);
  assert.match(rule('.override-block .override-reason'), /width:100%/); assert.match(rule('.override-block .override-reason'), /display:block/);
  assert.match(rule('.override-block .soak-banner'), /display:block/);
  assert.doesNotMatch(block, /flex-direction:(row|column-reverse)/); assert.doesNotMatch(css, /(^|[;{\s])order\s*:/, 'nothing reorders the banner visually');
  assert.equal((css.match(/(^|\})\s*\.btn\s*\{/g) || []).length, 1);
});
