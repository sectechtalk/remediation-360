import test from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { createApp } from '../server/app.mjs';
import { SessionStore, SESSION_COOKIE } from '../server/auth.mjs';
import { machineBlock } from '../server/changes.mjs';
import { loadConfig } from '../server/config.mjs';
import { diffLines } from '../public/changes.js';
import { ENV } from './fixtures.mjs';

// Drives the real public/app.js + public/changes.js in jsdom against the real Express app (fake GitHub behind it).
const OID = '94540000-0000-4000-8000-0000000000c3';
const UPN = 'admin@contoso.com';
const CANARY = '90000000-0000-4000-8000-0000000000c2';
const config = loadConfig({ ...ENV, R360_CANARY_GROUP_ID: CANARY });
const T0 = Date.now();
const MAIN_META = { displayName: 'Existing', description: 'old', publisher: 'p', runAs: 'system', runAs32Bit: false, schedule: { type: 'daily', interval: 1, time: '03:00:00' }, assignment: { groupId: CANARY, runRemediationScript: true } };

function world(roles = ['author']) {
  const w = { t: T0, events: [], gh: [], discards: [], pulls: [], roles };
  w.audit = { record: async e => { w.events.push({ ...e, at: new Date(w.t).toISOString() }); return e; }, list: async () => ({ rows: [...w.events].reverse(), truncated: false }) };
  w.auth = {
    writeConfigured: true, beginSignIn: async () => 'https://login.microsoftonline.com/x', completeSignIn: async s => { s.user = { oid: OID, upn: UPN, name: 'Aaron' }; }, graphToken: async () => 'GT',
    beginElevate: async s => { s.writePending = { state: 'ws', nonce: 'n', verifier: 'v', created: w.t }; return 'https://login.microsoftonline.com/write'; },
    completeElevate: async () => ({ oid: OID, upn: UPN, homeAccountId: 'ha.write', acrs: ['c1'], accessToken: 'WT' }), endWrite: async () => {}, signOut: async () => {},
  };
  w.github = {
    catalog: async () => ({ sha: 'm', items: [{ folder: 'Existing', meta: MAIN_META, detect: 'line1\nline2\n', remediate: 'fix\n' }], approvers: [{ entraObjectId: OID, roles: w.roles }] }),
    listPulls: async () => w.pulls, getPull: async n => w.pulls.find(p => p.number === n),
    proposeChange: async a => { w.gh.push(a); const m = /"folder":"([^"]+)"/.exec(a.body)[1]; w.pulls = [{ number: 12, state: 'open', merged: false, title: 't', url: 'https://github.com/your-org/remediations/pull/12', branch: a.branch, headSha: 'a'.repeat(40), body: a.body, checks: [{ name: 'PSScriptAnalyzer', status: 'completed', conclusion: 'success' }], createdAt: 'c', updatedAt: new Date(w.t).toISOString() }]; return { number: 12, url: w.pulls[0].url, headSha: 'a'.repeat(40), githubRequestId: 'R' }; },
    updateChange: async () => ({ headSha: 'b'.repeat(40) }), discardChange: async a => { w.discards.push(a); w.pulls = []; return {}; },
    readChangeFiles: async () => ({ meta: { ...MAIN_META, displayName: 'Brand new' }, detect: 'd\n', remediate: 'r\n' }),
  };
  w.data = { pim: async () => ({ gate: { ok: true, text: 'active' } }), remediations: async () => ({ repoSha: 'abcdef1234567890', repoDate: new Date(T0).toISOString(), repoMessage: 'm', rows: [{ name: 'Existing', folder: 'Existing', inRepo: true, source: 'repo' }, { name: 'Tenant only', inRepo: false }] }), fleet: async () => ({}), certificates: async () => ({}) };
  w.fetcher = async () => new Response('{}', { status: 200 });
  w.sessions = new SessionStore({ now: () => w.t });
  return w;
}
async function serve(w) {
  const app = createApp({ config, sessions: w.sessions, auth: w.auth, data: w.data, github: w.github, audit: w.audit, fetcher: w.fetcher, now: () => w.t, log: { error() {} } });
  const srv = app.listen(0); await new Promise(r => srv.once('listening', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  const s = w.sessions.create(); s.user = { oid: OID, upn: UPN, name: 'Aaron' };
  const headers = { cookie: `${SESSION_COOKIE}=${s.id}` };
  const get = p => fetch(base + p, { redirect: 'manual', headers });
  const elevate = async () => { await get('/auth/write/start'); return get('/auth/write/callback?code=0123456789&state=ws'); };
  return { base, s, headers, get, elevate, close: () => srv.close() };
}

const dom = new JSDOM('<!doctype html><div id="banners"></div><span id="who"></span><span id="writectl"></span><nav id="nav"><a href="#remediations" data-view="remediations">R</a><a href="#changes" data-view="changes">C</a></nav><main id="view"></main>', { url: config.publicUrl + '/' });
const target = { base: '', headers: {} };
const realFetch = globalThis.fetch;
const realSetTimeout = globalThis.setTimeout, realSetInterval = globalThis.setInterval;
globalThis.setTimeout = (...a) => { const t = realSetTimeout(...a); t.unref?.(); return t; };
globalThis.setInterval = (...a) => { const t = realSetInterval(...a); t.unref?.(); return t; };
Object.assign(globalThis, { Node: dom.window.Node, FileReader: dom.window.FileReader, document: dom.window.document, location: dom.window.location, addEventListener: dom.window.addEventListener.bind(dom.window), alert: () => { throw new Error('alert must not be used') } });
globalThis.fetch = (path, init = {}) => String(path).startsWith('/') ? realFetch(target.base + path, { ...init, headers: { ...init.headers, ...target.headers, origin: config.publicUrl } }) : realFetch(path, init);

const until = async (cond, what) => { for (let i = 0; i < 200; i++) { if (await cond()) return; await new Promise(r => realSetTimeout(r, 25)); } assert.fail(`timed out waiting for ${what}; hash=${location.hash}; view: ${document.getElementById('view').innerHTML.slice(0, 600)}`); };
const $ = sel => document.querySelector(sel);
const byText = (sel, re) => [...document.querySelectorAll(sel)].find(e => re.test(e.textContent));
const goto = async hash => { location.hash = hash; await new Promise(r => realSetTimeout(r, 30)); };
let app;
async function page(srv) {
  target.base = srv.base; target.headers = srv.headers;
  document.getElementById('banners').replaceChildren(); document.getElementById('view').replaceChildren();
  if (!app) app = await import('../public/app.js'); else app.boot?.();
  await until(() => document.getElementById('who').textContent === UPN, 'the page to load');
}
const set = (el, v) => { el.value = v; };

test('diffLines: common head/tail trimmed, additions and removals marked', () => {
  assert.deepEqual(diffLines('a\nb\nc', 'a\nB\nc').filter(([k]) => k !== ' '), [['-', 'b'], ['+', 'B']]);
  assert.deepEqual(diffLines('', 'x\n').filter(([k]) => k === '+').map(r => r[1]), ['x']);
  assert.ok(diffLines('a', 'a').every(([k]) => k === ' '));
  const big = Array.from({ length: 3000 }, (_, i) => `l${i}`).join('\n');
  assert.ok(diffLines(big, big.replace('l1500', 'X')).some(([k]) => k === '+'));
});

test('author flow in the UI: New remediation, validation errors shown, preview, create PR, Changes tab with stepper, discard', async () => {
  const w = world(); const srv = await serve(w);
  try {
    await srv.elevate();
    await page(srv);
    // Remediations page: a New remediation button and an Edit action for repo rows only.
    await goto('#remediations');
    await until(() => byText('#view a.btn', /New remediation/), 'the New remediation button');
    assert.equal(byText('#view a.btn', /New remediation/).getAttribute('aria-disabled'), null);
    await until(() => document.querySelectorAll('#view a.btn[href^="#edit/"]').length === 1, 'one Edit action (repo-backed rows only)');

    await goto('#new');
    await until(() => $('#view h1')?.textContent === 'New remediation' && $('#view textarea'), 'the form');
    const [folder, displayName, publisher] = [...document.querySelectorAll('#view input[type=text]')];
    const [description, detect, remediate] = [...document.querySelectorAll('#view textarea')];
    // Invalid first: the server's details are listed.
    set(folder, 'Stt-Ui'); set(displayName, 'x'); set(description, 'd'); set(detect, 'exit 1'); set(remediate, 'Write-Output fixed');
    byText('#view button', /Validate/).click();
    await until(() => $('#view [role=status]').className === 'error' && $('#view [role=status] li'), 'validation details');
    assert.match($('#view [role=status]').textContent, /Validation failed/); assert.match($('#view [role=status]').textContent, /displayName/);
    assert.deepEqual(w.gh, []);
    // Valid: a preview with diffs, nothing written yet.
    set(displayName, 'STT - UI test');
    byText('#view button', /Validate/).click();
    await until(() => /Nothing has been written yet/.test($('#view [role=status]').textContent), 'valid preview');
    assert.ok($('#view pre.diff .add'), 'the diff shows added lines'); assert.match($('#view').textContent, /canary|Assignment group 90000000/);
    assert.deepEqual(w.gh, []); assert.equal(w.events.filter(e => e.action === 'change.proposed').length, 0);
    // Create.
    byText('#view button', /Create pull request/).click();
    await until(() => byText('#view a', /Open pull request #12/), 'the PR link');
    const link = byText('#view a', /Open pull request #12/);
    assert.equal(link.href, 'https://github.com/your-org/remediations/pull/12'); assert.equal(link.rel, 'noopener');
    assert.equal(w.gh.length, 1); assert.equal(JSON.parse(w.gh[0].files[0].content).assignment.groupId, CANARY);
    assert.equal(byText('#view button', /Create pull request/).disabled, true, 'no double submit');
    assert.deepEqual(w.events.filter(e => e.action === 'change.proposed').map(e => e.result), ['intent', 'ok']);

    // Changes tab.
    await goto('#changes');
    await until(() => byText('#view td, #view tr', /#12/), 'the change row');
    assert.ok(byText('#view .stepper .step', /CI checks/)); assert.deepEqual([...document.querySelectorAll('#view .stepper .step')].map(s => s.textContent), ['Proposed', 'CI checks', 'Approved', 'Merged', 'Signed', 'Published', 'Soak', 'Production']);
    assert.ok($('#nav a[data-view=changes]').classList.contains('active'));
    const discard = byText('#view button', /^Discard$/);
    assert.equal(discard.disabled, false);
    discard.click(); assert.equal(discard.textContent, 'Confirm discard'); assert.deepEqual(w.discards, [], 'the first click only arms it');
    discard.click();
    await until(() => w.discards.length === 1, 'the discard call');
    assert.deepEqual(w.events.filter(e => e.action === 'change.discarded').map(e => e.result), ['intent', 'ok']);
    await until(() => /No changes have been proposed/.test($('#view').textContent), 'the empty list');
  } finally { srv.close(); }
});

test('without a write session the authoring buttons are inert and say why; submit is disabled in the form', async () => {
  const w = world(); const srv = await serve(w);
  try {
    await page(srv);
    await goto('#remediations');
    await until(() => byText('#view a.btn', /New remediation/), 'the button');
    const b = byText('#view a.btn', /New remediation/);
    assert.equal(b.getAttribute('aria-disabled'), 'true'); assert.match(b.title, /Elevate to write/);
    await goto('#new');
    await until(() => byText('#view button', /Create pull request/), 'the form');
    assert.equal(byText('#view button', /Create pull request/).disabled, true);
    assert.match($('#view').textContent, /Start a write session first/);
  } finally { srv.close(); }
});

test('Edit loads main, and Update loads the head of the open change', async () => {
  const w = world(); const srv = await serve(w);
  try {
    await srv.elevate(); await page(srv);
    await goto('#edit/Existing');
    await until(() => $('#view h1')?.textContent === 'Edit remediation Existing' && $('#view textarea'), 'the edit form');
    const [, detect] = [...document.querySelectorAll('#view textarea')];
    assert.equal(detect.value, 'line1\nline2\n');
    assert.equal(document.querySelector('#view input[type=text]').disabled, true, 'the folder cannot change');
    w.pulls = [{ number: 5, state: 'open', merged: false, title: 't', url: 'https://github.com/your-org/remediations/pull/5', branch: 'r360/Stt-Ui/202610271504-94540000', headSha: 'a'.repeat(40), body: machineBlock({ folder: 'Stt-Ui', authorOid: OID }), checks: null }];
    await goto('#update/5');
    await until(() => $('#view h1')?.textContent === 'Update change #5' && [...document.querySelectorAll('#view input[type=text]')].some(i => i.value === 'Brand new'), 'the update form with the branch content');
    await goto('#update/999');
    await until(() => $('#view .error'), 'an error for an unknown change');
  } finally { srv.close(); }
});

// ---- S4: approve, reject, merge in the browser ----
function s4World() {
  const w = world(['author', 'approver']);
  const HEAD = 'a'.repeat(40);
  const base = (n, folder) => ({ number: n, state: 'open', merged: false, draft: false, title: 't', url: `https://github.com/your-org/remediations/pull/${n}`, branch: `r360/${folder}/202610271504-94540000`, headSha: HEAD, headRepo: 'your-org/remediations', base: 'main', body: machineBlock({ folder, authorOid: OID }), checks: [{ name: 'PSScriptAnalyzer', status: 'completed', conclusion: 'success' }], mergeSha: null, mergedAt: null, createdAt: 'c', updatedAt: 'u' });
  w.pulls = [base(12, 'Stt-Ui')];
  w.audit.record = async e => { w.t += 1000; w.events.push({ ...e, at: new Date(w.t).toISOString() }); return e; };
  w.events.push({ action: 'change.proposed', result: 'ok', actorOid: OID, target: 'remediations/Stt-Ui', prNumber: 12, gitSha: HEAD, at: new Date(w.t).toISOString() });
  w.calls = [];
  Object.assign(w.github, {
    getChecks: async () => w.pulls[0].checks, behindBy: async () => 0, unresolvedThreads: async () => 0,
    commentOnPull: async a => { w.calls.push(['comment', a.body]); return { id: 1, githubRequestId: 'RC' }; },
    rejectChange: async a => { w.calls.push(['reject', a.comment]); w.pulls[0].state = 'closed'; return {}; },
    mergeChange: async a => { w.calls.push(['merge', a.sha]); Object.assign(w.pulls[0], { merged: true, state: 'closed', mergeSha: 'c'.repeat(40), mergedAt: new Date(w.t).toISOString() }); return { mergeSha: 'c'.repeat(40), branchDeleted: true, githubRequestId: 'RM' }; },
    signingRun: async () => null, downloadSignedArtifact: async () => null,
  });
  return w;
}

test('Approve then Merge in the UI: two clicks each, a self-approved pill in testing mode, audited, nothing happens on the first click', async () => {
  const w = s4World(); const srv = await serve(w);
  try {
    await page(srv);
    await goto('#changes');
    await until(() => byText('#view button', /^Approve$/), 'the Approve button');
    // No write session: every action is disabled with the reason.
    for (const re of [/^Approve$/, /^Merge$/, /^Reject$/]) { const b = byText('#view button', re); assert.equal(b.disabled, true, String(re)); assert.match(b.title, /Elevate to write/); }
    await srv.elevate();
    await page(srv); await goto('#changes');
    await until(() => byText('#view button', /^Approve$/)?.disabled === false, 'Approve to be enabled');
    assert.equal(byText('#view button', /^Merge$/).disabled, true, 'nothing to merge before an approval');
    assert.match(byText('#view button', /^Merge$/).title, /Approve this commit first/);
    assert.match(byText('#view button', /^Approve$/).title, /self-approval/);
    const approve = byText('#view button', /^Approve$/);
    approve.click();
    assert.equal(approve.textContent, 'Confirm approve'); assert.deepEqual(w.calls, []); assert.equal(w.events.filter(e => e.action === 'change.approved').length, 0, 'the first click only arms it');
    approve.click();
    await until(() => $('#view')?.textContent.includes('self-approved'), 'the self-approved pill');
    assert.deepEqual(w.events.filter(e => e.action === 'change.approved').map(e => e.result), ['intent', 'ok']);
    assert.match(w.calls[0][1], /SELF-APPROVED/);
    assert.match($('#view').textContent, new RegExp(UPN));
    await until(() => byText('#view button', /^Merge$/)?.disabled === false, 'Merge to be enabled');
    assert.equal(byText('#view button', /^Approve$/).disabled, true, 'already approved');
    const merge = byText('#view button', /^Merge$/);
    merge.click(); assert.equal(merge.textContent, 'Confirm merge'); assert.equal(w.calls.filter(c => c[0] === 'merge').length, 0);
    merge.click();
    await until(() => w.calls.some(c => c[0] === 'merge'), 'the merge call');
    assert.equal(w.calls.find(c => c[0] === 'merge')[1], 'a'.repeat(40), 'merge is pinned to the head the page showed');
    await until(() => /merged|signing|Signed/i.test($('#view tbody')?.textContent || '') && !byText('#view button', /^Merge$/), 'the merged row');
    assert.deepEqual(w.events.filter(e => e.action === 'change.merged').map(e => e.result), ['intent', 'ok']);
    await until(() => /Waiting for the signing run/.test($('#view tbody').textContent), 'the signing status of a just-merged change');
    assert.equal(byText('#view button', /Verify signing/), undefined, 'nothing to verify until CI has signed');
    const pub = byText('#view button', /Publish to canary/);
    assert.ok(pub, 'a merged change shows Publish'); assert.equal(pub.disabled, true); assert.match(pub.title, /Verify signing first/);
  } finally { srv.close(); }
});

test('Reject in the UI asks for a reason first', async () => {
  const w = s4World(); const srv = await serve(w);
  try {
    await srv.elevate(); await page(srv); await goto('#changes');
    await until(() => byText('#view button', /^Reject$/)?.disabled === false, 'Reject to be enabled');
    const reject = byText('#view button', /^Reject$/);
    reject.click(); assert.equal(reject.textContent, 'Confirm reject');
    const box = reject.nextElementSibling; assert.equal(box.tagName, 'INPUT'); assert.equal(box.placeholder, 'Reason');
    reject.click();
    await until(() => /at least 3 characters/.test($('#view')?.textContent), 'the reason requirement');
    assert.deepEqual(w.calls, []);
    set(box, 'Detection is too broad');
    reject.click();
    await until(() => w.calls.some(c => c[0] === 'reject'), 'the reject call');
    assert.match(w.calls.find(c => c[0] === 'reject')[1], /too broad/);
    assert.deepEqual(w.events.filter(e => e.action === 'change.rejected').map(e => e.result), ['intent', 'ok']);
  } finally { srv.close(); }
});

test('a server refusal is shown next to the buttons and the button is usable again', async () => {
  const w = s4World(); const srv = await serve(w);
  try {
    await srv.elevate(); await page(srv); await goto('#changes');
    await until(() => byText('#view button', /^Approve$/)?.disabled === false, 'Approve to be enabled');
    w.github.commentOnPull = async () => { throw Object.assign(new Error('boom'), { status: 502 }); };
    const approve = byText('#view button', /^Approve$/);
    approve.click(); approve.click();
    await until(() => $('#view .error') && /approval/i.test($('#view .error').textContent), 'the error text');
    await until(() => approve.disabled === false && approve.textContent === 'Approve', 'the button to be reset');
    assert.equal($('#view')?.textContent.includes('self-approved'), false);
  } finally { srv.close(); }
});

// ---- S3 fixes (reported after live testing) ----
const textNodes = root => { const out = []; const walk = n => { if (n.nodeType === 3) out.push(n.textContent); else n.childNodes.forEach(walk); }; walk(root); return out; };

test('create with an empty description: it defaults to the display name, nothing validates against it, and no literal "null" is shown anywhere', async () => {
  const w = world(); const srv = await serve(w);
  try {
    await srv.elevate(); await page(srv);
    await goto('#new');
    await until(() => $('#view h1')?.textContent === 'New remediation' && $('#view textarea'), 'the form');
    assert.ok(!textNodes($('#view')).some(t => t.trim() === 'null'), 'no "null" in the empty form');
    assert.match($('#view').textContent, /Optional. Left empty, it is the display name/);
    const [folder, displayName] = [...document.querySelectorAll('#view input[type=text]')];
    const [description, detect, remediate] = [...document.querySelectorAll('#view textarea')];
    set(folder, 'Stt-Ui2'); set(displayName, 'STT - UI two'); set(description, ''); set(detect, 'exit 1'); set(remediate, 'Write-Output fixed');
    byText('#view button', /Validate/).click();
    await until(() => /Nothing has been written yet/.test($('#view [role=status]')?.textContent || ''), 'a valid preview with an empty description');
    assert.doesNotMatch($('#view [role=status]').textContent, /description/i);
    byText('#view button', /Create pull request/).click();
    await until(() => byText('#view a', /Open pull request #12/), 'the PR link');
    assert.equal(JSON.parse(w.gh[0].files[0].content).description, 'STT - UI two');
    assert.ok(!textNodes($('#view')).some(t => t.trim() === 'null'), 'no "null" line under the PR link');
    assert.ok(!/(^|\s)null(\s|$)/.test($('#view').textContent), 'no "null" anywhere in the result panel');
  } finally { srv.close(); }
});
