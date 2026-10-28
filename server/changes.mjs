import { randomUUID } from 'node:crypto';
import { FILES, folderError, validateMeta, prepareScript, canonicalMeta, metaText, sha256, GUID, BRANCH_RE } from './remediation-schema.mjs';
import { fourEyes, samePerson } from './foureyes.mjs';
import { verifySignedArtifact, unzipArtifact, SIG_BEGIN } from './signing.mjs';
import { buildDesired, descriptionStamp, intuneDiff, GraphWriteError, sha256Hex } from './intune.mjs';
import { evaluateSoak, soakClock, cleanReason, validReason, DEFAULT_SOAK_DAYS, MIN_REASON } from './soak.mjs';
import { gitStamp } from './catalog.mjs';
import { ALL_DEVICES, assignmentFor, cleanName, groupsOf, groupsTarget, isCanaryOnly, isCanaryTarget, isGuid, parseTargetRequest, promotionDiff, sameTarget, targetFromKey, targetKey, targetOf, targetOfAssignments, targetText } from './target.mjs';

// Authoring: r360 turns a form into a branch + pull request in the remediations repo, as the GitHub App, on behalf of a
// signed-in author with a live write session. Nothing is held server side: the state of a change is derived from GitHub
// (the pull request, its checks) and the audit trail. Every mutation writes an audit "intent" row BEFORE it touches GitHub
// (if that write fails the action does not run) and a result row after.

export const REQUEST_KEYS = ['kind', 'folder', 'meta', 'detect', 'remediate', 'dryRun'];
const UPDATE_KEYS = ['meta', 'detect', 'remediate', 'expectHeadSha'];
export const REQUIRED_CHECK = 'PSScriptAnalyzer';
const PLACEHOLDER_DOMAIN = 'users.r360.invalid';

export class ChangeError extends Error {
  constructor(status, message, details) { super(message); this.status = status; this.details = details; this.expose = true; }
}

export const machineBlock = ({ folder, authorOid, promote = false }) => `<!-- r360:${JSON.stringify({ v: 1, kind: 'author', folder, authorOid, ...(promote ? { promote: true } : {}) })} -->`;
export function parseMachineBlock(body) {
  const m = /<!-- r360:(\{[^\n]*?\}) -->/.exec(body || '');
  if (!m) return null;
  try {
    const j = JSON.parse(m[1]);
    if (j.v !== 1 || j.kind !== 'author' || typeof j.folder !== 'string' || typeof j.authorOid !== 'string') return null;
    return j;
  } catch { return null; }
}

const stamp = ms => new Date(ms).toISOString().replace(/[-:T]/g, '').slice(0, 12);
export const branchName = ({ folder, ms, oid }) => `r360/${folder}/${stamp(ms)}-${String(oid).replace(/-/g, '').slice(0, 8).toLowerCase()}`;
const person = u => String(u.name || u.upn || 'unknown').replace(/[<>\r\n]/g, ' ').trim().slice(0, 100) || 'unknown';

export function commitMessage({ kind, folder, displayName, user, requestId, soakOverride = false, target = null, targetName = null }) {
  const verb = kind === 'new' ? 'add' : kind === 'promote' ? 'promote' : 'update';
  const promoted = kind === 'promote' && target;
  return [kind === 'promote' ? `r360: promote remediation ${folder} to ${promoted ? promoteLabel(target, targetName) : 'production'}` : `r360: ${verb} remediation ${folder}`, '', displayName.replace(/[\r\n]/g, ' '), '', `Proposed by ${String(user.upn || user.oid).replace(/[<>\r\n]/g, '')} through r360.`, '',
    `Co-authored-by: ${person(user)} <${user.oid}@${PLACEHOLDER_DOMAIN}>`, `R360-Entra-Oid: ${user.oid}`, `R360-Request-Id: ${requestId}`,
    ...(kind === 'promote' ? [`R360-Soak-Override: ${soakOverride ? 'true' : 'false'}`] : []),
    ...(promoted ? [`R360-Target: ${targetKey(target)}`, ...(target.kind === 'group' && cleanName(targetName) ? [`R360-Target-Name: ${cleanName(targetName)}`] : []),
      ...(target.kind === 'groups' ? target.groupIds.map((id, i) => `R360-Target-Name: ${id} ${cleanName((Array.isArray(targetName) ? targetName : [])[i]) || id}`) : [])] : [])].join('\n');
}

// "All devices" or group "Name": short text for a title or a commit subject.
export const promoteLabel = (t, name) => (t.kind === ALL_DEVICES ? 'All devices' : t.kind === 'groups' ? `${t.groupIds.length} groups`
  : cleanName(Array.isArray(name) ? name[0] : name, 60) ? `group "${cleanName(Array.isArray(name) ? name[0] : name, 60)}"` : `group ${t.groupId}`);

// Only the assignment target differs between the canary version and a promotion; this lists every leaf that does differ.
const flatLeaves = (o, p = '') => Object.entries(o && typeof o === 'object' ? o : {}).flatMap(([k, v]) => (v && typeof v === 'object' && !Array.isArray(v) ? flatLeaves(v, `${p}${k}.`) : [[`${p}${k}`, JSON.stringify(v)]]));
export function metaDiff(a, b) {
  const A = new Map(flatLeaves(a)), B = new Map(flatLeaves(b));
  return [...new Set([...A.keys(), ...B.keys()])].filter(k => A.get(k) !== B.get(k)).sort();
}

export function promoteBody({ displayName, proposer, authorOid, requestId, ms, folder, fromGroup, target, targetName, counts = null, canarySha, evidence, override, reason, fourEyes, selfPromoted }) {
  const safe = s => String(s ?? '').replace(/[<>|`\r\n]/g, ' ').trim();
  const rows = evidence.checks.map(c => `| ${safe(c.label)} | ${c.ok ? 'pass' : (override && c.id === 'soak' ? '**OVERRIDDEN**' : 'FAIL')} | ${safe(c.detail)} |`).join('\n');
  const where = targetText(target, targetName);
  const n = c => (c == null ? 'unknown' : String(c));
  return [`## Promote ${safe(displayName)} to ${safe(where)}`, '',
    ...(override ? [`> **SOAK OVERRIDE.** Only ${evidence.daysSoaked} of ${evidence.daysRequired} canary days had passed. ${safe(proposer)} overrode the soak days with a written reason, which is recorded in the audit trail.`, `> Reason: ${safe(reason)}`, ''] : []),
    `Proposed through r360 by ${safe(proposer)} on ${new Date(ms).toISOString()} (request \`${requestId}\`).`, '',
    target.kind === ALL_DEVICES
      ? `This changes the assignment only: canary group \`${fromGroup}\` to **All devices**, Intune's built-in target. It applies to every device Intune manages in the tenant. The scripts are the canary version \`${String(canarySha).slice(0, 12)}\`, byte for byte.`
      : target.kind === 'groups'
        ? [`This changes the assignment only: canary group \`${fromGroup}\` to ${target.groupIds.length} groups, one Intune assignment each (a device in several groups still runs it once). The scripts are the canary version \`${String(canarySha).slice(0, 12)}\`, byte for byte.`, '',
          '| Target group | Group id | Devices | Members |', '| --- | --- | --- | --- |',
          ...target.groupIds.map((id, i) => { const c = (Array.isArray(counts) ? counts : []).find(x => x.groupId === id) || {}; return `| ${safe(cleanName((Array.isArray(targetName) ? targetName : [])[i]) || id)} | \`${id}\` | ${n(c.deviceCount)} | ${n(c.memberCount)} |`; }),
          '', 'Counts are as of when this was proposed.'].join('\n')
        : `This changes the assignment only: canary group \`${fromGroup}\` to ${safe(where)}${counts ? `, which had ${n(counts.deviceCount)} devices and ${n(counts.memberCount)} members when it was proposed` : ''}. The scripts are the canary version \`${String(canarySha).slice(0, 12)}\`, byte for byte.`, '',
    '| Canary evidence | Result | Detail |', '| --- | --- | --- |', rows, '',
    `Four-eyes mode: **${fourEyes}**${fourEyes === 'testing' ? ' (testing mode: the author may also approve, and this is audited)' : ''}.`,
    ...(selfPromoted ? ['**SELF-PROMOTED:** the person who authored the canary change also proposed this promotion. Allowed only in testing mode and recorded in the audit trail.'] : []),
    `Target: **${safe(where)}**. r360 checked that ${target.kind === 'groups' ? 'each group exists' : 'it exists'} when this was proposed and checks again before publishing.`,
    'Scripts are signed again by CI after merge; r360 never holds the signing key. Publishing assigns this target only after a fresh evidence check.', '', machineBlock({ folder, authorOid, promote: true })].join('\n');
}

export function prBody({ kind, folder, displayName, proposer, authorOid, requestId, files, groupNote, fourEyes, ms }) {
  const rows = files.map(f => `| \`${f.path}\` | ${f.status} | ${f.bytes} bytes | \`${f.sha256.slice(0, 12)}\` |`).join('\n');
  return [`## ${kind === 'new' ? 'New remediation' : 'Change to remediation'}: ${displayName.replace(/[\r\n|]/g, ' ')}`, '',
    `Proposed through r360 by ${proposer} on ${new Date(ms).toISOString()} (request \`${requestId}\`).`, '',
    '| File | Status | Size | SHA-256 |', '| --- | --- | --- | --- |', rows, '', groupNote,
    '', `Four-eyes mode: **${fourEyes}**${fourEyes === 'testing' ? ' (testing mode: the author may also approve, and this is audited)' : ''}.`,
    'Scripts are unsigned here. CI signs them after merge; r360 never holds the signing key.', '', machineBlock({ folder, authorOid })].join('\n');
}

export function ciOf(checks) {
  let ci = 'pending';
  if (Array.isArray(checks) && checks.length) {
    const bad = checks.some(c => c.status === 'completed' && !['success', 'neutral', 'skipped'].includes(c.conclusion));
    const required = checks.find(c => c.name === REQUIRED_CHECK);
    ci = bad ? 'failed' : required?.status === 'completed' && required.conclusion === 'success' && checks.every(c => c.status === 'completed') ? 'passed' : 'running';
  }
  return ci;
}

// extra.approval: the valid approval for the current head (or null). extra.signing: { state } once the change is merged.
// Without extra the later steps stay "todo", which is what the Changes tab showed before approval existed.
export function stageOf(pr, extra = {}) {
  const ci = ciOf(pr.checks);
  const { approval = null, signing = null, published = null, promote = false } = extra;
  const later = ['Approved', 'Merged', 'Signed', 'Published', 'Soak', 'Production'];
  const steps = [{ id: 'proposed', label: 'Proposed', state: 'done' }];
  if (pr.merged) {
    const sg = signing?.state;
    const signed = sg === 'verified' ? 'done' : sg === 'workflow-failed' || sg === 'verify-failed' ? 'failed' : signing ? 'active' : 'todo';
    steps.push({ id: 'ci', label: 'CI checks', state: 'done' }, { id: 'approved', label: 'Approved', state: 'done' }, { id: 'merged', label: 'Merged', state: 'done' }, { id: 'signed', label: 'Signed', state: signed });
    for (const l of later.slice(3)) steps.push({ id: l.toLowerCase(), label: l, state: l === 'Published' ? (published ? 'done' : sg === 'verified' ? 'active' : 'todo') : promote && published && (l === 'Soak' || l === 'Production') ? 'done' : 'todo' });
    return { stage: published && sg === 'verified' ? 'published' : sg === 'verified' ? 'signed' : sg === 'workflow-failed' || sg === 'verify-failed' ? 'sign-failed' : signing ? 'signing' : 'merged', ci, steps };
  }
  if (pr.state === 'closed') {
    steps.push({ id: 'ci', label: 'CI checks', state: 'skipped' }, ...later.map(l => ({ id: l.toLowerCase(), label: l, state: 'skipped' })));
    return { stage: 'discarded', ci, steps };
  }
  steps.push({ id: 'ci', label: 'CI checks', state: ci === 'passed' ? 'done' : ci === 'failed' ? 'failed' : 'active' });
  steps.push({ id: 'approved', label: 'Approved', state: approval ? 'done' : ci === 'passed' ? 'active' : 'todo' });
  steps.push({ id: 'merged', label: 'Merged', state: approval ? 'active' : 'todo' });
  for (const l of later.slice(2)) steps.push({ id: l.toLowerCase(), label: l, state: 'todo' });
  return { stage: approval ? 'approved' : ci === 'passed' ? 'ci-passed' : ci === 'failed' ? 'ci-failed' : 'ci-running', ci, steps };
}

// ---- the audit ledger of one pull request (S4) ----
// Approval, provenance and "what is the current head" are all read from the audit trail, never from anything a caller sends.
const detailOf = r => { const d = r?.detail; if (d && typeof d === 'object') return d; try { return JSON.parse(d) || {}; } catch { return {}; } };
const atOf = r => r.at || '';
export function ledgerFor(rows, number) {
  const mine = (rows || []).map((r, i) => ({ r, i })).filter(x => Number(x.r.prNumber) === number && x.r.result === 'ok')
    .sort((a, b) => (atOf(a.r) < atOf(b.r) ? -1 : atOf(a.r) > atOf(b.r) ? 1 : 0) || a.i - b.i).map(x => x.r);
  const heads = mine.filter(r => ['change.proposed', 'promote.proposed', 'change.updated', 'change.branchupdated'].includes(r.action) && r.gitSha);
  return { rows: mine, recordedHead: heads.at(-1)?.gitSha || null, proposed: mine.find(r => r.action === 'change.proposed' || r.action === 'promote.proposed') || null };
}
// The shas that carry an approval given to `head`: itself, and earlier heads that an update-branch merged forward with the
// three files byte-identical. Any other new commit (an edit by the author, a hand push) is a different sha and voids the approval.
export function equivalentShas(L, head) {
  const set = new Set([head]);
  let cur = head;
  for (let i = 0; i < 10; i++) {
    const u = [...L.rows].reverse().find(r => r.action === 'change.branchupdated' && r.gitSha === cur && detailOf(r).treeIdentical === true);
    const prev = u && detailOf(u).previousHeadSha;
    if (!prev || set.has(prev)) break;
    set.add(prev); cur = prev;
  }
  return set;
}
export function currentApproval(L, head, { mode, authorOid }) {
  const shas = equivalentShas(L, head);
  const given = L.rows.filter(r => r.action === 'change.approved' && shas.has(r.gitSha));
  const valid = mode === 'enforced' ? given.filter(r => !samePerson(r.approverOid, authorOid)) : given;
  const r = valid.at(-1);
  return {
    approval: r ? { approverOid: r.approverOid, approverUpn: r.actorUpn || null, selfApproved: r.selfApproved === true || samePerson(r.approverOid, authorOid), sha: r.gitSha, at: r.at || null } : null,
    ignoredSelfApproval: mode === 'enforced' && given.length > 0 && !r,
  };
}
export function provenanceError(pr, m, L) {
  const p = L.proposed;
  if (!p || !samePerson(p.actorOid, m.authorOid) || p.target !== `remediations/${m.folder}`) return 'r360 has no audit record that it proposed this pull request, so it is read-only here.';
  if (L.recordedHead !== pr.headSha) return 'The branch head is not a commit that r360 recorded (something was pushed outside r360). Use Edit to push a recorded commit, or discard the change.';
  return null;
}
const normText = t => String(t ?? '').replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n').replace(/\n*$/, '\n');
const sameMeta = (a, b) => { try { return JSON.stringify(canonicalMeta(a)) === JSON.stringify(canonicalMeta(b)); } catch { return false; } };

export function createChanges({ config, github, audit, intune, now = () => Date.now(), log = console }) {
  let cache = null;
  const bust = () => { cache = null; };

  const must = (cond, status, msg, details) => { if (!cond) throw new ChangeError(status, msg, details); };
  const intent = async (user, event) => {
    try { return await audit.record({ actorOid: user.oid, actorUpn: user.upn, mode: config.fourEyes, ...event, result: 'intent' }); }
    catch (e) { log.error?.(`${event.action}: audit intent failed: ${e.message}`); throw new ChangeError(503, 'The audit trail is unavailable, so nothing was changed.'); }
  };
  const result = async (user, event) => {
    try { await audit.record({ actorOid: user.oid, actorUpn: user.upn, mode: config.fourEyes, ...event }); return null; }
    catch (e) { log.error?.(`${event.action}: audit result failed: ${e.message}`); return 'The change was made but its result row could not be written to the audit trail.'; }
  };

  // Validates the request and works out the exact files to commit. Pure apart from reading main.
  async function plan(body, { folder: fixedFolder, baseFiles } = {}) {
    must(body && typeof body === 'object' && !Array.isArray(body), 400, 'The request body must be a JSON object.');
    const allowed = fixedFolder ? UPDATE_KEYS : REQUEST_KEYS;
    const extra = Object.keys(body).filter(k => !allowed.includes(k));
    must(!extra.length, 400, `Unknown field(s): ${extra.join(', ')}`);
    const cat = await github.catalog();
    const folder = fixedFolder || body.folder;
    const fe = folderError(folder);
    must(!fe, 400, fe);
    const existing = cat.items.find(i => i.folder === folder);
    const kind = existing ? 'edit' : 'new';
    if (!fixedFolder) {
      must(body.kind === 'new' || body.kind === 'edit', 400, 'kind must be "new" or "edit".');
      must(body.kind === kind, existing ? 409 : 404, existing ? `Remediation "${folder}" already exists. Use edit.` : `Remediation "${folder}" does not exist. Use new.`);
    }
    let groupId;
    let groupNote;
    const cur = existing ? targetOf(existing.meta?.assignment) : null;
    must(!(existing && cur?.kind === ALL_DEVICES), 409, `"${folder}" is assigned to All devices on main. r360 does not edit a remediation that is already assigned beyond the canary group.`);
    must(!(existing && cur?.kind === 'groups'), 409, `"${folder}" is assigned to ${cur?.groupIds?.length} groups on main. r360 does not edit a remediation that is already assigned beyond the canary group.`);
    if (kind === 'new') {
      must(config.canaryGroupId, 503, 'R360_CANARY_GROUP_ID is not configured, so new remediations cannot be created.');
      groupId = config.canaryGroupId;
      groupNote = `New remediations are assigned to the canary group only (\`${groupId}\`). Promotion to production is a separate step.`;
    } else {
      groupId = existing.meta?.assignment?.groupId;
      must(groupId && GUID.test(groupId), 409, `The existing remediation "${folder}" has no valid assignment group on main, so it cannot be edited here.`);
      groupNote = `Assignment group is unchanged (\`${groupId}\`).`;
    }
    const errors = [];
    const meta0 = body.meta;
    must(meta0 && typeof meta0 === 'object' && !Array.isArray(meta0), 400, 'meta must be an object.');
    // The assignment group is decided here, never by the caller.
    // The description is optional: left empty it defaults to the display name (Intune wants one).
    const dn = typeof meta0.displayName === 'string' ? meta0.displayName.trim() : '';
    const blankDesc = meta0.description == null || (typeof meta0.description === 'string' && meta0.description.trim() === '');
    const meta = { ...meta0, ...(blankDesc && dn ? { description: dn } : {}), assignment: assignmentFor({ kind: 'group', groupId }, meta0.assignment) };
    const siblings = cat.items.filter(i => i.folder !== folder && i.meta?.displayName).map(i => i.meta.displayName);
    const vm = validateMeta(meta, { siblingNames: siblings, folder });
    errors.push(...vm.errors);
    const detect = prepareScript(body.detect, 'detect.ps1');
    const remediate = prepareScript(body.remediate, 'remediate.ps1');
    errors.push(...detect.errors, ...remediate.errors);
    if (errors.length) throw new ChangeError(400, 'Validation failed', errors);

    const base = `remediations/${folder}`;
    const next = { 'remediation.json': metaText(meta), 'detect.ps1': detect.text, 'remediate.ps1': remediate.text };
    const files = [];
    for (const n of FILES) {
      const content = next[n];
      let status = 'added';
      // An update is compared with the head of the open branch (so reverting a file is committed); a first proposal with main.
      const baseline = baseFiles || (kind === 'edit' ? existing : null);
      if (baseline) {
        const cur = n === 'remediation.json' ? baseline.meta : n === 'detect.ps1' ? baseline.detect : baseline.remediate;
        const same = n === 'remediation.json' ? baseline.meta && sameMeta(baseline.meta, JSON.parse(content)) : cur != null && normText(cur) === content;
        status = cur == null ? 'added' : same ? 'unchanged' : 'modified';
      }
      files.push({ path: `${base}/${n}`, content, status, bytes: Buffer.byteLength(content, 'utf8'), sha256: sha256(content) });
    }
    return { folder, kind, meta, groupId, groupNote, files, changed: files.filter(f => f.status !== 'unchanged'), displayName: meta.displayName };
  }

  async function openChanges() {
    const pulls = await github.listPulls({ state: 'open', withChecks: false, max: 100 });
    return pulls.filter(p => p.state === 'open').map(p => ({ ...p, machine: parseMachineBlock(p.body) })).filter(p => p.machine);
  }

  const summarize = f => ({ path: f.path, status: f.status, bytes: f.bytes });
  const proposer = u => String(u.upn || u.oid).replace(/[<>\r\n|]/g, '');

  async function ownOpenChange(user, roles, number) {
    must(Number.isInteger(number) && number > 0, 400, 'Invalid change number.');
    const pr = await github.getPull(number);
    const m = parseMachineBlock(pr.body);
    must(m && pr.state === 'open', 409, 'That pull request is not an open r360 change.');
    must(m.authorOid === user.oid || roles.includes('admin'), 403, 'Only the author or an admin can change this one.');
    return { pr, m };
  }

  // ---- S4 implementation ----
  const LEDGER_ACTIONS = ['change.proposed', 'change.updated', 'change.branchupdated', 'change.approved', 'change.rejected', 'change.merged', 'sign.verified', 'sign.verify.failed', 'publish.canary', 'promote.proposed', 'publish.production'];
  async function ledgerRows(days = 60) {
    const { rows } = await audit.list({ from: now() - days * 86400000, to: now() + 60000, actions: LEDGER_ACTIONS, limit: 2000 });
    return rows;
  }
  const needRoles = (roles, allowed, what) => must(roles.some(r => allowed.includes(r)), 403, `Only ${allowed.join(' or ')} can ${what}.`);
  const ciText = checks => {
    const ci = ciOf(checks);
    return { ci, failing: (checks || []).filter(c => c.status === 'completed' && !['success', 'neutral', 'skipped'].includes(c.conclusion)).map(c => c.name) };
  };
  const strictKeys = (body, allowed) => {
    must(body && typeof body === 'object' && !Array.isArray(body), 400, 'The request body must be a JSON object.');
    const extra = Object.keys(body).filter(k => !allowed.includes(k));
    must(!extra.length, 400, `Unknown field(s): ${extra.join(', ')}`);
  };
  const SHA40 = /^[0-9a-f]{40}$/;
  const short = s => String(s || '').slice(0, 12);

  // Loads and checks everything that must hold before any write: an open, non-draft, r360-made change whose head is the
  // recorded one, and (when given) the head the caller saw.
  async function inspect(number, headSha, { needOpen = true } = {}) {
    must(Number.isInteger(number) && number > 0, 400, 'Invalid change number.');
    const pr = await github.getPull(number);
    const m = parseMachineBlock(pr.body);
    must(m && pr.headRepo === config.repo && BRANCH_RE.test(pr.branch || '') && pr.base === config.branch, 409, 'That pull request is not an r360 change.');
    if (needOpen) {
      must(!pr.merged, 409, 'That change is already merged.');
      must(pr.state === 'open', 409, 'That change is closed.');
      must(!pr.draft, 409, 'That change is a draft.');
    }
    let rows;
    try { rows = await ledgerRows(); }
    catch (e) { log.error?.(`audit list failed: ${e.message}`); throw new ChangeError(503, 'The audit trail is unavailable, so approval and merge cannot be checked. Nothing was changed.'); }
    const L = ledgerFor(rows, number);
    if (needOpen) {
      must(SHA40.test(headSha || ''), 400, 'headSha (the commit you looked at) is required.');
      must(headSha === pr.headSha, 409, `The change moved to ${short(pr.headSha)} since you looked at it (you had ${short(headSha)}). Reload and review it again.`);
      const prov = provenanceError(pr, m, L);
      must(!prov, 409, prov);
    }
    return { pr, m, L };
  }
  async function requireGreen(pr) {
    const checks = await github.getChecks(pr.headSha);
    const { ci, failing } = ciText(checks);
    must(ci === 'passed', 409, ci === 'failed' ? `CI failed (${failing.join(', ') || 'a check'}). Fix it first.` : 'CI checks have not finished passing yet.', { checks: checks.map(c => `${c.name}:${c.conclusion || c.status}`) });
    return checks;
  }
  async function requireNoOpenThreads(pr) {
    let n = 0;
    try { n = await github.unresolvedThreads(pr.number); } catch (e) { log.error?.(`review thread check skipped: ${e.message}`); return; }
    must(n === 0, 409, `${n} review conversation(s) are still unresolved. Resolve them first.`);
  }
  const denyRow = async (user, event) => { try { await audit.record({ actorOid: user.oid, actorUpn: user.upn, mode: config.fourEyes, ...event, result: 'denied' }); } catch (e) { log.error?.(`denial row failed: ${e.message}`); } };
  // What the browser sees of a GitHub failure: GitHub's own reason, without the request line, URLs or anything token-shaped.
const cleanGithub = m => String(m ?? '').replace(/^GitHub [A-Z]+ \S+ failed: /, '').replace(/https?:\/\/\S+/g, '').replace(/Bearer\s+\S+/gi, '').replace(/\bgh[a-z]_\w+/g, '').replace(/\s+/g, ' ').trim().slice(0, 300);
const mapGithub = (e, what) => { const refused = e.status === 409 || e.status === 405 || e.status === 422; return new ChangeError(refused ? 409 : 502, refused ? `GitHub refused: ${cleanGithub(e.message)}` : `GitHub rejected the ${what}: ${cleanGithub(e.message)}`); };

  async function approveImpl(user, roles, number, body) {
    strictKeys(body, ['headSha']);
    needRoles(roles, ['approver'], 'approve changes');
    const { pr, m, L } = await inspect(number, body.headSha);
    const target = `remediations/${m.folder}`;
    const fe = fourEyes({ mode: config.fourEyes, step: 'approve', authorOid: m.authorOid, actorOid: user.oid });
    if (!fe.allowed) {
      await denyRow(user, { action: 'change.approval.denied', target, requestId: randomUUID(), prNumber: number, gitSha: pr.headSha, reason: fe.reason });
      throw new ChangeError(403, fe.message);
    }
    const prior = L.rows.find(r => r.action === 'change.approved' && r.gitSha === pr.headSha && samePerson(r.approverOid, user.oid));
    if (prior) return { ok: true, already: true, number, headSha: pr.headSha, selfApproved: prior.selfApproved === true };
    const checks = await requireGreen(pr);
    await requireNoOpenThreads(pr);
    const requestId = randomUUID();
    const detail = { authorOid: m.authorOid, folder: m.folder, selfApproved: fe.selfApproved, checks: checks.map(c => `${c.name}:${c.conclusion}`) };
    const base = { action: 'change.approved', target, requestId, prNumber: number, gitSha: pr.headSha, approverOid: user.oid, selfApproved: fe.selfApproved, detail };
    await intent(user, base);
    let out;
    try {
      out = await github.commentOnPull({ number, body: [
        `**Approved in r360** by ${proposer(user)} for commit \`${short(pr.headSha)}\`.`,
        fe.selfApproved ? `**SELF-APPROVED:** the author approved their own change. This is allowed only while four-eyes is in \`${config.fourEyes}\` mode and it is recorded in the audit trail.` : `Four-eyes: the approver is not the author.`,
        `The approval applies to this exact commit. Any new commit voids it.`, `r360 request \`${requestId}\``].join('\n\n') });
    } catch (e) {
      log.error?.(`change.approved failed: ${e.message}`);
      await result(user, { ...base, result: 'failed', reason: e.message, githubRequestId: e.githubRequestId });
      throw mapGithub(e, 'approval');
    }
    // The approval exists only as this row, so unlike other actions a failure to write it means the approval did not happen.
    try { await audit.record({ actorOid: user.oid, actorUpn: user.upn, mode: config.fourEyes, ...base, result: 'ok', githubRequestId: out.githubRequestId }); }
    catch (e) { log.error?.(`change.approved result failed: ${e.message}`); throw new ChangeError(503, 'The approval could not be written to the audit trail, so it did not take effect. Try again.'); }
    bust();
    return { ok: true, number, headSha: pr.headSha, selfApproved: fe.selfApproved, requestId };
  }

  async function rejectImpl(user, roles, number, body) {
    strictKeys(body, ['headSha', 'reason']);
    needRoles(roles, ['approver'], 'reject changes');
    const reason = String(body.reason ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, 500);
    must(reason.length >= 3, 400, 'A reason of at least 3 characters is required.');
    const { pr, m } = await inspect(number, body.headSha);
    const requestId = randomUUID();
    const base = { action: 'change.rejected', target: `remediations/${m.folder}`, requestId, prNumber: number, gitSha: pr.headSha, detail: { authorOid: m.authorOid, reason } };
    await intent(user, base);
    let out;
    try { out = await github.rejectChange({ number, comment: `**Rejected in r360** by ${proposer(user)} for commit \`${short(pr.headSha)}\`.\n\nReason: ${reason}\n\nThe change is closed. Its branch is kept so the commits can still be read.` }); }
    catch (e) {
      log.error?.(`change.rejected failed: ${e.message}`);
      await result(user, { ...base, result: 'failed', reason: e.message, githubRequestId: e.githubRequestId });
      throw mapGithub(e, 'rejection');
    }
    bust();
    const warning = await result(user, { ...base, result: 'ok', reason, githubRequestId: out.githubRequestId });
    return { ok: true, number, rejected: true, requestId, ...(warning ? { warning } : {}) };
  }

  // Merge main into the branch. If the three files are byte-identical afterwards the approval carries over (the audit row
  // links the two shas); otherwise the change needs a new approval.
  async function refreshBranch(user, { pr, m, behind }) {
    const requestId = randomUUID();
    const base = { action: 'change.branchupdated', target: `remediations/${m.folder}`, requestId, prNumber: pr.number };
    await intent(user, { ...base, gitSha: pr.headSha, detail: { previousHeadSha: pr.headSha, behindBy: behind } });
    let out;
    try { out = await github.updateBranch({ number: pr.number, expectHeadSha: pr.headSha }); }
    catch (e) {
      log.error?.(`change.branchupdated failed: ${e.message}`);
      await result(user, { ...base, gitSha: pr.headSha, result: 'failed', reason: e.message, githubRequestId: e.githubRequestId, detail: { previousHeadSha: pr.headSha } });
      throw mapGithub(e, 'branch update');
    }
    let identical = false;
    if (!out.pending) {
      try {
        const [a, b] = await Promise.all([github.readChangeFiles({ sha: pr.headSha, folder: m.folder }), github.readChangeFiles({ sha: out.headSha, folder: m.folder })]);
        identical = FILES.every(n => a.raw?.[n] != null && a.raw[n] === b.raw?.[n]);
      } catch (e) { log.error?.(`branch update comparison failed: ${e.message}`); }
    }
    bust();
    const warning = await result(user, { ...base, gitSha: out.headSha, result: 'ok', githubRequestId: out.githubRequestId, detail: { previousHeadSha: pr.headSha, treeIdentical: identical, pending: out.pending === true } });
    return { ok: true, merged: false, branchUpdated: true, headSha: out.headSha, approvalKept: identical, requestId, ...(warning ? { warning } : {}),
      message: out.pending ? 'GitHub is still updating the branch. Reload in a moment, wait for CI, then merge.'
        : identical ? 'The branch was behind main and has been brought up to date. The files are unchanged, so the approval still applies. Wait for CI to finish, then click Merge again.'
          : 'The branch was brought up to date with main, but the files changed, so the approval no longer applies. Review and approve the new commit.' };
  }

  async function mergeImpl(user, roles, number, body) {
    strictKeys(body, ['headSha']);
    needRoles(roles, ['approver'], 'merge changes');
    must(Number.isInteger(number) && number > 0, 400, 'Invalid change number.');
    const cur = await github.getPull(number);
    if (cur.merged) {
      let rows;
      try { rows = await ledgerRows(); } catch { throw new ChangeError(503, 'The audit trail is unavailable.'); }
      const done = rows.find(r => r.action === 'change.merged' && Number(r.prNumber) === number && r.result === 'ok');
      must(done, 409, 'That change was merged outside r360.');
      return { ok: true, already: true, number, mergeSha: cur.mergeSha };
    }
    const { pr, m, L } = await inspect(number, body.headSha);
    const target = `remediations/${m.folder}`;
    const { approval } = currentApproval(L, pr.headSha, { mode: config.fourEyes, authorOid: m.authorOid });
    must(approval, 409, config.fourEyes === 'enforced' && L.rows.some(r => r.action === 'change.approved') ? 'Only a self-approval exists, which does not count in enforced mode. A different approver must approve this commit.' : 'This commit has not been approved. Approve it first.');
    const fe = fourEyes({ mode: config.fourEyes, step: 'merge', authorOid: m.authorOid, actorOid: user.oid, approval: { approverOid: approval.approverOid } });
    if (!fe.allowed) {
      await denyRow(user, { action: 'change.approval.denied', target, requestId: randomUUID(), prNumber: number, gitSha: pr.headSha, reason: fe.reason });
      throw new ChangeError(403, fe.message);
    }
    await requireGreen(pr);
    await requireNoOpenThreads(pr);
    const behind = await github.behindBy(pr.headSha);
    if (behind > 0) return refreshBranch(user, { pr, m, behind });

    const requestId = randomUUID();
    const authorLabel = (await github.catalog().then(c => c.approvers?.find(a => samePerson(a.entraObjectId, m.authorOid))?.upn).catch(() => null)) || m.authorOid;
    const title = `${pr.title} (#${number})`;
    const message = [
      `Proposed by ${String(authorLabel).replace(/[<>\r\n|]/g, '')} through r360.`,
      `Approved by ${proposer({ upn: approval.approverUpn, oid: approval.approverOid })} through r360 (four-eyes ${config.fourEyes}${approval.selfApproved ? ', SELF-APPROVED' : ''}), merged by ${proposer(user)}.`, '',
      `Co-authored-by: ${proposer({ oid: m.authorOid })} <${m.authorOid}@users.r360.invalid>`,
      `R360-Entra-Oid: ${m.authorOid}`, `R360-Approver-Oid: ${approval.approverOid}`, `R360-Merged-By-Oid: ${user.oid}`,
      `R360-Self-Approved: ${approval.selfApproved ? 'true' : 'false'}`, `R360-Request-Id: ${requestId}`].join('\n');
    const base = { action: 'change.merged', target, requestId, prNumber: number, gitSha: pr.headSha, approverOid: approval.approverOid, selfApproved: approval.selfApproved };
    await intent(user, { ...base, detail: { approvalSha: approval.sha, approvedAt: approval.at, authorOid: m.authorOid } });
    let out;
    try { out = await github.mergeChange({ number, sha: pr.headSha, title, message }); }
    catch (e) {
      log.error?.(`change.merged failed: ${e.message}`);
      await result(user, { ...base, result: 'failed', reason: e.message, githubRequestId: e.githubRequestId, detail: { approvalSha: approval.sha } });
      throw mapGithub(e, 'merge');
    }
    bust();
    const warning = await result(user, { ...base, result: 'ok', githubRequestId: out.githubRequestId, detail: { approvalSha: approval.sha, mergeSha: out.mergeSha, branchDeleted: out.branchDeleted, authorOid: m.authorOid } });
    return { ok: true, number, merged: true, mergeSha: out.mergeSha, selfApproved: approval.selfApproved, requestId, ...(warning ? { warning } : {}) };
  }

  const SIGN_JOBS = ['Sign (Key Vault HSM)', 'Verify (Windows Authenticode)'];
  const jobsOk = jobs => SIGN_JOBS.every(n => (jobs || []).some(j => j.name === n && j.conclusion === 'success'));
  async function verifyImpl(user, roles, number) {
    needRoles(roles, ['author', 'approver', 'admin'], 'verify signing');
    must(Number.isInteger(number) && number > 0, 400, 'Invalid change number.');
    const pr = await github.getPull(number);
    const m = parseMachineBlock(pr.body);
    must(m && pr.headRepo === config.repo && BRANCH_RE.test(pr.branch || ''), 409, 'That pull request is not an r360 change.');
    must(pr.merged && SHA40.test(pr.mergeSha || ''), 409, 'That change is not merged yet.');
    let rows;
    try { rows = await ledgerRows(); } catch { throw new ChangeError(503, 'The audit trail is unavailable, so nothing was checked.'); }
    const L = ledgerFor(rows, number);
    must(L.proposed, 409, 'r360 has no audit record that it proposed this change.');
    const have = L.rows.find(r => r.action === 'sign.verified' && r.gitSha === pr.mergeSha);
    if (have) return { ok: true, already: true, number, mergeSha: pr.mergeSha, verifiedAt: have.at || null };
    let run;
    try { run = await github.signingRun(pr.mergeSha); } catch (e) { throw new ChangeError(502, `Could not read the signing workflow: ${e.message}`); }
    must(run, 409, 'The signing workflow has not started for this merge yet. Try again in a minute.');
    must(run.status === 'completed', 409, 'The signing workflow is still running. Try again when it finishes.');
    const requestId = randomUUID();
    const target = `remediations/${m.folder}`;
    const base = { target, requestId, prNumber: number, gitSha: pr.mergeSha };
    await intent(user, { ...base, action: 'sign.verified', detail: { runId: run.id, runUrl: run.url } });
    const fail = async (problems, extra = {}) => {
      const reason = problems.join('; ').slice(0, 900);
      await result(user, { ...base, action: 'sign.verify.failed', result: 'failed', reason, detail: { runId: run.id, problems: problems.slice(0, 20), ...extra } });
      bust();
      return { ok: false, number, mergeSha: pr.mergeSha, problems };
    };
    if (run.conclusion !== 'success' || !jobsOk(run.jobs)) return fail([`The signing workflow did not succeed (conclusion ${run.conclusion}). Both "${SIGN_JOBS.join('" and "')}" must pass.`]);
    let dl;
    try { dl = await github.downloadSignedArtifact(pr.mergeSha); } catch (e) { return fail([`Could not download the signed artifact: ${e.message}`]); }
    if (!dl) return fail([`There is no signed-${short(pr.mergeSha)} artifact for this commit (or it has expired).`]);
    let repoTexts = null;
    try { repoTexts = (await github.readChangeFiles({ sha: pr.mergeSha, folder: m.folder })).raw || null; } catch { /* verification then fails closed */ }
    const v = verifySignedArtifact({ zip: dl.buffer, commit: pr.mergeSha, folder: m.folder, thumbprint: config.codesignThumbprint, repo: repoTexts, now: now() });
    if (!v.ok) return fail(v.problems, { artifactId: dl.artifact.id });
    const warning = await result(user, { ...base, action: 'sign.verified', result: 'ok', detail: { runId: run.id, artifactId: dl.artifact.id, manifestSha256: v.manifestSha256, signerNotAfter: v.signerNotAfter, signedUtc: v.signedUtc, files: v.files } });
    bust();
    return { ok: true, number, mergeSha: pr.mergeSha, manifestSha256: v.manifestSha256, signerNotAfter: v.signerNotAfter, requestId, ...(warning ? { warning } : {}) };
  }

  // ---- S5: publish the CI-signed artifact to the canary group, as the signed-in publisher (delegated Graph only) ----
  // Order: every gate, then the audit intent row, then Intune. Content comes from the verified artifact bytes only, never from
  // the form, the pull request or the repo. A second publish of the same commit finds Intune already identical and does nothing.
  class PublishStop extends Error { constructor(code, message) { super(message); this.code = code; } }
  const chainOf = (L, pr, m) => {
    const p = L.proposed;
    const proposedOk = Boolean(p && samePerson(p.actorOid, m.authorOid) && p.target === `remediations/${m.folder}`);
    const merged = L.rows.find(r => r.action === 'change.merged' && r.gitSha === pr.headSha && detailOf(r).mergeSha === pr.mergeSha) || null;
    const { approval } = merged ? currentApproval(L, pr.headSha, { mode: config.fourEyes, authorOid: m.authorOid }) : { approval: null };
    return { ok: proposedOk && Boolean(merged && approval), approval, merged };
  };
  const requestIdOf = e => (e.graphRequestId ? ` (Graph request ${e.graphRequestId})` : '');
  const mapGraphWrite = e => {
    if (e instanceof GraphWriteError) {
      if (e.status === 401 || e.status === 403) return new ChangeError(403, `Microsoft Graph refused the write (HTTP ${e.status}). Check that your Intune Administrator role is active in PIM and that r360-write has admin consent for DeviceManagementScripts.ReadWrite.All${requestIdOf(e)}.`);
      return new ChangeError(502, `${e.message}${requestIdOf(e)}`);
    }
    return new ChangeError(502, 'Intune could not be reached. Nothing further was changed; try again.');
  };
  async function publishImpl(user, roles, number, body, publisher) {
    strictKeys(body, ['mergeSha']);
    needRoles(roles, ['approver'], 'publish');
    must(Number.isInteger(number) && number > 0, 400, 'Invalid change number.');
    must(SHA40.test(body.mergeSha || ''), 400, 'mergeSha (the merge commit you looked at) is required.');
    must(config.canaryGroupId, 503, 'No canary group is configured (R360_CANARY_GROUP_ID), so nothing can be published.');
    const pr = await github.getPull(number);
    const m = parseMachineBlock(pr.body);
    must(m && pr.headRepo === config.repo && BRANCH_RE.test(pr.branch || '') && pr.base === config.branch, 409, 'That pull request is not an r360 change.');
    must(pr.merged && SHA40.test(pr.mergeSha || ''), 409, 'That change is not merged yet.');
    must(body.mergeSha === pr.mergeSha, 409, `The merge commit is ${short(pr.mergeSha)}, not ${short(body.mergeSha)}. Reload and look again.`);
    let rows;
    try { rows = await ledgerRows(120); } catch { throw new ChangeError(503, 'The audit trail is unavailable, so nothing was published.'); }
    const L = ledgerFor(rows, number);
    must(L.proposed, 409, 'r360 has no audit record that it proposed this change.');
    const signedRow = L.rows.find(r => r.action === 'sign.verified' && r.gitSha === pr.mergeSha);
    must(signedRow, 409, 'Verify signing first. Only an artifact that r360 has verified can be published.');
    // Whether this is a promotion is decided by the audit row r360 wrote when it proposed the change, never by the pull request text.
    const promoRow = L.proposed.action === 'promote.proposed' ? L.proposed : null;
    const promo = promoRow ? detailOf(promoRow) : null;
    const target = `remediations/${m.folder}`;
    const requestId = randomUUID();
    const deny = async (reason, message, status = 409, extra = {}) => {
      await denyRow(user, { action: 'publish.denied', target, requestId, prNumber: number, gitSha: pr.mergeSha, reason, ...extra });
      throw new ChangeError(status, message);
    };
    if (promo && !SHA40.test(promo.canarySha || '')) await deny('promotion-record-invalid', 'The audit record of this promotion does not name the canary version it promotes, so it cannot be published.');
    const fe = fourEyes({ mode: config.fourEyes, step: 'publish', authorOid: m.authorOid, actorOid: user.oid });
    if (!fe.allowed) await deny(fe.reason, fe.message || 'Four-eyes does not allow you to publish this change.', 403, { detail: { authorOid: m.authorOid } });
    const chain = chainOf(L, pr, m);
    const override = !chain.ok && config.fourEyes === 'testing' && roles.includes('admin');
    if (!chain.ok && !override) await deny('provenance-none', config.fourEyes === 'enforced' ? 'There is no recorded approval and merge by someone other than the author for this commit, so it cannot be published.' : 'r360 has no audit record that this commit was approved and merged through r360. Only an admin can publish it, and only in testing mode.', 403);

    // The artifact must be exactly what is on main for this remediation.
    let mainSha;
    try { mainSha = (await github.catalog()).sha; } catch (e) { throw new ChangeError(502, `Could not read main: ${cleanGithub(e.message)}`); }
    let atMerge;
    try { atMerge = await github.readChangeFiles({ sha: pr.mergeSha, folder: m.folder }); } catch (e) { throw new ChangeError(502, `Could not read the merged files: ${cleanGithub(e.message)}`); }
    if (mainSha !== pr.mergeSha) {
      let same = false;
      try { const cur = await github.readChangeFiles({ sha: mainSha, folder: m.folder }); same = FILES.every(f => cur.raw[f] === atMerge.raw[f]); } catch { same = false; }
      if (!same) await deny('superseded', `A newer commit on main changed ${m.folder} (or removed it), so ${short(pr.mergeSha)} is not the current version. Publish the newer change instead.`);
    }
    let dl;
    try { dl = await github.downloadSignedArtifact(pr.mergeSha); } catch (e) { throw new ChangeError(502, `Could not download the signed artifact: ${cleanGithub(e.message)}`); }
    must(dl, 409, `There is no signed-${short(pr.mergeSha)} artifact for this commit (or it has expired).`);
    const v = verifySignedArtifact({ zip: dl.buffer, commit: pr.mergeSha, folder: m.folder, thumbprint: config.codesignThumbprint, repo: atMerge.raw, now: now() });
    if (!v.ok) await deny('artifact-verify-failed', `The signed artifact did not verify: ${v.problems.slice(0, 3).join('; ')}`, 409, { detail: { problems: v.problems.slice(0, 20) } });
    if (v.manifestSha256 !== detailOf(signedRow).manifestSha256) await deny('artifact-changed', 'The signed artifact is not the one that was verified earlier. Verify signing again.');
    let detect, remediate, meta;
    try {
      const files = unzipArtifact(dl.buffer);
      const pre = `remediations/${m.folder}/`;
      detect = files.get(`${pre}detect.ps1`); remediate = files.get(`${pre}remediate.ps1`);
      meta = JSON.parse(files.get(`${pre}remediation.json`).toString('utf8').replace(/^\uFEFF/, ''));
    } catch { await deny('artifact-unreadable', 'The signed artifact does not contain the three files of this remediation.'); }
    const vm = validateMeta(meta, { folder: m.folder });
    if (!vm.ok) await deny('artifact-meta-invalid', `remediation.json in the artifact is not valid: ${vm.errors.slice(0, 3).join('; ')}`);
    if (!detect?.includes(SIG_BEGIN) || !remediate?.includes(SIG_BEGIN)) await deny('unsigned-script', 'A script in the artifact has no signature block. Refusing to publish it.');
    if (meta.enforceSignatureCheck === false) await deny('unsigned-refused', 'remediation.json turns the signature check off. r360 only publishes with the check enforced.');
    const metaTarget = targetOf(meta.assignment);
    let soakOverride = null, evidenceDays = null, publishTarget = metaTarget, targetName = null, promoTarget = null;
    if (promo) {
      // The target was chosen when the promotion was proposed and sits in that audit row. The signed artifact must carry exactly that and nothing else.
      const rec = promo.toTarget;
      // The key and the recorded group list(s) must agree: "group:<id>" with toGroup, "groups:<a>,<b>" with toGroups, or "allDevices" alone.
      const t0 = targetFromKey(rec);
      promoTarget = !t0 ? null
        : t0.kind === ALL_DEVICES ? t0
        : t0.kind === 'group' ? (isGuid(promo.toGroup) && String(promo.toGroup).toLowerCase() === t0.groupId ? t0 : null)
        : (targetKey(groupsTarget(promo.toGroups)) === rec ? t0 : null);
      if (!promoTarget) await deny('promotion-record-invalid', 'The audit record of this promotion does not name a valid target, so it cannot be published.');
      if (isCanaryTarget(promoTarget, config.canaryGroupId)) await deny('target-is-canary', 'The target of this promotion is the canary group. A promotion needs a different group, or All devices.');
      if (!sameTarget(metaTarget, promoTarget)) await deny('target-mismatch', 'The assignment in the signed artifact is not the target that was chosen when this promotion was proposed.', 409, { detail: { recorded: targetKey(promoTarget), artifact: targetKey(metaTarget) } });
      publishTarget = promoTarget;
      // A promotion is the canary version with the assignment group changed and nothing else.
      let canaryFiles;
      try { canaryFiles = await github.readChangeFiles({ sha: promo.canarySha, folder: m.folder }); } catch (e) { throw new ChangeError(502, `Could not read the canary version: ${cleanGithub(e.message)}`); }
      const sameScripts = ['detect.ps1', 'remediate.ps1'].every(n => canaryFiles.raw[n] === atMerge.raw[n]);
      const differs = metaDiff(canaryFiles.meta, meta);
      if (!sameScripts || differs.join(',') !== promotionDiff(promoTarget)) await deny('promotion-changed-more-than-assignment', 'The promoted version differs from the canary version in more than the assignment, so it will not be published.', 409, { detail: { sameScripts, differs } });
      let readToken;
      try { readToken = await publisher.readToken(); } catch (e) { throw e.expose ? e : new ChangeError(403, 'Your sign-in could not get a Microsoft Graph read token. Sign in again.'); }
      // A group that was deleted since the promotion was proposed is refused here, before anything is written.
      if (promoTarget.kind !== ALL_DEVICES) targetName = await checkGroupTarget(promoTarget, readToken, deny);
      const ev = await soakEvidence({ folder: m.folder, rows, readToken: async () => readToken, sha: promo.canarySha, target: promoTarget });
      evidenceDays = ev.daysSoaked;
      if (!ev.alreadyPromoted && !ev.ready) {
        // Only the soak days can be waived, and only by the override that was recorded (with its reason) when the promotion was proposed.
        const waived = ev.overridable && promo.soakOverride === true && validReason(promo.overrideReason);
        if (!waived) await deny('evidence-failed', `The canary evidence is no longer clean: ${ev.checks.filter(c => !c.ok).map(c => `${c.label} (${c.detail})`).join('; ')}`, 409, { detail: { failing: ev.failing } });
        soakOverride = { days: ev.daysSoaked, required: ev.daysRequired };
      }
    } else if (!isCanaryOnly(metaTarget, config.canaryGroupId)) {
      await deny('group-not-canary', metaTarget ? 'Anything beyond the canary group (another group, or All devices) can only be assigned through Promote, never by publishing an ordinary change. Ordinary changes publish to the canary group only.' : 'The assignment group is not the canary group. Ordinary changes publish to the canary group only.');
    }

    const selfApproved = Boolean(fe.selfApproved || chain.approval?.selfApproved);
    const description = descriptionStamp({ description: meta.description, mergeSha: pr.mergeSha, authorUpn: L.proposed.actorUpn || m.authorOid, approverUpn: chain.approval?.approverUpn || chain.approval?.approverOid,
      publisherUpn: user.upn || user.oid, selfApproved, provenanceNone: !chain.ok, mode: config.fourEyes, soakOverride, target: promo ? promoTarget : null, targetName });
    const desired = buildDesired({ meta, detect, remediate, description, target: publishTarget });
    let token;
    try { token = await publisher.token(); } catch (e) { throw e.expose ? e : new ChangeError(403, e.status === 403 ? 'The write session is gone. Elevate again.' : 'Your write session could not get a Microsoft Graph token. Elevate again.'); }

    const publishAction = promo ? 'publish.production' : 'publish.canary';
    const groupLabel = promo ? 'target' : 'canary';
    const base = { action: publishAction, target, requestId, prNumber: number, gitSha: pr.mergeSha, approverOid: chain.approval?.approverOid, selfApproved, ...(promo ? { soakDays: evidenceDays, toTarget: targetKey(promoTarget) } : {}) };
    const info = { folder: m.folder, groupId: publishTarget.groupId || null, ...(publishTarget.kind === 'groups' ? { groupIds: publishTarget.groupIds } : {}), assignTarget: targetKey(publishTarget), authorOid: m.authorOid, publisherOid: user.oid, provenance: chain.ok ? 'chain' : 'admin-override', manifestSha256: v.manifestSha256, artifactId: dl.artifact.id, hashes: desired.hashes, displayName: meta.displayName,
      ...(promo ? { promote: true, targetName, canarySha: promo.canarySha, soakDays: evidenceDays, soakRequired: config.canarySoakDays, soakOverride: Boolean(soakOverride) } : {}) };
    await intent(user, { ...base, detail: info });
    const g = intune.scope();
    let intuneId = null, created = false;
    const finish = async (extra) => {
      const ids = g.requestIds().slice(-12);
      return result(user, { ...base, result: 'ok', graphRequestId: ids.at(-1), detail: { ...info, intuneId, created, ...extra, graphRequestIds: ids } });
    };
    try {
      const found = await g.findByName(token, meta.displayName);
      if (found.length > 1) throw new PublishStop('duplicate-name', `${found.length} remediations named "${meta.displayName}" exist in Intune. Resolve the duplicates there first; r360 will not guess.`);
      if (found.length) {
        intuneId = found[0].id;
        const cur = await g.read(token, intuneId);
        if (!intuneDiff({ existing: cur.script, assignments: cur.assignments, desired, mergeSha: pr.mergeSha, groupLabel }).length) {
          const warning = await finish({ noop: true });
          bust();
          return { ok: true, already: true, number, mergeSha: pr.mergeSha, intuneId, selfApproved, requestId, ...(warning ? { warning } : {}) };
        }
        await g.update(token, intuneId, desired.script);
      } else {
        const c = await g.create(token, desired.script);
        if (!c.id) throw new PublishStop('no-id', 'Intune created the remediation but did not return its id.');
        intuneId = c.id; created = true;
      }
      await g.assign(token, intuneId, desired.assign);
      const after = await g.read(token, intuneId);
      const problems = intuneDiff({ existing: after.script, assignments: after.assignments, desired, mergeSha: pr.mergeSha, groupLabel });
      if (problems.length) throw new PublishStop('post-check-failed', `Written, but Intune does not hold exactly the signed content afterwards (${problems.join('; ')}). Check it in Intune before trying again.`);
    } catch (e) {
      log.error?.(`${publishAction} failed: ${e.message}`);
      const stop = e instanceof PublishStop;
      await result(user, { ...base, result: 'failed', reason: stop ? e.code : String(e.message).slice(0, 300), graphRequestId: e.graphRequestId || g.requestIds().at(-1), detail: { ...info, intuneId, created, ...(stop ? { message: e.message } : {}), graphRequestIds: g.requestIds().slice(-12) } });
      bust();
      throw stop ? new ChangeError(409, e.message) : mapGraphWrite(e);
    }
    bust();
    const warning = await finish({ noop: false });
    return { ok: true, number, mergeSha: pr.mergeSha, intuneId, created, selfApproved, requestId, ...(warning ? { warning } : {}) };
  }
  // ---- S6: promote a change from the canary group to production ----
  // Evidence is read as the signed-in user (their delegated read token) and is judged by evaluateSoak. The canary publish row in the
  // audit trail is the only source of "when did the soak start" and "what was published"; nothing the caller sends is trusted.
  const byAt = (a, b) => (atOf(a) < atOf(b) ? -1 : atOf(a) > atOf(b) ? 1 : 0);
  const mapGraphRead = e => {
    if (e instanceof GraphWriteError) {
      if (e.status === 401 || e.status === 403) return new ChangeError(403, `Microsoft Graph refused the read of the canary evidence (HTTP ${e.status}). Sign in again and check your Intune permissions${requestIdOf(e)}.`);
      return new ChangeError(502, `${e.message}${requestIdOf(e)}`);
    }
    return new ChangeError(502, 'Intune could not be reached, so the canary evidence could not be read. Nothing was changed.');
  };
  async function soakEvidence({ folder, rows, readToken, sha = null, target: wantTarget = null }) {
    const target = `remediations/${folder}`;
    const canaryRows = (rows || []).filter(r => r.action === 'publish.canary' && r.result === 'ok' && r.target === target && SHA40.test(r.gitSha || '')).sort(byAt);
    const useSha = sha || canaryRows.at(-1)?.gitSha || null;
    const mine = useSha ? canaryRows.filter(r => r.gitSha === useSha) : [];
    // The clock starts at the first publish that really wrote to Intune; a later no-op row does not restart it.
    // If the write itself was recorded as failed (the old post-check), the first ok no-op row is the first proof Intune holds it; start there (later, so conservative).
    const real = mine.find(r => detailOf(r).noop !== true) || mine.find(r => detailOf(r).noop === true && detailOf(r).hashes?.detect) || null;
    const info = real ? detailOf(real) : {};
    let cat;
    try { cat = await github.catalog(); } catch (e) { throw new ChangeError(502, `Could not read main: ${cleanGithub(e.message)}`); }
    const item = cat.items.find(i => i.folder === folder);
    must(item, 404, 'No such remediation on main.');
    let newerOnMain = false;
    if (useSha && !sha && cat.sha !== useSha) {
      try {
        const [a, b] = await Promise.all([github.readChangeFiles({ sha: cat.sha, folder }), github.readChangeFiles({ sha: useSha, folder })]);
        newerOnMain = !FILES.every(n => a.raw[n] === b.raw[n]);
      } catch { newerOnMain = true; }
    }
    const drift = [];
    let alreadyPromoted = false, runStates = null, summary = null, intuneId = null, assignedTo = null;
    if (real) {
      const g = intune.scope();
      try {
        const token = await readToken();
        const found = await g.findByName(token, info.displayName || item.meta?.displayName || '');
        if (found.length !== 1) drift.push(found.length ? `${found.length} remediations with that name exist in Intune` : 'the remediation is not in Intune');
        else {
          intuneId = found[0].id;
          if (info.intuneId && info.intuneId !== intuneId) drift.push('the Intune remediation is not the one that was published');
          const cur = await g.read(token, intuneId);
          const list = cur.assignments || [];
          // The live assignments as one target set (null if it is not a clean set of groups, or All devices alone).
          const live = targetOfAssignments(list);
          assignedTo = live ? targetKey(live) : null;
          // Promoted means: the live set is real targets with no canary group in it (and, when a target is named, exactly that set).
          if (live && !isCanaryTarget(live, config.canaryGroupId) && (!wantTarget || sameTarget(live, wantTarget))) alreadyPromoted = true;
          else {
            if (!isCanaryOnly(live, config.canaryGroupId)) drift.push(`Intune does not have exactly one assignment, the canary group (${list.length} found)`);
            const st = gitStamp(cur.script?.description);
            if (!st || st.length < 8 || !useSha.startsWith(st)) drift.push('Intune holds a different git commit than the one published to canary');
            if (cur.script?.enforceSignatureCheck !== true) drift.push('enforceSignatureCheck is not true');
            const d = cur.script?.detectionScriptContent ? Buffer.from(cur.script.detectionScriptContent, 'base64') : null;
            const r = cur.script?.remediationScriptContent ? Buffer.from(cur.script.remediationScriptContent, 'base64') : null;
            if (!info.hashes?.detect || !info.hashes?.remediate) drift.push('the canary publish row has no content hashes to compare with');
            else if (!d || !r || sha256Hex(d) !== info.hashes.detect || sha256Hex(r) !== info.hashes.remediate) drift.push('the scripts in Intune are not the signed canary artifact');
          }
          [summary, runStates] = await Promise.all([g.runSummary(token, intuneId), g.runStates(token, intuneId)]);
        }
      } catch (e) { if (e instanceof ChangeError) throw e; log.error?.(`soak evidence read failed: ${e.message}`); throw mapGraphRead(e); }
    }
    const ev = evaluateSoak({ now: now(), soakDays: config.canarySoakDays, publishedAt: real?.at || null, newerOnMain, driftProblems: drift, alreadyPromoted, promotedLabel: wantTarget ? targetText(wantTarget) : 'a target outside the canary group', runStates, summary, canaryDevice: config.canaryDevice });
    const canaryPr = real ? Number(real.prNumber) : null;
    const origAuthorOid = canaryPr ? ledgerFor(rows, canaryPr).proposed?.actorOid || null : null;
    return { ...ev, canary: { sha: useSha, prNumber: canaryPr, at: real?.at || null, displayName: info.displayName || item.meta?.displayName || null, intuneId, originalAuthorOid: origAuthorOid }, assignedTo, mainSha: cat.sha, item };
  }
  const publicEvidence = ev => { const { item, ...rest } = ev; return rest; };

  // Entra groups are read as the signed-in user (delegated GroupMember.Read.All). Reads only.
  const mapGroupRead = e => {
    if (e instanceof GraphWriteError) {
      if (e.status === 401 || e.status === 403) return new ChangeError(403, `Microsoft Graph refused the group lookup (HTTP ${e.status}). Sign in again. r360-web needs the delegated GroupMember.Read.All permission with admin consent${requestIdOf(e)}.`);
      return new ChangeError(502, `${e.message}${requestIdOf(e)}`);
    }
    return new ChangeError(502, 'Microsoft Graph could not be reached, so the target group could not be checked. Nothing was changed.');
  };
  // Mail-only distribution lists cannot be Intune assignment targets.
  const suitableGroup = g => Boolean(g) && g.securityEnabled === true;
  const groupKind = g => (Array.isArray(g.groupTypes) && g.groupTypes.includes('Unified') ? 'Microsoft 365' : 'Security');
  const readTokenOf = async readToken => { try { return await readToken(); } catch (e) { throw e.expose ? e : new ChangeError(403, 'Your sign-in could not get a Microsoft Graph read token. Sign in again.'); } };
  // The chosen group must exist right now and must not be the canary group. Called before a promotion is proposed and again before it is published.
  // Every group of a multi-group target is checked. Returns the name (one group) or the names in group id order (several).
  async function checkGroupTarget(want, token, deny) {
    const ids = groupsOf(want);
    if (isCanaryTarget(want, config.canaryGroupId)) await deny('target-is-canary', ids.length > 1 ? 'The canary group is one of the chosen groups. Remove it: a promotion goes beyond the canary group, never to it.' : 'That is the canary group. A promotion needs a different group, or All devices.', 400);
    const names = [];
    for (const id of ids) {
      let grp;
      try { grp = await intune.scope().getGroup(token, id); } catch (e) { throw mapGroupRead(e); }
      const which = ids.length > 1 ? `Group ${id}` : 'That group';
      if (!grp || String(grp.id || '').toLowerCase() !== id) await deny('target-group-missing', `${which} does not exist in Entra ID (it may have been deleted). Pick another target.`, 409, ids.length > 1 ? { groupId: id } : {});
      if (!suitableGroup(grp)) await deny('target-group-unsuitable', `${which} is not a security group, so Intune cannot assign to it. Pick a security group.`, 409, ids.length > 1 ? { groupId: id } : {});
      names.push(cleanName(grp.displayName) || id);
    }
    return want.kind === 'groups' ? names : names[0];
  }

  async function promoteImpl(user, roles, body, { readToken }) {
    strictKeys(body, ['folder', 'canarySha', 'overrideReason', 'target']);
    needRoles(roles, ['approver'], 'promote changes');
    must(config.canaryGroupId, 503, 'No canary group is configured (R360_CANARY_GROUP_ID).');
    const fe0 = folderError(body.folder);
    must(!fe0, 400, fe0);
    const folder = body.folder;
    const parsed = parseTargetRequest(body.target);
    must(parsed.target, 400, parsed.error);
    const want = parsed.target;
    must(SHA40.test(body.canarySha || ''), 400, 'canarySha (the canary version you looked at) is required.');
    let rows;
    try { rows = await ledgerRows(120); } catch { throw new ChangeError(503, 'The audit trail is unavailable, so nothing was checked.'); }
    const ev = await soakEvidence({ folder, rows, readToken, target: want });
    const target = `remediations/${folder}`;
    const requestId = randomUUID();
    const deny = async (reason, message, status = 409, extra = {}) => {
      await denyRow(user, { action: 'promote.denied', target, requestId, reason, toTarget: targetKey(want), gitSha: ev.canary.sha || undefined, soakDays: ev.daysSoaked, detail: { canarySha: ev.canary.sha, failing: ev.failing, toTarget: targetKey(want), ...extra } });
      throw new ChangeError(status, message, { evidence: publicEvidence(ev) });
    };
    if (ev.canary.sha !== body.canarySha) await deny('canary-changed', `The canary version is now ${short(ev.canary.sha)}, not ${short(body.canarySha)}. Reload and look again.`);
    const orig = ev.canary.originalAuthorOid;
    let fe = { allowed: true, selfApproved: false, reason: 'author-unknown' };
    if (orig) {
      fe = fourEyes({ mode: config.fourEyes, step: 'promote', authorOid: orig, actorOid: user.oid });
      if (!fe.allowed) await deny(fe.reason, fe.message, 403, { originalAuthorOid: orig });
    } else if (config.fourEyes === 'enforced') await deny('author-unknown', 'r360 cannot tell who authored the canary change, so it cannot check four-eyes. Nothing was promoted.', 403);
    // The target is checked on the server whatever the page showed: the canary group is refused and a group must exist right now.
    let targetName = want.kind === ALL_DEVICES ? 'All devices' : null, counts = null;
    if (want.kind === 'group') {
      const token = await readTokenOf(readToken);
      targetName = await checkGroupTarget(want, token, deny);
      counts = await intune.scope().groupCounts(token, want.groupId);
    } else if (want.kind === 'groups') {
      const token = await readTokenOf(readToken);
      targetName = await checkGroupTarget(want, token, deny);
      counts = await Promise.all(want.groupIds.map(async groupId => ({ groupId, ...(await intune.scope().groupCounts(token, groupId)) })));
    }
    let override = false;
    if (!ev.ready) {
      const failing = ev.checks.filter(c => !c.ok);
      if (!ev.overridable) await deny('evidence-failed', `The canary evidence is not clean: ${failing.map(c => `${c.label} (${c.detail})`).join('; ')}`);
      if (body.overrideReason == null || body.overrideReason === '') await deny('soak-not-met', `Only ${ev.daysSoaked} of ${ev.daysRequired} canary days have passed. An approver can override the soak days with a written reason.`);
      must(validReason(body.overrideReason), 400, `The override reason must be at least ${MIN_REASON} characters.`);
      override = true;
    }
    const reason = override ? cleanReason(body.overrideReason) : null;
    const existing = ev.item;
    must(isCanaryOnly(targetOf(existing.meta?.assignment), config.canaryGroupId), 409, 'main does not assign this remediation to the canary group, so there is nothing to promote.');
    const meta = { ...existing.meta, assignment: assignmentFor(want, existing.meta.assignment) };
    const siblings = (await github.catalog()).items.filter(i => i.folder !== folder && i.meta?.displayName).map(i => i.meta.displayName);
    const vm = validateMeta(meta, { siblingNames: siblings, folder });
    must(vm.ok !== false && !vm.errors?.length, 400, `The promoted remediation.json is not valid: ${(vm.errors || []).slice(0, 3).join('; ')}`);
    const content = metaText(meta);
    must(metaDiff(existing.meta, JSON.parse(content)).join(',') === promotionDiff(want), 409, 'The promotion would change more than the assignment, so it was not created.');
    const open = await openChanges();
    const dup = open.find(o => o.machine.folder === folder);
    must(!dup, 409, `There is already an open change for "${folder}" (#${dup?.number}). Merge or discard it first.`);
    must(open.length < config.maxOpenChanges, 429, `There are already ${open.length} open changes (limit ${config.maxOpenChanges}). Merge or discard some first.`);

    const ms = now();
    const branch = branchName({ folder, ms, oid: user.oid });
    const checks = Object.fromEntries(ev.checks.map(c => [c.id, c.ok]));
    const detail = { folder, promote: true, canarySha: ev.canary.sha, canaryPr: ev.canary.prNumber, originalAuthorOid: orig, fromGroup: config.canaryGroupId, toTarget: targetKey(want), toGroup: want.groupId || null,
      ...(want.kind === 'groups' ? { toGroups: want.groupIds, targetNames: targetName, groupCounts: counts } : { targetName, ...(counts ? { deviceCount: counts.deviceCount, memberCount: counts.memberCount } : {}) }), branch,
      soakStartedAt: ev.startedAt, soakDays: ev.daysSoaked, soakRequired: ev.daysRequired, soakOverride: override, ...(override ? { overrideReason: reason } : {}), selfPromoted: fe.selfApproved === true, checks };
    const base = { action: 'promote.proposed', target, requestId, toTarget: targetKey(want), soakDays: ev.daysSoaked, selfApproved: fe.selfApproved === true, ...(override ? { reason } : {}) };
    await intent(user, { ...base, detail });
    let pr;
    try {
      pr = await github.proposeChange({
        branch, files: [{ path: `remediations/${folder}/remediation.json`, content }],
        message: commitMessage({ kind: 'promote', folder, displayName: ev.canary.displayName || folder, user, requestId, soakOverride: override, target: want, targetName }),
        title: `r360: promote remediation ${folder} to ${promoteLabel(want, targetName)}${override ? ' (SOAK OVERRIDE)' : ''}`,
        body: promoteBody({ displayName: ev.canary.displayName || folder, proposer: proposer(user), authorOid: user.oid, requestId, ms, folder, fromGroup: config.canaryGroupId, target: want, targetName, counts,
          canarySha: ev.canary.sha, evidence: ev, override, reason, fourEyes: config.fourEyes, selfPromoted: fe.selfApproved === true }),
      });
    } catch (e) {
      log.error?.(`promote.proposed failed: ${e.message}`);
      await result(user, { ...base, result: 'failed', reason: e.message, githubRequestId: e.githubRequestId, detail: { ...detail, rolledBack: e.rolledBack } });
      throw new ChangeError(502, e.permission ? `GitHub refused the write token: ${e.message}` : `GitHub rejected the promotion: ${cleanGithub(e.message)}`);
    }
    bust();
    const warning = await result(user, { ...base, result: 'ok', prNumber: pr.number, gitSha: pr.headSha, githubRequestId: pr.githubRequestId, detail });
    return { ok: true, number: pr.number, url: pr.url, branch, headSha: pr.headSha, promote: true, target: { kind: want.kind, groupId: want.groupId || null, ...(want.kind === 'groups' ? { groupIds: want.groupIds, names: targetName, counts } : { name: targetName }) }, soakOverride: override, soakDays: ev.daysSoaked, soakRequired: ev.daysRequired, selfPromoted: fe.selfApproved === true, requestId, ...(warning ? { warning } : {}) };
  }

  // What the Promote dialog shows: the evidence, and whether this person may go on. Reads only.
  async function promoteEvidenceImpl(user, roles, folder, { readToken }) {
    const fe0 = folderError(folder);
    must(!fe0, 400, fe0);
    let rows;
    try { rows = await ledgerRows(120); } catch { throw new ChangeError(503, 'The audit trail is unavailable, so the evidence cannot be shown.'); }
    const ev = await soakEvidence({ folder, rows, readToken });
    const orig = ev.canary.originalAuthorOid;
    const fe = orig ? fourEyes({ mode: config.fourEyes, step: 'promote', authorOid: orig, actorOid: user.oid }) : { allowed: config.fourEyes !== 'enforced', selfApproved: false, message: 'r360 cannot tell who authored the canary change.' };
    let block = null;
    if (!roles.includes('approver')) block = 'Only an approver (listed in approvers.json) can promote.';
    else if (ev.alreadyPromoted) block = 'Intune already assigns this remediation outside the canary group, so there is nothing to promote.';
    else if (!fe.allowed) block = fe.message;
    else if (!ev.ready && !ev.overridable) block = 'The canary evidence is not clean. Fix that first; the soak override cannot waive it.';
    return { folder, evidence: publicEvidence(ev), canarySha: ev.canary.sha, canary: ev.canary, canaryGroupId: config.canaryGroupId || null,
      defaultTarget: config.prodGroupId ? { type: 'group', groupId: config.prodGroupId } : null, requiredReasonLength: MIN_REASON, fourEyes: config.fourEyes, selfPromote: fe.selfApproved === true,
      block, canOverride: Boolean(!block && !ev.ready && ev.overridable), canPromote: Boolean(!block && ev.ready) };
  }

  // The Promote dialog's group picker: search Entra groups by display name as the signed-in user. Reads only. The canary group is never offered.
  async function promoteGroupsImpl(user, roles, query, { readToken }) {
    needRoles(roles, ['approver'], 'search for a promotion target');
    const q = String(query ?? '').trim();
    must(q.length >= 2 && q.length <= 64, 400, 'Type 2 to 64 characters to search for a group.');
    const token = await readTokenOf(readToken);
    const g = intune.scope();
    let found;
    try { found = isGuid(q) ? [await g.getGroup(token, q.toLowerCase())].filter(Boolean) : await g.searchGroups(token, q, { top: 10 }); }
    catch (e) { throw mapGroupRead(e); }
    const canary = String(config.canaryGroupId || '').toLowerCase();
    const real = found.filter(x => x && isGuid(x.id) && suitableGroup(x));
    const groups = await Promise.all(real.filter(x => x.id.toLowerCase() !== canary).map(async x => {
      const n = await g.groupCounts(token, x.id);
      return { id: x.id.toLowerCase(), displayName: cleanName(x.displayName) || x.id, description: cleanName(x.description, 120) || null, kind: groupKind(x), dynamic: Array.isArray(x.groupTypes) && x.groupTypes.includes('DynamicMembership'), deviceCount: n.deviceCount, memberCount: n.memberCount };
    }));
    groups.sort((a, b) => a.displayName.localeCompare(b.displayName));
    return { query: q, groups, canaryHidden: real.some(x => x.id.toLowerCase() === canary), more: !isGuid(q) && found.length >= 10 };
  }

  // Signing state for merged changes, shown in the list. Reads only; never throws.
  const signCache = new Map();
  async function signingState(pr, rows, budget) {
    const sha = pr.mergeSha;
    if (!sha) return null;
    const mine = (rows || []).filter(r => Number(r.prNumber) === pr.number && r.gitSha === sha);
    const ok = mine.filter(r => r.action === 'sign.verified' && r.result === 'ok').at(-1);
    if (ok) return { state: 'verified', verifiedAt: ok.at || null };
    const failed = mine.filter(r => r.action === 'sign.verify.failed').at(-1);
    const hit = signCache.get(sha);
    let run = hit && now() - hit.at < 15000 ? hit.run : undefined;
    if (run === undefined) {
      if (budget.n <= 0) return { state: 'unknown', note: 'Not checked in this refresh.' };
      budget.n--;
      try { run = await github.signingRun(sha); signCache.set(sha, { at: now(), run }); }
      catch (e) { return { state: 'unknown', note: `Signing status unavailable: ${String(e.message).slice(0, 120)}` }; }
    }
    if (!run) return { state: now() - Date.parse(pr.mergedAt || 0) > 600000 ? 'missing' : 'waiting' };
    const base = { runUrl: run.url };
    if (run.status !== 'completed') return { ...base, state: 'running' };
    if (run.conclusion !== 'success' || !jobsOk(run.jobs)) return { ...base, state: 'workflow-failed' };
    return failed ? { ...base, state: 'verify-failed', problems: (detailOf(failed).problems || []).slice(0, 5) } : { ...base, state: 'ready' };
  }

  const perUser = (item, user, roles) => {
    const isApprover = roles.includes('approver');
    let approveBlock = null, mergeBlock = null, rejectBlock = null;
    if (item.state === 'open') {
      if (!isApprover) approveBlock = mergeBlock = rejectBlock = 'Only an approver (listed in approvers.json) can do this.';
      else if (item.provenanceError) approveBlock = mergeBlock = rejectBlock = item.provenanceError;
      else {
        if (item.ci !== 'passed') approveBlock = mergeBlock = item.ci === 'failed' ? 'CI failed.' : 'CI has not finished yet.';
        const fe = fourEyes({ mode: config.fourEyes, step: 'approve', authorOid: item.authorOid, actorOid: user.oid });
        if (!approveBlock) approveBlock = item.approval ? `Already approved by ${item.approval.approverUpn || item.approval.approverOid}.` : fe.allowed ? null : fe.message;
        if (!mergeBlock && !item.approval) mergeBlock = item.ignoredSelfApproval ? 'Only a self-approval exists. Enforced mode needs a different approver.' : 'Approve this commit first.';
      }
    }
    const canVerify = item.merged && ['ready', 'verify-failed'].includes(item.signing?.state) && roles.some(r => ['author', 'approver', 'admin'].includes(r));
    let publishBlock = null;
    if (item.merged) {
      const fe = fourEyes({ mode: config.fourEyes, step: 'publish', authorOid: item.authorOid, actorOid: user.oid });
      if (item.published) publishBlock = item.promote ? 'Already published to production.' : 'Already published to the canary group.';
      else if (!isApprover) publishBlock = 'Only an approver (listed in approvers.json) can publish.';
      else if (item.signing?.state !== 'verified') publishBlock = 'Verify signing first.';
      else if (item.supersededBy) publishBlock = `Superseded by #${item.supersededBy}. Publish that one.`;
      else if (!config.canaryGroupId) publishBlock = 'No canary group is configured.';

      else if (!fe.allowed) publishBlock = fe.message;
      else if (item.chainOk === false && !(config.fourEyes === 'testing' && roles.includes('admin'))) publishBlock = 'No recorded approval and merge by r360 for this commit. Only an admin can publish it, in testing mode.';
    }
    let promoteBlock = null;
    const promotable = Boolean(item.merged && !item.promote && item.published && !item.supersededBy);
    if (promotable) {
      const fe = fourEyes({ mode: config.fourEyes, step: 'promote', authorOid: item.authorOid, actorOid: user.oid });
      if (!isApprover) promoteBlock = 'Only an approver (listed in approvers.json) can promote.';

      else if (item.folderHasOpen) promoteBlock = 'There is already an open change for this remediation. Merge or discard it first.';
      else if (!fe.allowed) promoteBlock = fe.message;
    }
    return { promoteBlock, canPromote: promotable && !promoteBlock, publishBlock, canPublish: Boolean(item.merged && !publishBlock), canEdit: item.state === 'open' && (item.authorOid === user.oid || roles.includes('admin')),
      canApprove: item.state === 'open' && !approveBlock, approveBlock, canMerge: item.state === 'open' && !mergeBlock, mergeBlock, canReject: item.state === 'open' && !rejectBlock, rejectBlock, canVerify };
  };
  return {
    async propose(user, body) {
      const p = await plan(body);
      must(p.changed.length, 400, 'Nothing changed. The files are identical to main.');
      const open = await openChanges();
      const dup = open.find(o => o.machine.folder === p.folder);
      must(!dup, 409, `There is already an open change for "${p.folder}" (#${dup?.number}). Update or discard it first.`);
      must(open.length < config.maxOpenChanges, 429, `There are already ${open.length} open changes (limit ${config.maxOpenChanges}). Merge or discard some first.`);
      if (body.dryRun === true) return { dryRun: true, kind: p.kind, folder: p.folder, groupId: p.groupId, files: p.files.map(summarize), openChanges: open.length, maxOpenChanges: config.maxOpenChanges };

      const requestId = randomUUID();
      const ms = now();
      const branch = branchName({ folder: p.folder, ms, oid: user.oid });
      const target = `remediations/${p.folder}`;
      const detail = { kind: p.kind, branch, displayName: p.displayName, groupId: p.groupId, files: p.changed.map(f => ({ path: f.path, sha256: f.sha256, status: f.status })) };
      await intent(user, { action: 'change.proposed', target, requestId, detail });
      let pr;
      try {
        pr = await github.proposeChange({
          branch, files: p.changed.map(f => ({ path: f.path, content: f.content })),
          message: commitMessage({ kind: p.kind, folder: p.folder, displayName: p.displayName, user, requestId }),
          title: `r360: ${p.kind === 'new' ? 'add' : 'update'} remediation ${p.folder}`,
          body: prBody({ kind: p.kind, folder: p.folder, displayName: p.displayName, proposer: proposer(user), authorOid: user.oid, requestId, files: p.files, groupNote: p.groupNote, fourEyes: config.fourEyes, ms }),
        });
      } catch (e) {
        log.error?.(`change.proposed failed: ${e.message}`);
        await result(user, { action: 'change.proposed', target, requestId, result: 'failed', reason: e.message, githubRequestId: e.githubRequestId, detail: { ...detail, rolledBack: e.rolledBack } });
        throw new ChangeError(502, e.permission ? `GitHub refused the write token: ${e.message}` : `GitHub rejected the change: ${e.message}`);
      }
      bust();
      const warning = await result(user, { action: 'change.proposed', target, requestId, result: 'ok', prNumber: pr.number, gitSha: pr.headSha, githubRequestId: pr.githubRequestId, detail });
      return { ok: true, number: pr.number, url: pr.url, branch, headSha: pr.headSha, kind: p.kind, requestId, files: p.files.map(summarize), ...(warning ? { warning } : {}) };
    },

    async update(user, roles, number, body) {
      const { pr, m } = await ownOpenChange(user, roles, number);
      must(m.promote !== true, 409, 'A promotion cannot be edited. Discard it and promote again.');
      const head = await github.readChangeFiles({ sha: pr.headSha, folder: m.folder });
      const p = await plan(body, { folder: m.folder, baseFiles: head });
      must(p.changed.length, 400, 'Nothing changed. The files are identical to the current ones in the pull request.');
      const requestId = randomUUID();
      const target = `remediations/${p.folder}`;
      const detail = { kind: p.kind, branch: pr.branch, displayName: p.displayName, previousHeadSha: pr.headSha, files: p.changed.map(f => ({ path: f.path, sha256: f.sha256, status: f.status })) };
      await intent(user, { action: 'change.updated', target, requestId, prNumber: number, gitSha: pr.headSha, detail });
      const originalProposer = /Proposed through r360 by (\S+) on /.exec(pr.body)?.[1] || proposer(user);
      let out;
      try {
        out = await github.updateChange({
          number, branch: pr.branch, expectHeadSha: body.expectHeadSha || pr.headSha, files: p.changed.map(f => ({ path: f.path, content: f.content })),
          message: commitMessage({ kind: 'edit', folder: p.folder, displayName: p.displayName, user, requestId }),
          body: prBody({ kind: p.kind, folder: p.folder, displayName: p.displayName, proposer: originalProposer, authorOid: m.authorOid, requestId, files: p.files, groupNote: p.groupNote, fourEyes: config.fourEyes, ms: now() }),
        });
      } catch (e) {
        log.error?.(`change.updated failed: ${e.message}`);
        await result(user, { action: 'change.updated', target, requestId, prNumber: number, result: 'failed', reason: e.message, githubRequestId: e.githubRequestId, detail });
        throw new ChangeError(e.status === 409 ? 409 : 502, e.status === 409 ? e.message : `GitHub rejected the update: ${e.message}`);
      }
      bust();
      const warning = await result(user, { action: 'change.updated', target, requestId, prNumber: number, result: 'ok', gitSha: out.headSha, githubRequestId: out.githubRequestId, detail });
      return { ok: true, number, headSha: out.headSha, requestId, files: p.files.map(summarize), ...(warning ? { warning } : {}) };
    },

    async discard(user, roles, number) {
      const { pr, m } = await ownOpenChange(user, roles, number);
      const requestId = randomUUID();
      const target = `remediations/${m.folder}`;
      const detail = { branch: pr.branch };
      await intent(user, { action: 'change.discarded', target, requestId, prNumber: number, gitSha: pr.headSha, detail });
      let out;
      try { out = await github.discardChange({ number, branch: pr.branch }); }
      catch (e) {
        log.error?.(`change.discarded failed: ${e.message}`);
        await result(user, { action: 'change.discarded', target, requestId, prNumber: number, result: 'failed', reason: e.message, githubRequestId: e.githubRequestId, detail });
        throw new ChangeError(e.status === 409 ? 409 : 502, e.status === 409 ? e.message : `GitHub rejected the discard: ${e.message}`);
      }
      bust();
      const warning = await result(user, { action: 'change.discarded', target, requestId, prNumber: number, result: 'ok', gitSha: pr.headSha, githubRequestId: out.githubRequestId, detail });
      return { ok: true, number, requestId, ...(warning ? { warning } : {}) };
    },

    // ---- S4: approve, reject, merge, verify signing ----
    // The change as it is now, only if r360 itself proposed it and its head is the commit r360 recorded. Everything the caller
    // sends (the headSha) is only compared against this, never trusted.
    async approve(user, roles, number, body) { return approveImpl(user, roles, number, body); },
    async reject(user, roles, number, body) { return rejectImpl(user, roles, number, body); },
    async merge(user, roles, number, body) { return mergeImpl(user, roles, number, body); },
    async verifySigning(user, roles, number) { return verifyImpl(user, roles, number); },
    async publish(user, roles, number, body, publisher) { return publishImpl(user, roles, number, body, publisher); },
    async promote(user, roles, body, tokens) { return promoteImpl(user, roles, body, tokens); },
    async promoteEvidence(user, roles, folder, tokens) { return promoteEvidenceImpl(user, roles, folder, tokens); },
    async promoteGroups(user, roles, query, tokens) { return promoteGroupsImpl(user, roles, query, tokens); },
    // Current content on main (the base for an edit), for the form.
    async source(folder) {
      const fe = folderError(folder);
      must(!fe, 400, fe);
      const cat = await github.catalog();
      const it = cat.items.find(i => i.folder === folder);
      must(it, 404, 'No such remediation on main.');
      return { folder, meta: it.meta, detect: it.detect, remediate: it.remediate, mainSha: cat.sha };
    },

    // The current files of an open change, for the Update form.
    async changeSource(user, roles, number) {
      const { pr, m } = await ownOpenChange(user, roles, number);
      const files = await github.readChangeFiles({ sha: pr.headSha, folder: m.folder });
      return { folder: m.folder, number, headSha: pr.headSha, ...files };
    },

    async list(user, roles) {
      if (!cache || now() - cache.at > 5000) {
        const [pulls, cat] = await Promise.all([github.listPulls({ withChecks: true }), github.catalog().catch(() => null)]);
        let rows = null;
        let auditNote = null;
        try { rows = await ledgerRows(); } catch (e) { auditNote = 'The audit trail could not be read, so approvals and signing are not shown.'; log.error?.(`list: audit unavailable: ${e.message}`); }
        const upn = oid => cat?.approvers?.find(a => a.entraObjectId === oid)?.upn || null;
        const budget = { n: 5 };
        const items = [];
        for (const p of pulls) {
          const m = parseMachineBlock(p.body);
          if (!m) continue;
          let published = null, chainOk = null, approval = null, ignoredSelfApproval = false, prov = rows ? null : (auditNote || 'The audit trail is unavailable.'), signing = null, promoInfo = null, soak = null;
          if (rows) {
            const L = ledgerFor(rows, p.number);
            if (L.proposed?.action === 'promote.proposed') {
              const d = detailOf(L.proposed);
              promoInfo = { canarySha: d.canarySha || null, soakOverride: d.soakOverride === true, overrideReason: d.soakOverride === true ? String(d.overrideReason || '') : null, soakDays: d.soakDays ?? null, soakRequired: d.soakRequired ?? null, selfPromoted: d.selfPromoted === true,
                target: d.toTarget === ALL_DEVICES ? { kind: ALL_DEVICES, name: 'All devices' }
                  : targetFromKey(d.toTarget)?.kind === 'groups' && targetKey(groupsTarget(d.toGroups)) === d.toTarget
                    ? { kind: 'groups', groupIds: groupsTarget(d.toGroups).groupIds, names: groupsTarget(d.toGroups).groupIds.map(id => { const i = d.toGroups.map(x => String(x).toLowerCase()).indexOf(id); return cleanName((d.targetNames || [])[i]) || null; }) }
                  : isGuid(d.toGroup) ? { kind: 'group', groupId: String(d.toGroup).toLowerCase(), name: cleanName(d.targetName) || null, deviceCount: d.deviceCount ?? null, memberCount: d.memberCount ?? null } : null };
            }
            if (p.state === 'open' && !p.merged) {
              prov = provenanceError(p, m, L);
              if (!prov) ({ approval, ignoredSelfApproval } = currentApproval(L, p.headSha, { mode: config.fourEyes, authorOid: m.authorOid }));
            }
          }
          if (p.merged && rows) {
            signing = await signingState(p, rows, budget);
            const L = ledgerFor(rows, p.number);
            const all = L.rows.filter(r => r.action === (promoInfo ? 'publish.production' : 'publish.canary') && r.gitSha === p.mergeSha);
            const pub = all.at(-1);
            if (pub) published = { at: pub.at || null, byOid: pub.actorOid, byUpn: pub.actorUpn || null, selfApproved: pub.selfApproved === true, noop: detailOf(pub).noop === true };
            const real = all.find(r => detailOf(r).noop !== true);
            if (!promoInfo && real) soak = soakClock({ now: now(), soakDays: config.canarySoakDays, publishedAt: real.at });
            chainOk = chainOf(L, p, m).ok;
          }
          const isPromote = m.promote === true || Boolean(promoInfo);
          const st = stageOf(p, { approval, signing, published, promote: isPromote });
          const failing = (p.checks || []).filter(c => c.status === 'completed' && !['success', 'neutral', 'skipped'].includes(c.conclusion)).map(c => c.name);
          items.push({ number: p.number, url: p.url, title: p.title, folder: m.folder, authorOid: m.authorOid, authorUpn: upn(m.authorOid), state: p.state, merged: p.merged, stage: st.stage, ci: st.ci, steps: st.steps,
            failingChecks: failing, headSha: p.headSha, mergeSha: p.mergeSha || null, branch: p.branch, createdAt: p.createdAt, updatedAt: p.updatedAt, mergedAt: p.mergedAt,
            approval, ignoredSelfApproval, provenanceError: p.state === 'open' && !p.merged ? prov : null, signing, published, chainOk, promote: isPromote, promoteInfo: promoInfo, soak });
        }
        // A later merge of the same remediation supersedes an earlier one.
        for (const i of items) {
          if (!i.merged) continue;
          const newer = items.filter(o => o.merged && o.folder === i.folder && Date.parse(o.mergedAt || 0) > Date.parse(i.mergedAt || 0)).sort((a, b) => Date.parse(b.mergedAt || 0) - Date.parse(a.mergedAt || 0))[0];
          i.supersededBy = newer ? newer.number : null;
        }
        const openFolders = new Set(items.filter(i => i.state === 'open').map(i => i.folder));
        for (const i of items) i.folderHasOpen = openFolders.has(i.folder);
        cache = { at: now(), items, auditNote };
      }
      return { fetchedAt: new Date(cache.at).toISOString(), changes: cache.items.map(i => ({ ...i, ...perUser(i, user, roles) })), maxOpenChanges: config.maxOpenChanges, openCount: cache.items.filter(i => i.state === 'open').length,
        fourEyes: config.fourEyes, prodDefault: config.prodGroupId || null, soakDays: config.canarySoakDays, soakDefault: DEFAULT_SOAK_DAYS, ...(cache.auditNote ? { warning: cache.auditNote } : {}) };
    },
  };
}
