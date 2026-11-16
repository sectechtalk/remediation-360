import { createHash } from 'node:crypto';
import { ChangeError } from './changes.mjs';
import { changeNumber, newPart, MAX_BODY } from './mailbox.mjs';
import { SUMMARY_SYSTEM, ACTIONS_SYSTEM, ACTIONS_SCHEMA } from './llm.mjs';

// Change requests tracked by email.
//   - "Get change number" opens a GitHub issue labeled r360-change on config.changeRepo. The number is R360-CHG-<issue number>.
//   - Organizations email the shared change mailbox with that number in the subject or body.
//   - r360 reads the mailbox with the operator's own delegated token whenever someone opens the page or asks for a summary,
//     and adds one comment per new email to the issue (sender, time, subject; the body stays in the mailbox).
//   - "Summarize now" sends the matched emails to the configured model and posts the summary on the issue.
//     "Make actionable" turns the latest summary into a task checklist on the issue.
//   - "Close" closes the issue. Every write is audited first ("no audit, no write").
export const CHANGE_LABEL = 'r360-change';
export const SUMMARY_REQUESTED_LABEL = 'r360-summary-requested';
export const REQUEST_ACTIONS = ['request.created', 'request.synced', 'request.summarized', 'request.actions', 'request.closed', 'request.summaryrequested'];
export const ROLES = ['author', 'approver', 'admin'];
const SYNC_TTL_MS = 120000;
const MAX_PROMPT_CHARS = 400000;
const MAX_NEW_PER_SYNC = 50;

// Machine lines in the issue and its comments. Only r360 writes them; their JSON is parsed defensively.
export const requestBlock = d => `<!-- r360:request ${JSON.stringify({ v: 1, ...d })} -->`;
export const mailBlock = id => `<!-- r360:mail ${JSON.stringify({ v: 1, id: mailKey(id) })} -->`;
export const summaryBlock = d => `<!-- r360:summary ${JSON.stringify({ v: 1, ...d })} -->`;
export const summaryRequestBlock = d => `<!-- r360:summary-request ${JSON.stringify({ v: 1, ...d })} -->`;
export const actionsBlock = d => `<!-- r360:actions ${JSON.stringify({ v: 1, ...d })} -->`;
export const mailKey = id => createHash('sha256').update(String(id)).digest('hex').slice(0, 32);
export function parseBlock(kind, body) {
  const m = new RegExp(`<!-- r360:${kind} (\\{[^\\n]*?\\}) -->`).exec(body || '');
  if (!m) return null;
  try { const j = JSON.parse(m[1]); return j && typeof j === 'object' ? j : null; } catch { return null; }
}

// Text from outside (subjects, names, model output) goes into GitHub Markdown: no mentions, no HTML, no fake machine lines.
export const mdSafe = (s, max = 300) => String(s ?? '').replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, ' ').replace(/<!--|-->/g, ' ')
  .replace(/[<>]/g, c => (c === '<' ? '&lt;' : '&gt;')).replace(/(^|[^A-Za-z0-9._%+-])@(?=[A-Za-z0-9])/g, '$1@\u200b').replace(/#(?=\d)/g, '#\u200b').slice(0, max);
export const inline = (s, max = 300) => mdSafe(s, max).replace(/[\r\n]+/g, ' ').replace(/([\\`*_[\]|])/g, '\\$1');

const pt = iso => (iso ? `${new Date(iso).toLocaleString('en-US', { timeZone: 'America/Los_Angeles', dateStyle: 'medium', timeStyle: 'short' })} PT` : 'unknown time');

export function validateCreate(body) {
  const b = body && typeof body === 'object' ? body : {};
  const title = String(b.title ?? '').trim();
  const org = String(b.organization ?? '').trim();
  const description = String(b.description ?? '').trim();
  const bad = [];
  if (title.length < 4 || title.length > 200) bad.push('Title must be 4 to 200 characters.');
  if (org.length < 2 || org.length > 120) bad.push('Requesting organization must be 2 to 120 characters.');
  if (description.length > 4000) bad.push('Description must be at most 4000 characters.');
  if (bad.length) throw new ChangeError(400, bad.join(' '), bad);
  return { title, org, description };
}

export function issueBody({ number, title, org, description, user, mailbox, at }) {
  return [
    `**${changeNumber(number)}**: ${inline(title, 200)}`, '',
    `| | |`, `|---|---|`,
    `| Requesting organization | ${inline(org, 120)} |`,
    `| Opened by | ${inline(user.name || user.upn, 120)} (${inline(user.upn, 200)}) in r360 |`,
    `| Opened | ${pt(at)} |`,
    `| Mailbox | ${inline(mailbox, 200)} |`, '',
    description ? `### Description\n\n${mdSafe(description, 4000)}\n` : '',
    `Emails to ${inline(mailbox, 200)} that contain **${changeNumber(number)}** in the subject or body are tracked on this issue.`,
    'Summaries and action items are posted here by r360. Close the change from r360.', '',
    requestBlock({ org: String(org).slice(0, 120), openedByOid: user.oid }),
  ].join('\n');
}

export const subjectLine = (number, title) => `[${changeNumber(number)}] ${String(title).slice(0, 150)}`;

export function mailComment(m) {
  return [
    `**Email received** ${pt(m.receivedAt)}`, '',
    `- From: ${inline(m.fromName || m.fromAddress, 200)}${m.fromName && m.fromAddress ? ` (${inline(m.fromAddress, 200)})` : ''}`,
    `- Subject: ${inline(m.subject, 300)}`,
    m.hasAttachments ? '- Has attachments (open them in the mailbox)' : null, '',
    mailBlock(m.id),
  ].filter(x => x !== null).join('\n');
}

// What an issue's comments say: which emails are already logged, the latest summary and action list.
export function ledgerOf(comments) {
  const mail = new Set();
  let summary = null, actions = null, lastMailAt = null;
  for (const c of comments || []) {
    const m = parseBlock('mail', c.body);
    if (m?.id) { mail.add(m.id); if (!lastMailAt || Date.parse(c.createdAt) > Date.parse(lastMailAt)) lastMailAt = c.createdAt; }
    const s = parseBlock('summary', c.body);
    if (s) summary = { ...s, at: c.createdAt, url: c.url, text: c.body.replace(/<!-- r360:summary [^\n]*-->/, '').replace(/^### Summary[^\n]*\n+/, '').trim() };
    const a = parseBlock('actions', c.body);
    if (a) actions = { ...a, at: c.createdAt, url: c.url };
  }
  return { mail, summary, actions, lastMailAt };
}

export function transcript(number, mails) {
  const parts = [];
  let used = 0;
  const sorted = [...mails].sort((a, b) => Date.parse(a.receivedAt) - Date.parse(b.receivedAt));
  for (const [i, m] of sorted.entries()) {
    const block = `<email index="${i + 1}">\nFrom: ${m.fromName} <${m.fromAddress}>\nReceived: ${m.receivedAt}\nSubject: ${m.subject}\n\n${newPart(m.body).slice(0, MAX_BODY)}\n</email>`;
    if (used + block.length > MAX_PROMPT_CHARS) { parts.push(`<note>${sorted.length - i} older emails were left out because the thread is too long.</note>`); break; }
    parts.push(block); used += block.length;
  }
  return `Change ${changeNumber(number)}. ${sorted.length} email(s), oldest first.\n\n${parts.join('\n\n')}`;
}

export function actionsComment(actions, meta) {
  const lines = actions.length ? actions.map(a => `- [ ] ${inline(a.title, 160)}${a.owner ? ` (owner: ${inline(a.owner, 80)})` : ''}${/^\d{4}-\d{2}-\d{2}$/.test(a.due || '') ? ` (due ${a.due})` : ''}`) : ['_No action items: the emails do not ask for anything that is still open._'];
  return [`### Action items`, '', ...lines, '', `_Generated by ${inline(meta.provider)} ${inline(meta.model)} from the summary of ${meta.emails} email(s), requested by ${inline(meta.by)}. Check each item before acting on it._`, '', actionsBlock(meta)].join('\n');
}

export function createRequests({ config, github, audit, mailbox, llm, now = () => Date.now(), log = console }) {
  const must = (cond, status, msg) => { if (!cond) throw new ChangeError(status, msg); };
  const enabled = () => must(config.changeMailbox, 503, 'Change requests are off. Set R360_CHANGE_MAILBOX with tools/Set-R360ChangeRequests.ps1.');
  const ai = () => must(llm.configured, 503, 'No AI provider is configured yet, so summaries are off. Add the API key with tools/Set-R360ChangeRequests.ps1 -Apply -SkipExchange -SetApiKey.');
  const role = roles => must(roles.some(r => ROLES.includes(r)), 403, 'Your approvers.json role does not allow changing change requests.');
  const who = u => ({ actorOid: u.oid, actorUpn: u.upn });
  const intent = async (user, event) => {
    try { await audit.record({ ...who(user), ...event, result: 'intent' }); }
    catch (e) { log.error?.(`${event.action}: audit intent failed: ${e.message}`); throw new ChangeError(503, 'The audit trail is unavailable, so nothing was changed.'); }
  };
  const done = async (user, event) => {
    try { await audit.record({ ...who(user), ...event }); return null; }
    catch (e) { log.error?.(`${event.action}: audit result failed: ${e.message}`); return 'The action was done but its result row could not be written to the audit trail.'; }
  };
  const ghFail = (e, what) => {
    if (e.expose) return e;
    log.error?.(`request ${what}: ${e.message}`);
    if (e.permission || e.status === 403) return new ChangeError(502, `GitHub refused to ${what}. The r360 GitHub App needs Issues: read and write on ${config.changeRepo}.`);
    return new ChangeError(502, `GitHub could not ${what}.`);
  };

  // The issue, only if it is an r360 change request.
  async function own(number, { open = true } = {}) {
    must(Number.isInteger(number) && number > 0, 404, 'No such change.');
    let i;
    try { i = await github.getIssue(number); } catch (e) { if (e.status === 404 || e.status === 410) throw new ChangeError(404, 'No such change.'); throw ghFail(e, 'read the change'); }
    must(!i.isPull && i.labels.includes(CHANGE_LABEL), 404, `${changeNumber(number)} is not an r360 change request.`);
    if (open) must(i.state === 'open', 409, `${changeNumber(number)} is closed.`);
    return i;
  }

  async function openIssues() {
    try { return await github.listIssues({ label: CHANGE_LABEL, state: 'open' }); } catch (e) { throw ghFail(e, 'list the change requests'); }
  }

  // Reads the mailbox once for all open changes and logs each new email on its issue. Throttled per replica.
  let lastSync = { at: 0, result: null };
  async function sync(user, token, { force = false } = {}) {
    enabled();
    if (!force && lastSync.result && now() - lastSync.at < SYNC_TTL_MS) return lastSync.result;
    const issues = await openIssues();
    const result = { at: new Date(now()).toISOString(), scanned: 0, truncated: false, added: 0, byNumber: {}, error: null };
    if (!issues.length) { lastSync = { at: now(), result }; return result; }
    const since = issues.reduce((min, i) => Math.min(min, Date.parse(i.createdAt)), now()) - 3600000;
    const { messages, truncated } = await mailbox.messagesSince(await token(), new Date(since).toISOString());
    result.scanned = messages.length; result.truncated = truncated;
    const open = new Map(issues.map(i => [i.number, i]));
    const matched = new Map();
    for (const m of messages) for (const n of m.numbers) if (open.has(n) && Date.parse(m.receivedAt) >= Date.parse(open.get(n).createdAt) - 3600000) (matched.get(n) || matched.set(n, []).get(n)).push(m);
    for (const [n, mails] of matched) {
      result.byNumber[n] = { emails: mails.length, lastEmailAt: mails[0]?.receivedAt || null };
      let ledger;
      try { ledger = ledgerOf(await github.issueComments(n)); } catch (e) { result.error = ghFail(e, 'read the change comments').message; continue; }
      const fresh = mails.filter(m => !ledger.mail.has(mailKey(m.id))).sort((a, b) => Date.parse(a.receivedAt) - Date.parse(b.receivedAt)).slice(0, MAX_NEW_PER_SYNC);
      if (!fresh.length) continue;
      try {
        const t = await github.issueWriteToken();
        for (const m of fresh) { await github.commentOnIssue({ number: n, body: mailComment(m), token: t }); result.added++; }
      } catch (e) { result.error = ghFail(e, 'log the new emails').message; }
      await done(user, { action: 'request.synced', result: result.error ? 'partial' : 'ok', target: changeNumber(n), prNumber: n, detail: { added: fresh.length, mailbox: config.changeMailbox } });
    }
    lastSync = { at: now(), result };
    return result;
  }

  async function list(user, { token, roles }) {
    const base = { enabled: Boolean(config.changeMailbox), mailbox: config.changeMailbox || null, repo: config.changeRepo, provider: config.llm.provider, model: config.llm.model || null, llmConfigured: llm.configured, canWrite: roles.some(r => ROLES.includes(r)), rows: [] };
    if (!config.changeMailbox) return base;
    let syncInfo, syncError = null;
    try { syncInfo = await sync(user, token); } catch (e) { syncError = e.expose ? e.message : 'The mailbox could not be read.'; if (!e.expose) log.error?.(`request sync: ${e.message}`); }
    const issues = await openIssues();
    const rows = [];
    for (const i of issues.slice(0, 50)) {
      let ledger = { mail: new Set(), summary: null, actions: null, lastMailAt: null };
      try { if (i.comments) ledger = ledgerOf(await github.issueComments(i.number)); } catch { /* shown as unknown counts */ }
      const meta = parseBlock('request', i.body) || {};
      rows.push({ number: i.number, changeNumber: changeNumber(i.number), title: i.title.replace(/^\[R360-CHG-\d+\]\s*/, ''), organization: String(meta.org || ''), url: i.url, createdAt: i.createdAt,
        subject: subjectLine(i.number, i.title.replace(/^\[R360-CHG-\d+\]\s*/, '')), emails: ledger.mail.size, lastEmailAt: syncInfo?.byNumber?.[i.number]?.lastEmailAt || ledger.lastMailAt,
        summary: ledger.summary ? { at: ledger.summary.at, url: ledger.summary.url, text: ledger.summary.text.slice(0, 6000), emails: ledger.summary.emails, model: ledger.summary.model } : null,
        actions: ledger.actions ? { at: ledger.actions.at, url: ledger.actions.url, count: ledger.actions.count } : null,
        summaryRequested: i.labels.includes(SUMMARY_REQUESTED_LABEL) });
    }
    return { ...base, rows, sync: syncInfo ? { at: syncInfo.at, scanned: syncInfo.scanned, truncated: syncInfo.truncated, added: syncInfo.added, error: syncInfo.error } : null, syncError };
  }

  async function create(user, roles, body) {
    enabled(); role(roles);
    const v = validateCreate(body);
    await intent(user, { action: 'request.created', target: config.changeRepo, detail: { title: v.title, org: v.org } });
    let issue;
    try {
      // The number is the issue number, so the issue is created first and its body filled in right after.
      issue = await github.createIssue({ title: v.title, body: `Creating change request in r360...\n\n${requestBlock({ org: v.org, openedByOid: user.oid })}`, labels: [CHANGE_LABEL] });
      const at = new Date(now()).toISOString();
      await github.updateIssue({ number: issue.number, title: subjectLine(issue.number, v.title), body: issueBody({ number: issue.number, ...v, user, mailbox: config.changeMailbox, at }) });
    } catch (e) {
      await done(user, { action: 'request.created', result: 'failed', target: config.changeRepo, reason: String(e.message).slice(0, 300) });
      throw ghFail(e, 'create the change request');
    }
    const warning = await done(user, { action: 'request.created', result: 'ok', target: changeNumber(issue.number), prNumber: issue.number, githubRequestId: issue.githubRequestId, detail: { org: v.org } });
    return { number: issue.number, changeNumber: changeNumber(issue.number), url: issue.url, mailbox: config.changeMailbox, subject: subjectLine(issue.number, v.title), ...(warning ? { warning } : {}) };
  }

  async function matchedMails(number, issue, token) {
    const { messages, truncated } = await mailbox.messagesSince(await token(), new Date(Date.parse(issue.createdAt) - 3600000).toISOString());
    return { mails: messages.filter(m => m.numbers.has(number)), truncated };
  }

  async function summarize(user, roles, number, { token }) {
    enabled(); role(roles); ai();
    const issue = await own(number);
    await sync(user, token, { force: true }).catch(e => { if (e.expose) throw e; log.error?.(`request sync: ${e.message}`); });
    const { mails, truncated } = await matchedMails(number, issue, token);
    must(mails.length, 409, `No emails with ${changeNumber(number)} have reached ${config.changeMailbox} yet.`);
    await intent(user, { action: 'request.summarized', target: changeNumber(number), prNumber: number, detail: { emails: mails.length, provider: llm.provider, model: llm.model } });
    let r;
    try { r = await llm.complete({ system: SUMMARY_SYSTEM, prompt: `${transcript(number, mails)}\n\nSummarize this change request.` }); }
    catch (e) { await done(user, { action: 'request.summarized', result: 'failed', target: changeNumber(number), prNumber: number, reason: String(e.message).slice(0, 300) }); throw e.expose ? e : new ChangeError(502, 'The summary could not be made.'); }
    const meta = { provider: r.provider, model: r.model, emails: mails.length, by: user.upn };
    const body = `### Summary of ${mails.length} email(s)\n\n${mdSafe(r.text, 20000)}\n\n_Generated by ${inline(r.provider)} ${inline(r.model)}, requested by ${inline(user.upn)} at ${pt(new Date(now()).toISOString())}${truncated ? '. The mailbox scan hit its limit, so the oldest emails may be missing' : ''}._\n\n${summaryBlock(meta)}`;
    let c;
    try { c = await github.commentOnIssue({ number, body }); }
    catch (e) { await done(user, { action: 'request.summarized', result: 'failed', target: changeNumber(number), prNumber: number, reason: 'summary made but not posted' }); throw ghFail(e, 'post the summary'); }
    const warning = await done(user, { action: 'request.summarized', result: 'ok', target: changeNumber(number), prNumber: number, githubRequestId: c.githubRequestId, detail: meta });
    return { number, changeNumber: changeNumber(number), summary: r.text, url: c.url, emails: mails.length, provider: r.provider, model: r.model, ...(warning ? { warning } : {}) };
  }

  async function actionable(user, roles, number, { token }) {
    enabled(); role(roles); ai();
    const issue = await own(number);
    const ledger = ledgerOf(await github.issueComments(number).catch(e => { throw ghFail(e, 'read the change comments'); }));
    must(ledger.summary, 409, `Summarize ${changeNumber(number)} first.`);
    const { mails } = await matchedMails(number, issue, token);
    await intent(user, { action: 'request.actions', target: changeNumber(number), prNumber: number, detail: { provider: llm.provider, model: llm.model } });
    let r;
    try { r = await llm.complete({ system: ACTIONS_SYSTEM, schema: ACTIONS_SCHEMA, prompt: `<summary>\n${ledger.summary.text}\n</summary>\n\n${transcript(number, mails)}\n\nList the action items.` }); }
    catch (e) { await done(user, { action: 'request.actions', result: 'failed', target: changeNumber(number), prNumber: number, reason: String(e.message).slice(0, 300) }); throw e.expose ? e : new ChangeError(502, 'The action items could not be made.'); }
    const actions = (Array.isArray(r.json?.actions) ? r.json.actions : []).filter(a => a && typeof a.title === 'string' && a.title.trim()).slice(0, 25)
      .map(a => ({ title: a.title.trim(), owner: String(a.owner || '').trim(), due: String(a.due || '').trim() }));
    const meta = { provider: r.provider, model: r.model, emails: mails.length, by: user.upn, count: actions.length };
    let c;
    try { c = await github.commentOnIssue({ number, body: actionsComment(actions, meta) }); }
    catch (e) { await done(user, { action: 'request.actions', result: 'failed', target: changeNumber(number), prNumber: number, reason: 'actions made but not posted' }); throw ghFail(e, 'post the action items'); }
    const warning = await done(user, { action: 'request.actions', result: 'ok', target: changeNumber(number), prNumber: number, githubRequestId: c.githubRequestId, detail: { count: actions.length } });
    return { number, changeNumber: changeNumber(number), actions, url: c.url, ...(warning ? { warning } : {}) };
  }

  // No API key yet: hand the summary to Claude outside r360. r360 labels the issue and leaves a request comment; the
  // summary watcher (tools/Watch-R360Summaries.ps1, run by an operator who has Claude Code) sees the label within a
  // minute, posts the summary with the r360:summary marker and removes the label. r360 itself calls no model.
  // Once an API key is configured this path turns off and Summarize now calls the provider directly.
  async function requestSummary(user, roles, number) {
    enabled(); role(roles);
    must(!llm.configured, 409, 'r360 summarizes directly now that an AI provider is configured. Use Summarize now.');
    const issue = await own(number);
    if (issue.labels.includes(SUMMARY_REQUESTED_LABEL)) return { number, changeNumber: changeNumber(number), requested: true, already: true, url: issue.url };
    await intent(user, { action: 'request.summaryrequested', target: changeNumber(number), prNumber: number });
    let c;
    try {
      c = await github.commentOnIssue({ number, body: `### Summary requested

${inline(user.name || user.upn, 120)} (${inline(user.upn, 200)}) asked for a summary of ${changeNumber(number)} at ${pt(new Date(now()).toISOString())}. The r360 summary watcher picks this up within about a minute, posts the summary here and removes the \`${SUMMARY_REQUESTED_LABEL}\` label.

${summaryRequestBlock({ by: user.upn })}` });
      await github.addIssueLabels({ number, labels: [SUMMARY_REQUESTED_LABEL] });
    } catch (e) { await done(user, { action: 'request.summaryrequested', result: 'failed', target: changeNumber(number), prNumber: number, reason: String(e.message).slice(0, 300) }); throw ghFail(e, 'request the summary'); }
    const warning = await done(user, { action: 'request.summaryrequested', result: 'ok', target: changeNumber(number), prNumber: number, githubRequestId: c.githubRequestId });
    return { number, changeNumber: changeNumber(number), requested: true, url: c.url, ...(warning ? { warning } : {}) };
  }

  async function close(user, roles, number, body) {
    enabled(); role(roles);
    const reason = body?.reason === 'cancelled' ? 'cancelled' : 'completed';
    const note = String(body?.note ?? '').trim();
    must(note.length <= 2000, 400, 'The closing note must be at most 2000 characters.');
    await own(number);
    await intent(user, { action: 'request.closed', target: changeNumber(number), prNumber: number, reason });
    let i;
    try {
      i = await github.closeIssue({ number, reason: reason === 'cancelled' ? 'not_planned' : 'completed',
        comment: `**${reason === 'cancelled' ? 'Cancelled' : 'Closed as completed'}** in r360 by ${inline(user.name || user.upn, 120)} (${inline(user.upn, 200)}) at ${pt(new Date(now()).toISOString())}.${note ? `\n\n${mdSafe(note, 2000)}` : ''}` });
    } catch (e) { await done(user, { action: 'request.closed', result: 'failed', target: changeNumber(number), prNumber: number, reason: String(e.message).slice(0, 300) }); throw ghFail(e, 'close the change'); }
    lastSync = { at: 0, result: null };
    const warning = await done(user, { action: 'request.closed', result: 'ok', target: changeNumber(number), prNumber: number, githubRequestId: i.githubRequestId, reason });
    return { number, changeNumber: changeNumber(number), state: i.state, url: i.url, ...(warning ? { warning } : {}) };
  }

  return { list, sync, create, summarize, actionable, close, requestSummary };
}
