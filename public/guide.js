// New hire: the pages a new owner of the pipeline reads first. Static content only (no API calls), so these pages
// work even before the operator has any r360 role. Overview is the page r360 opens on.
// Facts here match docs/guides/whats-supported.md and docs/guides/fast-or-slow-path.md; change them together.

export const GUIDE_DOCS = 'https://github.com/sectechtalk/remediation-360/blob/main/docs/guides';

// Tiny inline markup for the copy below: **bold**, `code` and [text](href). Built with DOM nodes, never innerHTML.
export function rich(el, text) {
  const out = [];
  const re = /\*\*([^*]+)\*\*|`([^`]+)`|\[([^\]]+)\]\(([^)\s]+)\)/g;
  let last = 0, m;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index));
    if (m[1]) out.push(el('strong', { textContent: m[1] }));
    else if (m[2]) out.push(el('code', { textContent: m[2] }));
    else {
      const external = /^https:\/\//.test(m[4]);
      out.push(el('a', { href: m[4], textContent: m[3], ...(external ? { target: '_blank', rel: 'noopener' } : {}) }));
    }
    last = re.lastIndex;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

// ---------- Overview ----------
export const PIPELINE = [
  ['Ask', 'Someone needs something fixed or changed on company PCs. It arrives as a Change request (by email) or a ServiceNow ticket.', '#requests'],
  ['Write', 'You write or edit a small PowerShell script pair in r360: one script that checks for the problem, one that fixes it.', '#remediations'],
  ['Review', 'r360 turns your edit into a GitHub pull request. A second person reads and approves it. Nobody ships their own unreviewed code.', '#changes'],
  ['Sign', 'GitHub Actions (the CI part) automatically checks the scripts and signs them with the company certificate, so PCs know the code came from r360.', '#changes'],
  ['Canary', 'The signed scripts go to a small test group of PCs first (the canary). You watch the results for 7 days.', '#fleet'],
  ['Promote', 'If the canary stayed clean, you widen it to the real groups of PCs. That is the CD part: delivery, a step at a time.', '#changes'],
  ['Watch', 'Every PC reports back. Fleet shows each run, Remediations shows drift, Audit shows who did what.', '#fleet'],
];

export const GLOSSARY = [
  ['CI/CD', 'Continuous integration and continuous delivery. CI: every change is checked and signed automatically the moment it is proposed. CD: checked changes reach devices in small, controlled steps. In this company, r360 is the front door to both.'],
  ['GitHub', 'Where the scripts live, with full history. Every change is a pull request (a proposed edit someone else approves). You rarely need to open GitHub: r360 does the GitHub work for you.'],
  ['Intune', 'Microsoft\'s device management service. It holds the scripts r360 publishes and runs them on enrolled PCs on a schedule. This is the slow path.'],
  ['Defender', 'Two different things. Defender Antivirus is free and built into every Windows PC. Defender for Endpoint (or Defender for Business) is the paid security service that can act on a PC in minutes (isolate it, scan it, quarantine a file). The paid one is the fast path, on the Emergency page.'],
  ['Remediation', 'A pair of scripts: detect (is the problem there? exit 1 means yes) and remediate (fix it). Intune runs detect on a schedule and runs remediate only when detect found the problem.'],
  ['Entra ID', 'Microsoft\'s sign-in and directory service (formerly Azure AD). It holds users, groups and devices. A PC must be joined to Entra (or hybrid joined) for Intune Remediations.'],
  ['Canary', 'A small, named test group of PCs that gets every new change first, so a bad script hurts a few PCs instead of all of them.'],
  ['Four-eyes', 'The rule that a second person approves every change. The author cannot approve their own change once it is enforced.'],
  ['Write session', 'r360 is read-only by default. To change anything you click Elevate to write, sign in again, and get a time-limited, audited session with a red banner.'],
  ['Drift', 'When what is running in Intune no longer matches what is approved in GitHub. Someone changed it outside r360; Remediations flags it.'],
];

export const FIRST_STEPS = [
  ['Read the three pages below this one', 'Ten minutes on [Fast or slow path](#paths), [What works where](#support) and [Licenses by feature](#licenses) will save you from the two most common surprises: a fix that takes a week when you needed it in an hour, and a PC that never runs anything because it lacks the right license or join state.', '#paths'],
  ['Look around, read-only', 'Open [Remediations](#remediations) (every script, and whether Intune still matches GitHub), [Fleet](#fleet) (what ran on which PC) and [Audit](#audit) (who did what). Nothing you click here changes a device.', '#remediations'],
  ['Check your access', 'Open [Settings](#settings). It shows your r360 roles and whether your Intune Administrator role is active. No role means you can read but not change anything; ask the admin listed in approvers.json.', '#settings'],
  ['Find the open work', 'Open [Change requests](#requests) and [ServiceNow](#servicenow). That is your queue: what people have asked for and what is still open.', '#requests'],
  ['Make your first change with a buddy', 'Pick a small fix, click New remediation on [Remediations](#remediations), and walk it through review, canary and promote with someone who has done it before. The [Changes](#changes) page shows where each change is.', '#changes'],
];

export function overviewPage({ el }) {
  const p = text => el('p', {}, ...rich(el, text));
  const flow = el('ol', { className: 'guide-flow' }, ...PIPELINE.map(([name, text, href], i) => el('li', { className: 'guide-flow-step' },
    el('span', { className: 'guide-flow-num', textContent: String(i + 1) }),
    el('a', { className: 'guide-flow-name', href, textContent: name }),
    el('span', { className: 'guide-flow-text', textContent: text }))));
  const steps = el('ol', { className: 'guide-steps' }, ...FIRST_STEPS.map(([title, text]) => el('li', {},
    el('strong', { textContent: title }), el('p', {}, ...rich(el, text)))));
  const glossary = el('dl', { className: 'guide-terms' }, ...GLOSSARY.flatMap(([term, text]) => [el('dt', { textContent: term }), el('dd', { textContent: text })]));
  return [
    el('h1', { textContent: 'Welcome to Remediation 360' }),
    el('p', { className: 'guide-lead', textContent: 'r360 is where every change to company Windows PCs starts and ends. If you have been told "you own the CI/CD pipeline", this is the pipeline: you ask, write, review, sign, test and roll out from here, and r360 keeps the record.' }),
    el('div', { className: 'cards guide-cards' },
      el('div', { className: 'card' }, el('h2', { textContent: 'What r360 does' }),
        p('It fixes and configures Windows PCs **with small, signed PowerShell scripts**, and makes sure every one of them was reviewed by a second person, tested on a few PCs first, and recorded.')),
      el('div', { className: 'card' }, el('h2', { textContent: 'What you do not need' }),
        p('You do not need to know Intune, Defender or GitHub to start. r360 talks to all three for you. You do need **PowerShell basics** and **someone to review your first changes**.')),
      el('div', { className: 'card' }, el('h2', { textContent: 'What r360 will not do' }),
        p('It never changes a PC without review, never skips the test group without a recorded reason, and does not manage users, mailboxes or app installs. Those stay in Entra and Intune.'))),
    el('h2', { textContent: 'How a change moves through r360' }),
    p('Every change follows the same seven steps. Each step name opens the page where it happens.'),
    flow,
    el('h2', { textContent: 'Your first week' }),
    steps,
    el('h2', { textContent: 'Words you will hear' }),
    glossary,
    el('h2', { textContent: 'When something is on fire' }),
    p('The steps above take days on purpose. If one PC is under attack or broken right now, read [Fast or slow path](#paths) before you do anything else.'),
    el('p', { className: 'muted' }, ...rich(el, `Longer guides for every topic: [docs/guides on GitHub](${GUIDE_DOCS}/README.md).`)),
  ];
}

// ---------- Fast or slow path ----------
export const PATH_COMPARE = [
  ['Speed', 'Minutes. The PC acts as soon as it is online.', 'Hours to days. PCs pick up new scripts about every 8 hours, then r360 holds the canary for 7 days before you widen it.'],
  ['How many PCs', 'One PC per request (the current r360 setting).', 'From a test group of a few to every PC in the company.'],
  ['How long the fix lasts', 'Once. The action happens and is done. If the problem comes back, so must you.', 'For good. Intune keeps running the check on its schedule and fixes the problem every time it returns.'],
  ['What you can do', 'Isolate the PC from the network (and release it), run an antivirus scan, stop and quarantine a file, and with Plan 2 collect an investigation package or restrict app execution.', 'Run any reviewed and signed detect/remediate script pair: settings, services, files, registry, certificates, cleanup.'],
  ['Review', 'A second person approves within 4 hours, then it runs.', 'A second person approves the pull request, CI signs it, and it soaks on the canary.'],
  ['What the PC needs', 'Onboarded to Defender for Endpoint (or Defender for Business) with a license. Join state does not matter.', 'Entra joined or hybrid joined, enrolled in Intune, Windows Pro/Enterprise/Education, a Windows Enterprise E3-class license and both r360 code-signing certificates.'],
  ['Where in r360', 'The Emergency page.', 'Remediations, Changes, Fleet, Certificates.'],
];

export const USE_FAST = [
  'A PC is compromised or showing an active attack, and you need it off the network now.',
  'One PC needs a scan or a file stopped and quarantined right away.',
  'You need evidence from one PC (an investigation package) before it is rebooted or wiped.',
  'The PC is not Entra joined, or its user has no Windows E3-class license, so Intune Remediations cannot reach it at all.',
];
export const USE_SLOW = [
  'The same fix belongs on many PCs, or on every PC.',
  'The problem keeps coming back (a setting users change, a service that stops) and you want it fixed every time automatically.',
  'It is a configuration standard: certificates, registry settings, cleanup, anything you would otherwise do by hand on each PC.',
  'Nothing is on fire. If it can wait for the canary, it should go through the slow path.',
];

export function pathsPage({ el }) {
  const p = text => el('p', {}, ...rich(el, text));
  const list = items => el('ul', {}, ...items.map(t => el('li', {}, ...rich(el, t))));
  const table = el('div', { className: 'tablewrap guide-table' }, el('table', {},
    el('thead', {}, el('tr', {}, el('th', { scope: 'col', textContent: '' }), el('th', { scope: 'col', textContent: 'Fast path: Defender' }), el('th', { scope: 'col', textContent: 'Slow path: Intune' }))),
    el('tbody', {}, ...PATH_COMPARE.map(([k, fast, slow]) => el('tr', {}, el('th', { scope: 'row', textContent: k }), el('td', { textContent: fast }), el('td', { textContent: slow }))))));
  return [
    el('h1', { textContent: 'Fast or slow path' }),
    el('p', { className: 'guide-lead', textContent: 'r360 has two ways to act on a PC. The slow path (Intune) is how almost everything should ship. The fast path (Defender) is for one PC that cannot wait.' }),
    el('div', { className: 'cards guide-cards' },
      el('div', { className: 'card guide-choice' }, el('h2', { textContent: 'Use the fast path when' }), list(USE_FAST)),
      el('div', { className: 'card guide-choice' }, el('h2', { textContent: 'Use the slow path when' }), list(USE_SLOW))),
    el('h2', { textContent: 'The rule of thumb' }),
    p('**Fast path to stop the bleeding, slow path to fix it for good.** If you used the fast path on a PC, follow it with a slow-path change so the same problem cannot come back on that PC or any other.'),
    el('h2', { textContent: 'Side by side' }),
    table,
    el('h2', { textContent: 'How to use the fast path' }),
    el('ol', { className: 'guide-steps' },
      el('li', {}, ...rich(el, '**Elevate to write** (bottom of the menu). The fast path uses your own Defender permissions, so you also need a Defender role with "Active remediation actions".')),
      el('li', {}, ...rich(el, 'Open [Emergency](#emergency), search for the PC by name, choose the action, and say why. One PC per request.')),
      el('li', {}, ...rich(el, 'A second person with the **emergencyApprover** role opens the same page within 4 hours and clicks **Approve and run now**. r360 sends it to Defender as that person.')),
      el('li', {}, ...rich(el, 'Watch the status on the request. When an isolation or app restriction is no longer needed, ask for the release from the same card.')),
      el('li', {}, ...rich(el, 'Follow up with a slow-path remediation if the problem could come back.'))),
    p('Live response (running a script on the PC right now) is not offered in r360 yet. Use the [Microsoft Defender portal](https://security.microsoft.com/machines) for it, then record what you did in a [Change request](#requests).'),
    el('h2', { textContent: 'A middle option: run one remediation now' }),
    p('Intune can also run an existing remediation on one PC immediately (Run remediation, a preview feature). It still needs everything the slow path needs (join state, license, enrollment, signed scripts), but skips the schedule. r360 does not offer it yet; use the Intune admin center for it.'),
    el('p', { className: 'muted' }, ...rich(el, `Full guide: [fast-or-slow-path.md](${GUIDE_DOCS}/fast-or-slow-path.md). What each PC can use: [What works where](#support).`)),
  ];
}

// ---------- What works where ----------
export const JOIN_STATES = [
  ['Entra joined', 'AzureAdJoined : YES, DomainJoined : NO', 'Yes', 'Yes, if licensed'],
  ['Entra hybrid joined', 'AzureAdJoined : YES, DomainJoined : YES', 'Yes', 'Yes, if licensed'],
  ['Entra registered (work account added to a personal PC)', 'WorkplaceJoined : YES only', 'No. Microsoft requires joined or hybrid joined.', 'Yes, if licensed'],
  ['Active Directory domain joined only', 'DomainJoined : YES, AzureAdJoined : NO', 'No. Sync the computer to Entra so it becomes hybrid joined first.', 'Yes, if licensed (onboard with Group Policy)'],
  ['Not joined to anything (workgroup)', 'All three NO', 'No', 'Yes, if licensed (onboard with the local script)'],
];

export const LICENSES = [
  ['No Microsoft 365 license (Windows Pro only)', 'No', 'None. Only the free Defender Antivirus, which has no remote control.'],
  ['Office 365 E1, E3 or E5', 'No. Office 365 has no Intune and no Windows Enterprise.', 'None. Office 365 E5 protects email and files, not PCs.'],
  ['Microsoft 365 Business Basic or Standard', 'No', 'None'],
  ['Microsoft 365 Business Premium', 'No. It has Intune but not Windows Enterprise E3, so Microsoft blocks Remediations. Add Windows E3 to fix that.', 'Defender for Business: isolate and scan. No stop and quarantine.'],
  ['Intune Plan 1 or EMS E3 alone', 'No (no Windows Enterprise E3)', 'None'],
  ['Microsoft 365 F3', 'Yes', 'None, unless Defender for Endpoint is added'],
  ['Microsoft 365 E3, or Windows Enterprise E3 plus Intune', 'Yes', 'Defender for Endpoint Plan 1: isolate, scan, stop and quarantine.'],
  ['Microsoft 365 E5, or E3 plus Defender for Endpoint Plan 2', 'Yes', 'Everything on the Emergency page, including investigation packages and restricting app execution.'],
  ['Microsoft 365 A3 / A5, Windows VDA per user', 'Yes', 'As E3 (A3) or E5 (A5)'],
];

export const MATRIX_COLS = ['Entra joined', 'Hybrid joined', 'Entra registered', 'AD joined only', 'Not joined'];
export const MATRIX = [
  ['No license, Office 365, Business Basic/Standard', ['none', 'none', 'none', 'none', 'none']],
  ['Business Premium', ['fast', 'fast', 'fast', 'fast', 'fast']],
  ['M365 E3 / F3 / A3, Windows E3', ['both', 'both', 'fast', 'fast', 'fast']],
  ['M365 E5 / A5', ['both', 'both', 'fast', 'fast', 'fast']],
];
const CELL = { none: ['Nothing', 'bad'], fast: ['Fast path only', 'warn'], both: ['Both paths', 'ok'] };

export const ENTRA_LICENSES = [
  ['Entra ID Free', 'Enough to Entra join or hybrid join a PC. PCs must then be enrolled in Intune by hand (Company Portal), because automatic enrollment needs P1.'],
  ['Entra ID P1', 'Turns on automatic Intune enrollment when a PC joins, plus Conditional Access and dynamic groups. Included in every Microsoft 365 suite above, not in Office 365.'],
  ['Entra ID P2', 'Adds Privileged Identity Management (PIM). r360 checks that your Intune Administrator role is active before writes; with PIM, operators turn that role on only when needed. Not required, but recommended for anyone who can publish.'],
];

export function supportPage({ el, pill }) {
  const p = text => el('p', {}, ...rich(el, text));
  const tbl = (head, rows) => el('div', { className: 'tablewrap guide-table' }, el('table', {},
    el('thead', {}, el('tr', {}, ...head.map(h => el('th', { scope: 'col', textContent: h })))),
    el('tbody', {}, ...rows.map(r => el('tr', {}, el('th', { scope: 'row', textContent: r[0] }), ...r.slice(1).map(c => el('td', {}, c)))))));
  const matrix = tbl(['License of the PC\'s user', ...MATRIX_COLS], MATRIX.map(([lic, cells]) => [lic, ...cells.map(c => pill(CELL[c][0], CELL[c][1]))]));
  return [
    el('h1', { textContent: 'What works where' }),
    el('p', { className: 'guide-lead', textContent: 'What r360 can do on a PC depends on two things: how the PC is joined, and which license its user has. Missing either one can make a PC invisible to the slow path.' }),
    el('h2', { textContent: 'The short answer' }),
    matrix,
    el('ul', { className: 'guide-notes' },
      el('li', {}, ...rich(el, '**Both paths** needs a joined or hybrid joined PC **and** a Windows Enterprise E3-class license (in Microsoft 365 E3, E5, F3, A3, A5 or Windows VDA). Missing either one, the slow path cannot reach that PC.')),
      el('li', {}, ...rich(el, '**The fast path ignores join state.** Any PC can be onboarded to Defender. Only the license matters.')),
      el('li', {}, ...rich(el, '**Business Premium is the common trap.** It includes Intune, so it looks like it should work, but it lacks Windows Enterprise E3. Add Windows E3 to those users to unlock the slow path.')),
      el('li', {}, ...rich(el, '**Office 365 is not Microsoft 365.** Office 365 E1/E3/E5 cover email, Teams and Office apps. They give r360 nothing on PCs.')),
      el('li', {}, ...rich(el, '**Everything not on a PC works for everyone:** Change requests, ServiceNow search, Deployments and Audit do not depend on any device license.'))),
    el('h2', { textContent: 'Step 1: how is the PC joined?' }),
    p('On the PC, run `dsregcmd /status` in PowerShell and compare the lines below.'),
    tbl(['Join state', 'What dsregcmd shows', 'Slow path (Intune)', 'Fast path (Defender)'], JOIN_STATES),
    el('h2', { textContent: 'Step 2: what license does the user have?' }),
    tbl(['License', 'Slow path (Intune Remediations)', 'Fast path (Defender actions)'], LICENSES),
    el('h2', { textContent: 'Where Entra ID licenses fit' }),
    el('dl', { className: 'guide-terms' }, ...ENTRA_LICENSES.flatMap(([k, v]) => [el('dt', { textContent: k }), el('dd', { textContent: v })])),
    el('h2', { textContent: 'And every slow-path PC also needs' }),
    el('ul', {},
      el('li', { textContent: 'Windows 10 or 11 Pro, Enterprise or Education (not Home, not S mode).' }),
      el('li', { textContent: 'Enrollment in Intune, and a recent check-in.' }),
      el('li', {}, ...rich(el, 'Both r360 code-signing certificate profiles. r360 adds them automatically with every publish; see [Certificates](#certificates).')),
      el('li', { textContent: 'Membership in a group the remediation is assigned to: the canary group first, then the promoted groups.' })),
    el('p', { className: 'muted' }, ...rich(el, `Full reference with the PowerShell to check a user and a PC: [whats-supported.md](${GUIDE_DOCS}/whats-supported.md) and [device-requirements.md](${GUIDE_DOCS}/device-requirements.md).`)),
  ];
}

// ---------- Licenses by feature ----------
// One row per r360 feature: what the tenant (or another service) must have, and what the person using the feature must
// have. Sources: Microsoft Learn (Remediations prerequisites, Intune unlicensed admins, shared mailboxes, Defender response
// actions, Key Vault tiers) and GitHub Docs (rulesets, deployment environments), checked 2026-11-16.
export const FEATURE_LICENSES = [
  ['Sign in and read pages (Overview, Remediations, Fleet, Certificates, Audit)', 'Entra ID (Free is enough). An Intune subscription for there to be anything to read.',
    'A work account in the tenant and an Intune role that can read (Intune Administrator or a read-only Intune role). Admins do not need an Intune license themselves.'],
  ['Changes: write or edit a remediation', 'GitHub. If the remediations repository is private, the rulesets that force a review need GitHub Pro (personal account) or GitHub Team (organization). On a public repository GitHub Free is enough.',
    'A GitHub account with write access to the remediations repository, and the author role in r360.'],
  ['Signing: every script signed in CI before it can reach a PC', 'Azure pay-as-you-go: Key Vault Premium, because the signing key is a non-exportable HSM key. GitHub Actions minutes (included in every GitHub plan, free on public repositories).',
    'Nothing. CI signs as its own identity; no person ever holds the key.'],
  ['Publish to canary and promote (the slow path)', 'Intune. Each target PC must be Entra joined or hybrid joined, and its user needs Windows Enterprise E3 or E5 (in Microsoft 365 E3, E5, F3, A3, A5 or Windows VDA). Business Premium alone is not enough.',
    'The approver role in r360 and an active Intune Administrator role. A second person approves (four-eyes).'],
  ['Emergency: Defender actions on one device (the fast path)', 'Defender for Endpoint Plan 1 or Plan 2, or Defender for Business (in Business Premium, or bought on its own for up to 300 users). The PC must be onboarded to Defender; how it is joined does not matter.',
    'Requester: the author, emergencyApprover or admin role. Approver: the emergencyApprover role, plus a Defender role with "Active remediation actions" that covers the device\'s device group.'],
  ['Change requests: email-tracked changes', 'Exchange Online for the shared change mailbox (a shared mailbox needs no license up to 50 GB) and GitHub for the change issues. AI summaries need an Anthropic API key, billed per use.',
    'A licensed Exchange Online mailbox of their own (any Microsoft 365 or Office 365 plan with Exchange) and Full Access to the shared mailbox.'],
  ['ServiceNow search', 'A ServiceNow instance. Licensing is between you and ServiceNow; r360 only reads.',
    'Nothing extra in r360. The ServiceNow account r360 is configured with needs read access to the tables you search.'],
  ['Deployments: Terraform through GitHub Actions', 'GitHub Actions and an environment per target. On a private repository, an environment with required reviewers needs GitHub Enterprise; Free, Pro and Team get that only on public repositories. r360 does not need a second reviewer here (four-eyes is off for this lane).',
    'The approver or admin role in r360 and write access to the target repository.'],
  ['Audit trail', 'Azure pay-as-you-go: one Storage account (append-only table and an immutable blob container). It costs cents a month.',
    'Nothing. Every signed-in person can read the audit trail; nobody can change it.'],
  ['Settings and Privileged Identity Management', 'Nothing for Settings. PIM (turning the Intune Administrator role on only when needed) needs Entra ID P2 or Entra ID Governance. Optional, but recommended for anyone who can publish.',
    'The admin role in r360 for Settings. With PIM, an eligible Intune Administrator assignment.'],
];

// What to buy for each FEATURE_LICENSES row (same order), the tiers that do the job cheapest first, and an estimated cost.
// US list prices per user per month on an annual commitment, read from Microsoft's and GitHub's pricing pages on
// 2026-11-16 (Microsoft prices effective July 1, 2026). Defender for Endpoint P1/P2 are not priced on Microsoft's site;
// those two are the usual partner list prices. Azure figures are estimates for r360's small footprint.
export const PRICES_CHECKED = '2026-11-16';
export const FEATURE_COSTS = [
  ['Sign in', 'Nothing per operator. The company needs Intune once, in any plan below.',
    ['Entra ID Free: included with any Microsoft 365 or Azure subscription', 'Intune Plan 1: $8, or already in Business Premium / Microsoft 365 E3'],
    '$0 per operator (Intune admins need no license of their own)'],
  ['Changes', 'GitHub Team for the organization (the remediations repository is private).',
    ['GitHub Free: $0, only if the repository is public', 'GitHub Team: $4 per user', 'GitHub Enterprise: $21 per user (not needed for this)'],
    '$0 to $4 per author'],
  ['Signing', 'An Azure subscription (pay as you go) with a Key Vault on the Premium tier.',
    ['Key Vault Premium: the only Key Vault tier that holds HSM keys', 'GitHub Actions minutes: included (3,000 a month on Team)'],
    'About $1 to $10 a month for the whole company (one HSM key plus signing operations)'],
  ['Publish', 'For each PC user: Windows Enterprise E3 plus Intune, bundled or bought separately.',
    ['Microsoft 365 F3: $10 (frontline workers only)', 'Windows E3 + Intune Plan 1: $15.63 ($7.63 + $8; add Entra ID P1 at $7 for automatic enrollment)', 'Business Premium + Windows E3: $29.63 ($22 + $7.63; also brings Defender for Business)', 'Microsoft 365 E3: $39 (also brings Defender for Endpoint P1)', 'Microsoft 365 E5: $60'],
    '$10 to $39 per PC user'],
  ['Emergency', 'Defender for Endpoint, or Defender for Business if you have 300 users or fewer, for each user whose PC you want to act on.',
    ['Defender for Business: $3 (up to 300 users; no stop and quarantine)', 'Defender for Endpoint Plan 1: about $3', 'Defender for Endpoint Plan 2: about $5.20 (all actions)', 'Already included: Business Premium (Defender for Business), Microsoft 365 E3 (P1), Microsoft 365 E5 (P2)'],
    '$3 to $5.20 per protected user, or $0 extra if a suite above already includes it'],
  ['Change requests', 'An Office 365 or Microsoft 365 plan with an Exchange mailbox for each operator. The shared mailbox itself is free.',
    ['Exchange Online Plan 1: $4 (mailbox only)', 'Microsoft 365 Business Basic: $7', 'Office 365 E1: $10', 'Any bigger Microsoft 365 or Office 365 plan already includes it', 'AI summaries: Anthropic API, billed per use'],
    '$4 to $10 per operator, plus a few cents per summary'],
  ['ServiceNow', 'A ServiceNow subscription (not from Microsoft).',
    ['ServiceNow does not publish prices; it quotes each customer'],
    'Quote from ServiceNow'],
  ['Deployments', 'GitHub (the same organization as Changes) and an Azure subscription for what Terraform deploys.',
    ['GitHub Free: $0, only if the target repository is public', 'GitHub Team: $4 per user', 'GitHub Enterprise: $21 per user, only if you want required reviewers on a private repository'],
    '$0 to $4 per user (r360 does not need Enterprise)'],
  ['Audit', 'An Azure subscription (pay as you go) with one Storage account.',
    ['Storage account, Standard locally redundant: the cheapest tier is enough'],
    'Under $1 a month for the whole company'],
  ['Settings', 'Entra ID P2 for each admin who uses PIM, or the Entra ID Governance add-on if you already have P1.',
    ['Nothing: PIM is optional', 'Entra ID Governance add-on: $7 (needs P1, which Business Premium and Microsoft 365 E3 include)', 'Entra ID P2: $10', 'Microsoft 365 E5: includes P2'],
    '$0, or $7 to $10 per admin who uses PIM'],
];

export const DEFENDER_ACTION_PLANS = [
  ['Isolate and release', 'Yes', 'Yes', 'Yes'],
  ['Run antivirus scan', 'Yes', 'Yes', 'Yes'],
  ['Stop and quarantine a file', 'Yes', 'No', 'Yes'],
  ['Collect investigation package', 'No', 'No', 'Yes'],
  ['Restrict app execution and remove it', 'No', 'No', 'Yes'],
];

export function licensesPage({ el }) {
  const tbl = (head, rows) => el('div', { className: 'tablewrap guide-table' }, el('table', {},
    el('thead', {}, el('tr', {}, ...head.map(h => el('th', { scope: 'col', textContent: h })))),
    el('tbody', {}, ...rows.map(r => el('tr', {}, el('th', { scope: 'row', textContent: r[0] }), ...r.slice(1).map(c => el('td', {}, ...rich(el, c))))))));
  return [
    el('h1', { textContent: 'Licenses by feature' }),
    el('p', { className: 'guide-lead', textContent: 'Each part of r360 leans on a different product. This page says, feature by feature, what the company must pay for and what the person using the feature must have. Turn on only the features you have licenses for; the rest of r360 keeps working.' }),
    el('div', { className: 'tablewrap guide-table guide-table-wide' }, el('table', {},
      el('thead', {}, el('tr', {}, ...['r360 feature', 'What to buy', 'Tiers, cheapest first', 'Estimated cost per month', 'The company needs', 'The person using it needs'].map(h => el('th', { scope: 'col', textContent: h })))),
      el('tbody', {}, ...FEATURE_LICENSES.map((r, i) => {
        const [, buy, tiers, cost] = FEATURE_COSTS[i];
        return el('tr', {}, el('th', { scope: 'row', textContent: r[0] }), el('td', { textContent: buy }),
          el('td', {}, el('ol', { className: 'guide-tiers' }, ...tiers.map(t => el('li', { textContent: t })))), el('td', { className: 'guide-cost', textContent: cost }),
          el('td', {}, ...rich(el, r[1])), el('td', {}, ...rich(el, r[2])));
      })))),
    el('p', { className: 'muted' }, ...rich(el, `Prices are estimates: US list prices per user per month on an annual commitment, from Microsoft's and GitHub's pricing pages on ${PRICES_CHECKED} (Microsoft's July 2026 prices). Defender for Endpoint Plan 1 and Plan 2 are not priced on Microsoft's site, so those are typical partner prices. Azure costs depend on use. Your agreement or reseller may charge differently.`)),
    el('h2', { textContent: 'Which Defender plan allows which emergency action' }),
    el('p', {}, ...rich(el, 'The Emergency page shows every action and marks the ones your plan lacks. Defender refuses an action the plan does not include, and r360 records the refusal.')),
    tbl(['Action', 'Defender for Endpoint P1', 'Defender for Business', 'Defender for Endpoint P2'], DEFENDER_ACTION_PLANS),
    el('h2', { textContent: 'What you can skip' }),
    el('ul', { className: 'guide-notes' },
      el('li', {}, ...rich(el, '**No Defender license?** The readiness check on the Emergency page says so, and Defender refuses every action. The slow path is unaffected.')),
      el('li', {}, ...rich(el, '**No Windows Enterprise E3?** The slow path cannot reach those PCs. See [What works where](#support) for the fix.')),
      el('li', {}, ...rich(el, '**No ServiceNow or Anthropic key?** Those pages say they are not configured. Nothing else depends on them.')),
      el('li', {}, ...rich(el, '**No Entra ID P2?** r360 still checks that your Intune Administrator role is active before every write. You just cannot make the role time-limited.'))),
    el('p', { className: 'muted' }, ...rich(el, `Full reference with sources: [licenses-by-feature.md](${GUIDE_DOCS}/licenses-by-feature.md).`)),
  ];
}

export function createGuideUi({ el, pill, view }) {
  const show = build => view().replaceChildren(el('div', { className: 'guide' }, ...build({ el, pill })));
  return { overview: () => show(overviewPage), paths: () => show(pathsPage), support: () => show(supportPage), licenses: () => show(licensesPage) };
}
