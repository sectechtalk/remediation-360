// Four-eyes, as one pure function so the rules are tested in one place and cannot drift between routes.
//
// testing:  the author may approve their own change. It is allowed but never silent: the caller records selfApproved = true in the
//           audit trail, comments on the pull request and the UI shows it.
// enforced: the approver must be a different Entra object id from the author, and so must the publisher. A self approval that
//           was recorded while the mode was "testing" is not accepted for a merge once the mode is "enforced".
//
// Anything unknown (mode, step, missing id) is denied. Roles (who holds "approver") are checked by the caller against
// approvers.json; this function only answers the "same person?" question.
export const MODES = ['testing', 'enforced'];
export const STEPS = ['approve', 'merge', 'publish', 'promote'];

const norm = v => String(v ?? '').trim().toLowerCase();
export const samePerson = (a, b) => !!norm(a) && norm(a) === norm(b);

export function fourEyes({ mode, step, authorOid, actorOid, approval = null }) {
  const deny = (reason, message) => ({ allowed: false, selfApproved: false, reason, message });
  if (!MODES.includes(mode)) return deny('unknown-mode', 'The four-eyes mode is not recognised, so this is refused.');
  if (!STEPS.includes(step)) return deny('unknown-step', 'The step is not recognised, so this is refused.');
  if (!norm(authorOid) || !norm(actorOid)) return deny('unknown-person', 'The author or the actor could not be identified, so this is refused.');
  const same = samePerson(authorOid, actorOid);
  if (step === 'approve') {
    if (same && mode === 'enforced') return deny('author-cannot-approve', 'You authored this change, so a different approver must approve it (four-eyes is enforced).');
    return { allowed: true, selfApproved: same, reason: same ? 'self-approval-testing' : 'ok', message: same ? 'Self-approval is allowed in testing mode and is audited.' : '' };
  }
  if (step === 'merge') {
    if (!approval || !norm(approval.approverOid)) return deny('not-approved', 'This change has no approval for its current commit.');
    const self = samePerson(authorOid, approval.approverOid);
    if (self && mode === 'enforced') return deny('self-approval-not-valid', 'The only approval was given by the author, which does not count while four-eyes is enforced. A different approver must approve.');
    return { allowed: true, selfApproved: self, reason: self ? 'self-approval-testing' : 'ok', message: '' };
  }
  if (step === 'promote') {
    // authorOid is the author of the change being promoted; the promoter proposes moving it from the canary group to production.
    if (same && mode === 'enforced') return deny('promoter-must-differ', 'The promoter must be a different person from the author of the change (four-eyes is enforced).');
    return { allowed: true, selfApproved: same, reason: same ? 'self-promote-testing' : 'ok', message: same ? 'Self-promotion is allowed in testing mode and is audited.' : '' };
  }
  // publish
  if (same && mode === 'enforced') return deny('publisher-must-differ', 'The publisher must be a different person from the author (four-eyes is enforced).');
  return { allowed: true, selfApproved: same, reason: same ? 'self-publish-testing' : 'ok', message: '' };
}
