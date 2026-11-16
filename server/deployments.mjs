import { randomUUID } from 'node:crypto';
import { ChangeError } from './changes.mjs';

// Deployments lane. r360 is the control plane and GitHub Actions does the running:
//   - A change is a pull request on the target repository. The target's deploy workflow posts the Terraform plan on it.
//   - Merging (from r360 or GitHub) pushes to the target branch, which starts the apply job behind the target's GitHub environment.
//   - A scheduled plan with -detailed-exitcode flags drift.
//   - r360 shows run status, links the logs, records each finished run in the audit trail, and can merge and start runs.
// Four-eyes is OFF for this lane (the owner's decision, 2026-11-12): a merge needs a write session, the approver or admin role
// and a successful plan for the exact head commit, but not a second person. Device remediations keep the Intune lane.
export const DEPLOY_FOUR_EYES = 'off';
export const DEPLOY_ACTIONS = ['deploy.merged', 'deploy.dispatched', 'deploy.run'];
export const DISPATCH_MODES = ['plan', 'drift'];
export const DRIFT_STEP = 'Drift detected';
const GITHUB = 'https://github.com';
const RUN_HISTORY_DAYS = 30;
const SYNC_BUDGET = 25;

// What kind of run this is. The reusable workflow sets run-name "r360:<kind> ..."; otherwise the trigger decides.
export function runKind(run) {
  const m = /^r360:(plan|apply|drift)\b/.exec(run?.title || '');
  if (m) return m[1];
  return { pull_request: 'plan', push: 'apply', schedule: 'drift' }[run?.event] || 'manual';
}

// A drift run fails its "Drift detected" step when the plan has changes (exit code 2). Any other failure is an error.
export function driftOf(run, jobs) {
  if (!run) return 'never';
  if (run.status !== 'completed') return 'running';
  if (run.conclusion === 'success') return 'clean';
  const steps = (jobs || []).flatMap(j => j.steps || []);
  if (steps.some(s => String(s.name).toLowerCase() === DRIFT_STEP.toLowerCase() && s.conclusion === 'failure')) return 'drift';
  return run.conclusion === 'cancelled' ? 'cancelled' : 'error';
}

// One word for a run's state, the same for every kind.
export function outcomeOf(run) {
  if (!run) return 'none';
  if (run.status === 'waiting') return 'waiting';
  if (run.status !== 'completed') return 'running';
  return { success: 'succeeded', failure: 'failed', cancelled: 'cancelled', timed_out: 'failed', action_required: 'waiting', skipped: 'skipped' }[run.conclusion] || 'failed';
}

// The plan run for one pull request head: the newest plan-kind run on that exact commit.
export function planRunFor(runs, pr) {
  return (runs || []).filter(r => runKind(r) === 'plan' && r.headSha === pr.headSha).sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt))[0] || null;
}

// Whether r360 may merge this pull request (four-eyes off). Every reason is shown to the operator as is.
export function mergeBlock({ target, pr, planRun, plan }) {
  if (pr.state !== 'open' || pr.merged) return 'The pull request is not open.';
  if (pr.draft) return 'The pull request is a draft.';
  if (pr.base !== target.branch) return `The pull request does not target ${target.branch}.`;
  if (!pr.sameRepo) return 'Pull requests from forks are not deployed through r360.';
  if (!planRun) return 'No plan has run on the current commit yet.';
  if (planRun.status !== 'completed') return 'The plan is still running.';
  if (planRun.conclusion !== 'success') return 'The plan failed. Fix it and push again.';
  if (!plan) return 'The plan comment is missing on the pull request.';
  if (plan.sha !== pr.headSha) return 'The plan comment is for an older commit.';
  return null;
}

const runKey = r => `${r.id}.${r.attempt || 1}`;
const auditResult = c => (c === 'success' ? 'ok' : String(c || 'unknown'));

export function createDeployments({ config, github, audit, now = () => Date.now(), log = console }) {
  const must = (cond, status, msg) => { if (!cond) throw new ChangeError(status, msg); };
  const who = u => ({ actorOid: u.oid, actorUpn: u.upn, mode: DEPLOY_FOUR_EYES });
  const intent = async (user, event) => {
    try { await audit.record({ ...who(user), ...event, result: 'intent' }); }
    catch (e) { log.error?.(`${event.action}: audit intent failed: ${e.message}`); throw new ChangeError(503, 'The audit trail is unavailable, so nothing was changed.'); }
  };
  const result = async (user, event) => {
    try { await audit.record({ ...who(user), ...event }); return null; }
    catch (e) { log.error?.(`${event.action}: audit result failed: ${e.message}`); return 'The action was done but its result row could not be written to the audit trail.'; }
  };
  const mapGithub = (e, what) => {
    if (e.status === 409 || e.status === 405) return new ChangeError(409, `GitHub refused the ${what}: ${String(e.message).replace(/^GitHub \S+ \S+ failed: /, '').slice(0, 200)}`);
    if (e.permission || e.status === 403 || e.status === 404) return new ChangeError(502, `GitHub refused the ${what}. Check that the r360 GitHub App is installed on the target repository with ${what === 'workflow run' ? 'actions: write' : 'contents: write and pull requests: write'}.`);
    return new ChangeError(502, `GitHub could not complete the ${what}.`);
  };
  const strictKeys = (body, keys) => {
    must(body && typeof body === 'object' && !Array.isArray(body), 400, 'The request body must be an object.');
    const extra = Object.keys(body).filter(k => !keys.includes(k));
    must(!extra.length, 400, `Unknown field(s): ${extra.join(', ')}`);
  };
  const needRoles = (roles, allowed, what) => must((roles || []).some(r => allowed.includes(r)), 403, `Your role does not allow you to ${what}.`);

  async function targets() { return config.deployTargets || []; }
  async function targetOf(id) {
    const t = (await targets()).find(x => x.id === id);
    must(t, 404, 'No such deployment target.');
    return t;
  }

  // Every finished run is recorded once in the audit trail, keyed by run id and attempt. Runs happen in GitHub, so r360
  // records them when it next looks (opening the Deployments page). The actor is GitHub Actions; the person who started
  // the run is in actorUpn as github:<login>. One sync at a time per replica.
  const syncing = new Map();
  async function syncAudit(t, runs, driftCache) {
    const done = runs.filter(r => r.status === 'completed' && now() - Date.parse(r.updatedAt || r.createdAt) < RUN_HISTORY_DAYS * 86400000);
    if (!done.length) return { recorded: 0 };
    const seen = new Set((await audit.list({ from: now() - (RUN_HISTORY_DAYS + 5) * 86400000, to: now(), actions: ['deploy.run'], target: `deploy/${t.id}`, limit: 2000 })).rows.filter(r => r.target === `deploy/${t.id}`).map(r => r.runId).filter(Boolean));
    let recorded = 0;
    for (const r of done.reverse()) {
      if (seen.has(runKey(r)) || recorded >= SYNC_BUDGET) continue;
      const kind = runKind(r);
      let drift;
      if (kind === 'drift') drift = driftCache.get(r.id) ?? driftOf(r, await github.deployRunJobs(t.repo, r.id).catch(() => null));
      await audit.record({ actorOid: 'github-actions', actorUpn: `github:${r.actor || 'unknown'}`, action: 'deploy.run', result: auditResult(r.conclusion), target: `deploy/${t.id}`,
        gitSha: r.headSha, prNumber: r.pullNumbers[0], runId: runKey(r), reason: kind, mode: DEPLOY_FOUR_EYES,
        detail: { kind, event: r.event, conclusion: r.conclusion, url: r.url, repo: t.repo, workflow: t.workflow, environment: t.environment, attempt: r.attempt, startedAt: r.startedAt, finishedAt: r.updatedAt, ...(drift ? { drift } : {}) } });
      seen.add(runKey(r));
      recorded++;
    }
    return { recorded };
  }

  async function oneTarget(t) {
    const base = { id: t.id, name: t.name, repo: t.repo, repoUrl: `${GITHUB}/${t.repo}`, branch: t.branch, workflow: t.workflow, workflowUrl: `${GITHUB}/${t.repo}/actions/workflows/${t.workflow}`,
      environment: t.environment, tenantId: t.tenantId, path: t.path, fourEyes: DEPLOY_FOUR_EYES };
    let runs, pulls;
    try { [runs, pulls] = await Promise.all([github.deployRuns(t.repo, t.workflow), github.deployPulls(t.repo, t.branch)]); }
    catch (e) {
      log.error?.(`deployments ${t.id}: ${e.message}`);
      return { ...base, error: e.permission ? 'The r360 GitHub App cannot read this repository. Install it on the repository with actions, contents, pull requests and checks read.' : 'GitHub could not be read for this target.', runs: [], changes: [], lastApply: null, drift: { state: 'unknown' } };
    }
    const driftCache = new Map();
    const latest = kind => runs.filter(r => runKind(r) === kind).sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
    const applies = latest('apply'), drifts = latest('drift');
    const lastApply = applies[0] ? { state: outcomeOf(applies[0]), at: applies[0].updatedAt, url: applies[0].url, sha: applies[0].headSha, actor: applies[0].actor } : null;
    let drift = { state: 'never' };
    if (drifts[0]) {
      const d = drifts[0];
      const jobs = d.status === 'completed' && d.conclusion !== 'success' ? await github.deployRunJobs(t.repo, d.id).catch(() => null) : null;
      const state = driftOf(d, jobs);
      driftCache.set(d.id, state);
      drift = { state, at: d.updatedAt, url: d.url, sha: d.headSha };
    }
    const changes = [];
    // Only pull requests the deploy workflow has planned are deployment changes (its path filter decides which PRs those are).
    const planned = pr => runs.some(r => runKind(r) === 'plan' && (r.pullNumbers.includes(pr.number) || r.headSha === pr.headSha));
    for (const pr of pulls.filter(planned).slice(0, 10)) {
      const planRun = planRunFor(runs, pr);
      let plan = null;
      if (planRun) plan = await github.deployPlanComment(t.repo, pr.number).catch(() => null);
      const blocked = mergeBlock({ target: t, pr, planRun, plan });
      changes.push({ number: pr.number, title: pr.title, url: pr.url, author: pr.author, headSha: pr.headSha, branch: pr.branch, draft: pr.draft, updatedAt: pr.updatedAt,
        plan: { state: planRun ? outcomeOf(planRun) : 'none', runUrl: planRun?.url || null, counts: plan && plan.sha === pr.headSha ? { add: plan.add, change: plan.change, destroy: plan.destroy, noChanges: plan.noChanges } : null, commentUrl: plan?.url || null, forHead: !!plan && plan.sha === pr.headSha },
        canMerge: !blocked, blockedReason: blocked });
    }
    let auditNote = null;
    try {
      if (!syncing.has(t.id)) syncing.set(t.id, syncAudit(t, runs, driftCache).finally(() => syncing.delete(t.id)));
      await syncing.get(t.id);
    } catch (e) { auditNote = 'Finished runs could not be recorded in the audit trail right now.'; log.error?.(`deployments ${t.id}: audit sync: ${e.message}`); }
    return { ...base, error: null, auditNote, lastApply, drift, changes,
      runs: runs.slice(0, 20).map(r => ({ id: r.id, kind: runKind(r), outcome: outcomeOf(r), status: r.status, conclusion: r.conclusion, event: r.event, actor: r.actor, headSha: r.headSha, url: r.url, startedAt: r.startedAt, updatedAt: r.updatedAt, pullNumbers: r.pullNumbers, attempt: r.attempt })) };
  }

  let cache = null;
  return {
    async list() {
      if (cache && now() - cache.at < 10000) return cache.value;
      const ts = await targets();
      const out = [];
      for (const t of ts) out.push(await oneTarget(t));
      const value = { targets: out, fourEyes: DEPLOY_FOUR_EYES };
      cache = { at: now(), value };
      return value;
    },

    // Merge a deployment pull request. GitHub then runs the apply on the target branch, behind the target's environment.
    async merge(user, roles, targetId, number, body) {
      strictKeys(body, ['headSha']);
      needRoles(roles, ['approver', 'admin'], 'merge deployment changes');
      must(Number.isInteger(number) && number > 0, 400, 'Invalid pull request number.');
      must(/^[0-9a-f]{40}$/.test(body.headSha || ''), 400, 'headSha must be the commit you reviewed.');
      const t = await targetOf(targetId);
      const pr = await github.deployPull(t.repo, number);
      must(pr.headSha === body.headSha, 409, 'The pull request changed after you loaded it. Reload and check the new plan.');
      const [runs, plan] = await Promise.all([github.deployRuns(t.repo, t.workflow), github.deployPlanComment(t.repo, number).catch(() => null)]);
      const planRun = planRunFor(runs, pr);
      const blocked = mergeBlock({ target: t, pr, planRun, plan });
      must(!blocked, 409, blocked);
      const requestId = randomUUID();
      const ev = { action: 'deploy.merged', target: `deploy/${t.id}`, requestId, prNumber: number, gitSha: pr.headSha, runId: runKey(planRun) };
      const detail = { repo: t.repo, branch: t.branch, environment: t.environment, planRunUrl: planRun.url, plan: { add: plan.add, change: plan.change, destroy: plan.destroy }, fourEyes: DEPLOY_FOUR_EYES };
      await intent(user, { ...ev, detail });
      const message = [`Merged by ${String(user.upn || user.oid).replace(/[<>\r\n|]/g, '')} through r360 (Deployments lane, four-eyes ${DEPLOY_FOUR_EYES}).`,
        `Plan: ${plan.add} to add, ${plan.change} to change, ${plan.destroy} to destroy (run ${planRun.url}).`, '', `R360-Merged-By-Oid: ${user.oid}`, `R360-Request-Id: ${requestId}`].join('\n');
      let out;
      try { out = await github.mergeDeployPull({ repo: t.repo, number, sha: pr.headSha, title: `${pr.title} (#${number})`, message }); }
      catch (e) {
        log.error?.(`deploy.merged failed: ${e.message}`);
        await result(user, { ...ev, result: 'failed', reason: String(e.message).slice(0, 300), githubRequestId: e.githubRequestId, detail });
        throw mapGithub(e, 'merge');
      }
      cache = null;
      const warning = await result(user, { ...ev, result: 'ok', githubRequestId: out.githubRequestId, detail: { ...detail, mergeSha: out.mergeSha } });
      return { ok: true, number, mergeSha: out.mergeSha, applyUrl: `${GITHUB}/${t.repo}/actions/workflows/${t.workflow}`, ...(warning ? { warning } : {}) };
    },

    // Start a plan or a drift check on the target branch now. Apply is never started this way: it runs only from a merge.
    async dispatch(user, roles, targetId, body) {
      strictKeys(body, ['mode']);
      needRoles(roles, ['author', 'approver', 'admin'], 'start deployment runs');
      must(DISPATCH_MODES.includes(body.mode), 400, `mode must be one of ${DISPATCH_MODES.join(', ')}.`);
      const t = await targetOf(targetId);
      const requestId = randomUUID();
      const ev = { action: 'deploy.dispatched', target: `deploy/${t.id}`, requestId, reason: body.mode, detail: { repo: t.repo, workflow: t.workflow, ref: t.branch, mode: body.mode } };
      await intent(user, ev);
      let out;
      try { out = await github.dispatchDeployWorkflow({ repo: t.repo, workflow: t.workflow, ref: t.branch, inputs: { mode: body.mode } }); }
      catch (e) {
        log.error?.(`deploy.dispatched failed: ${e.message}`);
        await result(user, { ...ev, result: 'failed', reason: String(e.message).slice(0, 300), githubRequestId: e.githubRequestId });
        throw mapGithub(e, 'workflow run');
      }
      cache = null;
      const warning = await result(user, { ...ev, result: 'ok', githubRequestId: out.githubRequestId });
      return { ok: true, mode: body.mode, runsUrl: `${GITHUB}/${t.repo}/actions/workflows/${t.workflow}`, ...(warning ? { warning } : {}) };
    },
  };
}
