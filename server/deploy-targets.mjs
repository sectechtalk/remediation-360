// R360_DEPLOY_TARGETS: the deployment targets r360 shows in the Deployments lane. A JSON document, or the same JSON
// base64-encoded (what tools/Set-R360DeployTargets.ps1 writes, so shell quoting cannot break it). Invalid stops the app.
//
// { "version": 1, "targets": [ { "id": "f360-lab", "name": "Federation 360 lab", "repo": "your-org/f-360", "branch": "main",
//     "workflow": "lab.yml", "environment": "lab", "tenantId": "<guid>", "path": "lab/terraform" } ] }
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ID = /^[a-z0-9][a-z0-9-]{1,39}$/;
const REPO = /^[A-Za-z0-9-]{1,39}\/[A-Za-z0-9._-]{1,100}$/;
const WORKFLOW = /^[A-Za-z0-9._-]{1,100}\.ya?ml$/;
const BRANCH = /^(?!.*\.\.)(?!\/)[A-Za-z0-9._/-]{1,100}(?<!\/)$/;
const ENVIRONMENT = /^[A-Za-z0-9._ -]{1,64}$/;
const PATH = /^(?!.*\.\.)[A-Za-z0-9._/-]{1,200}$/;
const KEYS = ['id', 'name', 'repo', 'branch', 'workflow', 'environment', 'tenantId', 'path'];
export const MAX_TARGETS = 20;

export const sameOwner = (a, b) => typeof a === 'string' && typeof b === 'string' && a.split('/')[0].toLowerCase() === b.split('/')[0].toLowerCase() && a.split('/').length === 2;

export function decodeDeployTargets(raw) {
  const v = String(raw || '').trim();
  if (!v) return '';
  if (v.startsWith('{')) return v;
  if (!/^[A-Za-z0-9+/=_-]+$/.test(v)) throw new Error('R360_DEPLOY_TARGETS must be JSON or base64-encoded JSON');
  return Buffer.from(v, 'base64').toString('utf8');
}

export function parseDeployTargets(text, { owner } = {}) {
  let j;
  try { j = JSON.parse(text); } catch (e) { throw new Error(`R360_DEPLOY_TARGETS is not valid JSON: ${e.message}`); }
  if (j?.version !== 1 || !Array.isArray(j.targets)) throw new Error('R360_DEPLOY_TARGETS: expected { version: 1, targets: [] }');
  if (j.targets.length > MAX_TARGETS) throw new Error(`R360_DEPLOY_TARGETS: at most ${MAX_TARGETS} targets`);
  const seen = new Set();
  return j.targets.map((t, i) => {
    const at = `R360_DEPLOY_TARGETS: target ${i}`;
    if (!t || typeof t !== 'object' || Array.isArray(t)) throw new Error(`${at} is not an object`);
    const extra = Object.keys(t).filter(k => !KEYS.includes(k));
    if (extra.length) throw new Error(`${at} has unknown field(s) ${extra.join(', ')}`);
    if (!ID.test(t.id || '')) throw new Error(`${at} needs an id (lowercase letters, digits and dashes)`);
    if (seen.has(t.id)) throw new Error(`R360_DEPLOY_TARGETS: duplicate id ${t.id}`);
    seen.add(t.id);
    if (!REPO.test(t.repo || '')) throw new Error(`${at} (${t.id}) needs repo as owner/name`);
    if (owner && t.repo.split('/')[0].toLowerCase() !== owner.toLowerCase()) throw new Error(`${at} (${t.id}): repo must belong to ${owner}, the owner the r360 GitHub App is installed on`);
    if (!WORKFLOW.test(t.workflow || '')) throw new Error(`${at} (${t.id}) needs workflow as a file name in .github/workflows, such as deploy.yml`);
    const branch = t.branch ?? 'main';
    if (!BRANCH.test(branch)) throw new Error(`${at} (${t.id}) has an invalid branch`);
    if (!ENVIRONMENT.test(t.environment || '')) throw new Error(`${at} (${t.id}) needs environment, the GitHub environment the apply job runs in`);
    if (t.tenantId != null && !GUID.test(t.tenantId)) throw new Error(`${at} (${t.id}): tenantId must be a GUID`);
    if (t.path != null && !PATH.test(t.path)) throw new Error(`${at} (${t.id}) has an invalid path`);
    if (t.name != null && (typeof t.name !== 'string' || t.name.length > 80)) throw new Error(`${at} (${t.id}): name must be text of at most 80 characters`);
    return Object.freeze({ id: t.id, name: (t.name || t.id).replace(/[\u0000-\u001f<>]/g, ' ').trim(), repo: t.repo, branch, workflow: t.workflow, environment: t.environment,
      tenantId: t.tenantId ? t.tenantId.toLowerCase() : null, path: t.path || null });
  });
}
