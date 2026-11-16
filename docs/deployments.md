# r360 Deployments lane

Status: built 2026-11-12, not yet run against a real target. First target: the Federation 360 lab tenant (`your-org/f-360`, `lab/terraform`).

The Deployments lane is a second lane next to device remediations. It is for configuration that lives as Terraform, such as an
Entra tenant's app registrations, groups and test users. **r360 stays the control plane and GitHub Actions does the running.**
Device remediations keep the existing Intune lane unchanged.

## How it works

```
Pull request on the target repo ──> plan job (GitHub Actions, plan identity) ──> plan comment on the PR with an r360:plan line
        │
        └─ Merge and apply in r360 (or merge in GitHub) ──> push to main ──> apply job in the GitHub environment (apply identity)
Nightly schedule ──> drift job: terraform plan -detailed-exitcode ──> step "Drift detected" fails when the tenant differs
r360 Deployments page ──> target status, open changes with their plan, recent runs with log links; every finished run is audited
```

| Step | Who runs it | What r360 does |
|---|---|---|
| Plan | GitHub Actions on `pull_request` | Shows the plan counts (+add ~change -destroy) and links the comment and logs. |
| Merge | r360 **Merge and apply** button, or GitHub | Checks the plan ran and passed on the exact head commit, audits intent, squash-merges pinned to that commit, audits the result. |
| Apply | GitHub Actions on `push` to the target branch, in the target's GitHub environment | Shows the result and links the logs. |
| Drift | GitHub Actions on `schedule` (or **Check drift now**) | Shows No drift / DRIFT / Check failed. |
| Audit | r360 | Records every finished run once as `deploy.run` (run id and attempt), plus `deploy.merged` and `deploy.dispatched`. |

**Four-eyes is off for this lane** (owner's decision, 2026-11-12). A merge from r360 needs a write session, the `approver` or
`admin` role and a successful plan for the current commit, but not a second person. Starting a plan or drift check needs a write
session and any r360 role. Apply never starts from a button: only a merge starts it.

## What the safety rests on

- **No Entra secrets.** Both identities sign in with GitHub OIDC through federated credentials, the same pattern as `r360-ci-signer`.
- **Two identities per target.**
  - The *plan identity* trusts `pull_request` and `ref:refs/heads/main`. Give it read-only Graph permissions. Anyone who can push
    a branch to the target repo can get its token, so it must not be able to change anything.
  - The *apply identity* trusts only `environment:<environment>`. Give it the permissions Terraform needs.
- **The GitHub environment is the gate.** Set the environment's deployment branches to the target branch only. No required
  reviewers while four-eyes is off; add them later to turn on a second person without changing r360.
- **r360's GitHub App tokens are narrowed** to one target repository and one action each time. The merge is pinned to the
  planned commit, so a push after the plan makes GitHub refuse the merge.
- **No paid services.** Plans and applies run on GitHub-hosted runners. State can live in HCP Terraform's free tier. The target
  tenant needs no Azure subscription or resource group: the azuread provider only talks to Microsoft Graph.

## Set up a target (the Federation 360 lab)

### 1. Identities in the target tenant
Create two app registrations in the lab tenant (or one, if you accept the plan risk above):

| App registration | Federated credential subjects | Graph application permissions |
|---|---|---|
| `f360-lab-plan` | `<prefix>:pull_request`, `<prefix>:ref:refs/heads/main` | `Application.Read.All`, `Group.Read.All`, `User.Read.All` |
| `f360-lab-deployer` | `<prefix>:environment:lab` | what `lab/terraform` needs (the f-360 bootstrap grants it) |

Issuer `https://token.actions.githubusercontent.com`, audience `api://AzureADTokenExchange`. `<prefix>` is what
`tools/Set-R360DeployTargets.ps1` prints. `f-360` was created after 2026-07-15, so GitHub uses the immutable form
`repo:sectechtalk@<owner id>/f-360@<repo id>`; a name-form subject would not match.

### 2. GitHub settings
- `your-org/r360` > Settings > Actions > General > Access: **Accessible from repositories owned by the user 'your-org'**,
  so private repos can call the reusable workflow.
- `your-org/f-360` > Settings > Environments > `lab`: deployment branches **main only**, no required reviewers.
- `your-org/f-360` > Settings > Secrets and variables > Actions: variables `LAB_TENANT_ID`, `LAB_CLIENT_ID` (apply),
  `LAB_PLAN_CLIENT_ID` (plan), `LAB_TFVARS_JSON` (a JSON object such as `{"lab_user_upns":["..."]}`),
  `TF_CLOUD_ORGANIZATION`; secret `TF_API_TOKEN`. In HCP Terraform set the workspace execution mode to **Local**.
- The r360 GitHub App (`r360-github-app`): add **Actions: Read and write** (for Run plan / Check drift; everything else works
  with the current permissions), then add `f-360` to the installation's repositories.

### 3. Caller workflow in the target repo
`.github/workflows/lab.yml` in `your-org/f-360` becomes:

```yaml
name: Lab tenant (Terraform)
run-name: >-
  r360:${{ github.event_name == 'pull_request' && 'plan' || github.event_name == 'push' && 'apply'
  || github.event_name == 'schedule' && 'drift' || inputs.mode }} ${{ github.event.pull_request.title || github.ref_name }}

on:
  pull_request:
    branches: [main]
    paths: ['lab/terraform/**']
  push:
    branches: [main]
    paths: ['lab/terraform/**']
  schedule:
    - cron: '17 13 * * *'   # nightly drift check
  workflow_dispatch:
    inputs:
      mode:
        type: choice
        options: [plan, drift]
        default: plan

permissions:
  id-token: write
  contents: read
  pull-requests: write

concurrency:
  group: lab-terraform
  cancel-in-progress: false

jobs:
  terraform:
    uses: your-org/r360/.github/workflows/r360-terraform.yml@main
    with:
      mode: >-
        ${{ github.event_name == 'pull_request' && 'plan' || github.event_name == 'push' && 'apply'
        || github.event_name == 'schedule' && 'drift' || inputs.mode }}
      working-directory: lab/terraform
      tenant-id: ${{ vars.LAB_TENANT_ID }}
      client-id: ${{ vars.LAB_CLIENT_ID }}
      plan-client-id: ${{ vars.LAB_PLAN_CLIENT_ID }}
      environment: lab
      tfvars-json: ${{ vars.LAB_TFVARS_JSON }}
      tf-cloud-organization: ${{ vars.TF_CLOUD_ORGANIZATION }}
      tf-workspace: f360-lab
    secrets: inherit
```

The `run-name` starting with `r360:<kind>` tells r360 what each run was. The reusable workflow posts the plan comment, fails the
**Drift detected** step on drift and runs apply in the `lab` environment. Destroy is not part of the lane; run it by hand.

### 4. Tell r360 about the target
Write `deploy-targets.json` (not committed; it holds no secrets) and run the tool:

```json
{ "version": 1, "targets": [ { "id": "f360-lab", "name": "Federation 360 lab", "repo": "your-org/f-360", "branch": "main",
  "workflow": "lab.yml", "environment": "lab", "tenantId": "<lab tenant id>", "path": "lab/terraform" } ] }
```

```powershell
pwsh -File tools/Set-R360DeployTargets.ps1 -Path ./deploy-targets.json -WhatIf
pwsh -File tools/Set-R360DeployTargets.ps1 -Path ./deploy-targets.json
```

It prints the federated credential subjects for step 1 and sets `R360_DEPLOY_TARGETS` on the Container App. r360 refuses to
start with an invalid value, and every target repo must belong to `your-org` (the App's installation).

## r360 API
| Route | Gate | What it does |
|---|---|---|
| `GET /api/deployments` | signed in | Targets, open changes with plan state, recent runs; records finished runs in the audit trail. |
| `POST /api/deployments/:target/pulls/:number/merge` `{headSha}` | write session, approver or admin, CSRF | Merge and apply. |
| `POST /api/deployments/:target/dispatch` `{mode: plan or drift}` | write session, any r360 role, CSRF | Starts the workflow on the target branch. |

## Later
- Turn on four-eyes: add required reviewers to the GitHub environment, and an r360 approval step like the Intune lane's.
- Release the reusable workflow from the public `remediation-360` repo so public targets (such as `federation-360`) can call it.
