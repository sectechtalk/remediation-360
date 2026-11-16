# Licenses by feature

Each part of r360 leans on a different product. This guide says, feature by feature, what the company must pay for and
what the person using the feature must have. The same content is in r360 under **New hire > Licenses by feature**. What a
single PC can use (join state and its user's license) is in [whats-supported.md](whats-supported.md).

Turn on only the features you have licenses for. A feature without its license says so on its page; the rest of r360
keeps working.

## Feature by feature

| r360 feature | The company needs | The person using it needs |
|---|---|---|
| Sign in and read pages (Overview, Remediations, Fleet, Certificates, Audit) | Entra ID (Free is enough). An Intune subscription for there to be anything to read. | A work account in the tenant and an Intune role that can read. Intune admins do not need an Intune license themselves (default for tenants created after July 2021; older tenants turn on "Allow access to unlicensed admins"). |
| Changes: write or edit a remediation | GitHub. If the remediations repository is private, rulesets that force a review need GitHub Pro (personal account) or GitHub Team (organization). On a public repository GitHub Free is enough. | A GitHub account with write access to the remediations repository, and the `author` role in r360. |
| Signing: every script signed in CI | Azure pay-as-you-go: **Key Vault Premium**, because the signing key is a non-exportable RSA-HSM key. GitHub Actions minutes (every plan includes some; public repositories are free). | Nothing. CI signs as its own identity; no person holds the key. |
| Publish to canary and promote (slow path) | Intune. Each target PC Entra joined or hybrid joined, and its user licensed for **Windows Enterprise E3 or E5** (Microsoft 365 E3, E5, F3, A3, A5 or Windows VDA). Business Premium alone is not enough. Automatic Intune enrollment needs Entra ID P1. | The `approver` role in r360 and an active Intune Administrator role. A second person approves (four-eyes). |
| Emergency: Defender actions on one device (fast path) | **Defender for Endpoint Plan 1 or Plan 2, or Defender for Business** (in Business Premium, or standalone for up to 300 users). The PC onboarded to Defender; join state does not matter. | Requester: `author`, `emergencyApprover` or `admin` role. Approver: `emergencyApprover` role plus a Defender role with **Active remediation actions** covering the device's device group. |
| Change requests: email-tracked changes | Exchange Online for the shared change mailbox (a shared mailbox needs no license up to 50 GB) and GitHub for the change issues. AI summaries need an Anthropic API key, billed per use. | A licensed Exchange Online mailbox of their own (any Microsoft 365 or Office 365 plan with Exchange) and Full Access to the shared mailbox. |
| ServiceNow search | A ServiceNow instance. Licensing is between you and ServiceNow; r360 only reads. | Nothing extra in r360. The configured ServiceNow account needs read access to the tables searched. |
| Deployments: Terraform through GitHub Actions | GitHub Actions and an environment per target. On a private repository, required reviewers on an environment need GitHub Enterprise; Free, Pro and Team get them only on public repositories. r360 does not need a second reviewer here (four-eyes is off for this lane). | The `approver` or `admin` role in r360 and write access to the target repository. |
| Audit trail | Azure pay-as-you-go: one Storage account (append-only table and immutable blob container). Cents a month. | Nothing. Every signed-in person can read it; nobody can change it. |
| Settings and PIM | Nothing for Settings. PIM (Intune Administrator only when needed) needs **Entra ID P2** or Entra ID Governance. Optional, recommended for anyone who can publish. | The `admin` role in r360 for Settings. With PIM, an eligible Intune Administrator assignment. |

## What to buy, cheapest first, and what it costs

US list prices per user per month on an annual commitment, read from Microsoft's and GitHub's pricing pages on
2026-11-16 (Microsoft's prices effective July 1, 2026). Defender for Endpoint Plan 1 and Plan 2 are not priced on
Microsoft's site, so those two are typical partner prices. Azure figures are estimates for r360's small footprint. Your
agreement or reseller may charge differently.

| r360 feature | What to buy | Tiers that do the job, cheapest first | Estimated cost per month |
|---|---|---|---|
| Sign in and read pages | Nothing per operator. The company needs Intune once. | Entra ID Free (included); Intune Plan 1 $8, or already in Business Premium / Microsoft 365 E3 | $0 per operator |
| Changes | GitHub Team for the organization (private repository) | GitHub Free $0 (public repository only); GitHub Team $4; GitHub Enterprise $21 (not needed) | $0 to $4 per author |
| Signing | Azure pay-as-you-go with Key Vault Premium | Key Vault Premium is the only tier with HSM keys; GitHub Actions minutes included (3,000 a month on Team) | About $1 to $10 for the company |
| Publish and promote | For each PC user: Windows Enterprise E3 plus Intune | Microsoft 365 F3 $10 (frontline only); Windows E3 + Intune Plan 1 $15.63 (add Entra ID P1 $7 for automatic enrollment); Business Premium + Windows E3 $29.63; Microsoft 365 E3 $39; Microsoft 365 E5 $60 | $10 to $39 per PC user |
| Emergency | Defender for Endpoint, or Defender for Business (300 users or fewer) | Defender for Business $3 (no stop and quarantine); Defender for Endpoint P1 about $3; P2 about $5.20; already in Business Premium, Microsoft 365 E3 (P1), E5 (P2) | $3 to $5.20 per protected user, or $0 extra |
| Change requests | An Office 365 or Microsoft 365 plan with a mailbox for each operator; the shared mailbox is free | Exchange Online Plan 1 $4; Microsoft 365 Business Basic $7; Office 365 E1 $10; Anthropic API per use for summaries | $4 to $10 per operator, plus cents per summary |
| ServiceNow search | A ServiceNow subscription | ServiceNow quotes each customer | Quote from ServiceNow |
| Deployments | GitHub (same organization) and Azure for what Terraform deploys | GitHub Free $0 (public only); Team $4; Enterprise $21 only for required reviewers on a private repository | $0 to $4 per user |
| Audit trail | Azure pay-as-you-go, one Storage account | Standard locally redundant storage | Under $1 for the company |
| Settings and PIM | Entra ID P2, or the Entra ID Governance add-on if you have P1 | Nothing (PIM optional); Entra ID Governance add-on $7 (needs P1); Entra ID P2 $10; Microsoft 365 E5 includes P2 | $0, or $7 to $10 per PIM admin |

## Which Defender plan allows which Emergency action

| Action | Defender for Endpoint P1 | Defender for Business | Defender for Endpoint P2 |
|---|---|---|---|
| Isolate and release | Yes | Yes | Yes |
| Run antivirus scan | Yes | Yes | Yes |
| Stop and quarantine a file | Yes | No | Yes |
| Collect investigation package | No | No | Yes |
| Restrict app execution and remove it | No | No | Yes |

Defender refuses an action the plan does not include, and r360 records the refusal in the audit trail.

## Check what the tenant has

Run on DEVICE02 (read-only):

```powershell
Connect-MgGraph -Scopes 'Organization.Read.All' -NoWelcome
Get-MgSubscribedSku | Select-Object SkuPartNumber, ConsumedUnits, @{n='Enabled';e={$_.PrepaidUnits.Enabled}} | Sort-Object SkuPartNumber | Format-Table -AutoSize
```

Look for `SPE_E3` or `SPE_E5` (Microsoft 365 E3/E5), `SPB` (Business Premium), `WIN_DEF_ATP` or `DEFENDER_ENDPOINT_P1`
(Defender for Endpoint), `MDE_SMB` (Defender for Business standalone) and `AAD_PREMIUM_P2` (Entra ID P2).

## Sources

- Microsoft 365 and Office 365 prices from July 1, 2026: https://www.microsoft.com/en-us/licensing/news/2026-M365-Packaging-Pricing-Updates
- Microsoft 365 business plans: https://www.microsoft.com/en-us/microsoft-365/business/microsoft-365-plans-and-pricing
- Microsoft 365 enterprise plans: https://www.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-plans-and-pricing
- Intune: https://www.microsoft.com/en-us/security/microsoft-intune-pricing
- Entra: https://www.microsoft.com/en-us/security/business/microsoft-entra-pricing
- Exchange Online: https://www.microsoft.com/en-us/microsoft-365/exchange/compare-microsoft-exchange-online-plans
- GitHub: https://github.com/pricing
- Key Vault: https://azure.microsoft.com/en-us/pricing/details/key-vault/

- Remediations licensing and prerequisites: https://learn.microsoft.com/intune/device-management/tools/deploy-remediations
- Intune unlicensed admins: https://learn.microsoft.com/intune/fundamentals/unlicensed-admins
- Shared mailbox licensing: https://learn.microsoft.com/exchange/collaboration-exo/shared-mailboxes
- Defender response actions by plan: https://learn.microsoft.com/defender-endpoint/respond-machine-alerts
- Key Vault tiers (HSM keys need Premium): https://learn.microsoft.com/azure/key-vault/general/overview
- GitHub rulesets availability: https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets
- GitHub environments and required reviewers: https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments
