# How to: set up and use email-driven change requests

An r360 **change request** is a GitHub issue that an outside organization feeds by email. You give the organization a
number such as `R360-CHG-42`; every email they send to `changes@contoso.com` with that number is logged on the issue,
and r360 summarizes the thread when you ask. Reference: [docs/change-requests.md](../change-requests.md).

## What you get

| You do | r360 does |
|---|---|
| **Get change number** on the Change requests page | Opens a GitHub issue on `your-org/r360` labeled `r360-change`. The number is `R360-CHG-<issue number>`. Shows a ready subject line like `[R360-CHG-42] Move DNS to new resolver`. |
| Send the organization the number | Nothing yet. |
| The organization emails `changes@contoso.com` | Nothing until someone opens the page. |
| Open **Change requests** or click **Check mailbox now** | Reads the shared mailbox with **your** sign-in and adds one issue comment per new email: sender, time, subject, attachments yes/no. Bodies stay in the mailbox. |
| **Summarize now** | Posts a summary (status, what was asked, decisions, open questions) on the issue and shows it in r360. |
| **Make actionable** | Posts a `- [ ]` task checklist from the latest summary. Needs the API key (see "Summaries"). |
| **Close R360-CHG-n** | Closes the issue as completed or cancelled with an optional note. |

Everything is in **Audit** as `request.*`. Creating, summarizing and closing need an `approvers.json` role (author,
approver or admin).

## One-time setup (DEVICE02, PowerShell 7)

The shared mailbox is free (no license under 50 GB, no archive, no hold). The script is a dry run until `-Apply`.
`Set-R360ChangeRequests.ps1` writes the settings to the Azure Container App `app-r360` (it scales to zero, so this costs
nothing); `-RefreshEnv` then copies them into local r360 at http://localhost:3660.

```powershell
cd C:\path\to\remediation-360
git switch main; git pull
Install-Module ExchangeOnlineManagement -Scope CurrentUser
az login --tenant 00000000-0000-4000-8000-0000000000b1
gh auth status

# 1. See what would change, then apply: mailbox, Full Access for sg-r360-operators, Mail.Read.Shared on r360-web, GitHub labels
pwsh -File .\tools\Set-R360ChangeRequests.ps1
pwsh -File .\tools\Set-R360ChangeRequests.ps1 -Apply

# 2. Copy the new settings into local r360 and restart it (elevated PowerShell 7)
pwsh -File .\tools\Install-R360Local.ps1 -RefreshEnv -Update -Apply

# 3. Summaries without an API key: Claude Code on DEVICE02 answers "Summarize now"
pwsh -File .\tools\Watch-R360Summaries.ps1 -Install -Apply

# 4. Confirm
Select-String -Path C:\ProgramData\r360-local\r360.env -Pattern '^R360_CHANGE_|^R360_LLM_'
Get-ScheduledTask -TaskName 'r360 summary watcher' | Select-Object TaskName, State
gh label list -R your-org/r360 --search r360-
Invoke-RestMethod http://localhost:3660/healthz
```

If the r360 GitHub App still lacks **Issues: Read and write** or access to `your-org/r360`, step 1 opens the two
GitHub pages and waits. That is a GitHub UI-only step (installation 12345678:
https://github.com/settings/installations/12345678). After setup, **sign out of r360 and sign in again** so your
session carries the mailbox scope. Settings on the Settings page then show the mailbox instead of `off`.

Any new operator needs: membership in `sg-r360-operators`, a role in `approvers.json`, then a rerun of step 1 with
`-Apply` (it grants Full Access to every enabled member), then sign out and in.

## Day-to-day use

1. **Open the change.** Change requests > **Get change number**. Title: what is changing, in the requester's words.
   Organization: who asked. Copy the subject line r360 shows.
2. **Hand the number over.** Send the organization this, filled in:

   > Please use subject `[R360-CHG-42] Move DNS to new resolver` and send every email about this change to
   > changes@contoso.com (Cc is fine). Keep `R360-CHG-42` in the subject when you reply.

3. **Let emails flow.** Anyone can reply-all; only messages that reach `changes@contoso.com` count. The number may be
   in the subject or body.
4. **Log them.** Open the page or click **Check mailbox now**. Each new email becomes one issue comment.
5. **Summarize** when you need the state of play: before a meeting, before approving, before closing.
   Without the API key the row shows **Summary requested** and the summary appears about a minute later.
6. **Close** when the work is done (completed) or dropped (cancelled). Add a one-line note: what was delivered, or why
   it stopped.

## Rules that keep it clean

- **One change, one number.** Do not reuse a number for follow-on work; get a new one and mention the old one in the title.
- **Exact match.** `R360-CHG-42` never matches `R360-CHG-420`. ServiceNow numbers such as `CHG0012345` are never
  treated as r360 numbers, so both can sit in one subject: `[R360-CHG-42] CHG0012345 Move DNS`.
- **Nothing sensitive in subjects.** Subjects, senders and summaries land on GitHub (escaped: no @mentions, no HTML).
  Bodies and attachments never leave the mailbox, but summaries quote their gist. Ask organizations not to email secrets.
- **Do not move or delete mail** in `changes@contoso.com`. r360 never does, and summaries read every matching email.
- **Summaries are drafts.** The model is told emails are data, not instructions, but read the summary before you act on it.
- **Work the issue in GitHub too.** Comments, assignees and links on the issue are fine; keep the `r360-change` label,
  or r360 stops seeing it.

## Summaries: watcher now, API key later

| Mode | How Summarize now works | Make actionable |
|---|---|---|
| **No API key** | r360 labels the issue `r360-summary-requested`. The scheduled task `r360 summary watcher` on DEVICE02 sees it within 30 seconds, reads the mailbox with Aaron's delegated sign-in, runs `claude -p` with every tool off, posts the summary and removes the label. Works only while Aaron is signed in to DEVICE02. Log: `%LOCALAPPDATA%\r360\summary-watcher.log`. | Off |
| **API key** | r360 calls the provider itself (Anthropic `claude-opus-5-5` by default, about 5 cents for 10 emails). | On |

**Moving to the API key (works for local r360 and Azure).** `-SetApiKey` stores the key in Key Vault as
`r360-llm-api-key`. On Azure, `app-r360` reads it through a secret reference. Locally, `Install-R360Local.ps1` gives this
PC's Arc identity read access to that one secret and adds the setting `R360_LLM_API_KEY_SECRET` (the secret's name, `r360-llm-api-key`) to `r360.env`; the
container reads the key from Key Vault at startup (log line `selfcheck llm-key: PASS ... (not shown)`). The key is never
written to disk. Run these in an elevated PowerShell 7 on DEVICE02:

```powershell
cd C:\path\to\remediation-360
git switch main; git pull
pwsh -File .\tools\Set-R360ChangeRequests.ps1 -Apply -SkipExchange -SetApiKey   # paste the key at the hidden prompt
pwsh -File .\tools\Install-R360Local.ps1 -RefreshEnv -Update -Apply             # grants the Arc identity, restarts r360
docker logs r360 2>&1 | Select-String 'selfcheck llm-key'                         # expect PASS
pwsh -File .\tools\Watch-R360Summaries.ps1 -Remove -Apply                       # r360 now summarizes by itself
```

After that, **Summarize now** answers in r360 directly, **Make actionable** turns on, and r360 refuses the old handoff (409).

## Troubleshooting

| Symptom | Fix |
|---|---|
| Page says change requests are off | `R360_CHANGE_MAILBOX` is missing locally: run step 2 of setup (`-RefreshEnv -Update -Apply`). |
| "Your account cannot read changes@contoso.com" | You lack Full Access or your session predates setup. Rerun step 1 with `-Apply`, wait 15 minutes for Exchange, sign out of r360 and in again. |
| An email is missing | It did not reach the shared mailbox, or the number is mistyped. Search the mailbox in Outlook for `R360-CHG-42`. |
| Stuck on **Summary requested** | The watcher is not running. `Get-ScheduledTask -TaskName 'r360 summary watcher'`, then `Start-ScheduledTask -TaskName 'r360 summary watcher'`, then read the log. |
| "Your approvers.json role does not allow..." | Add your account to `approvers.json` on `your-org/remediations` through a pull request. |

```powershell
Get-Content "$env:LOCALAPPDATA\r360\summary-watcher.log" -Tail 30
gh issue list -R your-org/r360 --label r360-change --state open
gh issue list -R your-org/r360 --label r360-summary-requested
```
