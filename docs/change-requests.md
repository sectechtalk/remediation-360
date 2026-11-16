# Change requests (tracked by email)

A change request is a change that an outside organization asks for and discusses by email. r360 gives it a number,
tracks every email that carries that number, summarizes the thread on request and closes it when it is done.

## How it works

| Step | What happens |
|---|---|
| **Get change number** | An operator enters a title and the requesting organization on **Change requests**. r360 opens a GitHub issue labeled `r360-change` on `your-org/r360` through the r360 GitHub App. The change number is `R360-CHG-<issue number>`, so it is unique by construction. r360 shows the number, the mailbox address and a ready subject line such as `[R360-CHG-42] Move DNS to new resolver`. |
| **Emails** | The organization writes to `changes@contoso.com` with the number anywhere in the subject or body. `R360-CHG-42` never matches `R360-CHG-420`, and ServiceNow-style `CHG0012345` numbers never match. |
| **Tracking** | Whenever an operator opens **Change requests** (at most every 2 minutes per replica) or clicks **Check mailbox now**, r360 reads the mailbox and adds one comment per new email to the issue: sender, time, subject and whether it has attachments. Email bodies stay in the mailbox; they are not copied to GitHub. |
| **Summarize now** | r360 reads every email for that change, drops quoted reply history, and sends the thread to the summary provider as untrusted data. The summary (status, what was asked, decisions, open questions) is posted on the issue and shown in r360. |
| **Make actionable** | Turns the latest summary into a task checklist (`- [ ]` items with owner and due date when the emails give them), posted on the issue. Optional. |
| **Close** | Closes the issue as completed or cancelled (`not_planned`), with an optional note. |
| **Open changes** | The page lists every open change: number, title, organization, email count, last email, latest summary and action items. |

Every write (create, log emails, summarize, action items, close) is recorded in **Audit** as `request.*`, and the intent
row must be stored before anything is written ("no audit, no write"). Creating, summarizing and closing need an
`approvers.json` role (author, approver or admin). No write session is needed: nothing here writes Intune.

## Security model

- **Delegated only.** The mailbox is read with the signed-in operator's own token (`Mail.Read.Shared` on `r360-web`).
  The operator needs Full Access to the shared mailbox in Exchange Online. r360 has no application permission and never
  moves, flags or deletes mail.
- **GitHub.** Issue reads use a cached `issues:read` token; each write mints its own `issues:write` token for
  `your-org/r360` only and drops it. r360 acts only on issues that carry the `r360-change` label.
- **Summary provider key.** Stored as the Key Vault secret `r360-llm-api-key`; the Container App secret `llm-api-key` is a
  Key Vault reference read by `id-r360`. The key is never logged, shown, audited or returned by the API.
- **Untrusted email.** Subjects, names and model output are escaped before they reach GitHub (no @mentions, no HTML, no
  forged r360 machine lines). The model is told the emails are data and never instructions.

## Providers

| `R360_LLM_PROVIDER` | Default `R360_LLM_MODEL` | Notes |
|---|---|---|
| `anthropic` (default) | `claude-opus-5-5` | Claude through the Anthropic API, with refusal fallback on. Pay per use: a 10-email summary is about 5 cents. |
| `openai` | `gpt-5` | OpenAI chat completions. |
| `azure-openai` | none: set the deployment name | Needs `R360_LLM_ENDPOINT` (https://<name>.openai.azure.com). |

## Running without an API key (Claude handoff)

Everything except Make actionable works with no key. **Summarize now** hands the change to Claude instead:

1. r360 labels the issue `r360-summary-requested`, posts a "Summary requested" comment (audited as
   `request.summaryrequested`) and the row shows **Summary requested**. The page checks again every 20 seconds.
2. The summary watcher on DEVICE02 (`tools/Watch-R360Summaries.ps1`, a Windows scheduled task that starts at logon)
   sees the label within 30 seconds. It reads `changes@contoso.com` with Aaron's own delegated Graph sign-in
   (`Mail.Read.Shared`, the same Full Access r360 uses), builds exactly the prompt r360 would
   (`tools/summarize-change.mjs` reuses r360's code), and runs Claude Code headless (`claude -p`) on his Claude
   subscription with every tool and MCP server turned off, so the emails can only be summarized.
3. It posts the summary on the issue with the `r360:summary` marker (escaped the same way r360 escapes it) and removes
   the label. The summary shows on **Change requests** about a minute after the click.

If no email matches, or a summary fails three times, the watcher says so on the issue and removes the label so the
button comes back. The watcher only runs while Aaron is signed in to DEVICE02. Its log (change numbers and results
only) is `%LOCALAPPDATA%\r360\summary-watcher.log`.

When the API key is added (`-Apply -SkipExchange -SetApiKey`; for local r360 follow it with
`Install-R360Local.ps1 -RefreshEnv -Update -Apply`, which lets the PC's Arc identity read the secret and sets
`R360_LLM_API_KEY_SECRET` so the container reads the key from Key Vault at startup), r360 summarizes directly, refuses handoff requests
(409) and never sets the label again. Remove the watcher then with
`pwsh -File .\tools\Watch-R360Summaries.ps1 -Remove -Apply`.

## Setup

The shared mailbox is free in Exchange Online: no license while it stays under 50 GB and has no archive or litigation
hold. Run everything on DEVICE02 in PowerShell 7 from `C:\path\to\remediation-360`:

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser
pwsh -File .\tools\Set-R360ChangeRequests.ps1                     # dry run: shows every change
pwsh -File .\tools\Set-R360ChangeRequests.ps1 -Apply              # creates the mailbox, grants access, labels, sets app-r360 (no key yet)
pwsh -File .\tools\Watch-R360Summaries.ps1 -Install -Apply        # interim: Summarize now through Claude Code on DEVICE02
pwsh -File .\tools\Set-R360ChangeRequests.ps1 -Apply -SkipExchange -SetApiKey   # later: r360 summarizes by itself
pwsh -File .\tools\Watch-R360Summaries.ps1 -Remove -Apply         # then remove the watcher
```

The script opens two GitHub pages if the r360 GitHub App still needs **Issues: Read and write** and access to
`your-org/r360`, and waits until you have saved and accepted the change. After it finishes, sign out of r360 and sign
in again so your session carries the mailbox scope.

Settings on `app-r360`: `R360_CHANGE_MAILBOX`, `R360_CHANGE_REPO` (default `your-org/r360`), `R360_LLM_PROVIDER`,
`R360_LLM_MODEL`, `R360_LLM_ENDPOINT` (Azure OpenAI only) and `R360_LLM_API_KEY=secretref:llm-api-key`. Local r360
uses `R360_LLM_API_KEY_SECRET` instead, which holds the name of the Key Vault secret (`r360-llm-api-key`, read with the managed identity). Without
`R360_CHANGE_MAILBOX` the feature is off and r360 never asks for mail access.
