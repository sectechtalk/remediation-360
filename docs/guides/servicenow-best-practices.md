# How to: work with ServiceNow from r360 (best practices)

The **ServiceNow** page (rail: Change > ServiceNow) searches ServiceNow **read-only** and shows, for each item, the r360
change request (GitHub issue labeled `r360-change`) that mentions its number. r360 never writes to ServiceNow.
Reference: [docs/servicenow.md](../servicenow.md).

## The model in one paragraph

ServiceNow stays the system of record for the request (RITM, INC, CHG, SCTASK). r360 is where the technical work is
tracked: one r360 change request per ServiceNow item, created with **Create issue**, titled `<number>: <short
description>` with the ServiceNow link in the body. From then on the ServiceNow number in the issue title is the link
between the two, and the GitHub column shows `R360-CHG-n` for that item.

## One-time setup (DEVICE02, elevated PowerShell 7)

```powershell
cd C:\path\to\remediation-360
git switch main; git pull
az login --tenant 00000000-0000-4000-8000-0000000000b1
pwsh -File .\tools\Set-R360ServiceNow.ps1            # dry run
pwsh -File .\tools\Set-R360ServiceNow.ps1 -Apply     # asks for the svc.r360 password only if Key Vault does not have it
pwsh -File .\tools\Install-R360Local.ps1 -Update -Apply
Select-String -Path C:\ProgramData\r360-local\r360.env -Pattern '^SERVICENOW_|^R360_SERVICENOW_'
Invoke-RestMethod http://localhost:3660/healthz
```

This stores the password as Key Vault secret `servicenow-r360-password` (read at run time by the PC's Arc identity; the
container holds no password), creates the Azure table `r360snqueries` for saved queries, and points r360 at
`https://your-instance.service-now.com` as `svc.r360`. Rotate the password with
`pwsh -File .\tools\Set-R360ServiceNow.ps1 -Apply -ResetSecret`, then `pwsh -File .\tools\Install-R360Local.ps1 -Update -Apply`.

### The ServiceNow account

- **Dedicated and non-interactive.** `svc.r360` is used by r360 only. In its user record tick **Web service access only**
  so nobody can sign in to the UI with it.
- **Read, nothing more.** Give it `snc_read_only` (blocks every write, even if another role would allow it) plus the
  narrowest role that can read the four tables r360 searches (`itil` on most instances). Do not give it `admin`.
- **Rotate on a schedule** (every 90 days or when someone leaves) with `-ResetSecret` as above.
- Errors that mention "refused the r360 service account (HTTP 401/403)" mean the password or roles are wrong, not r360.

## Searching well

| Need | Best way |
|---|---|
| One item you know | Free text: the number (`RITM0012345`). Fastest and exact. |
| A few items by words | Free text matches number, short description and description (`LIKE`). Keep it to one or two distinctive words. |
| A recurring view the team relies on | A **preconfigured query** in `config/servicenow-queries.json`, changed through a pull request. |
| Your own repeat view | A **saved query** (Save query on the page). Visible to everyone, audited. |
| Anything ServiceNow can filter | Build the filter in a ServiceNow list view, right-click the breadcrumb, **Copy query**, paste it into r360. |

Rules r360 enforces, so build queries to fit them:

- **Four tables only:** `sc_req_item` (Requested items), `incident`, `change_request`, `sc_task` (Catalog tasks).
- **100 rows, newest update first.** r360 adds `ORDERBYDESCsys_updated_on` itself; leave `ORDERBY` and `GROUPBY` out or
  the query is rejected. If you hit 100, narrow the query (add `active=true`, a date, an assignment group).
- **2,000 characters, one line.** Free text is cut at 100 characters and a `^` in it is removed.
- **Prefer stable fields.** Filter on `cat_item.name`, `assignment_group.name`, `state`, `active` rather than display text
  that people retype. Use `active=true` in almost every query: closed items rarely need r360 work.
- **Relative dates over fixed ones** in saved and preconfigured queries, for example
  `sys_updated_onONLast 30 days@javascript:gs.beginningOfLast30Days()@javascript:gs.endOfLast30Days()` as ServiceNow
  copies it from the list filter, so the view does not go stale.

### Preconfigured vs saved

| | Preconfigured | Saved |
|---|---|---|
| Where | `config/servicenow-queries.json` in the repo | Azure table `r360snqueries` |
| Who changes it | Anyone, through a reviewed pull request | Anyone with an `approvers.json` role, from the page |
| Use for | Views the process depends on, and anything that will get Action Templates | Personal or short-lived views |
| Audit | Git history | `servicenow.query.saved` / `servicenow.query.deleted` |

Promote a saved query to preconfigured once more than one person relies on it. Example: add an "Open incidents for
Endpoint" query and open the PR in one go:

```powershell
cd C:\path\to\remediation-360
git switch main; git pull
git switch -c config/sn-endpoint-incidents
$f = '.\config\servicenow-queries.json'
$doc = Get-Content $f -Raw | ConvertFrom-Json
$doc.queries += [pscustomobject]@{
  id = 'endpoint-open-incidents'; name = 'Open incidents: Endpoint'; table = 'incident'
  query = 'active=true^assignment_group.name=Endpoint'
  description = 'Active incidents assigned to the Endpoint group.'; actionTemplates = @()
}
$doc | ConvertTo-Json -Depth 5 | Set-Content $f -Encoding utf8NoBOM
npm test
git add $f; git commit -m 'ServiceNow: add Open incidents: Endpoint preconfigured query'
git push -u origin config/sn-endpoint-incidents
gh pr create -R your-org/r360 --fill --base main
```

`id` must be unique, lowercase letters, digits and dashes. r360 refuses to start if the file is invalid, so run
`npm test` before pushing and `Install-R360Local.ps1 -Update -Apply` after merging. Change the group name in the query
to your real assignment group before you run it.

## Linking ServiceNow items to r360 work

1. Search, find the item, click **Create issue**. r360 reads the item again from ServiceNow by `sys_id` (so the title
   cannot be spoofed from the browser) and opens `R360-CHG-n`. The organization defaults to the assignment group.
2. If the item already has an **open** change request, r360 refuses a second one (409) and shows the existing number.
   Reopen work on the existing issue instead.
3. To link an issue you opened by hand, put the ServiceNow number in its title or body, for example
   `RITM0012345: Revoke code-signing cert`. Numbers r360 recognizes: `RITM`, `REQ`, `INC`, `CHG`, `SCTASK`, `CTASK`,
   `PRB`, `TASK` followed by 7 to 10 digits.
4. When the requester emails about the work, give them the r360 number and use the email flow in
   [change-requests-email.md](change-requests-email.md). A subject can carry both: `[R360-CHG-42] RITM0012345 Revoke cert`.
5. **Close both sides.** Closing the r360 change request does not touch ServiceNow, and closing the ServiceNow item does
   not close the issue. Close the r360 issue with a note that names the ServiceNow number, then resolve the item in
   ServiceNow with `R360-CHG-n` in its work notes.

## Limits to know

- The GitHub column checks the **100 most recent** `r360-change` issues (open and closed), refreshed every minute. An
  older linked issue shows as **Create issue**; search GitHub before creating a duplicate:
  `gh issue list -R your-org/r360 --label r360-change --state all --search RITM0012345`.
- Results show number, short description, state, assignment group, priority, opened and updated times. Open the
  ServiceNow link for anything else.
- r360 searches; it does not update, assign, comment on or close ServiceNow records. Do that in ServiceNow.
- **Action Templates** listed on a preconfigured query are shown only; r360 does not run them yet.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Page says ServiceNow is not configured | `SERVICENOW_*` lines missing from `C:\ProgramData\r360-local\r360.env`: run `Set-R360ServiceNow.ps1 -Apply`, then `Install-R360Local.ps1 -Update -Apply`. |
| "ServiceNow refused the r360 service account (HTTP 401/403)" | Password wrong or expired (`-ResetSecret`), account locked, or missing read role. |
| "ServiceNow rejected the query" | Bad field name or table mismatch. Rebuild the filter in ServiceNow on the same table and **Copy query** again. |
| "The ServiceNow password could not be read" | The Arc identity cannot read `servicenow-r360-password`: rerun `Set-R360ServiceNow.ps1 -Apply` and check `Install-R360Local.ps1 -Status`. |
| Saved queries missing | `r360snqueries` table or its role assignment is missing: rerun `Set-R360ServiceNow.ps1 -Apply`. |
