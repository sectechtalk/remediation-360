# ServiceNow search

The **ServiceNow** page (rail: Change > ServiceNow) searches ServiceNow read-only and shows, for every item, the r360
change request (GitHub issue labeled `r360-change`) that mentions its number. It replaces the earlier "Check ServiceNow"
import of Certificate Revocation requests, which was never merged.

## Searching

| Way | How |
|---|---|
| Free text | Type a number or words. r360 matches the number, short description and description. |
| Preconfigured query | Pick one under *Preconfigured*. These live in `config/servicenow-queries.json` and change only through a pull request. |
| Saved query | Pick one under *Saved*. Anyone with an approvers.json role can save or delete them from the page. Both are audited. |
| Pasted query | Build any filter in a ServiceNow list view, right-click the filter breadcrumb, choose **Copy query**, and paste it. Every ServiceNow field works, so r360 does not need to know the fields in advance. |

Free text can be combined with any query. Results are the 100 most recently updated matches. Tables: Requested items
(`sc_req_item`), Incidents, Change requests, Catalog tasks.

## GitHub column

- **R360-CHG-n**: an r360 change request whose title or body contains the ServiceNow number (open ones win over closed).
- **Create issue**: opens a change request for that item. r360 reads the item again from ServiceNow by `sys_id`, titles
  the issue `<number>: <short description>` and puts the ServiceNow link in the body, so the two stay linked.

## Preconfigured queries file

```json
{
  "version": 1,
  "queries": [
    { "id": "certificate-revocations", "name": "Certificate revocations", "table": "sc_req_item",
      "query": "cat_item.name=Certificate Revocation^active=true", "description": "...", "actionTemplates": [] }
  ]
}
```

`actionTemplates` names the Action Templates that will apply to a query's results. r360 shows them but does not act on them yet.

## Setup (local r360 on DEVICE02)

```powershell
cd C:\path\to\remediation-360\tools
.\Set-R360ServiceNow.ps1            # dry run
.\Set-R360ServiceNow.ps1 -Apply     # elevated PowerShell 7
.\Install-R360Local.ps1 -Update -Apply
```

`Set-R360ServiceNow.ps1 -Apply` stores the svc.r360 password in Key Vault (`servicenow-r360-password`, asked for only if
it is missing or with `-ResetSecret`), lets the PC's Arc identity read that one secret, creates the table `r360snqueries`
with `Storage Table Data Contributor` on that one table, and writes the ServiceNow settings into
`C:\ProgramData\r360-local\r360.env`. The container holds no password: r360 reads it from Key Vault with the managed identity.
