# Exchange 360 config snapshots in r360

Exchange 360 (ex360) takes a read-only snapshot of every mail flow setting and sends it to r360. r360 keeps it in a private GitHub repository, one commit per snapshot. Exchange 360's Config snapshots page lists the snapshots and compares any two by reading them back from r360.

## How a snapshot travels

1. In Exchange 360, **Take snapshot** runs the read-only export (`Get-` cmdlets only) with the person's own sign-in.
2. The Exchange 360 server calls `POST {R360_URL}/api/ex360/snapshots` with the person's Entra access token for r360 (`api://<r360-web app id>/Snapshots.ReadWrite`).
3. r360 checks the token: RS256 signature against the tenant's signing keys, tenant, issuer, audience (r360-web), the `Snapshots.ReadWrite` scope, and expiry. Then it checks `approvers.json`: saving needs **author** or **admin**, and reading needs any r360 role.
4. r360 refuses a body that is not format `sectechtalk.mailflow-config` version 1 with `readOnly: true`, or that contains text shaped like a JSON Web Token, a private key block or a SAS signature.
5. The r360 GitHub App commits `snapshots/<name>.json` and an updated `snapshots/index.json` to `main` of `R360_EX360_SNAPSHOT_REPO`. The token is narrowed to that one repository with `contents: write`.
6. Each save is audited as `ex360.snapshot.save` (ok, denied or error), with the commit sha.

| Route | Who | What |
|---|---|---|
| `POST /api/ex360/snapshots` | author, admin | Store one snapshot |
| `GET /api/ex360/snapshots` | any r360 role | The index, newest first |
| `GET /api/ex360/snapshots/<name>` | any r360 role | One snapshot file |

These routes come before r360's browser sign-in and use no cookie. They answer 503 until `R360_EX360_SNAPSHOT_REPO` is set.

## Turn it on

Run on DEVICE02. It is a dry run first; read the table, then run it again with `-Apply`:

```powershell
cd C:\path\to\remediation-360
pwsh -File .\tools\Set-R360Ex360Snapshots.ps1 -Ex360ClientId <ENTRA_CLIENT_ID from Exchange 360 .env>
pwsh -File .\tools\Set-R360Ex360Snapshots.ps1 -Ex360ClientId <ENTRA_CLIENT_ID from Exchange 360 .env> -Apply
```

It creates the private repository `your-org/ex360-snapshots` and asks you to add the r360 GitHub App to it. It adds the `Snapshots.ReadWrite` scope to r360-web, gives the Exchange 360 app registration that permission with admin consent, and sets `R360_EX360_SNAPSHOT_REPO` on app-r360. The new routes also need the current image (`tools/Publish-R360Image.ps1`).

Nothing here costs money: a private GitHub repository and app registration settings are free.
