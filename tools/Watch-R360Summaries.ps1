#Requires -Version 7.4
<#
.SYNOPSIS
    Interim "Claude handoff" for r360 Summarize now while r360 has no AI provider API key: a small watcher on DEVICE02
    that makes each requested summary with Claude Code within about a minute of the click.
.DESCRIPTION
    With no API key, Summarize now in r360 labels the change's GitHub issue r360-summary-requested. This watcher checks for
    that label every 30 seconds. For each labeled change it:
      1. reads the shared change mailbox with YOUR delegated Microsoft Graph sign-in (Mail.Read.Shared; you already have
         Full Access to the mailbox as a member of sg-r360-operators). No application permission, no forwarding.
      2. builds the same prompt r360 would (tools/summarize-change.mjs reuses r360's own code) and runs Claude Code
         headless (claude -p) on your Claude subscription, with every tool and MCP server turned off, so the emails can
         only be summarized, never acted on.
      3. posts the summary on the issue with the r360:summary marker (r360 shows it on Change requests) and removes the label.
    Once an API key is added to r360 (Set-R360ChangeRequests.ps1 -Apply -SkipExchange -SetApiKey), r360 summarizes by
    itself, never sets the label again, and this watcher has nothing to do. Remove it then with -Remove -Apply.

    Modes (dry run unless -Apply where it changes something):
      -Install   Checks claude, gh, node and the Graph module, signs you in to Graph once, puts a clean copy of origin/main
                 in C:\path\to\remediation-360-watcher (so switching branches in C:\path\to\remediation-360 never affects it), and registers the
                 Windows scheduled task "r360 summary watcher" that starts at logon. Rerun with -Install -Apply to update.
      -Once      One pass now in this window, then exits. Use it to test.
      -Status    Shows the scheduled task and the last log lines.
      -Remove    Unregisters the scheduled task (with -Apply).
      -Run       The loop itself. The scheduled task uses this; you do not need to.
    Log (change numbers and results only, never email content): %LOCALAPPDATA%\r360\summary-watcher.log
.EXAMPLE
    pwsh -File .\tools\Watch-R360Summaries.ps1 -Install -Apply
.EXAMPLE
    pwsh -File .\tools\Watch-R360Summaries.ps1 -Status
#>
[CmdletBinding(DefaultParameterSetName = 'Status')]
param(
    [Parameter(ParameterSetName = 'Install', Mandatory)][switch]$Install,
    [Parameter(ParameterSetName = 'Once', Mandatory)][switch]$Once,
    [Parameter(ParameterSetName = 'Run', Mandatory)][switch]$Run,
    [Parameter(ParameterSetName = 'Status')][switch]$Status,
    [Parameter(ParameterSetName = 'Remove', Mandatory)][switch]$Remove,
    [Parameter(ParameterSetName = 'Install')][Parameter(ParameterSetName = 'Remove')][switch]$Apply,
    [string]$Mailbox = 'changes@contoso.com',
    [string]$Repo = 'your-org/r360',
    [ValidateRange(15, 600)][int]$IntervalSeconds = 30,
    [string]$WatcherPath = 'C:\path\to\remediation-360-watcher'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$OutputEncoding = [Text.UTF8Encoding]::new($false)
Import-Module (Join-Path $PSScriptRoot 'R360.Common.psm1') -Force
$cfg = Get-R360Config
$TaskName = 'r360 summary watcher'
$RequestedLabel = 'r360-summary-requested'
$ChangeLabel = 'r360-change'
$RepoRoot = Split-Path $PSScriptRoot -Parent
$Helper = Join-Path $PSScriptRoot 'summarize-change.mjs'
$LogDir = Join-Path $env:LOCALAPPDATA 'r360'
$LogFile = Join-Path $LogDir 'summary-watcher.log'
$MaxScan = 1000
$MaxFailures = 3

function Write-WatchLog([string]$Text) {
    if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $Text"
    Add-Content -Path $LogFile -Value $line -Encoding utf8
    Write-Host $line
    # Keep the log small: last 2000 lines.
    if ((Get-Item $LogFile).Length -gt 512KB) { Get-Content $LogFile -Tail 2000 | Set-Content $LogFile -Encoding utf8 }
}

function Connect-WatchGraph {
    # Delegated only. CurrentUser scope caches the sign-in so the scheduled task reuses it without a prompt.
    $ctx = Get-MgContext
    if ($ctx -and $ctx.TenantId -eq $cfg.TenantId -and 'Mail.Read.Shared' -in $ctx.Scopes) { return }
    Connect-MgGraph -TenantId $cfg.TenantId -Scopes 'Mail.Read.Shared' -ContextScope CurrentUser -NoWelcome | Out-Null
    $ctx = Get-MgContext
    if (-not $ctx -or $ctx.AuthType -ne 'Delegated') { throw 'Graph sign-in is not delegated; the watcher only uses your own sign-in.' }
    if ('Mail.Read.Shared' -notin $ctx.Scopes) { throw 'Graph sign-in is missing Mail.Read.Shared.' }
}

function Get-ChangeMail([datetime]$Since) {
    $box = [uri]::EscapeDataString($Mailbox)
    $filter = [uri]::EscapeDataString("receivedDateTime ge $($Since.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) and isDraft eq false")
    $next = "https://graph.microsoft.com/v1.0/users/$box/messages?`$filter=$filter&`$orderby=receivedDateTime%20desc&`$select=id,internetMessageId,subject,from,receivedDateTime,body,hasAttachments&`$top=100"
    $out = [System.Collections.Generic.List[object]]::new()
    while ($next -and $out.Count -lt $MaxScan) {
        if (-not $next.StartsWith('https://graph.microsoft.com/')) { throw 'Unexpected Graph nextLink host.' }
        $page = Invoke-MgGraphRequest -Method GET -Uri $next -Headers @{ Prefer = 'outlook.body-content-type="text"' } -OutputType PSObject
        foreach ($m in @($page.value)) { $out.Add($m) }
        $next = if ($page.PSObject.Properties['@odata.nextLink']) { $page.'@odata.nextLink' } else { $null }
    }
    [pscustomobject]@{ Messages = $out.ToArray(); Truncated = [bool]$next }
}

function Invoke-Helper([string]$Mode, [object]$InputObject) {
    $json = $InputObject | ConvertTo-Json -Depth 20 -Compress
    $out = $json | & node $Helper $Mode
    if ($LASTEXITCODE -ne 0) { throw "summarize-change.mjs $Mode failed (exit $LASTEXITCODE)." }
    ($out -join "`n") | ConvertFrom-Json -Depth 20
}

function Invoke-Claude([string]$System, [string]$Prompt) {
    $sysFile = New-TemporaryFile
    try {
        Set-R360PrivateFileAcl -Path $sysFile.FullName
        Set-Content -Path $sysFile.FullName -Value $System -Encoding utf8 -NoNewline
        # Headless Claude Code on the signed-in Claude subscription. No tools and no MCP servers: it can only write text.
        $out = $Prompt | & claude -p --output-format json --tools '' --strict-mcp-config --system-prompt-file $sysFile.FullName
        if ($LASTEXITCODE -ne 0) { throw "claude -p failed (exit $LASTEXITCODE). Run 'claude' once in a terminal to check that it is signed in." }
        $r = ($out -join "`n") | ConvertFrom-Json -Depth 20
        if ($r.is_error -or -not $r.result) { throw "claude -p returned an error: $([string]$r.subtype)" }
        [string]$r.result
    } finally { Remove-R360FileSecurely -Path $sysFile.FullName }
}

function Add-IssueComment([int]$Number, [string]$Body) {
    $tmp = New-TemporaryFile
    try {
        @{ body = $Body } | ConvertTo-Json -Compress | Set-Content -Path $tmp.FullName -Encoding utf8 -NoNewline
        Invoke-R360Gh -Arguments @('api', '-X', 'POST', "repos/$Repo/issues/$Number/comments", '--input', $tmp.FullName) | Out-Null
    } finally { Remove-Item $tmp.FullName -Force -ErrorAction SilentlyContinue }
}

function Clear-RequestLabel([int]$Number) {
    Invoke-R360Gh -Arguments @('api', '-X', 'DELETE', "repos/$Repo/issues/$Number/labels/$RequestedLabel") -AllowFailure | Out-Null
}

function Get-Requester([int]$Number) {
    $comments = @(Invoke-R360Gh -Arguments @('api', "repos/$Repo/issues/$Number/comments?per_page=100", '--paginate', '--slurp') | ForEach-Object { $_ } | ForEach-Object { $_ })
    for ($i = $comments.Count - 1; $i -ge 0; $i--) {
        if ([string]$comments[$i].body -match '<!-- r360:summary-request (\{[^\n]*?\}) -->') {
            try { return [string](($Matches[1] | ConvertFrom-Json).by) } catch { break }
        }
    }
    'r360'
}

$script:failures = @{}
function Invoke-WatchPass {
    $issues = @(Invoke-R360Gh -Arguments @('api', "repos/$Repo/issues?labels=$RequestedLabel&state=open&per_page=50") | ForEach-Object { $_ })
    $issues = @($issues | Where-Object { -not $_.PSObject.Properties['pull_request'] -and (@($_.labels.name) -contains $ChangeLabel) })
    if (-not $issues.Count) { return 0 }
    Connect-WatchGraph
    foreach ($i in $issues) {
        $n = [int]$i.number
        $chg = "R360-CHG-$n"
        try {
            Write-WatchLog "$chg summary requested: working"
            $by = Get-Requester -Number $n
            # ConvertFrom-Json may already have turned created_at into a DateTime.
            $created = if ($i.created_at -is [datetime]) { $i.created_at.ToUniversalTime() } else { [datetimeoffset]::Parse([string]$i.created_at).UtcDateTime }
            $mail = Get-ChangeMail -Since $created.AddHours(-1)
            $prep = Invoke-Helper -Mode 'prompt' -InputObject @{ number = $n; messages = $mail.Messages }
            if ([int]$prep.emails -eq 0) {
                Add-IssueComment -Number $n -Body (Invoke-Helper -Mode 'nomail' -InputObject @{ number = $n }).body
                Clear-RequestLabel -Number $n
                Write-WatchLog "$chg no matching emails in $Mailbox; told the issue and removed the label"
                continue
            }
            $text = Invoke-Claude -System $prep.system -Prompt $prep.prompt
            $body = (Invoke-Helper -Mode 'comment' -InputObject @{ number = $n; text = $text; emails = [int]$prep.emails; by = $by; truncated = $mail.Truncated }).body
            Add-IssueComment -Number $n -Body $body
            Clear-RequestLabel -Number $n
            $script:failures.Remove($n)
            Write-WatchLog "$chg summary of $($prep.emails) email(s) posted for $by"
        } catch {
            $count = 1 + [int]($script:failures[$n] ?? 0)
            $script:failures[$n] = $count
            $reason = ([string]$_.Exception.Message -replace '[\r\n]+', ' ')
            if ($reason.Length -gt 300) { $reason = $reason.Substring(0, 300) }
            Write-WatchLog "$chg attempt $count failed: $reason"
            if ($count -ge $MaxFailures) {
                $safe = $reason -replace '<', '&lt;' -replace '>', '&gt;' -replace '@', "@$([char]0x200B)"
                Add-IssueComment -Number $n -Body "### Summary not made`n`nThe summary watcher on DEVICE02 failed $count times: $safe`n`nFix the cause, then click **Summarize now** again in r360."
                Clear-RequestLabel -Number $n
                $script:failures.Remove($n)
            }
        }
    }
    $issues.Count
}

function Test-WatchPrerequisite {
    $rows = foreach ($c in 'claude', 'gh', 'node', 'git') {
        $cmd = Get-Command $c -ErrorAction SilentlyContinue
        [pscustomobject]@{ Check = $c; Status = ($cmd ? 'OK' : 'MISSING'); Detail = ($cmd ? $cmd.Source : "install $c and put it on PATH") }
    }
    $mg = Get-Module -ListAvailable Microsoft.Graph.Authentication
    $rows += [pscustomobject]@{ Check = 'Microsoft.Graph.Authentication'; Status = ($mg ? 'OK' : 'MISSING'); Detail = ($mg ? "$($mg[0].Version)" : 'Install-Module Microsoft.Graph.Authentication -Scope CurrentUser') }
    $rows
}

$mode = if ($Install) { 'Install' } elseif ($Once) { 'Once' } elseif ($Run) { 'Run' } elseif ($Remove) { 'Remove' } else { [void]$Status; 'Status' }
switch ($mode) {
    'Run' {
        Write-WatchLog "watcher started on $env:COMPUTERNAME, checking $Repo every $IntervalSeconds s"
        while ($true) {
            try { Invoke-WatchPass | Out-Null }
            catch {
                Write-WatchLog "pass failed: $(([string]$_.Exception.Message -replace '[\r\n]+', ' '))"
                Start-Sleep -Seconds 300
            }
            Start-Sleep -Seconds $IntervalSeconds
        }
    }
    'Once' {
        $count = Invoke-WatchPass
        Write-Host ($count ? "Handled $count requested summary(ies). See $LogFile" : 'No changes are waiting for a summary.')
    }
    'Status' {
        $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($t) {
            $info = $t | Get-ScheduledTaskInfo
            [pscustomobject]@{ Task = $TaskName; State = $t.State; LastRun = $info.LastRunTime; LastResult = $info.LastTaskResult; Runs = ($t.Actions[0].Arguments) } | Format-List
        } else { Write-Host "Scheduled task '$TaskName' is not installed. Run: pwsh -File .\tools\Watch-R360Summaries.ps1 -Install -Apply" -ForegroundColor Yellow }
        if (Test-Path $LogFile) { Write-Host "Last log lines ($LogFile):"; Get-Content $LogFile -Tail 15 }
    }
    'Remove' {
        $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if (-not $t) { Write-Host "Scheduled task '$TaskName' is not installed."; break }
        if (-not $Apply) { Write-Host "DRY RUN: would stop and unregister '$TaskName'. Add -Apply."; break }
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Removed '$TaskName'. $WatcherPath is left in place; delete it with: git -C $RepoRoot worktree remove --force $WatcherPath"
    }
    'Install' {
        if ($env:COMPUTERNAME -ne 'DEVICE02') { throw "Run this on DEVICE02 (this is $env:COMPUTERNAME)." }
        Write-R360Step ($Apply ? 'APPLY: changes will be made' : 'DRY RUN: nothing will be changed (add -Apply)')
        $pre = @(Test-WatchPrerequisite)
        $pre | Format-Table -AutoSize | Out-Host
        if ($pre.Status -contains 'MISSING') { throw 'Install the missing items above, then rerun.' }
        if (-not (Invoke-R360Gh -Arguments @('api', "repos/$Repo", '--jq', '.full_name') -AllowFailure)) { throw "gh cannot read $Repo. Run: gh auth login" }
        $claudeVersion = (& claude --version 2>$null) -join ' '
        Write-R360Step "Claude Code: $claudeVersion"
        if (-not $Apply) {
            Write-Host "Would: sign in to Graph (Mail.Read.Shared, delegated) and test reading $Mailbox; put origin/main in $WatcherPath and run npm ci there; register '$TaskName' (at logon, pwsh -File $WatcherPath\tools\Watch-R360Summaries.ps1 -Run) and start it."
            break
        }
        Write-R360Step 'Signing in to Microsoft Graph (your account, delegated Mail.Read.Shared). A browser may open once.'
        Connect-WatchGraph
        $box = [uri]::EscapeDataString($Mailbox)
        try { Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$box/messages?`$top=1&`$select=id" -OutputType PSObject | Out-Null }
        catch { throw "Your account cannot read $Mailbox yet. It needs Full Access: run pwsh -File .\tools\Set-R360ChangeRequests.ps1 -Apply first. ($($_.Exception.Message))" }
        Write-R360Step "Graph can read $Mailbox"

        Write-R360Step "Updating $WatcherPath from origin/main"
        & git -C $RepoRoot fetch origin main --quiet
        if ($LASTEXITCODE -ne 0) { throw 'git fetch origin main failed.' }
        if (Test-Path (Join-Path $WatcherPath '.git')) { & git -C $WatcherPath checkout --detach --force origin/main --quiet }
        else { & git -C $RepoRoot worktree add --detach --force $WatcherPath origin/main --quiet }
        if ($LASTEXITCODE -ne 0) { throw "Could not put origin/main in $WatcherPath." }
        if (-not (Test-Path (Join-Path $WatcherPath 'tools\summarize-change.mjs'))) { throw "origin/main has no tools/summarize-change.mjs yet. Merge the change requests pull request first." }
        Push-Location $WatcherPath
        try { & npm ci --omit=dev --no-audit --no-fund --loglevel=error; if ($LASTEXITCODE -ne 0) { throw 'npm ci failed.' } } finally { Pop-Location }

        $pwsh = (Get-Command pwsh).Source
        $scriptPath = Join-Path $WatcherPath 'tools\Watch-R360Summaries.ps1'
        $action = New-ScheduledTaskAction -Execute $pwsh -Argument "-NoProfile -WindowStyle Hidden -File `"$scriptPath`" -Run -Mailbox $Mailbox -Repo $Repo -IntervalSeconds $IntervalSeconds" -WorkingDirectory $WatcherPath
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited
        if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false }
        Register-ScheduledTask -TaskName $TaskName -Description 'r360: makes requested change summaries with Claude Code until r360 has an AI provider key. Remove with tools\Watch-R360Summaries.ps1 -Remove -Apply.' -Action $action -Trigger $trigger -Settings $settings -Principal $principal | Out-Null
        Start-ScheduledTask -TaskName $TaskName
        Write-R360Step "Installed and started '$TaskName'. It checks every $IntervalSeconds seconds while you are signed in to DEVICE02."
        Write-Host "Check it with: pwsh -File .\tools\Watch-R360Summaries.ps1 -Status"
    }
}
