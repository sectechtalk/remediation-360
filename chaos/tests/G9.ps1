# uses: Ad, Sysvol
# "Domain controller: Refuse setting default machine account password" is a Server 2025 security option, written to
# GptTmpl.inf under Netlogon\Parameters. The match below looks for that Netlogon value by its words, because the setting
# is new; on Server 2025 DCs the refusal is also the default.
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$hits = @(Find-DcGpoRegistryValue -Context $ctx -Pattern 'Netlogon\\Parameters\\[^=]*Default[^=]*(?:Machine|Pwd|Password)[^=]*')
$hits | ForEach-Object { Add-Detail "GPO $($_.Gpo): $($_.Key) = $($_.Value)" }
$dcs = @(Get-DomainController -Context $ctx)
$older = @($dcs | Where-Object { [string]$_.operatingsystem -notlike '*2025*' } | ForEach-Object { [string]$_.name })
Add-Detail "DCs older than Server 2025: $(if ($older.Count) { $older -join ', ' } else { 'none' })"
if ($hits | Where-Object { $_.Value -eq '0' }) { Write-Verdict -Verdict 'FAIL' -Summary 'a DC policy turns the refusal off.' }
if ($hits | Where-Object { $_.Value -eq '1' }) { Write-Verdict -Verdict 'PASS' -Summary 'a DC policy refuses default machine account passwords.' }
if ($older.Count -eq 0) { Write-Verdict -Verdict 'PASS' -Summary 'no GPO sets it, but every DC runs Server 2025, which refuses by default.' }
Write-Verdict -Verdict 'FAIL' -Summary "no DC policy refuses default machine passwords and $($older.Count) DC(s) predate Server 2025."
