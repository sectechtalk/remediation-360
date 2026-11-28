# uses: Laps
$p = Get-LapsPolicy
if ($null -eq $p) { Write-Verdict -Verdict 'FAIL' -Summary 'no LAPS policy reaches this machine.' }
if ($p.Legacy) { Write-Verdict -Verdict 'FAIL' -Summary 'the legacy Microsoft LAPS policy has no reset after use.' }
$delay = [int](Get-LapsSetting -Policy $p -Name 'PostAuthenticationResetDelay' -Default 24)
$action = [int](Get-LapsSetting -Policy $p -Name 'PostAuthenticationActions' -Default 3)
Add-Detail "Policy from $($p.Source); PostAuthenticationResetDelay = $delay hours; PostAuthenticationActions = $action"
if ($delay -lt 1 -or $delay -gt 24) { Write-Verdict -Verdict 'FAIL' -Summary "a used password is not reset within a day (delay $delay hours; 0 turns the reset off)." }
if (-not (($action -band 1) -and ($action -band 6))) { Write-Verdict -Verdict 'FAIL' -Summary "after use the password is not reset with a sign-out or restart (PostAuthenticationActions = $action)." }
Write-Verdict -Verdict 'PASS' -Summary "a used password is reset within $delay hours."
