# uses: Laps, Event
$p = Get-LapsPolicy
if ($null -eq $p) { Write-Verdict -Verdict 'FAIL' -Summary 'no LAPS policy reaches this machine.' }
if ($p.Legacy) { $dir = if ((Get-LapsSetting -Policy $p -Name 'AdmPwdEnabled' -Default 0) -eq 1) { 2 } else { 0 } } else { $dir = [int](Get-LapsSetting -Policy $p -Name 'BackupDirectory' -Default 0) }
$age = [int](Get-LapsSetting -Policy $p -Name 'PasswordAgeDays' -Default 30)
Add-Detail "Policy from $($p.Source); backup to $(@('nowhere (disabled)', 'Entra ID', 'Active Directory')[[Math]::Min($dir, 2)]); password age $age days"
if ($dir -notin 1, 2) { Write-Verdict -Verdict 'FAIL' -Summary 'LAPS does not back up the password (BackupDirectory is 0).' }
$window = [Math]::Max(30, $age + 1)
$events = Get-RecentEvent -LogName 'Microsoft-Windows-LAPS/Operational' -Id 10018, 10029 -Since (Get-Date).AddDays(-$window) -MaxEvents 1
if ($events.Count -eq 0) { Write-Verdict -Verdict 'FAIL' -Summary "no successful LAPS password backup (event 10018 or 10029) in the last $window days." }
Write-Verdict -Verdict 'PASS' -Summary "LAPS rotated and backed up the password on $($events[0].TimeCreated.ToString('yyyy-MM-dd'))."
