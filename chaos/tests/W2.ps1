# uses: Laps
$p = Get-LapsPolicy
if ($null -eq $p) { Write-Verdict -Verdict 'FAIL' -Summary 'no LAPS policy reaches this machine.' }
Add-Detail "Policy from $($p.Source)"
if ($p.Legacy) { Write-Verdict -Verdict 'FAIL' -Summary 'the legacy Microsoft LAPS policy stores the password in AD as clear text.' }
$dir = [int](Get-LapsSetting -Policy $p -Name 'BackupDirectory' -Default 0)
if ($dir -eq 1) { Write-Verdict -Verdict 'PASS' -Summary 'the password is backed up to Entra ID, not AD.' }
if ($dir -ne 2) { Write-Verdict -Verdict 'FAIL' -Summary 'LAPS does not back up the password (BackupDirectory is 0).' }
$enc = Get-LapsSetting -Policy $p -Name 'ADPasswordEncryptionEnabled' -Default 1
Add-Detail "ADPasswordEncryptionEnabled = $enc$(if (-not $p.Values.ContainsKey('ADPasswordEncryptionEnabled')) { ' (default)' })"
if ([int]$enc -eq 1) { Write-Verdict -Verdict 'PASS' -Summary 'the password is backed up to AD encrypted (needs domain level 2016, see G6).' }
Write-Verdict -Verdict 'FAIL' -Summary 'the password is backed up to AD as clear text (ADPasswordEncryptionEnabled = 0).'
