# uses: Laps
$p = Get-LapsPolicy
if ($null -eq $p) { Write-Verdict -Verdict 'FAIL' -Summary 'no LAPS policy reaches this machine.' }
$length = [int](Get-LapsSetting -Policy $p -Name 'PasswordLength' -Default 14)
$complexity = [int](Get-LapsSetting -Policy $p -Name 'PasswordComplexity' -Default 4)
$words = [int](Get-LapsSetting -Policy $p -Name 'PassphraseLength' -Default 6)
Add-Detail "Policy from $($p.Source); PasswordLength = $length; PasswordComplexity = $complexity; PassphraseLength = $words"
if ($complexity -in 6, 7, 8) {
    if ($words -ge 6) { Write-Verdict -Verdict 'PASS' -Summary "a passphrase of $words words." }
    Write-Verdict -Verdict 'FAIL' -Summary "the passphrase has only $words words (6 or more needed)."
}
if ($length -ge 14 -and $complexity -ge 4) { Write-Verdict -Verdict 'PASS' -Summary "$length characters with all four character types." }
Write-Verdict -Verdict 'FAIL' -Summary "the password is too weak ($length characters, complexity $complexity; 14 and 4 needed)."
