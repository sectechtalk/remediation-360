# uses: Reg
$ppl = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL'
$pplBoot = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPLBoot'
Add-Detail "RunAsPPL = $(if ($null -eq $ppl) { 'not set' } else { $ppl }); RunAsPPLBoot = $(if ($null -eq $pplBoot) { 'not set' } else { $pplBoot })"
$boot = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
$started = $false
try {
    $started = [bool](Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Wininit'; Id = 12; StartTime = $boot } -MaxEvents 1 -ErrorAction Stop)
} catch {
    if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') { throw }
}
Add-Detail "Wininit event 12 (LSASS started as a protected process) since boot: $(if ($started) { 'yes' } else { 'no' })"
if ($ppl -in 1, 2 -or $pplBoot -in 1, 2 -or $started) { Write-Verdict -Verdict 'PASS' -Summary 'LSA protection is on.' }
Write-Verdict -Verdict 'FAIL' -Summary 'LSA protection is off (RunAsPPL is not 1 or 2).'
