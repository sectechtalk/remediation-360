# uses: Reg
$build = [int](Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'CurrentBuildNumber')
Add-Detail "Windows build $build"
if ($build -ge 26100) { Write-Verdict -Verdict 'PASS' -Summary "Windows build $build (Windows 11 24H2 / Server 2025 or later) has no NTLMv1 at all." }
$lm = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel'
$cli = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'NtlmMinClientSec'
$srv = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'NtlmMinServerSec'
Add-Detail "LmCompatibilityLevel = $(if ($null -eq $lm) { 'not set' } else { $lm }); NtlmMinClientSec = $(if ($null -eq $cli) { 'not set' } else { '0x{0:X8}' -f [int64]$cli }); NtlmMinServerSec = $(if ($null -eq $srv) { 'not set' } else { '0x{0:X8}' -f [int64]$srv })"
$need = 0x20080000
$ok = ($lm -eq 5) -and ($null -ne $cli) -and (([int64]$cli -band $need) -eq $need) -and ($null -ne $srv) -and (([int64]$srv -band $need) -eq $need)
if ($ok) { Write-Verdict -Verdict 'PASS' -Summary 'LmCompatibilityLevel 5 with NTLMv2 session security and 128-bit required both ways.' }
Write-Verdict -Verdict 'FAIL' -Summary 'this Windows still has NTLMv1 and is not set to refuse it (LmCompatibilityLevel 5, NtlmMinClientSec/NtlmMinServerSec 0x20080000).'
