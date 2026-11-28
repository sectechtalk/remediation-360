# uses:
$cse = Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}'
$dll = Test-Path -LiteralPath (Join-Path -Path $env:ProgramFiles -ChildPath 'LAPS\CSE\AdmPwd.dll')
Add-Detail "Legacy LAPS Group Policy extension registered: $cse; AdmPwd.dll present: $dll"
if (-not $cse -and -not $dll) { Write-Verdict -Verdict 'PASS' -Summary 'the legacy LAPS client is not installed.' }
Write-Verdict -Verdict 'FAIL' -Summary 'the legacy LAPS client is still installed.'
