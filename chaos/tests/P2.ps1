# uses:
$dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName 'Win32_DeviceGuard' -ErrorAction SilentlyContinue
if ($null -eq $dg) { Write-Verdict -Verdict 'FAIL' -Summary 'Device Guard information is not available, so Credential Guard is not running.' }
Add-Detail "SecurityServicesConfigured = $(@($dg.SecurityServicesConfigured) -join ','); SecurityServicesRunning = $(@($dg.SecurityServicesRunning) -join ',')"
if (@($dg.SecurityServicesRunning) -contains 1) { Write-Verdict -Verdict 'PASS' -Summary 'Credential Guard is running.' }
Write-Verdict -Verdict 'FAIL' -Summary "Credential Guard is not running$(if (@($dg.SecurityServicesConfigured) -contains 1) { ' (configured, but not running)' })."
