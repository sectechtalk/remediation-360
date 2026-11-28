# uses: Reg
$enabled = (Get-SmbServerConfiguration).EnableSMB1Protocol
$feature = 'unknown'
try {
    $f = Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -ErrorAction Stop
    $feature = [string]$f.State
} catch {
    $start = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' -Name 'Start'
    $feature = if ($null -eq $start) { 'Disabled (no SMB1 driver)' } elseif ($start -eq 4) { 'Disabled (driver disabled)' } else { 'Enabled (SMB1 driver present)' }
}
Add-Detail "EnableSMB1Protocol = $enabled; SMB1 feature = $feature"
if (-not $enabled -and $feature -like 'Disabled*') { Write-Verdict -Verdict 'PASS' -Summary 'SMB1 is off and its feature is not installed.' }
Write-Verdict -Verdict 'FAIL' -Summary "SMB1 is still present (EnableSMB1Protocol = $enabled, feature $feature)."
