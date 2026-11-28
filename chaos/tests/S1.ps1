# uses:
$client = (Get-SmbClientConfiguration).RequireSecuritySignature
$server = (Get-SmbServerConfiguration).RequireSecuritySignature
Add-Detail "SMB client RequireSecuritySignature = $client; SMB server RequireSecuritySignature = $server"
if ($client -and $server) { Write-Verdict -Verdict 'PASS' -Summary 'SMB signing is required in and out.' }
$missing = @()
if (-not $client) { $missing += 'outgoing' }
if (-not $server) { $missing += 'incoming' }
Write-Verdict -Verdict 'FAIL' -Summary "SMB signing is not required for $($missing -join ' and ') connections."
