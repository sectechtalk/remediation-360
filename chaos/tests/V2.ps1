# uses: Reg
$cfg = Get-SmbClientConfiguration
$block = if ($cfg.PSObject.Properties['BlockNTLM']) { [bool]$cfg.BlockNTLM } else { $null }
$policy = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' -Name 'BlockNTLM'
$except = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' -Name 'BlockNTLMServerExceptionList'
Add-Detail "SMB client BlockNTLM = $(if ($null -eq $block) { 'not supported by this Windows (needs 11 24H2 or Server 2025)' } else { $block }); policy BlockNTLM = $(if ($null -eq $policy) { 'not set' } else { $policy })"
if ($except) { Add-Detail "Exceptions: $(@($except) -join ', ')" }
if ($block -or $policy -eq 1) { Write-Verdict -Verdict 'PASS' -Summary 'the SMB client never sends NTLM.' }
Write-Verdict -Verdict 'FAIL' -Summary 'the SMB client may still fall back to NTLM.'
