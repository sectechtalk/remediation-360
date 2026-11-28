# uses: Ad
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$a = @(Find-AdObject -SearchBase $ctx.DomainDn -Filter '(sAMAccountName=AZUREADSSOACC$)' -Property 'samaccountname', 'pwdlastset', 'msds-supportedencryptiontypes', 'useraccountcontrol', 'msds-allowedtodelegateto' -WithAcl)
if ($a.Count -eq 0) { Write-Verdict -Verdict 'PASS' -Summary 'Seamless SSO is not used (no AZUREADSSOACC account).' }
$a = $a[0]
$why = @()
$set = ConvertFrom-FileTime -Value $a.pwdlastset
Add-Detail "Password last set: $(if ($set) { $set.ToString('yyyy-MM-dd') } else { 'never' })"
if ($null -eq $set -or $set -lt (Get-Date).ToUniversalTime().AddDays(-30)) { $why += 'key not changed in the last 30 days' }
$et = $a.'msds-supportedencryptiontypes'
if ($null -eq $et -or ([int]$et -band 0x7) -or -not ([int]$et -band 0x18)) { $why += "not AES only (msDS-SupportedEncryptionTypes = $(if ($null -eq $et) { 'not set' } else { '0x{0:X}' -f [int]$et }))" }
if (([int64]$a.useraccountcontrol -band (0x80000 -bor 0x1000000)) -or $a.'msds-allowedtodelegateto') { $why += 'delegation is allowed' }
$allowed = Get-AdminSid -Context $ctx
$writers = @((Get-AdAclRule -AdObject $a).Rules | Where-Object { $allowed -notcontains $_.IdentityReference.Value -and (Test-WriteRule -Rule $_) } | ForEach-Object { $_.IdentityReference.Value } | Sort-Object -Unique)
if ($writers.Count) { $why += "writable by $(Format-SidList -Sid $writers)" }
if ($why.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "AZUREADSSOACC: $($why -join '; ')." }
Write-Verdict -Verdict 'PASS' -Summary 'the Seamless SSO account is AES only, recently rotated, not delegable and admin-only.'
