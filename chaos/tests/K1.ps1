# uses: Ad
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$cutoff = (Get-Date).ToUniversalTime().AddDays(-365)
$bad = foreach ($u in Find-AdObject -SearchBase $ctx.DomainDn -Filter '(&(samAccountType=805306368)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(sAMAccountName=krbtgt)))' -Property 'samaccountname', 'msds-supportedencryptiontypes', 'pwdlastset') {
    $why = @()
    $et = $u.'msds-supportedencryptiontypes'
    if ($null -eq $et) { $why += 'no encryption types set (domain default)' } elseif (([int]$et -band 4) -or -not ([int]$et -band 0x18)) { $why += "allows RC4 (0x$('{0:X}' -f [int]$et))" }
    $set = ConvertFrom-FileTime -Value $u.pwdlastset
    if ($null -eq $set -or $set -lt $cutoff) { $why += "password last set $(if ($set) { $set.ToString('yyyy-MM-dd') } else { 'never' })" }
    if ($why.Count) { "$($u.samaccountname): $($why -join ', ')" }
}
$bad = @($bad)
if ($bad.Count -gt 0) { $bad | Select-Object -First 20 | ForEach-Object { Add-Detail $_ }; Write-Verdict -Verdict 'FAIL' -Summary "$($bad.Count) user account(s) with a service name can be Kerberoasted." }
Write-Verdict -Verdict 'PASS' -Summary 'every enabled user account with a service name is AES only with a password under a year old.'
