# uses: Ad
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$d = @(Find-AdObject -SearchBase $ctx.DomainDn -Filter '(objectClass=*)' -Property 'msds-behavior-version' -Scope Base)[0]
$level = [int]$d.'msds-behavior-version'
$label = @{ 0 = '2000'; 1 = '2003 interim'; 2 = '2003'; 3 = '2008'; 4 = '2008 R2'; 5 = '2012'; 6 = '2012 R2'; 7 = '2016'; 10 = '2025' }[$level]
if ($level -ge 7) { Write-Verdict -Verdict 'PASS' -Summary "the domain is at the $label level ($level)." }
Write-Verdict -Verdict 'FAIL' -Summary "the domain is at the $label level ($level); LAPS encryption and DSRM backup need 2016 (7)."
