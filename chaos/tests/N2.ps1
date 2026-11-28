# uses:
# Counts successful logons (Security event 4624) that used NTLM V1 in the last 7 days.
$xpath = "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= 604800000]]] and *[EventData[Data[@Name='LmPackageName']='NTLM V1']]"
try {
    $events = @(Get-WinEvent -LogName 'Security' -FilterXPath $xpath -MaxEvents 1000 -ErrorAction Stop)
} catch {
    if ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound') { $events = @() } else { throw }
}
if ($events.Count -eq 0) { Write-Verdict -Verdict 'PASS' -Summary 'no NTLMv1 logon in the Security log in the last 7 days.' }
$from = @($events | ForEach-Object { ([xml]$_.ToXml()).Event.EventData.Data | Where-Object { $_.Name -eq 'WorkstationName' } | ForEach-Object { $_.'#text' } } | Where-Object { $_ } | Sort-Object -Unique)
Add-Detail "From workstations: $(($from | Select-Object -First 10) -join ', ')"
Write-Verdict -Verdict 'FAIL' -Summary "$($events.Count) NTLMv1 logon(s) in the last 7 days."
