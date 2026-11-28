# uses: Ad, Net
# Opens the spoolss named pipe on each DC and closes it again; no print call is made. A DC with the spooler stopped has
# no such pipe, so the open times out.
if (-not (Test-DomainJoined)) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'this machine is not joined to an AD domain.' }
$ctx = Get-AdContext
$dcs = @(Get-DomainController -Context $ctx)
if ($dcs.Count -eq 0) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'no domain controller was found in AD.' }
$open = @(); $unreachable = @()
foreach ($dc in $dcs) {
    $name = [string]$dc.dnshostname
    if (-not (Test-TcpPort -Target $name -Port 445)) { Add-Detail "$($dc.name): port 445 not reachable"; $unreachable += $dc.name; continue }
    $pipe = New-Object -TypeName System.IO.Pipes.NamedPipeClientStream -ArgumentList $name, 'spoolss', ([System.IO.Pipes.PipeDirection]::InOut)
    try {
        $pipe.Connect(3000)
        $state = 'spoolss pipe open'
    } catch [System.TimeoutException] {
        $state = 'no spoolss pipe'
    } catch [System.UnauthorizedAccessException] {
        $state = 'spoolss pipe present (access denied)'
    } catch {
        $state = "no spoolss pipe ($($_.Exception.GetType().Name))"
    } finally {
        $pipe.Dispose()
    }
    Add-Detail "$($dc.name): $state"
    if ($state -like 'spoolss pipe*') { $open += $dc.name }
}
if ($open.Count -gt 0) { Write-Verdict -Verdict 'FAIL' -Summary "Print Spooler answers on $($open.Count) of $($dcs.Count) DCs: $($open -join ', ')." }
if ($unreachable.Count -gt 0) { Write-Verdict -Verdict 'COULD NOT TEST' -Summary "could not reach $($unreachable -join ', ')." }
Write-Verdict -Verdict 'PASS' -Summary "no spoolss pipe on any of the $($dcs.Count) DCs."
