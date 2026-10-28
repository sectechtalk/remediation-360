# Rebuilds tests/data/signed-c0ffee00.zip: a fake "Sign and Verify" artifact for the tests.
# Uses a throwaway, in-memory, self-signed test certificate (never stored, never trusted anywhere) and a fake commit.
# Input: a directory laid out like the artifact (manifest-signed.json + remediations/<folder>/...).
# The scripts keep a placeholder signature block; only the manifest signature is real (RSA-SHA256 with the test key).
param([Parameter(Mandatory)][string]$Source, [string]$Out = (Join-Path $PSScriptRoot 'signed-c0ffee00.zip'),
      [string]$Commit = 'c0ffee0000000000000000000000000000000001')
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression
$sha = { param($bytes) -join ([Security.Cryptography.SHA256]::HashData([byte[]]$bytes) | ForEach-Object { $_.ToString('x2') }) }
$rsa = [Security.Cryptography.RSA]::Create(3072)
$req = [Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=Example Code Signing (test fixture)', $rsa, 'SHA256', [Security.Cryptography.RSASignaturePadding]::Pkcs1)
$cert = $req.CreateSelfSigned([DateTimeOffset]'2026-10-26T05:45:48Z', [DateTimeOffset]'2029-10-26T12:55:48Z')
$m = Get-Content -Raw (Join-Path $Source 'manifest-signed.json') | ConvertFrom-Json
$entries = [ordered]@{}
foreach ($f in $m.files) {
  $bytes = [IO.File]::ReadAllBytes((Join-Path $Source $f.path))
  if ($f.type -eq 'script') {
    $t = [Text.Encoding]::UTF8.GetString($bytes)
    $i = $t.IndexOf('# SIG # Begin signature block')
    $t = $t.Substring(0, $i) + "# SIG # Begin signature block`r`n# VGVzdCBmaXh0dXJlLCBub3QgYSByZWFsIHNpZ25hdHVyZQ==`r`n# SIG # End signature block`r`n"
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($t)
    $f.signedSha256 = & $sha $bytes
    $f.timestampAuthority = 'http://timestamp.example.com'
  } else { $f.sha256 = & $sha $bytes }
  $entries[$f.path] = $bytes
}
$m.commit = $Commit
$m.signer.thumbprint = $cert.Thumbprint
$m.signer.subject = $cert.Subject
$manifest = [Text.UTF8Encoding]::new($false).GetBytes(($m | ConvertTo-Json -Depth 6))
$sig = [Convert]::ToBase64String($rsa.SignData($manifest, 'SHA256', [Security.Cryptography.RSASignaturePadding]::Pkcs1))
$all = [ordered]@{ 'manifest-signed.json' = $manifest; 'manifest-signed.sig' = [Text.Encoding]::ASCII.GetBytes($sig); 'r360-codesign.cer' = $cert.RawData }
foreach ($k in $entries.Keys) { $all[$k] = $entries[$k] }
$fs = [IO.File]::Create($Out); $zip = [IO.Compression.ZipArchive]::new($fs, 'Create')
foreach ($k in $all.Keys) { $s = $zip.CreateEntry($k).Open(); $s.Write($all[$k], 0, $all[$k].Length); $s.Dispose() }
$zip.Dispose(); $fs.Dispose()
[pscustomobject]@{ Out = $Out; Commit = $Commit; Thumbprint = $cert.Thumbprint }