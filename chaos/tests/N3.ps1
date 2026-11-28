# uses:
# An NTLMv1 login needs a login client that still speaks NTLMv1 and a test account to log in with. Windows 11 24H2
# and Server 2025 removed NTLMv1, so Windows itself cannot make the attempt. Until that client is built this test
# reports COULD NOT TEST, never PASS.
Add-Detail 'Windows on this machine cannot send NTLMv1, so the attempt needs its own login client and a test account.'
Add-Detail 'Until then, N1 (this machine) and N2 (no NTLMv1 logons) show the configuration side.'
Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'needs its own NTLMv1 login client, which is not built yet.'
