# uses:
# An LDAPS login without channel binding needs a login client that can leave the binding out (Windows always adds it)
# and a test account. Until that client is built this test reports COULD NOT TEST, never PASS.
Add-Detail 'Windows always sends channel binding on LDAPS, so the attempt needs its own login client and a test account.'
Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'needs its own LDAPS login client, which is not built yet.'
