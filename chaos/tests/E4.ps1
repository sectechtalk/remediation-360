# uses:
# An HTTPS login without Extended Protection needs a login client that can leave the channel binding out (Windows adds
# it) and a test account. Until that client is built this test reports COULD NOT TEST, never PASS.
Add-Detail 'Windows adds channel binding to HTTPS logins, so the attempt needs its own login client and a test account.'
Add-Detail 'E1 and E2 cover the HTTP and HTTPS side of the same pages.'
Write-Verdict -Verdict 'COULD NOT TEST' -Summary 'needs its own HTTPS login client, which is not built yet.'
