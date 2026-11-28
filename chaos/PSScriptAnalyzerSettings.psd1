# Same rules as the remediations repo, where these scripts end up: Windows PowerShell 5.1 and PowerShell 7.4.
@{
    # Fail the PR on Error and Warning. Information is reported but does not fail.
    Severity            = @('Error', 'Warning')
    IncludeDefaultRules = $true
    # Security rules are all in the default set; listed here so nobody "excludes" one quietly.
    # Do not add any of these to ExcludeRules without a second reviewer.
    # PSAvoidUsingPlainTextForPassword, PSAvoidUsingConvertToSecureStringWithPlainText,
    # PSAvoidUsingUsernameAndPasswordParams, PSUsePSCredentialType, PSAvoidUsingInvokeExpression,
    # PSAvoidUsingComputerNameHardcoded, PSAvoidUsingAllowUnencryptedAuthentication,
    # PSAvoidUsingBrokenHashAlgorithms, PSAvoidGlobalVars, PSAvoidUsingEmptyCatchBlock
    ExcludeRules        = @(
        # Tools are interactive console scripts; device scripts use Write-Output.
        'PSAvoidUsingWriteHost'
    )
    Rules               = @{
        PSUseCompatibleSyntax = @{ Enable = $true; TargetVersions = @('5.1', '7.4') }
    }
}
