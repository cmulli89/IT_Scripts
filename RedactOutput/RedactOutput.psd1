@{
    RootModule            = 'RedactOutput.psm1'
    ModuleVersion         = '0.1.0'
    GUID                  = 'ca02221e-5a85-4b40-9c47-bf0e9165d9ca'
    Author                = 'Carl'
    Description           = 'Redact secrets and environment identifiers from text (script output, JSON, logs, .env files) before it leaves the security boundary, for example before pasting into a commercial AI chat. Secrets become [secret:type] tokens; identifiers become stable [type-NN] tokens.'
    PowerShellVersion     = '7.2'
    CompatiblePSEditions  = @('Core')
    FunctionsToExport     = @(
        'Protect-Output',
        'Test-RedactionResidual',
        'Restore-RedactedText',
        'Get-RedactionMap'
    )
    CmdletsToExport       = @()
    VariablesToExport     = @()
    AliasesToExport       = @('redact')
    PrivateData = @{
        PSData = @{
            Tags = @('Redaction', 'CMMC', 'GCCHigh', 'Secrets')
        }
    }
}
