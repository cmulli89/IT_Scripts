<#
    RedactOutput.psm1

    Scrubs secrets and environment identifiers out of text that is about to be
    shared outside the security boundary (script output, Graph JSON, logs,
    .env files, ...). Secrets become [secret:type] tokens; identifiers become
    stable [type-NN] tokens. No import side effects: no file IO, no changes to
    preference variables.

    Lessons folded in from earlier one-off scrubbers:
      - The JSON key-name walker (Open WebUI config exports): a property whose
        NAME looks secret has its value replaced, whatever the value is. This
        is rule S04 plus the structure-aware JSON path.
      - The bash redact() used in Run Command captures: KEY/SECRET/PASSWORD/
        TOKEN env lines and user:pass@ in URLs, tested against ENABLE_SIGNUP
        and plain URLs that must stay untouched (tests/Fixtures/bash-env.env).
      - The OpenSCAP facts collector's "values redacted" output: counts and
        shapes may be reported, identities and values never are.
#>

Set-StrictMode -Version Latest

foreach ($scope in 'Private', 'Public') {
    $files = Get-ChildItem -Path (Join-Path $PSScriptRoot $scope) -Filter '*.ps1' -File | Sort-Object -Property Name
    foreach ($file in $files) { . $file.FullName }
}

Set-Alias -Name redact -Value Protect-Output

Export-ModuleMember -Function Protect-Output, Test-RedactionResidual -Alias redact
