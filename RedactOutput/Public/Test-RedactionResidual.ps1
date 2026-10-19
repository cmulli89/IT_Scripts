function Test-RedactionResidual {
    <#
    .SYNOPSIS
        Rescans text or a file for anything that still looks sensitive. Report-only.

    .DESCRIPTION
        Runs every detection rule in detect-only mode plus the high-entropy check (S17) and returns one
        object per finding with Category, Line, Column and Length. It never returns or logs the matched
        value, and writes nothing. Hash-shaped values (GUID, 32/40/64 hex) are not findings.

    .PARAMETER Text
        Text to scan; accepts pipeline input. Strings are joined with newlines.

    .PARAMETER Path
        File(s) to scan; wildcards allowed. Findings gain a Path property.

    .PARAMETER LiteralPath
        File(s) to scan, taken literally. Findings gain a Path property.

    .PARAMETER ConfigPath
        Extra JSON config file layered above the local config.

    .EXAMPLE
        Get-Content .\redacted.txt | Test-RedactionResidual

    .EXAMPLE
        Test-RedactionResidual -Path .\redacted.txt

    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding(DefaultParameterSetName = 'Text')]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Text')][AllowEmptyString()][string[]]$Text,
        [Parameter(Mandatory, ParameterSetName = 'Path')][string[]]$Path,
        [Parameter(Mandatory, ParameterSetName = 'LiteralPath')][Alias('PSPath')][string[]]$LiteralPath,
        [string]$ConfigPath
    )

    begin { $lines = [System.Collections.Generic.List[string]]::new() }

    process { if ($PSCmdlet.ParameterSetName -eq 'Text') { $lines.AddRange($Text) } }

    end {
        $session = New-RedactSession -Config (Get-RedactConfig -ConfigPath $ConfigPath)
        if ($PSCmdlet.ParameterSetName -eq 'Text') {
            Find-RedactResidual -Text ($lines -join "`n") -Session $session | Write-Output
            return
        }
        $files = if ($PSCmdlet.ParameterSetName -eq 'Path') { Resolve-Path -Path $Path } else { Resolve-Path -LiteralPath $LiteralPath }
        foreach ($file in $files) {
            $findings = Find-RedactResidual -Text (Get-Content -LiteralPath $file.ProviderPath -Raw) -Session $session
            $findings | Add-Member -NotePropertyName Path -NotePropertyValue $file.ProviderPath -PassThru
        }
    }
}
