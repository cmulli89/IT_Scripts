<#
.SYNOPSIS
    Redacts secrets and environment identifiers without importing the module first.

.DESCRIPTION
    Thin wrapper around Protect-Output: it imports RedactOutput from this folder and passes the common parameters
    through (pipeline input, -Path, -LiteralPath, -Clipboard, -Preview, ...). See Get-Help Protect-Output.

    Exit codes: 0 clean, 1 residual findings were reported (without -Strict), 2 error (-Strict finding, bad config,
    binary file, bad parameters). Error messages never contain matched values.

.PARAMETER InputObject
    Text or objects from the pipeline.

.PARAMETER Path
    File or folder to redact; wildcards allowed.

.PARAMETER LiteralPath
    File or folder to redact, taken literally.

.PARAMETER Clipboard
    Redact the clipboard text in place.

.PARAMETER Preview
    Print the redacted text with highlighted tokens and write nothing (pipeline and clipboard input).

.PARAMETER OutDir
    Folder for output files.

.PARAMETER ConfigPath
    Extra JSON config file layered above the local config.

.PARAMETER Strict
    Fail (exit 2) before anything is written if the residual scan finds anything.

.PARAMETER MapPath
    Map file to save, for Restore-RedactedText.

.PARAMETER NoAudit
    Do not append an audit row.

.PARAMETER Recurse
    Include subfolders when a folder is given.

.PARAMETER Include
    Name patterns for files found in a folder.

.PARAMETER Force
    Overwrite existing output files.

.EXAMPLE
    .\redact.ps1 -Path .\dump.json -Strict

.EXAMPLE
    Get-Something | .\redact.ps1

.EXAMPLE
    .\redact.ps1 -Clipboard -Preview
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Pipeline')]
param(
    [Parameter(ValueFromPipeline, ParameterSetName = 'Pipeline')][AllowNull()][object]$InputObject,
    [Parameter(Mandatory, Position = 0, ParameterSetName = 'Path')][string[]]$Path,
    [Parameter(Mandatory, ParameterSetName = 'LiteralPath')][Alias('PSPath')][string[]]$LiteralPath,
    [Parameter(Mandatory, ParameterSetName = 'Clipboard')][switch]$Clipboard,
    [Parameter(ParameterSetName = 'Pipeline')][Parameter(ParameterSetName = 'Clipboard')][switch]$Preview,
    [string]$OutDir,
    [string]$ConfigPath,
    [switch]$Strict,
    [string]$MapPath,
    [switch]$NoAudit,
    [switch]$Recurse,
    [string[]]$Include,
    [switch]$Force
)

begin { $items = [System.Collections.Generic.List[object]]::new() }

process { if ($null -ne $InputObject) { $items.Add($InputObject) } }

end {
    try {
        # Errors are thrown as script-terminating errors, so every failure must land in the catch to get exit code 2.
        $ErrorActionPreference = 'Stop'
        Import-Module -Name (Join-Path $PSScriptRoot 'RedactOutput.psd1') -Force
        $parameters = [hashtable]$PSBoundParameters
        $parameters.Remove('InputObject')
        $warnings = $null
        $items | Protect-Output @parameters -WarningVariable warnings
        # Residual findings are reported as warnings that start with 'Residual'; without -Strict they only set the exit code.
        if (@($warnings).Where({ $_.Message -like 'Residual *' }).Count -gt 0) { exit 1 }
        exit 0
    }
    catch {
        [Console]::Error.WriteLine($_.Exception.Message)
        exit 2
    }
}
