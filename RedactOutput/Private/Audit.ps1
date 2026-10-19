# Audit CSV and the single place where findings become warnings. Neither ever receives matched text.

function Get-RedactAuditPath {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    if ($IsWindows) { Join-Path $env:LOCALAPPDATA 'RedactOutput/audit.csv' }
    else { Join-Path $HOME '.local/share/RedactOutput/audit.csv' }
}

function Get-RedactSha256 {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][Parameter(Mandatory)][string]$Text)

    [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($Text))).ToLowerInvariant()
}

function Write-RedactAudit {
    <#
    .SYNOPSIS
        Appends one audit row (counts and hashes only) to the audit CSV.
    .DESCRIPTION
        Columns: timestamp_utc, operator, input_source, input_sha256, output_path, one column per category
        label (fixed order from the rule table), residual_findings, strict. The header is written when the
        file is new; when an existing file has a different header it is renamed to audit-<yyyyMMddHHmmss>.csv
        in the same folder and a new file is started. Never writes original values, config terms or map content.
    .PARAMETER Session
        Session whose Counts and Findings are summarized.
    .PARAMETER InputSource
        One of path, pipeline, clipboard, command.
    .PARAMETER InputSha256
        SHA-256 of the input text.
    .PARAMETER OutputPath
        Output file path, or empty when the output is returned as text.
    .PARAMETER Strict
        Whether -Strict was in effect.
    .PARAMETER AuditPath
        Audit CSV to append to. Defaults to the per-user RedactOutput data folder.
    .EXAMPLE
        Write-RedactAudit -Session $session -InputSource pipeline -InputSha256 $hash -AuditPath .\audit.csv
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Session,
        [Parameter(Mandatory)][ValidateSet('path', 'pipeline', 'clipboard', 'command')][string]$InputSource,
        [Parameter(Mandatory)][string]$InputSha256,
        [string]$OutputPath = '',
        [switch]$Strict,
        [string]$AuditPath
    )

    if (-not $AuditPath) { $AuditPath = Get-RedactAuditPath }
    $path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($AuditPath)
    $row = [ordered]@{
        timestamp_utc = [datetime]::UtcNow.ToString('o')
        operator      = [Environment]::UserName
        input_source  = $InputSource
        input_sha256  = $InputSha256
        output_path   = $OutputPath
    }
    foreach ($label in $Session.Counts.Keys) { $row[$label] = $Session.Counts[$label] }
    $row['residual_findings'] = $Session.Findings.Count
    $row['strict'] = [bool]$Strict

    $lines = @([pscustomobject]$row | ConvertTo-Csv -NoTypeInformation -UseQuotes AsNeeded)
    $folder = [System.IO.Path]::GetDirectoryName($path)
    if (Test-Path -LiteralPath $path) {
        # A header change (new categories) rotates the old file; only its first line is read.
        if ((Get-Content -LiteralPath $path -TotalCount 1) -ceq $lines[0]) { $lines = $lines[1] }
        else { Move-Item -LiteralPath $path -Destination (Join-Path $folder ('audit-{0}.csv' -f [datetime]::UtcNow.ToString('yyyyMMddHHmmss'))) }
    }
    else { $null = New-Item -ItemType Directory -Force -Path $folder }
    Add-Content -LiteralPath $path -Value $lines -Encoding utf8NoBOM
}

function Write-RedactFinding {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Finding)

    Write-Warning "Residual $($Finding.Category) at line $($Finding.Line), column $($Finding.Column), length $($Finding.Length)"
}
