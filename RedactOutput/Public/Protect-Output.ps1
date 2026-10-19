function Protect-Output {
    <#
    .SYNOPSIS
        Redacts secrets and environment identifiers from text or objects.

    .DESCRIPTION
        Collects everything piped in (or passed with -InputObject), renders non-string objects with
        Out-String -Width 4096, redacts the result as one block and emits it as a single string. A residual
        scan then runs on the output: by default each finding becomes a warning (category, line, column and
        length only); with -Strict any finding throws before any output or audit write.

        -WhatIf runs the engine in memory, writes per-category counts to the host and emits no text and no
        audit row. Matched values are never written to any stream or to the audit log. Alias: redact.

    .PARAMETER InputObject
        Text or objects to redact; accepts pipeline input. Strings are joined with newlines.

    .PARAMETER ConfigPath
        Extra JSON config file layered above the local config.

    .PARAMETER Strict
        Throw a terminating error, before any output or audit write, if the residual scan finds anything.

    .PARAMETER NoAudit
        Do not append an audit row.

    .PARAMETER AuditPath
        Audit CSV to append to. Defaults to the per-user RedactOutput data folder.

    .EXAMPLE
        Get-Content .\app.env | redact

    .EXAMPLE
        Get-Something | Protect-Output -Strict -AuditPath .\audit.csv

    .EXAMPLE
        'password=example' | Protect-Output -WhatIf

    .OUTPUTS
        System.String
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'WhatIf reports per-category counts to the host; counts only, never values.')]
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param(
        [Parameter(ValueFromPipeline)][AllowNull()][object]$InputObject,
        [string]$ConfigPath,
        [switch]$Strict,
        [switch]$NoAudit,
        [string]$AuditPath
    )

    begin { $items = [System.Collections.Generic.List[object]]::new() }

    process { if ($null -ne $InputObject) { $items.Add($InputObject) } }

    end {
        if ($items.Count -eq 0) { return }
        $text = if (@($items | Where-Object { $_ -isnot [string] }).Count -eq 0) { $items -join "`n" }
        else { ($items | Out-String -Width 4096).TrimEnd() }

        $session = New-RedactSession -Config (Get-RedactConfig -ConfigPath $ConfigPath)
        $redacted = Invoke-RedactText -Text $text -Session $session
        [void](Find-RedactResidual -Text $redacted -Session $session)

        if ($Strict -and $session.Findings.Count -gt 0) {
            $categories = ($session.Findings.Category | Sort-Object -Unique) -join ', '
            $PSCmdlet.ThrowTerminatingError((Get-RedactErrorRecord -ErrorId 'RedactOutput.StrictResidual' -Message "-Strict: $($session.Findings.Count) residual finding(s) in: $categories. Nothing was written."))
        }
        foreach ($finding in $session.Findings) { Write-RedactFinding -Finding $finding }

        if (-not $PSCmdlet.ShouldProcess('redaction result', 'Emit redacted text and write audit row')) {
            foreach ($label in $session.Counts.Keys) {
                if ($session.Counts[$label] -gt 0) { Write-Host "${label}: $($session.Counts[$label])" }
            }
            Write-Host "residual findings: $($session.Findings.Count)"
            return
        }
        if (-not $NoAudit) {
            Write-RedactAudit -Session $session -InputSource pipeline -InputSha256 (Get-RedactSha256 -Text $text) -Strict:$Strict -AuditPath $AuditPath
        }
        $redacted
    }
}
