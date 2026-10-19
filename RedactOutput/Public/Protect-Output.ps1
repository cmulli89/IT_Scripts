function Protect-Output {
    <#
    .SYNOPSIS
        Redacts secrets and environment identifiers from text, objects or files.

    .DESCRIPTION
        Pipeline input (or -InputObject) is collected, rendered with Out-String -Width 4096 (or, with -As Json,
        ConvertTo-Json -Depth 100 and the JSON handler), redacted as one block and emitted as a single string.

        -Path (wildcards) and -LiteralPath redact files with the handler for their type (json, jsonl, csv, tsv, xml,
        keyvalue, reg, script, html, text), keeping encoding, BOM and each line's own terminator. A folder is
        processed file by file (-Recurse, -Include); binary files, *.redacted.* files and links are skipped. The
        output is <base>.redacted<ext> next to the input, or under -OutDir; the input is never modified, an
        existing output needs -Force, and text files above -LargeFileThresholdMB stream in chunks.

        A residual scan runs on every result: by default each finding becomes a warning (category, line, column
        and length only); with -Strict any finding throws before anything is written. -WhatIf runs the engine in
        memory, writes counts to the host and writes no output, map or audit row.

        -MapPath saves the original-to-token pairs (never secrets) as JSON for Restore-RedactedText, after a
        successful run only. The file is created owner-only (Windows ACL, Linux/macOS mode 600) before anything
        is written, and a bare file name goes to the per-user maps folder. An existing map is loaded first, so
        numbering continues and existing entries are kept. The map holds original values: keep it local, never in
        a synced folder (a warning is given), and never share it. Matched values are never written
        to any stream or to the audit log. Alias: redact.

    .PARAMETER InputObject
        Text or objects to redact; accepts pipeline input. Strings are joined with newlines.

    .PARAMETER Path
        File or folder to redact; wildcards allowed.

    .PARAMETER LiteralPath
        File or folder to redact, taken literally.

    .PARAMETER As
        How pipeline objects are rendered: Text (default, Out-String) or Json (ConvertTo-Json, structure-aware).

    .PARAMETER Recurse
        Include subfolders when a folder is given.

    .PARAMETER Include
        Name patterns for files found in a folder (default all files).

    .PARAMETER OutDir
        Folder for output files (the folder structure below a given folder is kept).

    .PARAMETER OutFile
        Output file for a single input file.

    .PARAMETER Force
        Overwrite an existing output file.

    .PARAMETER PassThru
        Emit one RedactOutput.Result per file (Path, OutPath, DetectedType, Encoding, Counts, ResidualWarnings).

    .PARAMETER Encoding
        Forces the encoding for reading and writing a file (UTF8, Unicode, BigEndianUnicode, UTF32,
        BigEndianUTF32, Windows1252). Needed for UTF-16 files that have no BOM.

    .PARAMETER Head
        Keep the first N lines of line-oriented input and mark the rest as omitted. Ignored, with a warning, for
        json, csv, tsv, xml and reg.

    .PARAMETER Tail
        Keep the last M lines of line-oriented input and mark the rest as omitted. Ignored, with a warning, for
        json, csv, tsv, xml and reg.

    .PARAMETER LargeFileThresholdMB
        Text files larger than this many MB are redacted in chunks instead of in memory (default 50).

    .PARAMETER ConfigPath
        Extra JSON config file layered above the local config.

    .PARAMETER Strict
        Throw a terminating error, before any output or audit write, if the residual scan finds anything.

    .PARAMETER MapPath
        Map file to save (and reuse when it exists). A bare file name is created under
        %LOCALAPPDATA%\RedactOutput\maps (Linux/macOS: ~/.local/share/RedactOutput/maps).

    .PARAMETER NoAudit
        Do not append an audit row.

    .PARAMETER AuditPath
        Audit CSV to append to. Defaults to the per-user RedactOutput data folder.

    .EXAMPLE
        Get-Content .\app.env | redact

    .EXAMPLE
        Get-Something | Protect-Output -As Json -Strict -AuditPath .\audit.csv

    .EXAMPLE
        Get-Something | redact -MapPath .\session1.redactmap.json

    .EXAMPLE
        redact -Path .\dump.json -PassThru

    .EXAMPLE
        redact -Path .\logs -Recurse -Include *.log,*.json -OutDir .\redacted -WhatIf

    .OUTPUTS
        System.String for pipeline input; RedactOutput.Result with -PassThru for files.
    #>
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Pipeline')]
    [OutputType([string])]
    [OutputType('RedactOutput.Result')]
    param(
        [Parameter(ValueFromPipeline, ParameterSetName = 'Pipeline')][AllowNull()][object]$InputObject,
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'Path')][string[]]$Path,
        [Parameter(Mandatory, ParameterSetName = 'LiteralPath')][Alias('PSPath')][string[]]$LiteralPath,
        [Parameter(ParameterSetName = 'Pipeline')][ValidateSet('Text', 'Json')][string]$As = 'Text',
        [switch]$Recurse,
        [string[]]$Include = '*',
        [string]$OutDir,
        [string]$OutFile,
        [switch]$Force,
        [switch]$PassThru,
        [ValidateSet('UTF8', 'Unicode', 'BigEndianUnicode', 'UTF32', 'BigEndianUTF32', 'Windows1252')][string]$Encoding,
        [ValidateRange(1, [int]::MaxValue)][int]$Head,
        [ValidateRange(1, [int]::MaxValue)][int]$Tail,
        [ValidateRange(0, [int]::MaxValue)][int]$LargeFileThresholdMB = 50,
        [string]$ConfigPath,
        [string]$MapPath,
        [switch]$Strict,
        [switch]$NoAudit,
        [string]$AuditPath
    )

    begin { $items = [System.Collections.Generic.List[object]]::new() }

    process { if ($null -ne $InputObject) { $items.Add($InputObject) } }

    end {
        $fileMode = $PSCmdlet.ParameterSetName -ne 'Pipeline'
        if (-not $fileMode -and $items.Count -eq 0) { return }
        $session = New-RedactSession -Config (Get-RedactConfig -ConfigPath $ConfigPath)
        $mapFile = if ($MapPath) { Resolve-RedactMapPath -MapPath $MapPath }
        if ($mapFile -and (Test-Path -LiteralPath $mapFile)) { Import-RedactMap -Session $session -Path $mapFile }

        if ($fileMode) {
            $plan = Get-RedactFilePlan -Path $Path -LiteralPath $LiteralPath -Recurse:$Recurse -Include $Include -OutDir $OutDir -OutFile $OutFile
            if ($plan.Count -eq 0) { Write-Warning 'No input files found.' }
            # One terminating error for the whole run, before any file is written. ThrowTerminatingError (not throw) so -ErrorVariable
            # holds exactly one entry; its message is in .Message and .ErrorRecord.Exception.Message ($e[0] is the wrapping exception).
            $existing = @($plan.Where({ Test-Path -LiteralPath $_.OutPath }))
            if ($existing.Count -gt 0 -and -not $Force) {
                $PSCmdlet.ThrowTerminatingError((Get-RedactErrorRecord -ErrorId 'RedactOutput.OutputExists' -Category ResourceExists -Message "$($existing.Count) output file(s) already exist (first: '$($existing[0].Relative)'). Use -Force to overwrite."))
            }
            $fileOption = @{ Encoding = $Encoding; Head = $Head; Tail = $Tail; LargeFileThresholdMB = $LargeFileThresholdMB; Strict = $Strict; NoAudit = $NoAudit; AuditPath = $AuditPath }
            foreach ($entry in $plan) {
                $result = Invoke-RedactFile -Entry $entry -Session $session -SkipBinary:($entry.Folder -or $plan.Count -gt 1) @fileOption
                if ($PassThru -and $result) { $result }
            }
            if ($mapFile -and $PSCmdlet.ShouldProcess($mapFile, 'Write map file')) { Save-RedactMap -Session $session -Path $mapFile }
            return
        }

        $type = if ($As -eq 'Json') { 'json' } else { 'text' }
        $text = if ($As -eq 'Json') { ConvertTo-Json -InputObject $(if ($items.Count -eq 1) { $items[0] } else { $items.ToArray() }) -Depth 100 }
        elseif (@($items | Where-Object { $_ -isnot [string] }).Count -eq 0) { $items -join "`n" }
        else { ($items | Out-String -Width 4096).TrimEnd() }
        $text = Select-RedactLine -Text $text -Type $type -Head $Head -Tail $Tail

        $redacted = Invoke-RedactContent -Text $text -Type $type -Session $session
        [void](Find-RedactResidual -Text $redacted -Session $session)
        Confirm-RedactFinding -Session $session -Strict:$Strict

        if (-not $PSCmdlet.ShouldProcess('redaction result', 'Emit redacted text and write audit row')) {
            Write-RedactSummary -Session $session
            return
        }
        if ($mapFile -and $PSCmdlet.ShouldProcess($mapFile, 'Write map file')) { Save-RedactMap -Session $session -Path $mapFile }
        if (-not $NoAudit) {
            Write-RedactAudit -Session $session -InputSource pipeline -InputSha256 (Get-RedactSha256 -Text $text) -Strict:$Strict -AuditPath $AuditPath
        }
        $redacted
    }
}
