# The in-memory run shared by Protect-Output (pipeline, clipboard) and Invoke-RedactedCommand, plus its inputs and
# outputs: clipboard, command records, preview. None of these ever receive or print a matched value.

#region Clipboard

function Get-RedactClipboardTool {
    # 'builtin' (Get-/Set-Clipboard: Windows, macOS, or Linux with xclip, the only tool they drive) or 'wl-clipboard'.
    [CmdletBinding()]
    [OutputType([string])]
    param()

    if (-not $IsLinux -or (Get-Command -Name xclip -ErrorAction Ignore)) { return 'builtin' }
    if ((Get-Command -Name wl-copy -ErrorAction Ignore) -and (Get-Command -Name wl-paste -ErrorAction Ignore)) { return 'wl-clipboard' }
    throw (Get-RedactErrorRecord -ErrorId 'RedactOutput.ClipboardTool' -Message 'Clipboard on Linux needs xclip or wl-clipboard')
}

function Invoke-RedactWlClipboard {
    # The only place wl-paste / wl-copy are called (kept tiny so tests can mock it). Reads return the text, or nothing when
    # the clipboard has no text; writes pipe the text to wl-copy.
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$Text,
        [switch]$Write
    )

    if ($Write) {
        $Text | & wl-copy --trim-newline
        if ($LASTEXITCODE -ne 0) { throw 'wl-copy failed' }
        return
    }
    $lines = & wl-paste --no-newline 2>$null
    if ($LASTEXITCODE -eq 0) { $lines -join "`n" }
}

function Get-RedactClipboard {
    # Clipboard text; an empty or non-text clipboard is an error (kept tiny so tests can mock it).
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $tool = Get-RedactClipboardTool
    try { $text = if ($tool -eq 'builtin') { Get-Clipboard -Raw -ErrorAction Stop } else { Invoke-RedactWlClipboard } }
    catch { throw (Get-RedactErrorRecord -ErrorId 'RedactOutput.ClipboardRead' -Message 'The clipboard could not be read.') }
    if ($text -isnot [string] -or [string]::IsNullOrWhiteSpace($text)) {
        throw (Get-RedactErrorRecord -ErrorId 'RedactOutput.ClipboardEmpty' -Message 'The clipboard is empty or does not hold text.')
    }
    $text
}

function Set-RedactClipboard {
    # Callers confirm with ShouldProcess before calling.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'The caller confirms with ShouldProcess before calling.')]
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    $tool = Get-RedactClipboardTool
    try { if ($tool -eq 'builtin') { Set-Clipboard -Value $Text -ErrorAction Stop } else { Invoke-RedactWlClipboard -Text $Text -Write } }
    catch { throw (Get-RedactErrorRecord -ErrorId 'RedactOutput.ClipboardWrite' -Message 'The clipboard could not be written.') }
}

#endregion

#region Command records

function Invoke-RedactScriptBlock {
    # Runs the block with every stream merged into one list. A throw is kept as the last record, so the command's own
    # failure never stops the caller. The preference is set globally because the block is bound to the caller's
    # session state and does not see this module's scope.
    [CmdletBinding()]
    [OutputType([object[]])]
    param([Parameter(Mandatory)][scriptblock]$ScriptBlock)

    $records = [System.Collections.Generic.List[object]]::new()
    $saved = $global:ErrorActionPreference
    $global:ErrorActionPreference = 'Continue'
    try { & $ScriptBlock *>&1 | ForEach-Object { $records.Add($_) } }
    catch { $records.Add($_) }
    finally { $global:ErrorActionPreference = $saved }
    $records.ToArray()
}

function ConvertTo-RedactRecordText {
    # Records become text: an error as its Out-String form, other streams as their message with a prefix, and
    # consecutive plain objects together (so a table keeps one header).
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyCollection()][object[]]$Record = @())

    $prefix = @{ WarningRecord = 'WARNING: '; VerboseRecord = 'VERBOSE: '; DebugRecord = 'DEBUG: '; InformationRecord = 'INFORMATION: ' }
    $parts = [System.Collections.Generic.List[string]]::new()
    $plain = [System.Collections.Generic.List[object]]::new()
    $flush = { if ($plain.Count -gt 0) { $parts.Add(($plain | Out-String -Width 4096).TrimEnd()); $plain.Clear() } }
    foreach ($item in $Record) {
        $name = if ($null -ne $item) { $item.GetType().Name }
        if ($item -is [System.Management.Automation.ErrorRecord]) { & $flush; $parts.Add(($item | Out-String -Width 4096).TrimEnd()) }
        elseif ($name -and $prefix.ContainsKey($name)) { & $flush; $parts.Add($prefix[$name] + [string]$item) }
        elseif ($null -ne $item) { $plain.Add($item) }
    }
    & $flush
    $parts -join "`n"
}

#endregion

function Write-RedactPreview {
    # Redacted text with tokens in colour (secrets red, identifiers cyan); writes nothing else.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Preview is host output by design; it shows redacted text only.')]
    [CmdletBinding()]
    param([AllowEmptyString()][Parameter(Mandatory)][string]$Text)

    $position = 0
    foreach ($m in (Get-RedactTokenPattern).Matches($Text)) {
        Write-Host -Object $Text.Substring($position, $m.Index - $position) -NoNewline
        Write-Host -Object $m.Value -NoNewline -ForegroundColor $(if ($m.Value.StartsWith('[secret:')) { 'Red' } else { 'Cyan' })
        $position = $m.Index + $m.Length
    }
    Write-Host -Object $Text.Substring($position)
}

function Initialize-RedactRun {
    # Config, session and (when given) the map file, with an existing map loaded so numbering continues.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory session and reads a map; nothing is written.')]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string]$ConfigPath,
        [string]$MapPath
    )

    $session = New-RedactSession -Config (Get-RedactConfig -ConfigPath $ConfigPath)
    $mapFile = if ($MapPath) { Resolve-RedactMapPath -MapPath $MapPath }
    if ($mapFile -and (Test-Path -LiteralPath $mapFile)) { Import-RedactMap -Session $session -Path $mapFile }
    [pscustomobject]@{ Session = $session; MapFile = $mapFile }
}

function Invoke-RedactTextRun {
    <#
    .SYNOPSIS
        Redacts one block of text and delivers it: returned, to the clipboard, to a file, or as a preview.
    .DESCRIPTION
        The engine and residual scan always run first, so -Strict throws before anything is written. -Preview then
        prints and stops. Otherwise one ShouldProcess confirms the delivery (-WhatIf reports counts only); the
        clipboard or file is written, then the map (when -MapFile is given) and the audit row. Text is returned
        only when it goes nowhere else; with -PassThru a result object is emitted for clipboard or file output.
    .PARAMETER Cmdlet
        The calling cmdlet ($PSCmdlet); its ShouldProcess and -WhatIf apply.
    .PARAMETER Text
        Text to redact.
    .PARAMETER Type
        Handler type from Get-RedactFileType (text or json).
    .PARAMETER Session
        Session from Initialize-RedactRun.
    .PARAMETER InputSource
        Audit input_source: pipeline, clipboard or command.
    .PARAMETER Clipboard
        Write the result to the clipboard.
    .PARAMETER OutFile
        Write the result (UTF-8, no BOM) to this file.
    .PARAMETER Force
        Overwrite an existing -OutFile.
    .PARAMETER Preview
        Print the result with highlighted tokens and write nothing.
    .PARAMETER MapFile
        Full path of the map to save.
    .PARAMETER Strict
        Throw if the residual scan finds anything.
    .PARAMETER NoAudit
        Do not append an audit row.
    .PARAMETER AuditPath
        Audit CSV to append to.
    .PARAMETER PassThru
        Emit a RedactOutput.Result for clipboard or file output.
    .EXAMPLE
        Invoke-RedactTextRun -Cmdlet $PSCmdlet -Text $text -Session $run.Session -InputSource command
    .OUTPUTS
        System.String, or RedactOutput.Result
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '', Justification = 'Confirmation is delegated to the calling cmdlet, which owns -WhatIf and -Confirm.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Management.Automation.PSCmdlet]$Cmdlet,
        [AllowEmptyString()][Parameter(Mandatory)][string]$Text,
        [string]$Type = 'text',
        [Parameter(Mandatory)][object]$Session,
        [Parameter(Mandatory)][ValidateSet('pipeline', 'clipboard', 'command')][string]$InputSource,
        [switch]$Clipboard,
        [string]$OutFile,
        [switch]$Force,
        [switch]$Preview,
        [string]$MapFile,
        [switch]$Strict,
        [switch]$NoAudit,
        [string]$AuditPath,
        [switch]$PassThru
    )

    $out = if ($OutFile) { $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile) }
    if ($out -and (Test-Path -LiteralPath $out) -and -not $Force -and -not $Preview) {
        throw (Get-RedactErrorRecord -ErrorId 'RedactOutput.OutputExists' -Category ResourceExists -Message 'The -OutFile file already exists. Use -Force to overwrite.')
    }
    $redacted = Invoke-RedactContent -Text $Text -Type $Type -Session $Session
    [void](Find-RedactResidual -Text $redacted -Session $Session)
    Confirm-RedactFinding -Session $Session -Strict:$Strict
    if ($Preview) { Write-RedactPreview -Text $redacted; return }

    $target = if ($Clipboard -and $out) { 'clipboard and output file' } elseif ($Clipboard) { 'clipboard' } elseif ($out) { $out } else { 'redaction result' }
    if (-not $Cmdlet.ShouldProcess($target, 'Deliver redacted text and write audit row')) { Write-RedactSummary -Session $Session; return }
    if ($Clipboard) { Set-RedactClipboard -Text $redacted }
    if ($out) {
        [void][System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($out))
        Write-RedactFile -LiteralPath $out -Text $redacted -Encoding ([System.Text.UTF8Encoding]::new($false))
    }
    if ($MapFile -and $Cmdlet.ShouldProcess($MapFile, 'Write map file')) { Save-RedactMap -Session $Session -Path $MapFile }
    if (-not $NoAudit) {
        Write-RedactAudit -Session $Session -InputSource $InputSource -InputSha256 (Get-RedactSha256 -Text $Text) -OutputPath $out -Strict:$Strict -AuditPath $AuditPath
    }
    if (-not ($Clipboard -or $out)) { $redacted }
    elseif ($PassThru) { New-RedactResult -OutPath $out -DetectedType $Type -Encoding 'utf-8' -Session $Session }
}
