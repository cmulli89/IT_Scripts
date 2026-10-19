function Invoke-RedactedCommand {
    <#
    .SYNOPSIS
        Runs a script block, captures everything it produces (errors and native stderr included) and redacts it.

    .DESCRIPTION
        The block runs with all streams merged (*>&1). Every record becomes text: errors as their Out-String form,
        warning, verbose, information and debug records as their message with a WARNING: / VERBOSE: / INFORMATION: /
        DEBUG: prefix, anything else with Out-String -Width 4096. The command's own errors, and a throw inside it,
        are captured as text and never stop the wrapper; a failure inside redaction does. PowerShell itself also keeps
        a thrown exception in $Error (and any -ErrorVariable) as for any caught exception: clear $Error before
        sharing it.

        The text then takes the same path as Protect-Output: redaction, residual scan, -Strict (throws before any
        write), -WhatIf (counts only), map, audit (input_source command). Without -Clipboard, -OutFile or -Preview
        the redacted text is returned. -Preview prints it with highlighted tokens and writes nothing.

    .PARAMETER ScriptBlock
        The commands to run.

    .PARAMETER Clipboard
        Put the redacted text on the clipboard (Linux needs xclip or wl-clipboard).

    .PARAMETER OutFile
        Write the redacted text (UTF-8, no BOM) to this file.

    .PARAMETER Force
        Overwrite an existing -OutFile.

    .PARAMETER Preview
        Print the redacted text with highlighted tokens and write nothing.

    .PARAMETER Strict
        Throw a terminating error, before anything is written, if the residual scan finds anything.

    .PARAMETER ConfigPath
        Extra JSON config file layered above the local config.

    .PARAMETER MapPath
        Map file to save (and reuse when it exists); see Protect-Output.

    .PARAMETER NoAudit
        Do not append an audit row.

    .PARAMETER AuditPath
        Audit CSV to append to. Defaults to the per-user RedactOutput data folder.

    .PARAMETER PassThru
        Emit a RedactOutput.Result when the text went to the clipboard or -OutFile.

    .EXAMPLE
        Invoke-RedactedCommand { gpresult /r } -Clipboard

    .EXAMPLE
        Invoke-RedactedCommand { Get-ChildItem Env: } -Preview

    .EXAMPLE
        Invoke-RedactedCommand { az account show } -OutFile .\account.redacted.txt -Strict

    .OUTPUTS
        System.String, or RedactOutput.Result with -PassThru.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '', Justification = 'Invoke-RedactTextRun calls $PSCmdlet.ShouldProcess for this command before any write.')]
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Output')]
    [OutputType([string])]
    [OutputType('RedactOutput.Result')]
    param(
        [Parameter(Mandatory, Position = 0)][scriptblock]$ScriptBlock,
        [Parameter(ParameterSetName = 'Output')][switch]$Clipboard,
        [Parameter(ParameterSetName = 'Output')][string]$OutFile,
        [Parameter(ParameterSetName = 'Output')][switch]$Force,
        [Parameter(Mandatory, ParameterSetName = 'Preview')][switch]$Preview,
        [switch]$Strict,
        [string]$ConfigPath,
        [string]$MapPath,
        [switch]$NoAudit,
        [string]$AuditPath,
        [switch]$PassThru
    )

    # Config and map are loaded first, so a bad config stops the run before the command executes.
    $run = Initialize-RedactRun -ConfigPath $ConfigPath -MapPath $MapPath
    $text = ConvertTo-RedactRecordText -Record @(Invoke-RedactScriptBlock -ScriptBlock $ScriptBlock)
    Invoke-RedactTextRun -Cmdlet $PSCmdlet -Text $text -Session $run.Session -InputSource command -Clipboard:$Clipboard -OutFile $OutFile -Force:$Force `
        -Preview:$Preview -MapFile $run.MapFile -Strict:$Strict -NoAudit:$NoAudit -AuditPath $AuditPath -PassThru:$PassThru
}
