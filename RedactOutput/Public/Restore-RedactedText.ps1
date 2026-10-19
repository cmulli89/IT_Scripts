function Restore-RedactedText {
    <#
    .SYNOPSIS
        Swaps [type-NN] tokens in text (for example a reply to redacted output) back to their originals.

    .DESCRIPTION
        LOCAL USE ONLY: the result contains the original values, so it must not be pasted into the system the
        text was redacted for. Tokens come from a map saved by Protect-Output -MapPath. Matching is exact,
        longest token first, in a single pass, so a restored value is never scanned again. A token that has
        several originals (a NetBIOS name shares its domain's token) restores to the first one recorded; names
        are restored with the casing first seen. [secret:...] tokens
        stay as they are (secrets are never in a map); their count is reported with Write-Verbose. Text is returned, or written to -OutputPath (a file input keeps
        its encoding, BOM and line endings). An existing output file needs -Force and the input is never
        overwritten. -WhatIf writes nothing.

    .PARAMETER Text
        Text to restore; accepts pipeline input. Strings are joined with newlines.

    .PARAMETER Path
        File to restore; wildcards allowed but they must match exactly one file.

    .PARAMETER LiteralPath
        File to restore, taken literally.

    .PARAMETER MapPath
        Map file saved by Protect-Output -MapPath. A bare file name is looked up in the per-user maps folder.

    .PARAMETER OutputPath
        Write the restored text to this file instead of returning it.

    .PARAMETER Force
        Overwrite an existing -OutputPath file.

    .EXAMPLE
        Get-Clipboard -Raw | Restore-RedactedText -MapPath .\session1.redactmap.json

    .EXAMPLE
        Restore-RedactedText -Path .\reply.txt -MapPath session1.redactmap.json -OutputPath .\reply.restored.txt

    .OUTPUTS
        System.String
    #>
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Text')]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Text')][AllowEmptyString()][string[]]$Text,
        [Parameter(Mandatory, ParameterSetName = 'Path')][string]$Path,
        [Parameter(Mandatory, ParameterSetName = 'LiteralPath')][Alias('PSPath')][string]$LiteralPath,
        [Parameter(Mandatory)][string]$MapPath,
        [string]$OutputPath,
        [switch]$Force
    )

    begin { $lines = [System.Collections.Generic.List[string]]::new() }

    process { if ($PSCmdlet.ParameterSetName -eq 'Text') { $lines.AddRange($Text) } }

    end {
        $tokens = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::Ordinal)
        foreach ($e in (Read-RedactMap -Path (Resolve-RedactMapPath -MapPath $MapPath)).Entries) { [void]$tokens.TryAdd($e.Token, $e.Original) }

        $file = $null
        if ($PSCmdlet.ParameterSetName -eq 'Text') { $body = $lines -join "`n" }
        else {
            $found = @(if ($Path) { Resolve-Path -Path $Path } else { Resolve-Path -LiteralPath $LiteralPath })
            if ($found.Count -ne 1) { throw (Get-RedactErrorRecord -ErrorId 'RedactOutput.OneFileOnly' -Message 'Restore takes exactly one input file.') }
            $file = Read-RedactFile -LiteralPath $found[0].ProviderPath
            if ($file.IsBinary) { throw (Get-RedactBinaryError -Path $found[0].ProviderPath) }
            $body = $file.Text
        }

        Write-Verbose "$((Get-RedactRegex -Pattern '\[secret:[a-z0-9-]+\]').Matches($body).Count) secret token(s) left as is."
        $restored = $body
        if ($tokens.Count -gt 0) {
            $alternatives = foreach ($token in ($tokens.Keys | Sort-Object -Property Length -Descending)) {
                $escaped = [regex]::Escape($token)
                $escaped
            }
            $regex = Get-RedactRegex -Pattern ($alternatives -join '|')
            try { $restored = $regex.Replace($body, [System.Text.RegularExpressions.MatchEvaluator]{ param($m) $tokens[$m.Value] }) }
            catch [System.Text.RegularExpressions.RegexMatchTimeoutException] {
                throw (Get-RedactErrorRecord -ErrorId 'RedactOutput.RegexTimeout' -Message 'Restoring exceeded the regex time limit.')
            }
        }

        if (-not $OutputPath) { return $restored }
        $out = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
        if ($file -and (Test-RedactSamePath -Left $out -Right $found[0].ProviderPath)) {
            throw (Get-RedactErrorRecord -ErrorId 'RedactOutput.OutputIsInput' -Message 'The -OutputPath is the input file; the input is never modified.')
        }
        if ((Test-Path -LiteralPath $out) -and -not $Force) {
            throw (Get-RedactErrorRecord -ErrorId 'RedactOutput.OutputExists' -Category ResourceExists -Message 'The -OutputPath file already exists. Use -Force to overwrite.')
        }
        if (-not $PSCmdlet.ShouldProcess($out, 'Write restored text')) { return }
        [void][System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($out))
        if ($file) { Write-RedactFile -LiteralPath $out -Text $restored -Encoding $file.Encoding -HasBom:$file.HasBom }
        else { Write-RedactFile -LiteralPath $out -Text $restored -Encoding ([System.Text.UTF8Encoding]::new($false)) }
    }
}
