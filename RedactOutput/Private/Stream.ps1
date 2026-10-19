# Large-file path for text-mode files: ~1 MB chunks on line boundaries, one session for the whole file (tokens stay
# consistent), engine and residual scan once per chunk. A private key or a wrapped list entry that spans a chunk edge is kept whole.

function Test-RedactOpenPem {
    # True when the text has more BEGIN ... PRIVATE KEY lines than END lines.
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$Text)

    if (-not $Text.Contains('PRIVATE KEY')) { return $false }
    $begin = (Get-RedactRegex -Pattern '-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----').Matches($Text).Count
    $end = (Get-RedactRegex -Pattern '-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----').Matches($Text).Count
    $begin -gt $end
}

function Invoke-RedactStream {
    <#
    .SYNOPSIS
        Redacts a large text file chunk by chunk and replaces Session.Findings with the findings of the whole file.
    .DESCRIPTION
        Chunks end on a line terminator (so CRLF is never split) and are extended while a private key is open;
        a wrapped list entry that may continue in the next chunk is held back for it (Get-RedactOpenWrapStart).
        Residual line numbers are offset by the lines already written. Output goes to OutputPath, which is
        left empty-handed (no file) when it is not given.
    .PARAMETER InputPath
        File to read.
    .PARAMETER File
        Encoding and HasBom from Get-RedactEncoding.
    .PARAMETER Session
        Session shared by the whole file.
    .PARAMETER OutputPath
        File to write; omit to run the engine only (-WhatIf).
    .EXAMPLE
        Invoke-RedactStream -InputPath .\big.log -File $info -Session $session -OutputPath .\big.tmp
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [Parameter(Mandatory)][object]$File,
        [Parameter(Mandatory)][object]$Session,
        [string]$OutputPath
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $pending = [System.Text.StringBuilder]::new()
    $buffer = [char[]]::new(1MB)
    $lineOffset = 0
    if ($OutputPath) { Write-RedactFile -LiteralPath $OutputPath -Text '' -Encoding $File.Encoding -HasBom:$File.HasBom }
    $reader = Open-RedactReader -LiteralPath $InputPath -Encoding $File.Encoding
    try {
        do {
            $n = $reader.Read($buffer, 0, $buffer.Length)
            [void]$pending.Append($buffer, 0, $n)
            $text = $pending.ToString()
            $cut = if ($n -eq 0) { $text.Length } else { $text.LastIndexOf("`n") + 1 }
            $chunk = $text.Substring(0, $cut)
            if ($n -gt 0) { $chunk = $chunk.Substring(0, (Get-RedactOpenWrapStart -Text $chunk)) }
            if ($chunk.Length -eq 0 -or ($n -gt 0 -and (Test-RedactOpenPem -Text $chunk))) { continue }
            [void]$pending.Clear().Append($text.Substring($chunk.Length))
            $redacted = Invoke-RedactContent -Text $chunk -Type text -Session $Session
            [void](Find-RedactResidual -Text $redacted -Session $Session)
            foreach ($f in $Session.Findings) {
                $findings.Add([pscustomobject]@{ Category = $f.Category; Line = $f.Line + $lineOffset; Column = $f.Column; Length = $f.Length })
            }
            $lineOffset += $redacted.Split("`n").Length - 1
            if ($OutputPath) { Write-RedactFile -LiteralPath $OutputPath -Text $redacted -Encoding $File.Encoding -Append }
        } while ($n -gt 0)
    }
    finally { $reader.Dispose() }
    $Session.Findings.Clear()
    $Session.Findings.AddRange($findings)
}
