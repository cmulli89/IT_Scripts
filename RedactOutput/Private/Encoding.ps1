# File encoding: BOM and binary sniffing, strict decoding, writing, and line splitting that keeps each terminator.

# BOM signatures (as hex) and the encoding each one means. UTF-32LE must come before UTF-16LE (same first two bytes).
$script:BomTable = @(
    @{ Hex = 'FFFE0000'; Name = 'UTF32' }
    @{ Hex = '0000FEFF'; Name = 'BigEndianUTF32' }
    @{ Hex = 'EFBBBF'; Name = 'UTF8' }
    @{ Hex = 'FFFE'; Name = 'Unicode' }
    @{ Hex = 'FEFF'; Name = 'BigEndianUnicode' }
)
$script:SniffLength = 8192

function Get-RedactEncodingByName {
    # Every encoding throws on invalid bytes and carries its BOM as the preamble (HasBom decides whether it is written).
    [CmdletBinding()]
    [OutputType([System.Text.Encoding])]
    param([Parameter(Mandatory)][ValidateSet('UTF8', 'Unicode', 'BigEndianUnicode', 'UTF32', 'BigEndianUTF32', 'Windows1252')][string]$Name)

    switch ($Name) {
        'UTF8' { [System.Text.UTF8Encoding]::new($true, $true) }
        'Unicode' { [System.Text.UnicodeEncoding]::new($false, $true, $true) }
        'BigEndianUnicode' { [System.Text.UnicodeEncoding]::new($true, $true, $true) }
        'UTF32' { [System.Text.UTF32Encoding]::new($false, $true, $true) }
        'BigEndianUTF32' { [System.Text.UTF32Encoding]::new($true, $true, $true) }
        'Windows1252' {
            [System.Text.Encoding]::RegisterProvider([System.Text.CodePagesEncodingProvider]::Instance)
            [System.Text.Encoding]::GetEncoding(1252)
        }
    }
}

function Test-RedactUtf8 {
    # Streams the whole file through a strict UTF-8 decoder; $false at the first invalid sequence.
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][System.IO.Stream]$Stream)

    $decoder = [System.Text.UTF8Encoding]::new($false, $true).GetDecoder()
    $bytes = [byte[]]::new(1MB)
    $chars = [char[]]::new(1MB + 4)
    try {
        while (($n = $Stream.Read($bytes, 0, $bytes.Length)) -gt 0) { [void]$decoder.GetChars($bytes, 0, $n, $chars, 0, $false) }
        [void]$decoder.GetChars($bytes, 0, 0, $chars, 0, $true)
        $true
    }
    catch [System.Text.DecoderFallbackException] { $false }
}

function Get-RedactNulPattern {
    # 'binary' (NULs scattered), 'Unicode' / 'BigEndianUnicode' (NULs on every other byte: BOM-less UTF-16) or '' (no NUL).
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][byte[]]$Head,
        [Parameter(Mandatory)][int]$Length
    )

    if ([Array]::IndexOf($Head, [byte]0, 0, $Length) -lt 0) { return '' }
    $nul = @(0, 0)
    for ($i = 0; $i -lt $Length; $i++) { if ($Head[$i] -eq 0) { $nul[$i % 2]++ } }
    $slots = [math]::Max(1, [math]::Floor($Length / 2))
    if ($nul[1] -ge 0.3 * $slots -and $nul[0] -le 0.05 * $slots) { return 'Unicode' }
    if ($nul[0] -ge 0.3 * $slots -and $nul[1] -le 0.05 * $slots) { return 'BigEndianUnicode' }
    'binary'
}

function Get-RedactEncoding {
    <#
    .SYNOPSIS
        Detects the encoding of a file without reading it into memory.
    .DESCRIPTION
        BOM first (UTF-8, UTF-16LE/BE, UTF-32LE/BE). With no BOM, a NUL byte in the first 8 KB means binary,
        unless the NULs sit on every other byte (BOM-less UTF-16), which is an error that names the -Encoding
        value to use. With no BOM and no NUL the file is UTF-8 when it decodes strictly, otherwise
        Windows-1252 with a warning. -Encoding overrides detection. Returns Encoding, HasBom and IsBinary.
    .PARAMETER LiteralPath
        File to inspect.
    .PARAMETER Encoding
        Forces the encoding (UTF8, Unicode, BigEndianUnicode, UTF32, BigEndianUTF32, Windows1252).
    .EXAMPLE
        Get-RedactEncoding -LiteralPath .\dump.reg
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$LiteralPath,
        [string]$Encoding
    )

    $stream = [System.IO.FileStream]::new($LiteralPath, 'Open', 'Read', 'ReadWrite')
    try {
        $head = [byte[]]::new($script:SniffLength)
        $n = $stream.Read($head, 0, $head.Length)
        $hex = [Convert]::ToHexString($head, 0, [math]::Min(4, $n))
        $bom = $script:BomTable.Where({ $hex.StartsWith($_.Hex, [StringComparison]::Ordinal) }, 'First')
        $name = if ($Encoding) { $Encoding } elseif ($bom) { $bom[0].Name }
        $hasBom = [bool]($bom -and $bom[0].Name -eq $name)
        $nul = if ($name) { '' } else { Get-RedactNulPattern -Head $head -Length $n }
        if ($nul -eq 'binary') { return [pscustomobject]@{ Encoding = $null; HasBom = $false; IsBinary = $true } }
        if ($nul) {
            throw (Get-RedactErrorRecord -ErrorId 'RedactOutput.Utf16NoBom' -Message "'$([IO.Path]::GetFileName($LiteralPath))' looks like UTF-16 without a BOM. Rerun with -Encoding $nul.")
        }
        if (-not $name) {
            $stream.Position = 0
            if (Test-RedactUtf8 -Stream $stream) { $name = 'UTF8' }
            else {
                $name = 'Windows1252'
                Write-Warning "'$([IO.Path]::GetFileName($LiteralPath))' is not valid UTF-8; decoded as Windows-1252."
            }
        }
        [pscustomobject]@{ Encoding = Get-RedactEncodingByName -Name $name; HasBom = $hasBom; IsBinary = $false }
    }
    finally { $stream.Dispose() }
}

function Open-RedactReader {
    # Read-only (FileShare.ReadWrite) reader; a matching BOM is skipped by the reader itself.
    [CmdletBinding()]
    [OutputType([System.IO.StreamReader])]
    param(
        [Parameter(Mandatory)][string]$LiteralPath,
        [Parameter(Mandatory)][System.Text.Encoding]$Encoding
    )

    $stream = [System.IO.FileStream]::new($LiteralPath, 'Open', 'Read', 'ReadWrite')
    [System.IO.StreamReader]::new($stream, $Encoding, $false, 1MB)
}

function Read-RedactFile {
    <#
    .SYNOPSIS
        Reads a text file with encoding detection.
    .DESCRIPTION
        Returns Text, Encoding (a System.Text.Encoding), HasBom and IsBinary. A binary file returns IsBinary
        with no Text. See Get-RedactEncoding for the detection rules. Line endings are left exactly as read.
    .PARAMETER LiteralPath
        File to read.
    .PARAMETER Encoding
        Forces the encoding (UTF8, Unicode, BigEndianUnicode, UTF32, BigEndianUTF32, Windows1252).
    .EXAMPLE
        Read-RedactFile -LiteralPath .\dump.reg -Encoding Unicode
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$LiteralPath,
        [string]$Encoding
    )

    $info = Get-RedactEncoding -LiteralPath $LiteralPath -Encoding $Encoding
    if ($info.IsBinary) { return [pscustomobject]@{ Text = $null; Encoding = $null; HasBom = $false; IsBinary = $true } }
    $reader = Open-RedactReader -LiteralPath $LiteralPath -Encoding $info.Encoding
    try { $text = $reader.ReadToEnd() }
    catch [System.Text.DecoderFallbackException] {
        throw (Get-RedactErrorRecord -ErrorId 'RedactOutput.InvalidBytes' -Message "'$([IO.Path]::GetFileName($LiteralPath))' has bytes that are not valid for its encoding. Try -Encoding Windows1252.")
    }
    finally { $reader.Dispose() }
    [pscustomobject]@{ Text = $text; Encoding = $info.Encoding; HasBom = $info.HasBom; IsBinary = $false }
}

function Write-RedactFile {
    <#
    .SYNOPSIS
        Writes text with the given encoding, optionally preceded by its BOM.
    .DESCRIPTION
        Text is written exactly as given: line endings are never normalized. -Append adds to a file that an
        earlier call created (used by the streaming path).
    .PARAMETER LiteralPath
        Output file.
    .PARAMETER Text
        Text to write.
    .PARAMETER Encoding
        Encoding object from Read-RedactFile.
    .PARAMETER HasBom
        Write the encoding's BOM first (ignored with -Append).
    .PARAMETER Append
        Append instead of creating or overwriting the file.
    .EXAMPLE
        Write-RedactFile -LiteralPath .\out.txt -Text $text -Encoding $file.Encoding -HasBom:$file.HasBom
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LiteralPath,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][System.Text.Encoding]$Encoding,
        [switch]$HasBom,
        [switch]$Append
    )

    $bytes = $Encoding.GetBytes($Text)
    $stream = [System.IO.FileStream]::new($LiteralPath, $(if ($Append) { 'Append' } else { 'Create' }), 'Write', 'None')
    try {
        if ($HasBom -and -not $Append) {
            $preamble = $Encoding.GetPreamble()
            $stream.Write($preamble, 0, $preamble.Length)
        }
        $stream.Write($bytes, 0, $bytes.Length)
    }
    finally { $stream.Dispose() }
}

#region Lines

function Split-RedactLine {
    # Each line with its own terminator; text without a final terminator has a last line whose Eol is empty.
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[object]])]
    param([AllowEmptyString()][Parameter(Mandatory)][string]$Text)

    $lines = [System.Collections.Generic.List[object]]::new()
    foreach ($m in (Get-RedactRegex -Pattern '([^\r\n]*)(\r\n|\n|\r|\z)').Matches($Text)) {
        if ($m.Length -gt 0) { $lines.Add([pscustomobject]@{ Line = $m.Groups[1].Value; Eol = $m.Groups[2].Value }) }
    }
    , $lines
}

function Join-RedactLine {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.IEnumerable[object]]$Line)

    $sb = [System.Text.StringBuilder]::new()
    foreach ($l in $Line) { [void]$sb.Append($l.Line).Append($l.Eol) }
    $sb.ToString()
}

function Select-RedactLine {
    # -Head / -Tail: keep the first and last lines and put a marker where the rest was. Structured types are left whole.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][string]$Type,
        [ValidateRange(0, [int]::MaxValue)][int]$Head,
        [ValidateRange(0, [int]::MaxValue)][int]$Tail
    )

    if ($Head -le 0 -and $Tail -le 0) { return $Text }
    if ($Type -in $script:StructuredType) {
        Write-Warning "-Head/-Tail ignored for $Type input."
        return $Text
    }
    $lines = Split-RedactLine -Text $Text
    $omitted = $lines.Count - $Head - $Tail
    if ($omitted -le 0) { return $Text }
    $kept = [System.Collections.Generic.List[object]]::new()
    $kept.AddRange($lines.GetRange(0, $Head))
    $kept.Add([pscustomobject]@{ Line = "... [$omitted lines omitted] ..."; Eol = $(if ($Tail -gt 0) { $lines[0].Eol } else { $lines[$lines.Count - 1].Eol }) })
    $kept.AddRange($lines.GetRange($lines.Count - $Tail, $Tail))
    Join-RedactLine -Line $kept
}

#endregion
