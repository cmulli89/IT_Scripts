# CSV / TSV handler. Quote-aware splitter (RFC 4180), not Import-Csv: the header row and every untouched cell
# survive byte for byte. Ragged rows, duplicate headers or broken quoting return $null (text fallback).

function Get-RedactCsvDelimiter {
    # The most frequent of comma, tab, semicolon and pipe outside quotes in the header line (comma on a tie or none).
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Text)

    $header = (Get-RedactRegex -Pattern '^[^\r\n]*').Match($Text).Value
    $bare = (Get-RedactRegex -Pattern '"(?:[^"]|"")*"').Replace($header, '')
    $best = ','
    $most = 0
    foreach ($d in ',', "`t", ';', '|') {
        $n = $bare.Length - $bare.Replace($d, '').Length
        if ($n -gt $most) { $best = $d; $most = $n }
    }
    $best
}

function ConvertFrom-RedactCsv {
    # Records as { Field = raw fields (quotes included); Eol }, or $null if the quoting does not parse to the end.
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[object]])]
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string]$Delimiter
    )

    $escaped = [regex]::Escape($Delimiter)
    $field = Get-RedactRegex -Pattern ('\G(?:"(?:[^"]|"")*"|[^"' + $escaped + '\r\n]*)(' + $escaped + '|\r\n|\n|\r|\z)')
    $records = [System.Collections.Generic.List[object]]::new()
    $fields = [System.Collections.Generic.List[string]]::new()
    $end = 0
    try {
        for ($m = $field.Match($Text); $m.Success; $m = $m.NextMatch()) {
            if ($m.Length -eq 0 -and $fields.Count -eq 0) { break }
            $end = $m.Index + $m.Length
            $sep = $m.Groups[1].Value
            $fields.Add($m.Value.Substring(0, $m.Length - $sep.Length))
            if ($sep -ne $Delimiter) {
                $records.Add([pscustomobject]@{ Field = $fields; Eol = $sep })
                $fields = [System.Collections.Generic.List[string]]::new()
            }
        }
    }
    catch [System.Text.RegularExpressions.RegexMatchTimeoutException] { return $null }
    if ($end -ne $Text.Length) { return $null }
    , $records
}

function ConvertFrom-RedactCsvField {
    # Raw field -> value (quotes removed, doubled quotes collapsed).
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Raw)

    if ($Raw.StartsWith('"')) { $Raw.Substring(1, $Raw.Length - 2).Replace('""', '"') } else { $Raw }
}

function ConvertTo-RedactCsvField {
    # Value -> raw field: quoted when it was quoted or now needs it.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][bool]$Quoted,
        [Parameter(Mandatory)][string]$Delimiter
    )

    if ($Quoted -or $Value.IndexOfAny([char[]]@($Delimiter[0], '"', "`r", "`n")) -ge 0) { '"' + $Value.Replace('"', '""') + '"' } else { $Value }
}

function Invoke-RedactCsv {
    # The header record is copied as is. A secret-named column has its non-empty cells replaced; every other cell goes
    # through the engine. Cells the engine leaves alone keep their exact original bytes.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][object]$Session,
        [string]$Delimiter
    )

    if (-not $Delimiter) { $Delimiter = Get-RedactCsvDelimiter -Text $Text }
    $records = ConvertFrom-RedactCsv -Text $Text -Delimiter $Delimiter
    if ($null -eq $records -or $records.Count -eq 0) { return $null }

    $names = [string[]]@($records[0].Field | ForEach-Object { ConvertFrom-RedactCsvField -Raw $_ })
    if ([System.Collections.Generic.HashSet[string]]::new($names, [System.StringComparer]::OrdinalIgnoreCase).Count -ne $names.Count) { return $null }
    # Only a blank line may have a different field count.
    foreach ($r in $records) {
        if ($r.Field.Count -ne $names.Count -and -not ($r.Field.Count -eq 1 -and $r.Field[0] -eq '')) { return $null }
    }
    $secret = @($names | ForEach-Object { Test-RedactSecretName -Name $_ -Session $Session })

    $sb = [System.Text.StringBuilder]::new($Text.Length)
    for ($row = 0; $row -lt $records.Count; $row++) {
        $r = $records[$row]
        for ($i = 0; $i -lt $r.Field.Count; $i++) {
            $raw = $r.Field[$i]
            if ($i -gt 0) { [void]$sb.Append($Delimiter) }
            if ($row -eq 0 -or $raw -eq '' -or $r.Field.Count -ne $names.Count) { [void]$sb.Append($raw); continue }
            $value = ConvertFrom-RedactCsvField -Raw $raw
            $new = if ($secret[$i]) { Protect-RedactSecretValue -Value $value -Session $Session } else { Invoke-RedactText -Text $value -Session $Session }
            [void]$sb.Append($(if ($new -ceq $value) { $raw } else { ConvertTo-RedactCsvField -Value $new -Quoted $raw.StartsWith('"') -Delimiter $Delimiter }))
        }
        [void]$sb.Append($r.Eol)
    }
    $sb.ToString()
}
