# Redaction engine: sessions, token protection, rule application and the residual scan.

# Ordered residual checks; each is called as & $check $text $session and emits { Category; Offset; Length }.
$script:ResidualCheck = @('Get-RedactRuleResidual', 'Get-RedactEntropyResidual', 'Get-RedactLiteralResidual')

#region Helpers

function Get-RedactErrorRecord {
    # Messages passed here must name categories, rule ids or parameters only, never matched text.
    # Raise the record with throw, not ThrowTerminatingError: from a helper that only ends the calling statement, so a loop or
    # a later statement would carry on (and could still write output).
    [CmdletBinding()]
    [OutputType([System.Management.Automation.ErrorRecord])]
    param(
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][string]$ErrorId,
        [System.Management.Automation.ErrorCategory]$Category = 'InvalidOperation'
    )

    [System.Management.Automation.ErrorRecord]::new([System.InvalidOperationException]::new($Message), $ErrorId, $Category, $null)
}

function ConvertTo-LineColumn {
    # 1-based line and column of a 0-based offset.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][int]$Offset
    )

    $line = 1
    $lineStart = 0
    $i = $Text.IndexOf("`n")
    while ($i -ge 0 -and $i -lt $Offset) {
        $line++
        $lineStart = $i + 1
        $i = $Text.IndexOf("`n", $lineStart)
    }
    [pscustomobject]@{ Line = $line; Column = $Offset - $lineStart + 1 }
}

function Edit-RedactText {
    # Applies sorted, non-overlapping { Start; Length; Replacement } edits in one StringBuilder pass.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][object[]]$Edit
    )

    # Substring, not Append(string, int, int): PowerShell binds that call to the char[] overload and copies the whole text each time.
    $sb = [System.Text.StringBuilder]::new($Text.Length)
    $pos = 0
    foreach ($e in $Edit) {
        [void]$sb.Append($Text.Substring($pos, $e.Start - $pos)).Append($e.Replacement)
        $pos = $e.Start + $e.Length
    }
    [void]$sb.Append($Text.Substring($pos))
    $sb.ToString()
}

#endregion

#region Sentinels

# A sentinel is U+E000, the index as base-16 digits in U+E010..U+E01F, then U+E001, optionally padded with
# U+E002 to the length of what it replaces (so offsets in protected text equal offsets in the real text).
# Only private-use characters are used, so no rule can ever match inside one.
function ConvertTo-RedactSentinel {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][int]$Index,
        [int]$Length = 0
    )

    $digits = foreach ($c in $Index.ToString('x').ToCharArray()) { [char](0xE010 + [Convert]::ToInt32([string]$c, 16)) }
    ([string][char]0xE000 + (-join $digits) + [char]0xE001).PadRight($Length, [char]0xE002)
}

function Protect-RedactToken {
    # Swaps every existing token for a sentinel; originals are appended to $Store.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$Store
    )

    $edits = foreach ($m in (Get-RedactTokenPattern).Matches($Text)) {
        $index = $Store.Count
        $Store.Add($m.Value)
        [pscustomobject]@{ Start = $m.Index; Length = $m.Length; Replacement = ConvertTo-RedactSentinel -Index $index -Length $m.Length }
    }
    if (-not $edits) { return $Text }
    Edit-RedactText -Text $Text -Edit @($edits)
}

function Restore-RedactSentinel {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$Store
    )

    # An evaluator may build a replacement from text that still holds sentinels, so repeat (capped) until none is left.
    $pattern = Get-RedactRegex -Pattern '\uE000[\uE010-\uE01F]+\uE001\uE002*'
    $work = $Text
    for ($pass = 0; $pass -lt 8; $pass++) {
        $edits = foreach ($m in $pattern.Matches($work)) {
            $index = 0
            foreach ($c in $m.Value.Substring(1).TrimEnd([char]0xE002).TrimEnd([char]0xE001).ToCharArray()) { $index = $index * 16 + [int]$c - 0xE010 }
            [pscustomobject]@{ Start = $m.Index; Length = $m.Length; Replacement = $Store[$index] }
        }
        if (-not $edits) { break }
        $work = Edit-RedactText -Text $work -Edit @($edits)
    }
    $work
}

#endregion

#region Session and rule application

function New-RedactSession {
    <#
    .SYNOPSIS
        Creates the per-invocation redaction session.
    .DESCRIPTION
        Holds the merged config, the ordered rule list, per-category counts, the token maps, counters and
        entries (Token, Type, Original), the allowlists, the residual findings and the S04 deny-list.
    .PARAMETER Config
        Merged configuration from Get-RedactConfig.
    .EXAMPLE
        New-RedactSession -Config (Get-RedactConfig)
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory object only.')]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][hashtable]$Config)

    $rules = [System.Collections.Generic.List[object]]::new()
    $counts = [ordered]@{}
    # Every labelled rule gets a count (so audit columns never depend on config); only enabled rules run.
    foreach ($rule in @(Get-RedactSecretRule -Config $Config) + @(Get-RedactIdentifierRule -Config $Config)) {
        if ($rule.Label) { $counts[$rule.Label] = 0 }
        if ($rule.Enabled) { $rules.Add($rule) }
    }
    $deny = [System.Collections.Generic.HashSet[string]]::new([string[]]@($script:NonSecretNameSeed + @($Config['nonSecretNames'])), [System.StringComparer]::OrdinalIgnoreCase)

    [pscustomobject]@{
        Config         = $Config
        Rules          = $rules
        Counts         = $counts
        Maps           = [System.Collections.Generic.Dictionary[string, string]]::new()
        Counters       = @{}
        Entries        = [System.Collections.Generic.List[object]]::new()
        Allow          = Get-RedactAllowlist -Config $Config
        Findings       = [System.Collections.Generic.List[object]]::new()
        HashLike       = 0
        NonSecretNames = $deny
    }
}

function Protect-RedactSecretValue {
    # A value under a secret-named JSON property, CSV column or XML name: [secret:kv], counted as S04.
    # Empty, null-ish and already-tokenized values are returned unchanged.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Value,
        [Parameter(Mandatory)][object]$Session
    )

    if (Test-RedactSkipValue -Value $Value) { return $Value }
    $Session.Counts['kv'] += 1
    '[secret:kv]'
}

function Reset-RedactCount {
    # Zeroes the per-category counts (not the token maps), so each file in a run reports its own counts.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Resets an in-memory counter only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Session)

    foreach ($label in @($Session.Counts.Keys)) { $Session.Counts[$label] = 0 }
}

function Select-RedactNonOverlap {
    # Longest-first, then leftmost; returns the accepted spans in position order.
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$Span)

    $accepted = [System.Collections.Generic.List[object]]::new()
    foreach ($c in ($Span | Sort-Object -Property @{ Expression = 'Length'; Descending = $true }, 'Start')) {
        $end = $c.Start + $c.Length
        $clash = $false
        foreach ($a in $accepted) {
            if ($c.Start -lt ($a.Start + $a.Length) -and $a.Start -lt $end) { $clash = $true; break }
        }
        if (-not $clash) { $accepted.Add($c) }
    }
    $accepted | Sort-Object -Property Start
}

function Get-RedactSpan {
    # Spans a rule would replace: the 'val' group if present, else the whole match; Test-approved, overlap-free.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][hashtable]$Rule,
        [Parameter(Mandatory)][object]$Session
    )

    $skippable = Get-RedactRegex -Pattern '^[\uE000-\uE01F;,\s]+$'
    $found = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($regex in $Rule.Regex) {
            foreach ($m in $regex.Matches($Text)) {
                $g = $m.Groups['val']
                $span = if ($g.Success) { $g } else { $m }
                # Already-redacted content (sentinels, with separators) is never redacted again.
                if ($span.Length -eq 0 -or $skippable.IsMatch($span.Value)) { continue }
                if ($Rule.Test -and -not (& $Rule.Test $m $Session $Rule)) { continue }
                $found.Add([pscustomobject]@{ Start = $span.Index; Length = $span.Length; Match = $m })
            }
        }
    }
    catch [System.Text.RegularExpressions.RegexMatchTimeoutException] {
        throw (Get-RedactErrorRecord -Message "Rule $($Rule.Id) exceeded the regex time limit." -ErrorId 'RedactOutput.RegexTimeout')
    }
    if ($found.Count -le 1 -or $Rule.Regex.Count -eq 1) { return $found }
    Select-RedactNonOverlap -Span $found.ToArray()
}

function Invoke-RedactRule {
    # Applies one rule to protected text. Each replacement (a secret token, or what the Evaluator returns) is stored
    # behind a sentinel padded to the span's length, so later rules cannot match inside it and offsets stay put.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][hashtable]$Rule,
        [Parameter(Mandatory)][object]$Session,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$Store
    )

    $spans = @(Get-RedactSpan -Text $Text -Rule $Rule -Session $Session)
    if ($spans.Count -eq 0) { return $Text }
    $edits = foreach ($s in $spans) {
        $index = $Store.Count
        $Store.Add($(if ($Rule.Evaluator) { & $Rule.Evaluator $s.Match $Session } else { "[secret:$($Rule.Label)]" }))
        [pscustomobject]@{ Start = $s.Start; Length = $s.Length; Replacement = ConvertTo-RedactSentinel -Index $index -Length $s.Length }
    }
    if ($Rule.Label) { $Session.Counts[$Rule.Label] += $spans.Count }
    Edit-RedactText -Text $Text -Edit @($edits)
}

function Invoke-RedactText {
    <#
    .SYNOPSIS
        Applies every rule in the session to a string and returns the redacted string.
    .DESCRIPTION
        Existing tokens are protected first, each rule's replacement is protected immediately, and all
        sentinels are restored at the end, so redacting twice gives the same result as redacting once.
    .PARAMETER Text
        Text to redact.
    .PARAMETER Session
        Session from New-RedactSession; its Counts are updated.
    .EXAMPLE
        Invoke-RedactText -Text $text -Session $session
    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][object]$Session
    )

    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $store = [System.Collections.Generic.List[string]]::new()
    $work = Protect-RedactToken -Text $Text -Store $store
    foreach ($rule in $Session.Rules) {
        if ($rule.Probe -and -not $rule.Probe.IsMatch($work)) { continue }
        $work = Invoke-RedactRule -Text $work -Rule $rule -Session $Session -Store $store
    }
    Restore-RedactSentinel -Text $work -Store $store
}

#endregion

#region Wrapped list entries

# Console-width wrapping of Format-List output: a long value continues on lines indented to the value column, so
# neither half matches a rule. These are the pieces of the re-join: the cheap pre-check, the entry head and the width.
$script:WrapWidth = 79
$script:WrapCandidate = "(?m)^[^\r\n]{$script:WrapWidth,}(?:\r\n|\n|\r)[ ]+[^ \t\r\n]"
$script:WrapEntry = '^[A-Za-z0-9_.-][A-Za-z0-9_. -]*: (?=[^ \t])'

function Join-RedactWrappedLine {
    <#
    .SYNOPSIS
        Re-joins Format-List values that were wrapped at console width.
    .DESCRIPTION
        A line "<name><spaces>: <value>" fixes the value column V. The next line is a continuation when it starts with
        exactly V spaces and then a non-space, and the previous physical line (entry or earlier continuation) is at
        least 79 characters long, i.e. it reached the console width. Continuations are appended without their indent
        (PowerShell inserts nothing when it wraps), chains included; the joined line keeps the last line's terminator.
        Only the number of joined lines is reported (verbose).
    .PARAMETER Text
        Text-mode input (pipeline, clipboard, command output, text, log and script files).
    .EXAMPLE
        Join-RedactWrappedLine -Text $text
    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][Parameter(Mandatory)][string]$Text)

    if (-not (Get-RedactRegex -Pattern $script:WrapCandidate).IsMatch($Text)) { return $Text }
    $entry = Get-RedactRegex -Pattern $script:WrapEntry
    $lines = [System.Collections.Generic.List[object]]::new()
    $indent = $null
    $previousLength = 0
    $joined = 0
    foreach ($l in (Split-RedactLine -Text $Text)) {
        $line = $l.Line
        if ($indent -and $previousLength -ge $script:WrapWidth -and $line.Length -gt $indent.Length -and $line.StartsWith($indent, [StringComparison]::Ordinal) -and $line[$indent.Length] -notin ' ', "`t") {
            $lines[$lines.Count - 1].Line += $line.Substring($indent.Length)
            $lines[$lines.Count - 1].Eol = $l.Eol
            $joined++
        }
        else {
            $lines.Add($l)
            $head = $entry.Match($line)
            $indent = if ($head.Success) { ' ' * $head.Length }
        }
        $previousLength = $line.Length
    }
    if ($joined -gt 0) { Write-Verbose "Joined $joined wrapped continuation line(s)." }
    Join-RedactLine -Line $lines
}

function Get-RedactOpenWrapStart {
    # For chunked reading: text that ends on a line terminator may end inside a wrapped entry whose next line is not read
    # yet. Returns the offset of that entry (so the chunk can stop before it), else the text length. Walks back over
    # indented lines that reached the console width up to a list entry; a chain is a handful of lines, so the walk is capped.
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)][string]$Text)

    $entry = Get-RedactRegex -Pattern $script:WrapEntry
    $end = $Text.Length
    for ($i = 0; $i -lt 64 -and $end -gt 0; $i++) {
        $start = if ($end -ge 2) { $Text.LastIndexOf([char]10, $end - 2) + 1 } else { 0 }
        $line = $Text.Substring($start, $end - $start).TrimEnd("`r", "`n")
        if ($line.Length -lt $script:WrapWidth) { break }
        if ($entry.IsMatch($line)) { return $start }
        if ($line[0] -ne ' ') { break }
        $end = $start
    }
    $Text.Length
}

#endregion

#region Residual scan

function Get-RedactEntropy {
    [CmdletBinding()]
    [OutputType([double])]
    param([Parameter(Mandatory)][string]$Value)

    $freq = [System.Collections.Generic.Dictionary[char, int]]::new()
    foreach ($c in $Value.ToCharArray()) { $freq[$c] = 1 + $(if ($freq.ContainsKey($c)) { $freq[$c] } else { 0 }) }
    $entropy = 0.0
    foreach ($n in $freq.Values) {
        $p = $n / $Value.Length
        $entropy -= $p * [math]::Log($p, 2)
    }
    $entropy
}

function Get-RedactRuleResidual {
    # Every mutating rule in detect-only mode. Mask rules still apply, so allowlisted spans are hidden from later rules.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][object]$Session
    )

    $store = [System.Collections.Generic.List[string]]::new()
    $work = $Text
    foreach ($rule in $Session.Rules) {
        if ($rule.Probe -and -not $rule.Probe.IsMatch($work)) { continue }
        if ($rule.Kind -eq 'mask') { $work = Invoke-RedactRule -Text $work -Rule $rule -Session $Session -Store $store; continue }
        foreach ($s in @(Get-RedactSpan -Text $work -Rule $rule -Session $Session)) {
            [pscustomobject]@{ Category = $rule.Label; Offset = $s.Start; Length = $s.Length }
        }
    }
}

function Get-RedactLiteralResidual {
    # Config literals (internal domains, NetBIOS names, host names, users, extra terms) still present, as a plain
    # case-insensitive substring search. The category is the config key; the value is never reported.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][object]$Session
    )

    $literal = [ordered]@{
        internalDomains = @(Get-RedactConfigList -Config $Session.Config -Key 'internalDomains')
        netbiosDomains  = @(Get-RedactConfigList -Config $Session.Config -Key 'netbiosDomains' | ForEach-Object { $_['netbios'] })
        hostList        = @(Get-RedactConfigList -Config $Session.Config -Key 'hostList')
        usernames       = @(Get-RedactConfigList -Config $Session.Config -Key 'usernames')
        extraTerms      = @(Get-RedactConfigList -Config $Session.Config -Key 'extraTerms' | ForEach-Object { $_['term'] })
    }
    foreach ($key in $literal.Keys) {
        $alternation = Get-RedactAlternation -Term $literal[$key]
        if (-not $alternation) { continue }
        foreach ($m in (Get-RedactRegex -Pattern $alternation -IgnoreCase).Matches($Text)) {
            [pscustomobject]@{ Category = $key; Offset = $m.Index; Length = $m.Length }
        }
    }
}

function Get-RedactEntropyResidual {
    # S17, report-only: long high-entropy strings; hash-shaped values are counted in Session.HashLike instead.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][object]$Session
    )

    $hashShape = Get-RedactRegex -Pattern "^(?:$script:GUID|[0-9A-Fa-f]{32}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$"
    $hex = Get-RedactRegex -Pattern '^[0-9A-Fa-f]+$'
    $letter = Get-RedactRegex -Pattern '[A-Za-z]'
    $digit = Get-RedactRegex -Pattern '[0-9]'
    try {
        foreach ($m in (Get-RedactRegex -Pattern '[A-Za-z0-9+/_-]{32,}={0,2}').Matches($Text)) {
            $core = $m.Value.TrimEnd('=')
            if ($hashShape.IsMatch($core)) { $Session.HashLike++; continue }
            $minimum = if ($hex.IsMatch($core)) { 3.0 } else { 4.0 }
            if ($letter.IsMatch($core) -and $digit.IsMatch($core) -and (Get-RedactEntropy -Value $core) -ge $minimum) {
                [pscustomobject]@{ Category = 'high-entropy'; Offset = $m.Index; Length = $m.Length }
            }
        }
    }
    catch [System.Text.RegularExpressions.RegexMatchTimeoutException] {
        throw (Get-RedactErrorRecord -Message 'Rule S17 exceeded the regex time limit.' -ErrorId 'RedactOutput.RegexTimeout')
    }
}

function Find-RedactResidual {
    <#
    .SYNOPSIS
        Scans text for anything that still looks sensitive and fills Session.Findings.
    .DESCRIPTION
        Runs every residual check on the text (existing tokens protected). Findings carry only
        Category, Line, Column and Length; never the matched value.
    .PARAMETER Text
        Text to scan (normally already redacted).
    .PARAMETER Session
        Session from New-RedactSession; Findings and HashLike are reset and refilled.
    .EXAMPLE
        Find-RedactResidual -Text $redacted -Session $session
    .OUTPUTS
        System.Collections.Generic.List[object]
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][object]$Session
    )

    $Session.Findings.Clear()
    $Session.HashLike = 0
    if (-not [string]::IsNullOrEmpty($Text)) {
        $protected = Protect-RedactToken -Text $Text -Store ([System.Collections.Generic.List[string]]::new())
        $raw = foreach ($check in $script:ResidualCheck) { & $check $protected $Session }
        $seen = [System.Collections.Generic.HashSet[int]]::new()
        foreach ($f in ($raw | Sort-Object -Property Offset)) {
            if (-not $seen.Add($f.Offset)) { continue }
            $pos = ConvertTo-LineColumn -Text $protected -Offset $f.Offset
            $Session.Findings.Add([pscustomobject]@{ Category = $f.Category; Line = $pos.Line; Column = $pos.Column; Length = $f.Length })
        }
    }
    , $Session.Findings
}

#endregion
