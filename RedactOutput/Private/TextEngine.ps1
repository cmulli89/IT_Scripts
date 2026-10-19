# Redaction engine: sessions, token protection, rule application and the residual scan.

# Ordered residual checks; each is called as & $check $text $session and emits { Category; Offset; Length }.
# Stage 2 appends the config-literal and identifier checks here.
$script:ResidualCheck = @('Get-RedactRuleResidual', 'Get-RedactEntropyResidual')

#region Helpers

function Get-RedactErrorRecord {
    # Messages passed here must name categories, rule ids or parameters only, never matched text.
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

    $sb = [System.Text.StringBuilder]::new($Text.Length)
    $pos = 0
    foreach ($e in $Edit) {
        [void]$sb.Append($Text, $pos, $e.Start - $pos).Append($e.Replacement)
        $pos = $e.Start + $e.Length
    }
    [void]$sb.Append($Text, $pos, $Text.Length - $pos)
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

    $edits = foreach ($m in (Get-RedactRegex -Pattern '\uE000[\uE010-\uE01F]+\uE001\uE002*').Matches($Text)) {
        $index = 0
        foreach ($c in $m.Value.Substring(1).TrimEnd([char]0xE002).TrimEnd([char]0xE001).ToCharArray()) { $index = $index * 16 + [int]$c - 0xE010 }
        [pscustomobject]@{ Start = $m.Index; Length = $m.Length; Replacement = $Store[$index] }
    }
    if (-not $edits) { return $Text }
    Edit-RedactText -Text $Text -Edit @($edits)
}

#endregion

#region Session and rule application

function New-RedactSession {
    <#
    .SYNOPSIS
        Creates the per-invocation redaction session.
    .DESCRIPTION
        Holds the merged config, the ordered rule list, per-category counts, the (stage 2) maps and
        counters, the residual findings and the S04 deny-list.
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
    foreach ($rule in @(Get-RedactSecretRule -Config $Config)) {
        $rules.Add($rule)
        $counts[$rule.Label] = 0
    }
    $deny = [System.Collections.Generic.HashSet[string]]::new([string[]]@($script:NonSecretNameSeed + @($Config['nonSecretNames'])), [System.StringComparer]::OrdinalIgnoreCase)

    [pscustomobject]@{
        Config         = $Config
        Rules          = $rules
        Counts         = $counts
        Maps           = @{}
        Counters       = @{}
        Findings       = [System.Collections.Generic.List[object]]::new()
        HashLike       = 0
        NonSecretNames = $deny
    }
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
                if ($Rule.Test -and -not (& $Rule.Test $m $Session)) { continue }
                $found.Add([pscustomobject]@{ Start = $span.Index; Length = $span.Length; Match = $m })
            }
        }
    }
    catch [System.Text.RegularExpressions.RegexMatchTimeoutException] {
        $PSCmdlet.ThrowTerminatingError((Get-RedactErrorRecord -Message "Rule $($Rule.Id) exceeded the regex time limit." -ErrorId 'RedactOutput.RegexTimeout'))
    }
    if ($found.Count -le 1 -or $Rule.Regex.Count -eq 1) { return $found }
    Select-RedactNonOverlap -Span $found.ToArray()
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
        $spans = @(Get-RedactSpan -Text $work -Rule $rule -Session $Session)
        if ($spans.Count -eq 0) { continue }
        $edits = foreach ($s in $spans) {
            $index = $store.Count
            $store.Add($(if ($rule.ContainsKey('Replace')) { & $rule.Replace $s.Match $Session } else { "[secret:$($rule.Label)]" }))
            [pscustomobject]@{ Start = $s.Start; Length = $s.Length; Replacement = ConvertTo-RedactSentinel -Index $index }
        }
        $work = Edit-RedactText -Text $work -Edit @($edits)
        $Session.Counts[$rule.Label] += $spans.Count
    }
    Restore-RedactSentinel -Text $work -Store $store
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
    # Every mutating rule in detect-only mode.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][object]$Session
    )

    foreach ($rule in $Session.Rules) {
        foreach ($s in @(Get-RedactSpan -Text $Text -Rule $rule -Session $Session)) {
            [pscustomobject]@{ Category = $rule.Label; Offset = $s.Start; Length = $s.Length }
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
        $PSCmdlet.ThrowTerminatingError((Get-RedactErrorRecord -Message 'Rule S17 exceeded the regex time limit.' -ErrorId 'RedactOutput.RegexTimeout'))
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
