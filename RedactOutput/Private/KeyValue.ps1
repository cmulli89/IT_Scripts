# .env / .ini / .conf / .properties / .yaml handlers and .reg dumps. Both reuse the engine for every string.

# A commented-out or list-item line that still looks like KEY=value or key: value (the S04 line rule needs the name first).
$script:CommentKeyValue = '(?m)^(?<lead>[ \t]*(?:(?:[#;]+|//)[ \t]*|-[ \t]+))(?<rest>[A-Za-z0-9_.-]+[ \t]*[:=][^\r\n]*)'

# A .reg binary value: "Name"=hex:..., hex(2):..., hex(7):... with its backslash line continuations. Group t is the registry type.
$script:RegHexValue = '(?m)^(?<head>(?:"(?:[^"\\\r\n]|\\.)*"|@)=hex(?:\((?<t>[0-9a-fA-F]+)\))?:)(?<val>(?:[0-9A-Fa-f]{2}|,|\\\r?\n[ \t]*)*)'

function Invoke-RedactKeyValue {
    # The text pass covers KEY=value, key = value and key: value lines (S04); comments are scanned too, because
    # commented-out credentials are common.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][object]$Session
    )

    $redacted = Invoke-RedactText -Text $Text -Session $Session
    (Get-RedactRegex -Pattern $script:CommentKeyValue).Replace($redacted, {
            param($m)
            $m.Groups['lead'].Value + (Invoke-RedactText -Text $m.Groups['rest'].Value -Session $Session)
        })
}

#region .reg

function ConvertFrom-RedactRegHex {
    # Decodes a hex payload for scanning only. REG_SZ / EXPAND_SZ / MULTI_SZ (hex(1), hex(2), hex(7)) are UTF-16LE; plain
    # hex: is read as both Latin-1 and UTF-16LE. Control characters (string separators) become line breaks.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Data,
        [string]$Type
    )

    $hex = (Get-RedactRegex -Pattern '[^0-9A-Fa-f]').Replace($Data, '')
    $bytes = [Convert]::FromHexString($hex.Substring(0, $hex.Length - ($hex.Length % 2)))
    $utf16 = [System.Text.Encoding]::Unicode.GetString($bytes)
    $text = if ($Type -in '1', '2', '7') { $utf16 } else { [System.Text.Encoding]::Latin1.GetString($bytes) + "`n" + $utf16 }
    (Get-RedactRegex -Pattern '[\u0000-\u0008\u000B-\u001F\u007F]+').Replace($text, "`n")
}

function Get-RedactSecretCount {
    # Total hits of the secret rules so far in this session.
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)][object]$Session)

    $sum = 0
    foreach ($rule in $Session.Rules) { if ($rule.Kind -eq 'secret') { $sum += $Session.Counts[$rule.Label] } }
    $sum
}

function Protect-RedactRegHex {
    # Scans one decoded payload with the shared session. When any rule would change it, the whole payload is replaced:
    # by [secret:reg-hex] when a secret rule hit, otherwise by the first identifier token. Otherwise it is untouched.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][System.Text.RegularExpressions.Match]$Match,
        [Parameter(Mandatory)][object]$Session
    )

    $decoded = ConvertFrom-RedactRegHex -Data $Match.Groups['val'].Value -Type $Match.Groups['t'].Value
    $before = Get-RedactSecretCount -Session $Session
    $redacted = Invoke-RedactText -Text $decoded -Session $Session
    if ($redacted -ceq $decoded) { return $Match.Value }
    $token = (Get-RedactTokenPattern).Match($redacted)
    $payload = if ((Get-RedactSecretCount -Session $Session) -gt $before -or -not $token.Success) { '[secret:reg-hex]' } else { $token.Value }
    $Match.Groups['head'].Value + $payload
}

function Invoke-RedactReg {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][object]$Session
    )

    $edited = (Get-RedactRegex -Pattern $script:RegHexValue).Replace($Text, { param($m) Protect-RedactRegHex -Match $m -Session $Session })
    Invoke-RedactText -Text $edited -Session $Session
}

#endregion
