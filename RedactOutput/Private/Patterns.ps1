# Regex construction, shared fragments, the token pattern and the secret rule table.

# Fragments reused by the identifier rules (stage 2) and the residual check.
$script:OCT  = '(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
$script:GUID = '[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}'

# S04 name fragment (any name containing one of these) and the built-in deny-list.
$script:SecretNameBase = 'key|secret|token|passw(?:or)?d|pwd|credential|apikey|connectionstring|sas|signature|client_id|tenant'
$script:NonSecretNameSeed = @(
    'KeyVaultName', 'KeyName', 'KeyId', 'KeyUsage', 'KeyType', 'KeyLength', 'KeySize', 'KeyboardLayout',
    'PublicKeyToken', 'RegistryKey', 'PasswordLastSet', 'PasswordNeverExpires', 'PasswordExpired',
    'PasswordNotRequired', 'PasswordPolicy', 'TokenLifetime', 'TokenType', 'SasUrlSupported',
    'ms-Mcs-AdmPwdExpirationTime', 'msLAPS-PasswordExpirationTime'
)

$script:RegexCache = @{}

function New-RedactRegex {
    <#
    .SYNOPSIS
        Builds a compiled, culture-invariant regex with a 2-second match timeout.
    .DESCRIPTION
        The only place regexes are constructed, so every pattern gets the same options and timeout.
    .PARAMETER Pattern
        .NET regex pattern. Use explicit [0-9] and [A-Za-z0-9_] classes, never the shorthand classes.
    .PARAMETER IgnoreCase
        Adds RegexOptions.IgnoreCase.
    .EXAMPLE
        New-RedactRegex -Pattern '[0-9]{4}' -IgnoreCase
    .OUTPUTS
        System.Text.RegularExpressions.Regex
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory object only.')]
    [CmdletBinding()]
    [OutputType([regex])]
    param(
        [Parameter(Mandatory)][string]$Pattern,
        [switch]$IgnoreCase
    )

    $options = [System.Text.RegularExpressions.RegexOptions]::Compiled -bor [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    if ($IgnoreCase) { $options = $options -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase }
    [regex]::new($Pattern, $options, [timespan]::FromSeconds(2))
}

function Get-RedactRegex {
    # Compile each distinct pattern once per module load.
    [CmdletBinding()]
    [OutputType([regex])]
    param(
        [Parameter(Mandatory)][string]$Pattern,
        [switch]$IgnoreCase
    )

    $key = "$($IgnoreCase.IsPresent)|$Pattern"
    if (-not $script:RegexCache.ContainsKey($key)) {
        $script:RegexCache[$key] = New-RedactRegex -Pattern $Pattern -IgnoreCase:$IgnoreCase
    }
    $script:RegexCache[$key]
}

function Get-RedactTokenPattern {
    # Any existing token: [type-NN], [type-sub-NN], [term-LABEL-NN] or [secret:label].
    [CmdletBinding()]
    [OutputType([regex])]
    param()

    Get-RedactRegex -Pattern '\[(?:secret:[a-z0-9-]+|[a-z][a-z0-9]*(?:-[A-Za-z0-9_]+)*-[0-9]{2,})\]'
}

function Test-RedactSkipValue {
    # True for values S04/S05 must leave alone: empty, null-ish, booleans, masks and PowerShell variable references.
    [CmdletBinding()]
    [OutputType([bool])]
    param([string]$Value)

    $v = $Value.Trim().TrimEnd(',').Trim()
    ($v.Length -eq 0) -or ($v -in '$null', 'null', 'true', 'false', 'none') -or ($v[0] -eq '$') -or ($v.Trim('*').Length -eq 0)
}

function Get-RedactSecretRule {
    <#
    .SYNOPSIS
        Returns the ordered secret rule table (S01-S16, S04 last).
    .DESCRIPTION
        A rule is a hashtable: Id, Label, Kind, Regex (compiled), optional Test scriptblock
        { param($match, $session) } returning $false to leave a match alone. If a match has a
        successful named group 'val', only that span is replaced; otherwise the whole match.
    .PARAMETER Config
        Merged configuration; secretNames extends the S04 name list.
    .EXAMPLE
        Get-RedactSecretRule -Config @{ secretNames = @('badge_pin') }
    .OUTPUTS
        System.Collections.Hashtable[]
    #>
    [CmdletBinding()]
    [OutputType([hashtable[]])]
    param([hashtable]$Config = @{})

    $terms = [System.Collections.Generic.List[string]]::new()
    $terms.Add($script:SecretNameBase)
    foreach ($name in @($Config['secretNames'])) {
        if ($name) {
            $escaped = [regex]::Escape($name)
            $terms.Add($escaped)
        }
    }
    $nameRx = '[A-Za-z0-9_.-]*(?:' + ($terms -join '|') + ')[A-Za-z0-9_.-]*'
    # S04 value: quoted (quotes kept) or unquoted to end of line.
    $lineVal = '(?:"(?<val>[^"\r\n]+)"|''(?<val>[^''\r\n]+)''|(?<val>[^\s"''][^\r\n]*?)(?=[ \t]*\r?$))'
    $jsonStr = '(?:[^"\\]|\\.)*'
    $kvPatterns = @(
        '(?m)^[ \t]*(?:export[ \t]+)?(?:"(?<name>@@N@@)"|''(?<name>@@N@@)''|(?<name>@@N@@))[ \t]*[:=][ \t]*' + $lineVal
        '"(?<name>@@N@@)"\s*:\s*"(?<val>' + $jsonStr + ')"'
        '"(?<name>@@N@@)=(?<val>' + $jsonStr + ')"'
        '(?<![A-Za-z0-9_-])-(?:Password|Secret|Token|Key|ApiKey|ClientSecret)[ \t]+(?:"(?<val>[^"\r\n]+)"|''(?<val>[^''\r\n]+)''|(?<val>[^\s"''-]\S*))'
        '<(?<name>@@N@@)(?:\s[^<>]*)?>(?<val>[^<>]+)</\k<name>>'
        '<(?<name>@@N@@)(?:\s[^<>]*)?>\s*<Value>(?<val>[^<>]+)</Value>'
        '(?<![A-Za-z0-9_.-])(?<name>@@N@@)[ \t]*=[ \t]*(?:"(?<val>[^"\r\n]*)"|''(?<val>[^''\r\n]*)'')'
    ) | ForEach-Object { $_.Replace('@@N@@', $nameRx) }

    $valueTest = {
        param($m, $session)
        $name = $m.Groups['name'].Value
        -not ($name -and $session.NonSecretNames.Contains($name)) -and -not (Test-RedactSkipValue -Value $m.Groups['val'].Value)
    }

    # Order matters: specific types first so they win the label; S04 last.
    $table = @(
        @{ Id = 'S01'; Label = 'pem-key'; Patterns = @(
            '(?s)-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----(?:.*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----|.*\z)') }
        @{ Id = 'S16'; Label = 'dpapi'; IgnoreCase = $true; Patterns = @(
            '(?<![A-Za-z0-9_])01000000d08c9ddf0115d1118c7a00c04fc297eb[0-9a-f]{40,}') }
        @{ Id = 'S02'; Label = 'jwt'; Patterns = @(
            '(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*') }
        @{ Id = 'S07'; Label = 'url-cred'; IgnoreCase = $true; Test = $valueTest; Patterns = @(
            '(?<![A-Za-z0-9_])[a-z][a-z0-9+.-]{1,15}://(?<val>[^/\s@''"]*:[^/\s@''"]+)@'
            '(?<![A-Za-z0-9_])[a-z][a-z0-9+.-]{1,15}://(?<val>[^/\s:@''"]{20,})@') }
        @{ Id = 'S03'; Label = 'auth-header'; IgnoreCase = $true; Patterns = @(
            '(?<![A-Za-z0-9_])(?:Proxy-)?Authorization["'']?[ \t]*[:=][ \t]*["'']?(?:Bearer|Basic|Negotiate|NTLM|Digest|Token)[ \t]+(?<val>[^\s''"]+)'
            '(?<![A-Za-z0-9_])(?-i:Bearer)[ \t]+(?<val>[A-Za-z0-9._~+/=-]{20,})') }
        @{ Id = 'S05'; Label = 'connstr'; IgnoreCase = $true; Test = $valueTest; Patterns = @(
            '(?<![A-Za-z0-9_])(?:AccountKey|SharedAccessKey|SharedAccessSignature|Password|Pwd|ClientSecret|AccessKey)[ \t]*=[ \t]*(?<val>[^;"''\r\n]+)') }
        @{ Id = 'S06'; Label = 'sas-sig'; IgnoreCase = $true; Patterns = @(
            '[?&;]sig=(?<val>[^&\s"''#]+)') }
        @{ Id = 'S11'; Label = 'git-token'; Patterns = @(
            '(?<![A-Za-z0-9_])gl(?:pat|ptt|rt|dt|oas|cbt|imt|ffct|soat|agent)-[A-Za-z0-9_-]{20,}'
            '(?<![A-Za-z0-9_])GR1348941[A-Za-z0-9_-]{20}'
            '(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9]{36,255}'
            '(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{50,255}') }
        @{ Id = 'S10'; Label = 'api-key'; Patterns = @(
            '(?<![A-Za-z0-9_-])sk-(?:proj-|svcacct-|admin-|ant-[a-z0-9]+-)?[A-Za-z0-9_-]{20,}') }
        @{ Id = 'S09'; Label = 'entra-secret'; Patterns = @(
            '(?<![A-Za-z0-9_.~-])[A-Za-z0-9_.-]{3}[0-9]Q~[A-Za-z0-9_.~-]{31,34}(?![A-Za-z0-9_.~-])') }
        @{ Id = 'S08'; Label = 'storage-key'; Patterns = @(
            '(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{86}==(?![A-Za-z0-9+/=])') }
        @{ Id = 'S13'; Label = 'bitlocker'; Patterns = @(
            '(?<![0-9])(?:[0-9]{6}-){7}[0-9]{6}(?![0-9])') }
        @{ Id = 'S15'; Label = 'ntlm'; IgnoreCase = $true; Patterns = @(
            '(?<![0-9a-f])[0-9a-f]{32}:[0-9a-f]{32}(?![0-9a-f])'
            '(?<![A-Za-z0-9_])nt(?:lm)?(?:hash)?[ \t]*[:=][ \t]*["'']?(?<val>[0-9a-f]{32})(?![0-9a-f])') }
        @{ Id = 'S14'; Label = 'laps'; IgnoreCase = $true; Test = $valueTest; Patterns = @(
            '(?<![A-Za-z0-9_-])(?:ms-Mcs-AdmPwd|msLAPS-(?:Encrypted)?Password(?:History)?)[ \t]*[:=][ \t]*(?<val>[^\r\n]+)'
            '(?:"[nt]"[ \t]*:[ \t]*"[^"\\]*"[ \t]*,[ \t]*)+"p"[ \t]*:[ \t]*"(?<val>' + $jsonStr + ')"') }
        @{ Id = 'S12'; Label = 'duo-skey'; IgnoreCase = $true; Patterns = @(
            '(?<![A-Za-z0-9_])(?:duo[_.-]?)?(?:skey|secret[_ -]?key)[ \t]*[:=][ \t]*["'']?(?<val>[A-Za-z0-9]{40})(?![A-Za-z0-9])') }
        @{ Id = 'S04'; Label = 'kv'; IgnoreCase = $true; Test = $valueTest; Patterns = $kvPatterns }
    )

    foreach ($row in $table) {
        $ignoreCase = [bool]$row['IgnoreCase']
        $regex = foreach ($pattern in $row['Patterns']) { Get-RedactRegex -Pattern $pattern -IgnoreCase:$ignoreCase }
        @{ Id = $row['Id']; Label = $row['Label']; Kind = 'secret'; Regex = [regex[]]@($regex); Test = $row['Test'] }
    }
}
