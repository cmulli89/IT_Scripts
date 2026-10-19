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

function ConvertTo-RedactRule {
    # Table row -> rule. Patterns are compiled through Get-RedactRegex; Enabled is false for a row with no patterns,
    # a row switched off by its Off flag, or an identifier whose categories.<label> is false (secrets cannot be disabled).
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][hashtable]$Row,
        [Parameter(Mandatory)][ValidateSet('secret', 'identifier')][string]$Kind,
        [Parameter(Mandatory)][hashtable]$Config
    )

    $regex = @(foreach ($pattern in $Row['Patterns']) { Get-RedactRegex -Pattern $pattern -IgnoreCase:([bool]$Row['IgnoreCase']) })
    $disabled = $Kind -eq 'identifier' -and $Row['Label'] -and $Config.ContainsKey('categories') -and $Config['categories'][$Row['Label']] -eq $false
    @{
        Id         = $Row['Id']
        Label      = $Row['Label']
        Kind       = if ($Row['Kind']) { $Row['Kind'] } else { $Kind }
        Regex      = [regex[]]$regex
        Test       = $Row['Test']
        Evaluator  = $Row['Evaluator']
        MinLength  = [int]$Row['MinLength']
        Enabled    = $regex.Count -gt 0 -and -not $Row['Off'] -and -not $disabled
    }
}

function Get-RedactSecretRule {
    <#
    .SYNOPSIS
        Returns the ordered secret rule table (S01-S16, S04 last).
    .DESCRIPTION
        A rule is a hashtable: Id, Label, Kind, Regex (compiled), Enabled, optional Test scriptblock
        { param($match, $session, $rule) } returning $false to leave a match alone. If a match has a
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

    foreach ($row in $table) { ConvertTo-RedactRule -Row $row -Kind secret -Config $Config }
}

#region Identifier helpers

# JSON person fields (text mode) and the token type each one gets.
$script:PersonField = @{ givenname = 'name'; surname = 'name'; mobilephone = 'phone'; employeeid = 'emp' }

function Get-RedactAlternation {
    # One alternation of escaped literals, longest first; nothing when there are no terms.
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyCollection()][string[]]$Term = @())

    $parts = foreach ($item in ($Term | Where-Object { $_ } | Sort-Object -Property Length -Descending | Select-Object -Unique)) {
        $escaped = [regex]::Escape($item)
        $escaped
    }
    if ($parts) { $parts -join '|' }
}

function ConvertTo-RedactWordPattern {
    # Config literals and patterns match as whole words; the 'val' group is the span that gets replaced.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Pattern)

    '(?<![A-Za-z0-9_-])(?<val>(?:' + $Pattern + '))(?![A-Za-z0-9_-])'
}

function Get-RedactIpToken {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Ip,
        [Parameter(Mandatory)][object]$Session
    )

    $type = if (Test-RedactPrivateIp -Ip $Ip) { 'ip-priv' } else { 'ip-pub' }
    Get-RedactToken -Session $Session -Type $type -Original $Ip
}

function Resolve-RedactFqdn {
    # host.rest -> [host-NN].[domain-NN]; the domain token covers everything after the first label.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][object]$Session
    )

    $dot = $Name.IndexOf('.')
    '{0}.{1}' -f (Get-RedactToken -Session $Session -Type host -Original $Name.Substring(0, $dot)),
        (Get-RedactToken -Session $Session -Type domain -Original $Name.Substring($dot + 1))
}

function Resolve-RedactMailDomain {
    # Tenant onmicrosoft names become tenant tokens, public domains stay, everything else gets a domain token.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Domain,
        [Parameter(Mandatory)][object]$Session
    )

    $tenant = (Get-RedactRegex -Pattern '^(?<name>[A-Za-z0-9-]+)(?<suffix>\.onmicrosoft\.(?:us|com))$' -IgnoreCase).Match($Domain)
    if ($tenant.Success) { return (Get-RedactToken -Session $Session -Type tenant -Original $tenant.Groups['name'].Value) + $tenant.Groups['suffix'].Value }
    if (Test-RedactNameSet -Set $Session.Allow.Domain -Name $Domain) { return $Domain }
    Get-RedactToken -Session $Session -Type domain -Original $Domain
}

function Resolve-RedactMailUser {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Local,
        [Parameter(Mandatory)][object]$Session
    )

    if ($Local -in $script:KeepLocalPart) { $Local } else { Get-RedactToken -Session $Session -Type user -Original $Local }
}

function Resolve-RedactMail {
    # [user-NN]@[domain-NN]; the guest form local_dom#EXT#@tenant becomes [user-NN]_[domain-NN]#EXT#@[tenant-NN].onmicrosoft.xx.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][System.Text.RegularExpressions.Match]$Match,
        [Parameter(Mandatory)][object]$Session
    )

    $local = $Match.Groups['local'].Value
    $domain = Resolve-RedactMailDomain -Domain $Match.Groups['dom'].Value -Session $Session
    if (-not $Match.Groups['ext'].Success) { return '{0}@{1}' -f (Resolve-RedactMailUser -Local $local -Session $Session), $domain }
    $underscore = $local.LastIndexOf('_')
    $head = if ($underscore -gt 0) {
        '{0}_{1}' -f (Resolve-RedactMailUser -Local $local.Substring(0, $underscore) -Session $Session),
            (Resolve-RedactMailDomain -Domain $local.Substring($underscore + 1) -Session $Session)
    }
    else { Resolve-RedactMailUser -Local $local -Session $Session }
    '{0}{1}@{2}' -f $head, $Match.Groups['ext'].Value, $domain
}

function Resolve-RedactResourceId {
    # Walks /key/name pairs: subscriptions -> sub token (and registers the GUID as an alias), resourceGroups -> rg token,
    # providers and locations keep their name, every other pair keeps the type and tokenizes the name as res.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][object]$Session
    )

    $segment = $Path.Split('/')
    $out = [System.Collections.Generic.List[string]]::new()
    $out.Add('')
    for ($i = 1; $i -lt $segment.Count; $i += 2) {
        $out.Add($segment[$i])
        if ($i + 1 -ge $segment.Count) { break }
        $name = $segment[$i + 1]
        $out.Add($(switch ($segment[$i]) {
            { $_ -in 'providers', 'locations' } { $name }
            'subscriptions' {
                $token = Get-RedactToken -Session $Session -Type sub -Original $name
                Add-RedactAlias -Session $Session -Type guid -Original $name -Token $token
                $token
            }
            'resourceGroups' { Get-RedactToken -Session $Session -Type rg -Original $name }
            default { Get-RedactToken -Session $Session -Type res -Original $name }
        }))
    }
    $out -join '/'
}

function Test-RedactKeepShare {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$Name)

    (Get-RedactRegex -Pattern '^(?:[A-Za-z]\$|IPC\$|ADMIN\$|NETLOGON|SYSVOL|print\$)$' -IgnoreCase).IsMatch($Name)
}

function Test-RedactKeepHost {
    # Only keep-listed IPv4 addresses (loopback, ...) are kept as UNC hosts.
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][object]$Session
    )

    (Test-RedactIpv4 -Text $Name) -and (Test-RedactKeepIp -Ip $Name -Session $Session)
}

function Resolve-RedactUnc {
    # \\host\share in raw or JSON-escaped form: host by kind (IP, internal FQDN, other), share unless administrative.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][System.Text.RegularExpressions.Match]$Match,
        [Parameter(Mandatory)][object]$Session
    )

    $name = $Match.Groups['h'].Value
    $share = $Match.Groups['sh'].Value
    $hostPart = if (Test-RedactKeepHost -Name $name -Session $Session) { $name }
    elseif (Test-RedactIpv4 -Text $name) { Get-RedactIpToken -Ip $name -Session $Session }
    elseif (Test-RedactInternalName -Name $name -Session $Session) { Resolve-RedactFqdn -Name $name -Session $Session }
    else { Get-RedactToken -Session $Session -Type host -Original $name }
    $sharePart = if (Test-RedactKeepShare -Name $share) { $share } else { Get-RedactToken -Session $Session -Type share -Original $share }
    if ($Match.Value.StartsWith('\\\\', [StringComparison]::Ordinal)) { '\\\\' + $hostPart + '\\' + $sharePart } else { '\\' + $hostPart + '\' + $sharePart }
}

function Get-RedactCnType {
    # A DN CN value that is already a known host or user (map, config list or host pattern) keeps that shared token type.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][object]$Session
    )

    $key = $Value.ToLowerInvariant()
    $isHost = $Session.Maps.ContainsKey("host|$key") -or $Value -in @(Get-RedactConfigList -Config $Session.Config -Key 'hostList')
    foreach ($entry in (Get-RedactConfigList -Config $Session.Config -Key 'hostPatterns')) {
        $pattern = Get-RedactPatternEntry -Entry $entry
        $isHost = $isHost -or ($Value.Length -ge $pattern.MinLength -and (Get-RedactRegex -Pattern ('^(?:' + $pattern.Regex + ')$') -IgnoreCase).IsMatch($Value))
    }
    if ($isHost) { return 'host' }
    if ($Session.Maps.ContainsKey("user|$key") -or $Value -in @(Get-RedactConfigList -Config $Session.Config -Key 'usernames')) { return 'user' }
    'name'
}

function Resolve-RedactDn {
    # Non-structural CN values become the shared host/user token when known, else [name-NN]; OU values [ou-NN]; the DC chain becomes DC=[domain-NN].
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][System.Text.RegularExpressions.Match]$Match,
        [Parameter(Mandatory)][object]$Session
    )

    $rdn = $Match.Groups['rdn'].Value
    $edits = foreach ($component in (Get-RedactRegex -Pattern '(?<type>CN|OU)=(?<value>(?:[^,\\]|\\.)*)' -IgnoreCase).Matches($rdn)) {
        $value = $component.Groups['value']
        $type = if ($component.Groups['type'].Value -ieq 'OU') { 'ou' } elseif ($value.Value -notin $script:StructuralCn) { Get-RedactCnType -Value $value.Value -Session $Session }
        if ($type -and $value.Length -gt 0) {
            [pscustomobject]@{ Start = $value.Index; Length = $value.Length; Replacement = Get-RedactToken -Session $Session -Type $type -Original $value.Value }
        }
    }
    if ($edits) { $rdn = Edit-RedactText -Text $rdn -Edit @($edits) }
    $chain = (Get-RedactRegex -Pattern 'DC=' -IgnoreCase).Replace($Match.Groups['dom'].Value, '').Replace(',', '.')
    $rdn + 'DC=' + (Get-RedactToken -Session $Session -Type domain -Original $chain)
}

function Get-RedactPathPart {
    # Splits a path into parts classified sep | keep | user | path. Pure: allocates no tokens.
    # The folder after Users or home is the user; with -Full every other non-system folder is a path part.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Full
    )

    $previous = ''
    foreach ($m in (Get-RedactRegex -Pattern '[^\\/]+|[\\/]+').Matches($Path)) {
        $text = $m.Value
        $lower = $text.ToLowerInvariant()
        $kind = if ($text[0] -in '\', '/') { 'sep' }
        elseif ($text.IndexOf([char]0xE000) -ge 0 -or $text.EndsWith(':')) { 'keep' }
        elseif ($previous -in 'users', 'home') { if ($lower.Split('.')[0] -and $lower.Split('.')[0] -notin $script:KeepProfile) { 'user' } else { 'keep' } }
        elseif ($Full -and $lower -notin $script:SystemFolder) { 'path' }
        else { 'keep' }
        if ($kind -ne 'sep') { $previous = $lower }
        [pscustomobject]@{ Text = $text; Kind = $kind }
    }
}

function Resolve-RedactPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][object]$Session
    )

    -join @(foreach ($part in (Get-RedactPathPart -Path $Path -Full:($Session.Config['pathMode'] -eq 'Full'))) {
        switch ($part.Kind) {
            'user' { Get-RedactToken -Session $Session -Type user -Original $part.Text.Split('.')[0] }
            'path' { Get-RedactToken -Session $Session -Type path -Original $part.Text }
            default { $part.Text }
        }
    })
}

#endregion

#region Identifier rule table

function Get-RedactIdentifierRule {
    <#
    .SYNOPSIS
        Returns the ordered identifier rule table (I11, endpoint mask, I10 ... I12).
    .DESCRIPTION
        Same row format as Get-RedactSecretRule plus an Evaluator scriptblock { param($m, $session) } that
        returns the replacement for the matched span (the 'val' group when present, else the whole match).
        Rows built from config (hostList, hostPatterns, usernames, extraTerms, ...) have no patterns, and are
        therefore disabled, when the config has no such entries. The mask row (Kind 'mask') protects
        allowlisted endpoint hostnames from the identifier rules that follow it; it never counts or reports.
    .PARAMETER Config
        Merged configuration from Get-RedactConfig.
    .EXAMPLE
        Get-RedactIdentifierRule -Config (Get-RedactConfig)
    .OUTPUTS
        System.Collections.Hashtable[]
    #>
    [CmdletBinding()]
    [OutputType([hashtable[]])]
    param([hashtable]$Config = @{})

    $domains = @(Get-RedactConfigList -Config $Config -Key 'internalDomains')
    $domainAlt = Get-RedactAlternation -Term $domains
    $dnAlt = Get-RedactAlternation -Term @($domains | ForEach-Object { 'DC=' + $_.Replace('.', ',DC=') })
    $netbiosAlt = Get-RedactAlternation -Term @(Get-RedactConfigList -Config $Config -Key 'netbiosDomains' | ForEach-Object { $_['netbios'] })
    $groupAlt = Get-RedactAlternation -Term $script:WellKnownGroup
    $prefixAlt = Get-RedactAlternation -Term @(Get-RedactConfigList -Config $Config -Key 'resourcePrefixes')
    $termAlt = Get-RedactAlternation -Term @(Get-RedactConfigList -Config $Config -Key 'extraTerms' | ForEach-Object { $_['term'] })
    $hostAlt = Get-RedactAlternation -Term @(Get-RedactConfigList -Config $Config -Key 'hostList')
    $userAlt = Get-RedactAlternation -Term @(Get-RedactConfigList -Config $Config -Key 'usernames')

    $segment = '[A-Za-z0-9_~:-]+(?:\.[A-Za-z0-9_~:-]+)*'
    $sep = '(?:\\\\|[\\/])'
    $pathPart = '(?:Program Files(?: \(x86\))?|[^\\/\s"''<>|:*?,;()\[\]{}]+)'
    $uncStart = '(?<![A-Za-z0-9_\\:.$-])'
    $uncHost = '(?<h>[A-Za-z0-9_][A-Za-z0-9_.-]*)'
    $uncShare = '(?<sh>[A-Za-z0-9_.$-]+)'
    $thumbKeyword = 'thumbprint|fingerprint|cert|x509'
    $hex40 = '(?<![0-9A-Fa-f])(?<val>[0-9A-Fa-f]{40})(?![0-9A-Fa-f])'
    $profilePath = if ($Config['pathMode'] -eq 'Full') {
        '(?<![A-Za-z0-9_])[A-Za-z]:(?:' + $sep + $pathPart + ')+'
        '(?<![A-Za-z0-9_.:\\-])/(?:etc|usr|var|opt|bin|sbin|lib|tmp|home|srv|mnt|root|Users)(?:/' + $pathPart + ')+'
    }
    else {
        '(?<![A-Za-z0-9_])[A-Za-z]:' + $sep + 'Users' + $sep + $pathPart
        '(?<![A-Za-z0-9_.:\\-])/(?:home|Users)/' + $pathPart
    }

    $hostToken = { param($m, $s) Get-RedactToken -Session $s -Type host -Original $m.Groups['val'].Value }
    $userToken = { param($m, $s) Get-RedactToken -Session $s -Type user -Original $m.Groups['val'].Value }
    $minLength = { param($m, $s, $rule) $m.Groups['val'].Value.Length -ge $rule.MinLength }
    $skipValue = { param($m) -not (Test-RedactSkipValue -Value $m.Groups['val'].Value) }
    $personToken = {
        param($m, $s)
        $field = $m.Groups['field'].Value
        $type = if ($field) { $script:PersonField[$field.ToLowerInvariant()] } else { 'phone' }
        Get-RedactToken -Session $s -Type $type -Original $m.Groups['val'].Value
    }
    $serialToken = { param($m, $s) Get-RedactToken -Session $s -Type serial -Original $m.Groups['val'].Value }

    $hostRows = foreach ($entry in (Get-RedactConfigList -Config $Config -Key 'hostPatterns')) {
        $pattern = Get-RedactPatternEntry -Entry $entry
        @{ Id = 'I06'; Label = 'host'; IgnoreCase = $true; MinLength = $pattern.MinLength; Test = $minLength; Evaluator = $hostToken
           Patterns = @(ConvertTo-RedactWordPattern -Pattern $pattern.Regex) }
    }
    $serialRows = foreach ($entry in (Get-RedactConfigList -Config $Config -Key 'deviceSerialPatterns')) {
        $pattern = Get-RedactPatternEntry -Entry $entry
        @{ Id = 'I12'; Label = 'thumbprint'; IgnoreCase = $true; MinLength = $pattern.MinLength; Test = $minLength; Evaluator = $serialToken
           Patterns = @(ConvertTo-RedactWordPattern -Pattern $pattern.Regex) }
    }

    $table = @(
        @{ Id = 'I11'; Label = 'azure-host'; IgnoreCase = $true
           Evaluator = { param($m, $s) Get-RedactToken -Session $s -Type res -Original $m.Groups['val'].Value }
           Patterns = @(
            '\b(?<val>[a-z0-9][a-z0-9-]{1,62})\.(?:blob|file|queue|table|dfs|vault|vaultcore|database|servicebus|azurecr|azurewebsites|scm\.azurewebsites|search|openai|cognitiveservices)(?:\.core)?\.(?:usgovcloudapi\.net|azure\.us|azurewebsites\.us|windows\.net)(?![A-Za-z0-9-])'
            '\b(?<val>[a-z0-9][a-z0-9-]{1,62})(?:\.scm)?\.(?:azurewebsites\.(?:us|net)|azurecr\.(?:us|io))(?![A-Za-z0-9-])') }
        @{ Id = 'MASK'; Label = ''; Kind = 'mask'
           Test = { param($m, $s) Test-RedactPublicHost -Name $m.Value -Session $s }
           Evaluator = { param($m) $m.Value }
           Patterns = @('(?<![A-Za-z0-9@.-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?![A-Za-z0-9-])') }
        @{ Id = 'I10'; Label = 'azure-resource'; IgnoreCase = $true
           Evaluator = { param($m, $s) Resolve-RedactResourceId -Path $m.Value -Session $s }
           Patterns = @('/subscriptions/' + $script:GUID + '(?:/' + $segment + ')*') }
        @{ Id = 'I10'; Label = 'azure-resource'; IgnoreCase = $true
           Evaluator = { param($m, $s) Get-RedactToken -Session $s -Type $(if ($m.Value.StartsWith('rg-', [StringComparison]::OrdinalIgnoreCase)) { 'rg' } else { 'res' }) -Original $m.Value }
           Patterns = @(if ($prefixAlt) { '(?<![A-Za-z0-9_-])(?:' + $prefixAlt + ')[A-Za-z0-9_-]*' }) }
        @{ Id = 'I03'; Label = 'upn'; IgnoreCase = $true
           Test = { param($m, $s)
               $m.Groups['ext'].Success -or ($m.Groups['local'].Value -notin $script:KeepLocalPart) -or
                   -not (Test-RedactNameSet -Set $s.Allow.Domain -Name $m.Groups['dom'].Value) }
           Evaluator = { param($m, $s) Resolve-RedactMail -Match $m -Session $s }
           Patterns = @('(?<![A-Za-z0-9._%+-])(?<local>[A-Za-z0-9._%+-]+)(?<ext>#EXT#)?@(?<dom>(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})(?![A-Za-z0-9-])') }
        @{ Id = 'I04'; Label = 'tenant'; IgnoreCase = $true
           Evaluator = { param($m, $s) Get-RedactToken -Session $s -Type tenant -Original $m.Groups['val'].Value }
           Patterns = @(
            '(?<![A-Za-z0-9-])(?<val>[A-Za-z0-9][A-Za-z0-9-]*)\.onmicrosoft\.(?:us|com)(?![A-Za-z0-9-])'
            '(?<![A-Za-z0-9-])(?<val>[A-Za-z0-9][A-Za-z0-9-]*?)(?:-my|-admin)?\.sharepoint\.(?:us|com)(?![A-Za-z0-9-])') }
        @{ Id = 'I13'; Label = 'unc'; IgnoreCase = $true
           Test = { param($m, $s) -not ((Test-RedactKeepHost -Name $m.Groups['h'].Value -Session $s) -and (Test-RedactKeepShare -Name $m.Groups['sh'].Value)) }
           Evaluator = { param($m, $s) Resolve-RedactUnc -Match $m -Session $s }
           Patterns = @(
            $uncStart + '\\\\' + $uncHost + '\\' + $uncShare
            $uncStart + '\\\\\\\\' + $uncHost + '\\\\' + $uncShare) }
        @{ Id = 'I15'; Label = 'domain-user'; IgnoreCase = $true
           Evaluator = {
               param($m, $s)
               $pair = @(Get-RedactConfigList -Config $s.Config -Key 'netbiosDomains').Where({ $_['netbios'] -ieq $m.Groups['nb'].Value }, 'First')[0]
               $token = Get-RedactToken -Session $s -Type domain -Original ([string]$pair['fqdn'])
               Add-RedactAlias -Session $s -Type domain -Original ([string]$pair['netbios']) -Token $token
               $account = $m.Groups['acct'].Value
               $bs = $m.Groups['bs'].Value
               if ($m.Groups['grp'].Success) { $token + $bs + $m.Groups['grp'].Value }
               elseif ($account.EndsWith('$')) { $token + $bs + (Get-RedactToken -Session $s -Type host -Original $account.TrimEnd('$')) + '$' }
               elseif ($account) { $token + $bs + (Get-RedactToken -Session $s -Type user -Original $account) }
               else { $token }
           }
           Patterns = @(if ($netbiosAlt) {
            '(?<![A-Za-z0-9_.\\-])(?<!DC=)(?<nb>' + $netbiosAlt + ')(?:(?<bs>\\\\|\\)(?:(?<grp>' + $groupAlt + ')(?![A-Za-z0-9_$-])|(?<acct>[A-Za-z0-9_$-]+(?:\.[A-Za-z0-9_$-]+)*)))?(?![A-Za-z0-9_]|\.[A-Za-z0-9])' }) }
        @{ Id = 'I14'; Label = 'profile-path'; IgnoreCase = $true; Off = ($Config['pathMode'] -eq 'Keep')
           Test = { param($m, $s) @(Get-RedactPathPart -Path $m.Value -Full:($s.Config['pathMode'] -eq 'Full')).Where({ $_.Kind -in 'user', 'path' }).Count -gt 0 }
           Evaluator = { param($m, $s) Resolve-RedactPath -Path $m.Value -Session $s }
           Patterns = @($profilePath) }
        @{ Id = 'I05'; Label = 'fqdn'; IgnoreCase = $true
           Evaluator = { param($m, $s) Resolve-RedactDn -Match $m -Session $s }
           Patterns = @(if ($dnAlt) {
            '(?<![A-Za-z0-9_=,-])(?<rdn>(?>(?:(?:CN|OU)=(?:[^,=\\\r\n]|\\.)*,[ ]?)*))(?<dom>(?:DC=[A-Za-z0-9_-]+,)*(?:' + $dnAlt + '))(?![A-Za-z0-9_-])' }) }
        @{ Id = 'I05'; Label = 'fqdn'; IgnoreCase = $true
           Evaluator = {
               param($m, $s)
               $domainToken = Get-RedactToken -Session $s -Type domain -Original $m.Groups['dom'].Value
               if ($m.Groups['h'].Success) { (Get-RedactToken -Session $s -Type host -Original $m.Groups['h'].Value) + '.' + $domainToken } else { $domainToken }
           }
           Patterns = @(if ($domainAlt) {
            '(?<![A-Za-z0-9_.-])(?:(?<dom>' + $domainAlt + ')|(?<h>[A-Za-z0-9_-]+)\.(?<dom>(?:[A-Za-z0-9_-]+\.)*?(?:' + $domainAlt + ')))(?![A-Za-z0-9_-])' }) }
        @{ Id = 'I02'; Label = 'sid'; IgnoreCase = $true
           Evaluator = {
               param($m, $s)
               if ($m.Groups['cloud'].Success) { return Get-RedactToken -Session $s -Type sid-cloud -Original $m.Groups['cloud'].Value }
               $token = Get-RedactToken -Session $s -Type sid-dom -Original $m.Groups['dom'].Value
               if ($s.Config['sidKeepRid'] -eq $false) { $token } else { 'S-1-5-21-' + $token + $m.Groups['rid'].Value }
           }
           Patterns = @(
            '(?<![A-Za-z0-9_-])S-1-5-21-(?<dom>[0-9]{1,10}-[0-9]{1,10}-[0-9]{1,10})(?<rid>-[0-9]{1,10})?(?![A-Za-z0-9_])'
            '(?<![A-Za-z0-9_-])S-1-12-1-(?<cloud>[0-9]{1,10}(?:-[0-9]{1,10}){3})(?![A-Za-z0-9_])') }
        @{ Id = 'I01'; Label = 'guid'; IgnoreCase = $true
           Test = { param($m, $s) -not (Test-RedactAllowedGuid -Guid $m.Groups['val'].Value -Session $s) }
           Evaluator = { param($m, $s) Get-RedactToken -Session $s -Type guid -Original $m.Groups['val'].Value }
           Patterns = @(
            '(?<![0-9A-Fa-f])(?<val>' + $script:GUID + ')(?![0-9A-Fa-f])'
            '(?<![A-Za-z0-9_.-])[A-Za-z0-9_.-]*(?:id|guid)["'']?[ \t]*[:=][ \t]*["'']?(?<val>[0-9a-f]{32})(?![0-9A-Za-z])') }
        @{ Id = 'I17'; Label = 'extra-term'; IgnoreCase = $true
           Evaluator = {
               param($m, $s)
               $term = $m.Groups['val'].Value
               $entry = @(Get-RedactConfigList -Config $s.Config -Key 'extraTerms').Where({ $_['term'] -ieq $term }, 'First')[0]
               Get-RedactToken -Session $s -Type ('term-' + (ConvertTo-RedactLabel -Label ([string]$entry['label']))) -Original $term
           }
           Patterns = @(if ($termAlt) { ConvertTo-RedactWordPattern -Pattern $termAlt }) }
        @{ Id = 'I06'; Label = 'host'; IgnoreCase = $true; Evaluator = $hostToken
           Patterns = @(if ($hostAlt) { ConvertTo-RedactWordPattern -Pattern $hostAlt }) }
        $hostRows
        @{ Id = 'I16'; Label = 'person'; IgnoreCase = $true; Evaluator = $userToken
           Patterns = @(if ($userAlt) { ConvertTo-RedactWordPattern -Pattern $userAlt }) }
        @{ Id = 'I16'; Label = 'person'; IgnoreCase = $true; Evaluator = $personToken
           Patterns = @(
            '"(?<field>givenName|surname|mobilePhone|employeeId)"[ \t]*:[ \t]*"(?<val>(?:[^"\\]|\\.)*)"'
            '(?<="businessPhones"\s*:\s*\[(?:\s*"(?:[^"\\]|\\.)*"\s*,)*\s*)"(?<val>(?:[^"\\]|\\.)*)"') }
        @{ Id = 'I09'; Label = 'mac'
           Test = { param($m) -not (Get-RedactRegex -Pattern '^(?:[Ff]+|0+)$').IsMatch((Get-RedactRegex -Pattern '[:.-]').Replace($m.Value, '')) }
           Evaluator = { param($m, $s) Get-RedactToken -Session $s -Type mac -Original $m.Value }
           Patterns = @(
            '(?<![0-9A-Fa-f:.-])[0-9A-Fa-f]{2}(?<sep>[:-])(?:[0-9A-Fa-f]{2}\k<sep>){4}[0-9A-Fa-f]{2}(?![0-9A-Fa-f])'
            '(?<![0-9A-Fa-f:.-])[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}(?![0-9A-Fa-f.])') }
        @{ Id = 'I07'; Label = 'ipv4'; IgnoreCase = $true; Off = ($Config['ipMode'] -eq 'Keep')
           Test = { param($m, $s) -not (Test-RedactKeepIp -Ip $m.Groups['ip'].Value -Session $s) }
           Evaluator = { param($m, $s) (Get-RedactIpToken -Ip $m.Groups['ip'].Value -Session $s) + $m.Groups['cidr'].Value }
           Patterns = @('(?<![0-9.])(?<!(?:\bversion|\bver|\bbuild)[ \t:=]{0,3})(?<!\bv)(?<ip>(?:' + $script:OCT + '\.){3}' + $script:OCT + ')(?![0-9]|\.[0-9])(?<cidr>/(?:3[0-2]|[12]?[0-9]))?') }
        @{ Id = 'I08'; Label = 'ipv6'; Off = ($Config['ipMode'] -eq 'Keep')
           Test = {
               param($m)
               $ip = $m.Groups['ip'].Value
               $address = $null
               ($ip.Contains('::') -or ($ip.Length - $ip.Replace(':', '').Length) -eq 7) -and
                   [System.Net.IPAddress]::TryParse($ip, [ref]$address) -and $address.AddressFamily -eq 'InterNetworkV6' -and
                   -not ($address.Equals([System.Net.IPAddress]::IPv6Loopback) -or $address.Equals([System.Net.IPAddress]::IPv6Any))
           }
           Evaluator = { param($m, $s) Get-RedactToken -Session $s -Type ip6 -Original $m.Groups['ip'].Value }
           Patterns = @('(?<![A-Za-z0-9:.])(?<ip>[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*[0-9A-Fa-f:])(?:%[A-Za-z0-9]+)?(?![A-Za-z0-9:])') }
        @{ Id = 'I12'; Label = 'thumbprint'; IgnoreCase = $true
           Evaluator = { param($m, $s) Get-RedactToken -Session $s -Type thumb -Original $m.Groups['val'].Value }
           Patterns = @($hex40 + '(?:(?<=(?:' + $thumbKeyword + ')[^\r\n]*)|(?=[^\r\n]*(?:' + $thumbKeyword + ')))') }
        @{ Id = 'I12'; Label = 'thumbprint'; IgnoreCase = $true; Test = $skipValue; Evaluator = $serialToken
           Patterns = @('(?<![A-Za-z0-9_])(?:SerialNumber|Serial|ServiceTag|IdentifyingNumber)(?![A-Za-z0-9_])["'']?[ \t]*[:=][ \t]*["'']?(?<val>[A-Za-z0-9-]{4,})') }
        $serialRows
    )
    foreach ($row in $table) { ConvertTo-RedactRule -Row $row -Kind identifier -Config $Config }
}

#endregion
