# Layered configuration: built-in defaults < sample < local < -ConfigPath < -Override.

$script:ConfigEnum = @{ ipMode = @('Classify', 'KeepPrivate', 'Keep'); pathMode = @('UserOnly', 'Full', 'Keep') }
# Object-array keys and the fields every entry needs.
$script:ConfigShape = @{ netbiosDomains = @('netbios', 'fqdn'); extraTerms = @('term', 'label'); hostPatterns = @('regex') }
# New-RedactionConfig: parameter name -> config key (TenantPrefix joins the resource prefixes).
$script:ConfigParameter = [ordered]@{
    InternalDomains = 'internalDomains'; NetbiosDomain = 'netbiosDomains'; HostPattern = 'hostPatterns'; HostList = 'hostList'
    ResourcePrefix = 'resourcePrefixes'; TenantPrefix = 'resourcePrefixes'; Username = 'usernames'; ExtraTerm = 'extraTerms'
    GuidAllowlist = 'guidAllowlist'; PublicHostAllowlist = 'publicHostAllowlist'; PublicDomain = 'publicDomains'
    IpAllowlist = 'ipAllowlist'; IpMode = 'ipMode'; PathMode = 'pathMode'; SidKeepRid = 'sidKeepRid'; Categories = 'categories'
    SecretName = 'secretNames'; NonSecretName = 'nonSecretNames'; DeviceSerialPattern = 'deviceSerialPatterns'
}
# Interactive questions: parameter (or NetbiosName/NetbiosFqdn, joined afterwards), prompt, and whether a comma splits the answer.
$script:ConfigQuestion = @(
    @('InternalDomains', 'Internal domains, comma separated (e.g. ad.contoso.example)', $true),
    @('NetbiosName', 'NetBIOS domain name (e.g. CONTOSO)', $false),
    @('NetbiosFqdn', 'FQDN of that NetBIOS domain', $false),
    @('HostPattern', 'Desktop host name regex (e.g. WS-[0-9]{3,})', $false),
    @('HostPattern', 'Laptop host name regex (e.g. LT-[0-9]{3,})', $false),
    @('HostPattern', 'Server host name regex (e.g. SRV-[A-Z]{2,4}[0-9]{2,})', $false),
    @('HostPattern', 'VM host name regex (e.g. VM-[0-9]{3,})', $false),
    @('HostPattern', 'Linux host name regex (e.g. dkr-[0-9]{2,})', $false),
    @('ResourcePrefix', 'Azure resource and resource group prefixes, comma separated (e.g. rg-contoso-)', $true),
    @('Username', 'User and service account names, comma separated', $true),
    @('TenantPrefix', 'Tenant prefix (the part before .onmicrosoft.us)', $false),
    @('ExtraTerm', 'Extra terms as TERM=label, comma separated (e.g. Project Placeholder=proj)', $true)
)

function Get-RedactConfigDir {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    if ($env:REDACTOUTPUT_CONFIG_DIR) { $env:REDACTOUTPUT_CONFIG_DIR } else { Join-Path $PSScriptRoot '../config' }
}

function Get-RedactConfigList {
    # Non-empty entries of a list key; a missing key gives an empty list.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Config,
        [Parameter(Mandatory)][string]$Key
    )

    @($Config[$Key]).Where({ $null -ne $_ -and $_ -ne '' })
}

function Get-RedactConfigDefault {
    @{
        internalDomains = @(); netbiosDomains = @(); hostPatterns = @(); hostList = @(); resourcePrefixes = @()
        usernames = @(); extraTerms = @(); guidAllowlist = @(); publicHostAllowlist = @(); publicDomains = @()
        ipAllowlist = @(); ipMode = 'Classify'; pathMode = 'UserOnly'; sidKeepRid = $true
        categories = @{}; secretNames = @(); nonSecretNames = @(); deviceSerialPatterns = @()
    }
}

function Get-RedactPatternEntry {
    # hostPatterns entries are { regex, minLength }; deviceSerialPatterns entries are plain regex strings.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][object]$Entry)

    if ($Entry -is [System.Collections.IDictionary]) { [pscustomobject]@{ Regex = [string]$Entry['regex']; MinLength = [int]$Entry['minLength'] } }
    else { [pscustomobject]@{ Regex = [string]$Entry; MinLength = 0 } }
}

function ConvertTo-RedactLabel {
    # Term labels become token types: lower-case letters and digits only.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Label)

    (Get-RedactRegex -Pattern '[^a-z0-9]').Replace($Label.ToLowerInvariant(), '')
}

# Pattern -> compile/probe outcome ('' when fine), so each config pattern is probed once per session.
$script:PatternProbe = @{}

function Test-RedactPatternCompile {
    # Compiles each pattern and runs it once over a long probe string (catastrophic backtracking hits the 2-second timeout).
    # This runs in a throw-away runspace because a .NET parse error embeds the pattern text, and PowerShell keeps that
    # text in $Error and in any -ErrorVariable even when the error is caught. The option set mirrors New-RedactRegex.
    # Returns one reason per pattern ('' when fine), in order; reasons never contain pattern text.
    [CmdletBinding()]
    [OutputType([string[]])]
    param([AllowEmptyCollection()][string[]]$Pattern = @())

    $todo = @($Pattern | Select-Object -Unique).Where({ -not $script:PatternProbe.ContainsKey($_) })
    if ($todo.Count -gt 0) {
        $probe = {
            param([string[]]$Pattern)
            $text = ('a' * 2500) + ('1' * 2499) + '!'
            $options = [System.Text.RegularExpressions.RegexOptions]'Compiled, CultureInvariant, IgnoreCase'
            foreach ($p in $Pattern) {
                try { [void][regex]::new($p, $options, [timespan]::FromSeconds(2)).IsMatch($text); '' }
                catch [System.Text.RegularExpressions.RegexMatchTimeoutException] { 'exceeded the regex time limit' }
                catch { 'does not compile' }
            }
        }
        $shell = [powershell]::Create()
        try { $outcome = @($shell.AddScript($probe).AddArgument($todo).Invoke()) }
        finally { $shell.Dispose() }
        for ($i = 0; $i -lt $todo.Count; $i++) { $script:PatternProbe[$todo[$i]] = [string]$outcome[$i] }
    }
    $Pattern.ForEach({ $script:PatternProbe[$_] })
}

function Get-RedactPatternProblem {
    # Why a config regex is rejected, or nothing. The reason never contains the pattern text.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Pattern,
        [string]$CompileProblem
    )

    $text = $Pattern.Regex
    if ($text.Length -lt 3) { return 'too short' }
    if ($CompileProblem -eq 'does not compile') { return $CompileProblem }
    if ((Get-RedactRegex -Pattern '\((?:[^()\\]|\\.)*(?:[+*]|\{[0-9]+,[0-9]*\})(?:[^()\\]|\\.)*\)(?:[+*]|\{[0-9]+,)').IsMatch($text)) { return 'nested quantifier' }
    if ($Pattern.MinLength -lt 4 -and -not (Get-RedactRegex -Pattern '0-9|\\d').IsMatch($text)) { return 'needs minLength >= 4 or a digit class' }
    $CompileProblem
}

function Get-RedactConfigProblem {
    # First problem in a merged config as text naming the key and index only; never the offending value.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][hashtable]$Config)

    foreach ($key in $script:ConfigEnum.Keys) {
        if ($Config[$key] -notin $script:ConfigEnum[$key]) { return "$key must be one of: $($script:ConfigEnum[$key] -join ', ')." }
    }
    foreach ($key in $script:ConfigShape.Keys) {
        $fields = $script:ConfigShape[$key]
        $i = 0
        foreach ($entry in (Get-RedactConfigList -Config $Config -Key $key)) {
            if ($entry -isnot [System.Collections.IDictionary] -or @($fields.Where({ -not $entry[$_] })).Count -gt 0) {
                return "${key}[$i] rejected: needs $($fields -join ', ')."
            }
            if ($key -eq 'extraTerms' -and -not (ConvertTo-RedactLabel -Label ([string]$entry['label']))) {
                return "${key}[$i] rejected: label needs a letter or digit."
            }
            $i++
        }
    }
    foreach ($key in 'hostPatterns', 'deviceSerialPatterns') {
        $entries = @(Get-RedactConfigList -Config $Config -Key $key | ForEach-Object { Get-RedactPatternEntry -Entry $_ })
        $compiled = @(Test-RedactPatternCompile -Pattern @($entries.ForEach({ $_.Regex })))
        for ($i = 0; $i -lt $entries.Count; $i++) {
            $problem = Get-RedactPatternProblem -Pattern $entries[$i] -CompileProblem $compiled[$i]
            if ($problem) { return "${key}[$i] rejected: $problem." }
        }
    }
}

function Read-RedactConfigFile {
    # Errors name the layer only; file content is never echoed.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Layer
    )

    try {
        $data = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -AsHashtable -Depth 100 -ErrorAction Stop
        if ($data -isnot [hashtable]) { throw 'not an object' }
        $data
    }
    catch {
        throw (Get-RedactErrorRecord -Message "Config layer '$Layer' could not be read as a JSON object." -ErrorId 'RedactOutput.ConfigInvalid')
    }
}

function Merge-RedactConfig {
    # Scalars and arrays replace; 'categories' merges key by key; keys starting with '_' are comments.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Base,
        [Parameter(Mandatory)][hashtable]$Layer
    )

    foreach ($key in $Layer.Keys) {
        if ($key.StartsWith('_')) { continue }
        if ($key -eq 'categories' -and $Layer[$key] -is [System.Collections.IDictionary]) {
            foreach ($category in $Layer[$key].Keys) { $Base['categories'][$category] = $Layer[$key][$category] }
        }
        else { $Base[$key] = $Layer[$key] }
    }
}

function Get-RedactConfig {
    <#
    .SYNOPSIS
        Loads and layers the RedactOutput configuration.
    .DESCRIPTION
        Layers, lowest to highest: built-in defaults, config/redact.config.sample.json,
        config/redact.config.local.json, -ConfigPath, -Override. The config directory is
        $env:REDACTOUTPUT_CONFIG_DIR when set, otherwise the module's config folder. Missing sample and
        local files are skipped. The merged result is validated (enum values, entry shapes, host and
        serial regexes). Error messages name the layer, key and index, never file content or patterns.
    .PARAMETER ConfigPath
        Extra JSON config file layered above the local file. Must exist.
    .PARAMETER Override
        Hashtable layered above everything else.
    .EXAMPLE
        Get-RedactConfig -ConfigPath .\my-config.json
    .OUTPUTS
        System.Collections.Hashtable
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [string]$ConfigPath,
        [hashtable]$Override
    )

    $dir = Get-RedactConfigDir
    $layers = [ordered]@{
        sample = Join-Path $dir 'redact.config.sample.json'
        local  = Join-Path $dir 'redact.config.local.json'
    }
    if ($ConfigPath) { $layers['ConfigPath'] = $ConfigPath }

    $config = Get-RedactConfigDefault
    foreach ($layer in $layers.Keys) {
        if (-not (Test-Path -LiteralPath $layers[$layer] -PathType Leaf)) {
            if ($layer -eq 'ConfigPath') {
                throw (Get-RedactErrorRecord -Message 'The file given by -ConfigPath was not found.' -ErrorId 'RedactOutput.ConfigNotFound' -Category ObjectNotFound)
            }
            continue
        }
        Merge-RedactConfig -Base $config -Layer (Read-RedactConfigFile -Path $layers[$layer] -Layer $layer)
    }
    if ($Override) { Merge-RedactConfig -Base $config -Layer $Override }
    $problem = Get-RedactConfigProblem -Config $config
    if ($problem) {
        throw (Get-RedactErrorRecord -Message "Config rejected: $problem" -ErrorId 'RedactOutput.ConfigInvalid')
    }
    $config
}

#region Scaffolding (New-RedactionConfig)

function ConvertTo-RedactConfigEntry {
    # Shorthand to an object entry: 'NETBIOS=fqdn' and 'TERM=label' (split at the last '='), a bare host regex (minLength 6).
    # A string that does not fit becomes an incomplete entry, which the config validator then rejects by key and index.
    [CmdletBinding()]
    [OutputType([System.Collections.IDictionary])]
    param(
        [Parameter(Mandatory)][object]$Value,
        [Parameter(Mandatory)][string]$Key
    )

    if ($Value -is [System.Collections.IDictionary]) { return $Value }
    $fields = $script:ConfigShape[$Key]
    if ($Key -eq 'hostPatterns') { return @{ regex = [string]$Value; minLength = 6 } }
    $at = ([string]$Value).LastIndexOf('=')
    if ($at -lt 1) { return @{ $fields[0] = [string]$Value } }
    @{ $fields[0] = $Value.Substring(0, $at).Trim(); $fields[1] = $Value.Substring($at + 1).Trim() }
}

function Test-RedactInteractive {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    [Environment]::UserInteractive -and -not [Console]::IsInputRedirected
}

function Read-RedactConfigAnswer {
    # Asks the questions in $script:ConfigQuestion; returns parameter name -> answers (blank answers are dropped).
    # Answers are never echoed back.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $answers = @{}
    foreach ($question in $script:ConfigQuestion) {
        $name, $prompt, $split = $question
        $reply = (Read-Host -Prompt $prompt).Trim()
        $list = @(if ($split) { $reply -split ',' | ForEach-Object { $_.Trim() } } else { $reply }).Where({ $_ })
        if ($list.Count -gt 0) { $answers[$name] = @(if ($answers.ContainsKey($name)) { $answers[$name] }) + $list }
    }
    if ($answers.ContainsKey('NetbiosName') -and $answers.ContainsKey('NetbiosFqdn')) {
        $answers['NetbiosDomain'] = @("$($answers['NetbiosName'][0])=$($answers['NetbiosFqdn'][0])")
    }
    $answers.Remove('NetbiosName')
    $answers.Remove('NetbiosFqdn')
    $answers
}

function Test-RedactGitIgnored {
    # $true or $false from git check-ignore; $null when git is missing or the file is not inside a repository.
    [CmdletBinding()]
    [OutputType([object])]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Get-Command -Name git -ErrorAction Ignore)) { return $null }
    $folder = [System.IO.Path]::GetDirectoryName($Path)
    $null = & git -C $folder rev-parse --is-inside-work-tree 2>$null
    if ($LASTEXITCODE -ne 0) { return $null }
    $null = & git -C $folder check-ignore -q -- $Path 2>$null
    $LASTEXITCODE -eq 0
}

#endregion
