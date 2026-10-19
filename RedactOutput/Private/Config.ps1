# Layered configuration: built-in defaults < sample < local < -ConfigPath < -Override.

$script:ConfigEnum = @{ ipMode = @('Classify', 'KeepPrivate', 'Keep'); pathMode = @('UserOnly', 'Full', 'Keep') }
# Object-array keys and the fields every entry needs.
$script:ConfigShape = @{ netbiosDomains = @('netbios', 'fqdn'); extraTerms = @('term', 'label'); hostPatterns = @('regex') }

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

function Get-RedactPatternProblem {
    # Why a config regex is rejected, or nothing. The reason never contains the pattern text.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][pscustomobject]$Pattern)

    $text = $Pattern.Regex
    if ($text.Length -lt 3) { return 'too short' }
    try {
        $regex = Get-RedactRegex -Pattern $text -IgnoreCase
        if ((Get-RedactRegex -Pattern '\((?:[^()\\]|\\.)*(?:[+*]|\{[0-9]+,[0-9]*\})(?:[^()\\]|\\.)*\)(?:[+*]|\{[0-9]+,)').IsMatch($text)) { return 'nested quantifier' }
        if ($Pattern.MinLength -lt 4 -and -not (Get-RedactRegex -Pattern '0-9|\\d').IsMatch($text)) { return 'needs minLength >= 4 or a digit class' }
        [void]$regex.IsMatch(('a' * 2500) + ('1' * 2499) + '!')
    }
    catch [System.Text.RegularExpressions.RegexMatchTimeoutException] { return 'exceeded the regex time limit' }
    catch [System.ArgumentException] { return 'does not compile' }
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
        $i = 0
        foreach ($entry in (Get-RedactConfigList -Config $Config -Key $key)) {
            $problem = Get-RedactPatternProblem -Pattern (Get-RedactPatternEntry -Entry $entry)
            if ($problem) { return "${key}[$i] rejected: $problem." }
            $i++
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
