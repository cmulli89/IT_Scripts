# Layered configuration: built-in defaults < sample < local < -ConfigPath < -Override.

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
        $PSCmdlet.ThrowTerminatingError((Get-RedactErrorRecord -Message "Config layer '$Layer' could not be read as a JSON object." -ErrorId 'RedactOutput.ConfigInvalid'))
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
        local files are skipped. Error messages name the layer, never file content.
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

    $dir = if ($env:REDACTOUTPUT_CONFIG_DIR) { $env:REDACTOUTPUT_CONFIG_DIR } else { Join-Path $PSScriptRoot '../config' }
    $layers = [ordered]@{
        sample = Join-Path $dir 'redact.config.sample.json'
        local  = Join-Path $dir 'redact.config.local.json'
    }
    if ($ConfigPath) { $layers['ConfigPath'] = $ConfigPath }

    $config = @{ secretNames = @(); nonSecretNames = @(); categories = @{} }
    foreach ($layer in $layers.Keys) {
        if (-not (Test-Path -LiteralPath $layers[$layer] -PathType Leaf)) {
            if ($layer -eq 'ConfigPath') {
                $PSCmdlet.ThrowTerminatingError((Get-RedactErrorRecord -Message 'The file given by -ConfigPath was not found.' -ErrorId 'RedactOutput.ConfigNotFound' -Category ObjectNotFound))
            }
            continue
        }
        Merge-RedactConfig -Base $config -Layer (Read-RedactConfigFile -Path $layers[$layer] -Layer $layer)
    }
    if ($Override) { Merge-RedactConfig -Base $config -Layer $Override }
    $config
}
