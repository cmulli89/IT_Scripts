# File type detection and routing of text to the right handler. Every handler reuses the engine for each string;
# a handler that cannot parse its input returns $null and the text goes through the plain engine with a warning.

$script:TypeExtension = [ordered]@{
    binary   = '.zip .evtx .etl .cab .xlsx .docx .pptx .pdf .png .jpg .jpeg .gif .bmp .ico .exe .dll .7z .gz .msi'
    text     = '.txt .log .out'
    json     = '.json'
    jsonl    = '.jsonl .ndjson'
    csv      = '.csv'
    tsv      = '.tsv'
    xml      = '.xml .wsb'
    keyvalue = '.env .ini .conf .properties .yaml .yml'
    reg      = '.reg'
    script   = '.ps1 .psm1 .psd1 .sh .py'
    html     = '.html .htm'
}
# Types where -Head / -Tail would break the structure.
$script:StructuredType = @('json', 'csv', 'tsv', 'xml', 'reg')
$script:BinaryHint = 'Get-WinEvent -LogName System -MaxEvents 500 | Select-Object TimeCreated,Id,LevelDisplayName,Message | redact'

function Get-RedactFileType {
    <#
    .SYNOPSIS
        Detects the handling type of a file: text, json, jsonl, csv, tsv, xml, keyvalue, reg, script, html or binary.
    .DESCRIPTION
        By extension first; a file named .env* is keyvalue. Unknown extensions and plain text types get a content
        check on -Text (an XML declaration means xml, a registry header means reg), otherwise text.
    .PARAMETER Path
        File name or path; only the name is used.
    .PARAMETER Text
        Start of the file's text for the content check.
    .EXAMPLE
        Get-RedactFileType -Path .\dump.reg
    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$Text = ''
    )

    $name = [System.IO.Path]::GetFileName($Path)
    $extension = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
    $type = if ($name.StartsWith('.env', [StringComparison]::OrdinalIgnoreCase)) { 'keyvalue' }
    else { foreach ($key in $script:TypeExtension.Keys) { if ($script:TypeExtension[$key].Split(' ') -contains $extension) { $key; break } } }
    if ($type -and $type -ne 'text') { return $type }
    if ((Get-RedactRegex -Pattern '^\s*<\?xml').IsMatch($Text)) { return 'xml' }
    if ((Get-RedactRegex -Pattern '^\s*(?:Windows Registry Editor Version|REGEDIT4)').IsMatch($Text)) { return 'reg' }
    'text'
}

function Get-RedactBinaryError {
    [CmdletBinding()]
    [OutputType([System.Management.Automation.ErrorRecord])]
    param([Parameter(Mandatory)][string]$Path)

    Get-RedactErrorRecord -ErrorId 'RedactOutput.Binary' -Message "'$([System.IO.Path]::GetFileName($Path))' is a binary file; RedactOutput handles text only. For event logs, export text instead: $script:BinaryHint"
}

function Invoke-RedactHtml {
    # Text mode; embedded base64 data: URIs are counted in a warning (they are not decoded or scanned).
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][object]$Session
    )

    $uris = (Get-RedactRegex -Pattern 'data:[A-Za-z0-9.+/-]+;base64,' -IgnoreCase).Matches($Text).Count
    if ($uris -gt 0) { Write-Warning "HTML input contains $uris base64 data: URI(s); embedded content is not scanned." }
    Invoke-RedactText -Text $Text -Session $Session
}

function Invoke-RedactContent {
    <#
    .SYNOPSIS
        Redacts text with the handler for its file type.
    .DESCRIPTION
        json, jsonl, csv, tsv, xml, keyvalue, reg and html have their own handler; text and script use the
        plain engine, after wrapped Format-List values are re-joined (Join-RedactWrappedLine). A handler that cannot parse its input returns $null and the text is redacted as plain
        text with a warning that names the type, never the content.
    .PARAMETER Text
        Text to redact.
    .PARAMETER Type
        Type from Get-RedactFileType.
    .PARAMETER Session
        Session from New-RedactSession.
    .EXAMPLE
        Invoke-RedactContent -Text $json -Type json -Session $session
    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][object]$Session
    )

    if ([string]::IsNullOrEmpty($Text)) { return '' }
    if ($Type -in 'text', 'script') { $Text = Join-RedactWrappedLine -Text $Text }
    $result = switch ($Type) {
        'json' { Invoke-RedactJson -Text $Text -Session $Session }
        'jsonl' { Invoke-RedactJsonLine -Text $Text -Session $Session }
        'csv' { Invoke-RedactCsv -Text $Text -Session $Session }
        'tsv' { Invoke-RedactCsv -Text $Text -Session $Session -Delimiter "`t" }
        'xml' { Invoke-RedactXml -Text $Text -Session $Session }
        'keyvalue' { Invoke-RedactKeyValue -Text $Text -Session $Session }
        'reg' { Invoke-RedactReg -Text $Text -Session $Session }
        'html' { Invoke-RedactHtml -Text $Text -Session $Session }
    }
    if ($null -ne $result) { return $result }
    if ($Type -notin 'text', 'script') { Write-Warning "Could not parse the input as $Type; processed as text." }
    Invoke-RedactText -Text $Text -Session $Session
}
