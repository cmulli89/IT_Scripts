# Structure-aware JSON handler: parses, walks every dictionary and list, and sends each string through the shared
# engine. A secret-named property replaces every string under it; person fields get their I16 token.

function Get-RedactPersonType {
    # Token type for a person field (givenName, surname, mobilePhone, businessPhones, employeeId, displayName), or ''.
    # displayName counts only inside an object that has a non-empty userPrincipalName or mail (Graph groups carry mail: null).
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Name,
        [Parameter(Mandatory)][bool]$HasIdentity,
        [Parameter(Mandatory)][object]$Session
    )

    $type = $script:PersonField[$Name.ToLowerInvariant()]
    if ($Session.Config['categories']['person'] -eq $false -or -not $type -or ($Name -ieq 'displayName' -and -not $HasIdentity)) { return '' }
    $type
}

function Protect-RedactJsonNode {
    # Returns a redacted copy of a Newtonsoft JToken. Objects keep their key order (names are tokenized too). Only string
    # values change; numbers, booleans and null are cloned as they are. Results are returned with a leading comma because
    # a JValue or JArray would otherwise be enumerated by the pipeline. Type tests use -is: on a JObject PowerShell reads
    # .Type as a dictionary key lookup.
    [CmdletBinding()]
    param(
        [AllowNull()][Newtonsoft.Json.Linq.JToken]$Node,
        [Parameter(Mandatory)][object]$Session,
        [bool]$Secret = $false,
        [string]$PersonType = ''
    )

    if ($Node -is [Newtonsoft.Json.Linq.JObject]) {
        $hasIdentity = $Node.Properties().Where({ $_.Name -in 'userPrincipalName', 'mail' -and $_.Value -is [Newtonsoft.Json.Linq.JValue] -and -not [string]::IsNullOrWhiteSpace([string]$_.Value.Value) }, 'First').Count -gt 0
        $copy = [Newtonsoft.Json.Linq.JObject]::new()
        $used = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($property in $Node.Properties()) {
            $tokenized = Invoke-RedactText -Text $property.Name -Session $Session
            $name = $tokenized
            # Different names can share a token (host names are case-insensitive); keep every key.
            for ($n = 2; -not $used.Add($name); $n++) { $name = "$tokenized-$n" }
            $child = Protect-RedactJsonNode -Node $property.Value -Session $Session `
                -Secret ($Secret -or (Test-RedactSecretName -Name $property.Name -Session $Session)) `
                -PersonType (Get-RedactPersonType -Name $property.Name -HasIdentity $hasIdentity -Session $Session)
            $copy.Add($name, $child)
        }
        return , $copy
    }
    if ($Node -is [Newtonsoft.Json.Linq.JArray]) {
        $copy = [Newtonsoft.Json.Linq.JArray]::new()
        foreach ($item in $Node) { $copy.Add((Protect-RedactJsonNode -Node $item -Session $Session -Secret $Secret -PersonType $PersonType)) }
        return , $copy
    }
    if ($Node.Type -ne [Newtonsoft.Json.Linq.JTokenType]::String) { return , $Node.DeepClone() }
    $value = [string]$Node.Value
    $new = if ($Secret) { Protect-RedactSecretValue -Value $value -Session $Session }
    elseif ($PersonType -and -not (Test-RedactSkipValue -Value $value)) {
        $Session.Counts['person'] += 1
        Get-RedactToken -Session $Session -Type $PersonType -Original $value
    }
    else { Invoke-RedactText -Text $value -Session $Session }
    , [Newtonsoft.Json.Linq.JValue]::new([string]$new)
}

function Invoke-RedactJson {
    # Returns the re-serialized JSON, or $null when the text does not parse (or has content after the first value). Parsed with
    # Newtonsoft (ships with pwsh 7.2+) so dates stay strings and numbers keep their exact text: DateParseHandling None,
    # FloatParseHandling Decimal. Comments are dropped. A final line terminator is kept.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][object]$Session,
        [switch]$Compress
    )

    try {
        $reader = [Newtonsoft.Json.JsonTextReader]::new([System.IO.StringReader]::new($Text))
        $reader.DateParseHandling = 'None'
        $reader.FloatParseHandling = 'Decimal'
        $reader.MaxDepth = 200
        $settings = [Newtonsoft.Json.Linq.JsonLoadSettings]::new()
        $settings.CommentHandling = 'Ignore'
        $root = [Newtonsoft.Json.Linq.JToken]::ReadFrom($reader, $settings)
        if ($reader.Read()) { return $null }
    }
    catch { return $null }
    $format = if ($Compress) { [Newtonsoft.Json.Formatting]::None } else { [Newtonsoft.Json.Formatting]::Indented }
    (Protect-RedactJsonNode -Node $root -Session $Session).ToString($format) + (Get-RedactRegex -Pattern '(?:\r\n|\n|\r)\z').Match($Text).Value
}

function Invoke-RedactJsonLine {
    # .jsonl / .ndjson: every line that parses as a JSON object or array takes the structured path (compressed to one
    # line); other lines go through the plain engine. Line count and terminators are unchanged.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][object]$Session
    )

    $lines = Split-RedactLine -Text $Text
    foreach ($l in $lines) {
        $start = $l.Line.TrimStart()
        $json = if ($start.StartsWith('{') -or $start.StartsWith('[')) { Invoke-RedactJson -Text $l.Line -Session $Session -Compress }
        $l.Line = if ($null -ne $json) { $json } else { Invoke-RedactText -Text $l.Line -Session $Session }
    }
    Join-RedactLine -Line $lines
}
