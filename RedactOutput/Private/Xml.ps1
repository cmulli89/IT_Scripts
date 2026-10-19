# XML handler: text mode, so every untouched byte survives. Secret-named values the plain S04 rule cannot see are
# replaced with element-aware regexes (not a DOM rewrite); S04 itself already covers <Password>x</Password>, the
# unattend <Password><Value>x</Value> form and secret-named attributes. The tokens are [..], so the output stays well-formed.

# Group n is the name that is tested for a secret-looking name, group val the span that is replaced.
$script:XmlValuePattern = @(
    # CDATA content: <ApiKey><![CDATA[...]]></ApiKey>
    '<(?<n>[A-Za-z_][A-Za-z0-9_.:-]*)(?:\s[^<>]*)?>\s*<!\[CDATA\[(?<val>(?:(?!\]\]>)[\s\S])*)\]\]>'
    # name/value attribute pairs: <add key="ApiKey" value="..."/>, <Setting Name="ClientSecret" Value="..."/>
    '<[A-Za-z_][A-Za-z0-9_.:-]*\s[^<>]*?(?<![A-Za-z0-9_:-])(?:name|key|id)\s*=\s*"(?<n>[^"]*)"[^<>]*?(?<![A-Za-z0-9_:-])value\s*=\s*"(?<val>[^"]*)"'
)

function Invoke-RedactXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][object]$Session
    )

    $edited = $Text
    foreach ($pattern in $script:XmlValuePattern) {
        $edited = (Get-RedactRegex -Pattern $pattern -IgnoreCase).Replace($edited, {
                param($m)
                if (-not (Test-RedactSecretName -Name $m.Groups['n'].Value -Session $Session)) { return $m.Value }
                $val = $m.Groups['val']
                $offset = $val.Index - $m.Index
                $m.Value.Substring(0, $offset) + (Protect-RedactSecretValue -Value $val.Value -Session $Session) + $m.Value.Substring($offset + $val.Length)
            })
    }
    Invoke-RedactText -Text $edited -Session $Session
}
