# Token allocation: stable [type-NN] tokens per session. In memory only; stage 4 persists Session.Entries.
# Secrets never come through here.

function ConvertTo-RedactGuidKey {
    # Canonical lower-case hyphenated GUID (braces stripped, 32-hex expanded); $null when it is not a GUID.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Guid)

    $hex = $Guid.Trim().Trim('{', '}').Replace('-', '').ToLowerInvariant()
    $parsed = [guid]::Empty
    if ([guid]::TryParseExact($hex, 'N', [ref]$parsed)) { $parsed.ToString() }
}

function Get-RedactKey {
    # Normalized lookup key: lower-case for names, canonical form for GUIDs, everything else as is.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][string]$Original
    )

    if ($Type -in 'guid', 'sub') {
        $key = ConvertTo-RedactGuidKey -Guid $Original
        if ($key) { return $key }
    }
    if ($Type -in 'host', 'domain', 'user', 'tenant', 'share', 'name', 'guid', 'sub' -or $Type.StartsWith('term-', [StringComparison]::Ordinal)) {
        return $Original.ToLowerInvariant()
    }
    $Original
}

function Get-RedactToken {
    <#
    .SYNOPSIS
        Returns the session's token for an original value, allocating the next [type-NN] on first use.
    .DESCRIPTION
        NN is a per-type counter, zero-padded to 2 digits (3 past 99). The same normalized original always
        gets the same token within the session. New entries are recorded in Session.Entries.
    .PARAMETER Session
        Session from New-RedactSession.
    .PARAMETER Type
        Token type, for example host, user, domain, ip-priv, or term-<label>.
    .PARAMETER Original
        The value being replaced.
    .EXAMPLE
        Get-RedactToken -Session $session -Type host -Original 'WS-1234'
    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][object]$Session,
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][string]$Original
    )

    $mapKey = "$Type|$(Get-RedactKey -Type $Type -Original $Original)"
    $token = $null
    if ($Session.Maps.TryGetValue($mapKey, [ref]$token)) { return $token }

    $number = 1 + $(if ($Session.Counters.ContainsKey($Type)) { $Session.Counters[$Type] } else { 0 })
    $Session.Counters[$Type] = $number
    $token = '[{0}-{1:D2}]' -f $Type, $number
    $Session.Maps[$mapKey] = $token
    $Session.Entries.Add([pscustomobject]@{ Token = $token; Type = $Type; Original = $Original })
    $token
}

function Add-RedactAlias {
    <#
    .SYNOPSIS
        Registers an extra original for an existing token.
    .DESCRIPTION
        A NetBIOS name shares its FQDN's domain token; a subscription GUID registers so bare repeats of it
        become [sub-NN]. An original that already has a token keeps it.
    .PARAMETER Session
        Session from New-RedactSession.
    .PARAMETER Type
        Map the alias is looked up in (for example domain or guid).
    .PARAMETER Original
        The alias value.
    .PARAMETER Token
        The existing token the alias resolves to.
    .EXAMPLE
        Add-RedactAlias -Session $session -Type domain -Original 'CONTOSO' -Token '[domain-01]'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Session,
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][string]$Original,
        [Parameter(Mandatory)][string]$Token
    )

    $mapKey = "$Type|$(Get-RedactKey -Type $Type -Original $Original)"
    if ($Session.Maps.ContainsKey($mapKey)) { return }
    $Session.Maps[$mapKey] = $Token
    $Session.Entries.Add([pscustomobject]@{ Token = $Token; Type = $Type; Original = $Original })
}
