# Built-in allowlists and the tests that use them. Config can only extend these sets, never shrink them.

$script:PublicHostSeed = @(
    'login.microsoftonline.us', '*.microsoftonline.us', 'graph.microsoft.us', '*.office365.us', '*.microsoft.us',
    '*.azure.us', '*.usgovcloudapi.net', 'learn.microsoft.com', 'login.microsoftonline.com', 'graph.microsoft.com',
    'aka.ms', 'github.com'
)
$script:PublicDomainSeed = @(
    'microsoft.com', 'microsoft.us', 'office365.us', 'outlook.com', 'hotmail.com', 'live.com', 'gmail.com',
    'yahoo.com', 'github.com', 'users.noreply.github.com'
)
$script:KeepLocalPart = @('git', 'root', 'noreply', 'no-reply')
$script:GuidSeed = @(
    '00000000-0000-0000-0000-000000000000'
    '04b07795-8ddb-461a-bbee-02f9e1bf7b46' # Azure CLI
    '1950a258-227b-4e31-a9cf-717495945fc2' # Azure PowerShell
    '14d82eec-204b-4c2f-b7e8-296a70dab67e' # Graph PowerShell
    '797f4846-ba00-4fd7-ba43-dac1f8f63013' # Azure Service Management
    '62e90394-69f5-4237-9190-012177145e10' # Global Administrator role template
)
$script:GuidFirstParty = '^000000[0-9a-f]{2}-0000-(?:0000-c000|0ff1-ce00)-000000000000$'
$script:KeepIpSeed = @('168.63.129.16', '169.254.169.254')
# Well-known SIDs (S-1-5-18/19/20, S-1-5-32-*, S-1-1-0, S-1-5-11, S-1-5-80-*) are never matched by rule I02,
# which only targets S-1-5-21 domain SIDs and S-1-12-1 cloud SIDs.
$script:WellKnownGroup = @(
    'Domain Admins', 'Domain Users', 'Domain Guests', 'Domain Computers', 'Domain Controllers', 'Enterprise Admins',
    'Schema Admins', 'Administrators', 'Users', 'Guests', 'Remote Desktop Users', 'Group Policy Creator Owners',
    'Cert Publishers', 'Protected Users', 'DnsAdmins', 'Backup Operators', 'Account Operators', 'Print Operators',
    'Server Operators', 'Power Users', 'Read-only Domain Controllers'
)
$script:StructuralCn = @(
    'Users', 'Computers', 'Builtin', 'System', 'Domain Admins', 'Domain Users', 'Domain Controllers', 'Configuration',
    'Schema', 'Microsoft Exchange Security Groups', 'ForeignSecurityPrincipals', 'Managed Service Accounts', 'Program Data'
)
$script:KeepProfile = @('public', 'default', 'default user', 'all users')
# Full path mode keeps these folder names (lower-case) instead of tokenizing them. On Unix, Full mode only
# applies to paths under the standard roots (etc, usr, var, opt, ..., home), so URL paths and resource IDs are safe.
$script:SystemFolder = @(
    'windows', 'program files', 'program files (x86)', 'programdata', 'appdata', 'local', 'roaming', 'locallow', 'temp',
    'desktop', 'documents', 'downloads', 'system32', 'etc', 'usr', 'var', 'opt', 'bin', 'sbin', 'lib', 'tmp', 'home', 'srv', 'mnt', 'root', 'users'
)
$script:BuiltInGuid = $null

#region Name sets (hosts and domains)

function ConvertTo-RedactNameSet {
    # Entries '*.x' become label-boundary suffixes ('.x'); others are exact. -Subdomains also makes each exact entry a suffix.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [AllowEmptyCollection()][string[]]$Entry = @(),
        [switch]$Subdomains
    )

    $exact = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $suffix = [System.Collections.Generic.List[string]]::new()
    foreach ($item in $Entry) {
        if (-not $item) { continue }
        $name = $item.Trim().ToLowerInvariant()
        if ($name.StartsWith('*.', [StringComparison]::Ordinal)) { $suffix.Add($name.Substring(1)) }
        else {
            [void]$exact.Add($name)
            if ($Subdomains) { $suffix.Add(".$name") }
        }
    }
    @{ Exact = $exact; Suffix = $suffix }
}

function Test-RedactNameSet {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][hashtable]$Set,
        [Parameter(Mandatory)][string]$Name
    )

    $lower = $Name.ToLowerInvariant()
    if ($Set.Exact.Contains($lower)) { return $true }
    foreach ($suffix in $Set.Suffix) {
        if ($lower.Length -gt $suffix.Length -and $lower.EndsWith($suffix, [StringComparison]::Ordinal)) { return $true }
    }
    $false
}

function Test-RedactPublicHost {
    # Exact match, or label-boundary suffix match for '*.x' entries: a.x yes; evilx and x.example no.
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][object]$Session
    )

    Test-RedactNameSet -Set $Session.Allow.Host -Name $Name
}

function Test-RedactInternalName {
    # True when the name ends with one of the configured internal domains.
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][object]$Session
    )

    foreach ($domain in (Get-RedactConfigList -Config $Session.Config -Key 'internalDomains')) {
        if ($Name.EndsWith(".$domain", [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    $false
}

#endregion

#region GUIDs

function Read-RedactGuidList {
    # GUIDs from a 'guid # comment' file; blank and comment lines are skipped. Missing file gives nothing.
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return @() }
    $line = Get-RedactRegex -Pattern "^[ \t]*($script:GUID)"
    [string[]]@(foreach ($text in (Get-Content -LiteralPath $Path)) {
        $m = $line.Match($text)
        if ($m.Success) { $m.Groups[1].Value }
    })
}

function Get-RedactAllowlist {
    <#
    .SYNOPSIS
        Builds the session's allowlists: built-in sets plus whatever config adds.
    .DESCRIPTION
        Host and Domain are name sets, Guid holds canonical GUIDs (built-in seed, Entra role templates,
        config guidAllowlist, guid-allowlist.txt), Ip holds exact keep-list addresses.
    .PARAMETER Config
        Merged configuration from Get-RedactConfig.
    .EXAMPLE
        Get-RedactAllowlist -Config (Get-RedactConfig)
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][hashtable]$Config)

    if (-not $script:BuiltInGuid) {
        $script:BuiltInGuid = @($script:GuidSeed) + @(Read-RedactGuidList -Path (Join-Path $PSScriptRoot 'entra-role-templates.txt'))
    }
    $guids = [System.Collections.Generic.HashSet[string]]::new()
    $extra = @(Get-RedactConfigList -Config $Config -Key 'guidAllowlist') + @(Read-RedactGuidList -Path (Join-Path (Get-RedactConfigDir) 'guid-allowlist.txt'))
    foreach ($guid in @($script:BuiltInGuid) + $extra) {
        $key = ConvertTo-RedactGuidKey -Guid ([string]$guid)
        if ($key) { [void]$guids.Add($key) }
    }
    [pscustomobject]@{
        Host   = ConvertTo-RedactNameSet -Entry ($script:PublicHostSeed + @(Get-RedactConfigList -Config $Config -Key 'publicHostAllowlist'))
        Domain = ConvertTo-RedactNameSet -Entry ($script:PublicDomainSeed + @(Get-RedactConfigList -Config $Config -Key 'publicDomains')) -Subdomains
        Guid   = $guids
        Ip     = [System.Collections.Generic.HashSet[string]]::new([string[]]@($script:KeepIpSeed + @(Get-RedactConfigList -Config $Config -Key 'ipAllowlist')))
    }
}

function Test-RedactAllowedGuid {
    # Zero GUID, first-party family, seed IDs, Entra role templates and config entries are kept verbatim.
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$Guid,
        [Parameter(Mandatory)][object]$Session
    )

    $key = ConvertTo-RedactGuidKey -Guid $Guid
    [bool]$key -and ($Session.Allow.Guid.Contains($key) -or (Get-RedactRegex -Pattern $script:GuidFirstParty).IsMatch($key))
}

#endregion

#region IP addresses

function Test-RedactIpv4 {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$Text)

    (Get-RedactRegex -Pattern ('^' + $script:OCT + '(?:\.' + $script:OCT + '){3}$')).IsMatch($Text)
}

function Test-RedactPrivateIp {
    # RFC 1918 plus 100.64.0.0/10.
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$Ip)

    $o = [int[]]$Ip.Split('.')
    ($o[0] -eq 10) -or ($o[0] -eq 172 -and $o[1] -in 16..31) -or ($o[0] -eq 192 -and $o[1] -eq 168) -or ($o[0] -eq 100 -and $o[1] -in 64..127)
}

function Test-RedactKeepIp {
    # Keep-list: loopback, unspecified, broadcast, link-local, multicast, netmasks, wildcard masks, Azure platform
    # addresses and config ipAllowlist; private addresses too in KeepPrivate mode, everything in Keep mode.
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$Ip,
        [Parameter(Mandatory)][object]$Session
    )

    $mode = $Session.Config['ipMode']
    if ($mode -eq 'Keep' -or $Session.Allow.Ip.Contains($Ip)) { return $true }
    $o = [long[]]$Ip.Split('.')
    $value = ($o[0] -shl 24) + ($o[1] -shl 16) + ($o[2] -shl 8) + $o[3]
    $inverse = 4294967295 - $value
    ($o[0] -eq 127) -or ($o[0] -eq 169 -and $o[1] -eq 254) -or ($o[0] -ge 224 -and $o[0] -le 239) -or
        ($value -eq 0) -or ($value -eq 4294967295) -or
        (($inverse -band ($inverse + 1)) -eq 0) -or (($value -band ($value + 1)) -eq 0) -or
        ($mode -eq 'KeepPrivate' -and (Test-RedactPrivateIp -Ip $Ip))
}

#endregion
