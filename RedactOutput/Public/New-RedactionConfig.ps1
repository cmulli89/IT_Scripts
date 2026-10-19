function New-RedactionConfig {
    <#
    .SYNOPSIS
        Writes the local RedactOutput config (config/redact.config.local.json) from parameters or interactive answers.

    .DESCRIPTION
        Only the keys you give are written; everything else keeps coming from the sample file. With no parameters in an
        interactive session you are asked for internal domains, the NetBIOS name and FQDN, desktop, laptop, server, VM and
        Linux host patterns, Azure resource prefixes, user names, the tenant prefix and extra terms. A tenant prefix is
        added to the resource prefixes. Entered values are written to the file only; they are never echoed.

        The result is checked with the validator the config loader uses; a rejected entry is reported by key and index,
        never by value. An existing file is not read and is replaced only with -Force. After writing, git check-ignore
        confirms that .gitignore covers the file and a warning says so when it does not (the file holds your
        environment's identifiers: never commit it).

    .PARAMETER Path
        Config file to write. Defaults to redact.config.local.json in the module's config folder.

    .PARAMETER Force
        Replace an existing file.

    .PARAMETER InternalDomains
        AD and UPN domains; subdomains are included.

    .PARAMETER NetbiosDomain
        NetBIOS names with their FQDN, as hashtables @{ netbios = 'CONTOSO'; fqdn = 'ad.contoso.example' } or 'NETBIOS=fqdn' strings.

    .PARAMETER HostPattern
        Host naming regexes, as strings (minLength 6) or hashtables @{ regex = 'WS-[0-9]{3,}'; minLength = 6 }.

    .PARAMETER HostList
        Exact host names.

    .PARAMETER ResourcePrefix
        Azure resource and resource group naming prefixes.

    .PARAMETER TenantPrefix
        Tenant name prefix; added to the resource prefixes.

    .PARAMETER Username
        Explicit user or service account names.

    .PARAMETER ExtraTerm
        Project names, contract numbers and similar, as hashtables @{ term = 'CTR-0000'; label = 'contract' } or 'TERM=label' strings.

    .PARAMETER GuidAllowlist
        GUIDs to keep verbatim.

    .PARAMETER PublicHostAllowlist
        Extra public endpoints to keep readable.

    .PARAMETER PublicDomain
        Extra public email domains.

    .PARAMETER IpAllowlist
        IP addresses to keep.

    .PARAMETER IpMode
        Classify (default), KeepPrivate or Keep.

    .PARAMETER PathMode
        UserOnly (default), Full or Keep.

    .PARAMETER SidKeepRid
        Keep the RID of S-1-5-21 SIDs (default true).

    .PARAMETER Categories
        Per-category on/off, for example @{ mac = $false }.

    .PARAMETER SecretName
        Extra names whose values are secrets.

    .PARAMETER NonSecretName
        Extra names that look secret but are not.

    .PARAMETER DeviceSerialPattern
        Regexes for device serial numbers.

    .EXAMPLE
        New-RedactionConfig

    .EXAMPLE
        New-RedactionConfig -InternalDomains ad.contoso.example, contoso.example -NetbiosDomain 'CONTOSO=ad.contoso.example' -HostPattern 'WS-[0-9]{3,}' -Force

    .OUTPUTS
        System.IO.FileInfo
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.IO.FileInfo])]
    param(
        [string]$Path,
        [switch]$Force,
        [string[]]$InternalDomains,
        [object[]]$NetbiosDomain,
        [object[]]$HostPattern,
        [string[]]$HostList,
        [string[]]$ResourcePrefix,
        [string[]]$TenantPrefix,
        [string[]]$Username,
        [object[]]$ExtraTerm,
        [string[]]$GuidAllowlist,
        [string[]]$PublicHostAllowlist,
        [string[]]$PublicDomain,
        [string[]]$IpAllowlist,
        [ValidateSet('Classify', 'KeepPrivate', 'Keep')][string]$IpMode,
        [ValidateSet('UserOnly', 'Full', 'Keep')][string]$PathMode,
        [bool]$SidKeepRid,
        [hashtable]$Categories,
        [string[]]$SecretName,
        [string[]]$NonSecretName,
        [string[]]$DeviceSerialPattern
    )

    $target = if ($Path) { $Path } else { Join-Path (Get-RedactConfigDir) 'redact.config.local.json' }
    $target = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($target)
    if ((Test-Path -LiteralPath $target) -and -not $Force) {
        $PSCmdlet.ThrowTerminatingError((Get-RedactErrorRecord -ErrorId 'RedactOutput.ConfigExists' -Category ResourceExists -Message 'The config file already exists. Use -Force to replace it.'))
    }

    $given = @{}
    foreach ($name in $script:ConfigParameter.Keys) { if ($PSBoundParameters.ContainsKey($name)) { $given[$name] = $PSBoundParameters[$name] } }
    if ($given.Count -eq 0) {
        if (-not (Test-RedactInteractive)) {
            $PSCmdlet.ThrowTerminatingError((Get-RedactErrorRecord -ErrorId 'RedactOutput.ConfigNoValues' -Category InvalidArgument -Message 'No config parameters were given and the session is not interactive.'))
        }
        $given = Read-RedactConfigAnswer
    }

    $config = [ordered]@{ _comment = 'Local values, git-ignored. Same keys as redact.config.sample.json; keys not listed here come from the sample.' }
    foreach ($name in $script:ConfigParameter.Keys) {
        if (-not $given.ContainsKey($name)) { continue }
        $key = $script:ConfigParameter[$name]
        $value = $given[$name]
        if ($script:ConfigShape.ContainsKey($key)) { $value = @($value | ForEach-Object { ConvertTo-RedactConfigEntry -Value $_ -Key $key }) }
        if ($config.Contains($key)) { $value = @($config[$key]) + @($value) }
        $config[$key] = $value
    }

    $checked = Get-RedactConfigDefault
    Merge-RedactConfig -Base $checked -Layer ([hashtable]$config)
    $problem = Get-RedactConfigProblem -Config $checked
    if ($problem) {
        $PSCmdlet.ThrowTerminatingError((Get-RedactErrorRecord -ErrorId 'RedactOutput.ConfigInvalid' -Category InvalidData -Message "Config rejected: $problem"))
    }

    if (-not $PSCmdlet.ShouldProcess($target, 'Write local config')) { return }
    [void][System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($target))
    [System.IO.File]::WriteAllText($target, ($config | ConvertTo-Json -Depth 10) + "`n", [System.Text.UTF8Encoding]::new($false))
    if ((Test-RedactGitIgnored -Path $target) -eq $false) {
        Write-Warning 'The config file is inside a git repository but not covered by .gitignore. Add it before committing: it holds your environment identifiers.'
    }
    Get-Item -LiteralPath $target
}
