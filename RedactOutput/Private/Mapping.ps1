# Token allocation (stable [type-NN] tokens per session) and the map file that persists Session.Entries.
# Secrets never come through here and are never stored in a map.

function Assert-RedactNoSecret {
    # The one place that enforces "secrets are never in a map": no secret type and no [secret:...] token.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Type,
        [string]$Token
    )

    if ($Type -eq 'secret' -or $Token.StartsWith('[secret:', [StringComparison]::Ordinal)) {
        throw (Get-RedactErrorRecord -ErrorId 'RedactOutput.SecretInMap' -Message 'Secrets are never stored in a map (type secret).')
    }
}

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
    Assert-RedactNoSecret -Type $Type

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
    Assert-RedactNoSecret -Type $Type -Token $Token
    $Session.Maps[$mapKey] = $Token
    $Session.Entries.Add([pscustomobject]@{ Token = $Token; Type = $Type; Original = $Original })
}

#region Map file

function Test-RedactSyncedPath {
    # True when the path is under a OneDrive root from the environment or has a OneDrive, Dropbox, Google Drive or iCloud segment.
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$Path)

    foreach ($root in $env:OneDrive, $env:OneDriveCommercial, $env:OneDriveConsumer) {
        if ($root -and $Path.StartsWith($root.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    $segment = Get-RedactRegex -Pattern '^(?:OneDrive|Dropbox|Google ?Drive|iCloud|com~apple~CloudDocs)' -IgnoreCase
    @($Path.Split([char[]]'\/')).Where({ $segment.IsMatch($_) }, 'First').Count -gt 0
}

function Resolve-RedactMapPath {
    <#
    .SYNOPSIS
        Full path of a map file; a bare file name goes to the default map folder. Warns about synced folders.
    .DESCRIPTION
        The default folder is $env:LOCALAPPDATA\RedactOutput\maps on Windows and ~/.local/share/RedactOutput/maps
        elsewhere. The warning never names the path.
    .PARAMETER MapPath
        Map file path or bare file name.
    .EXAMPLE
        Resolve-RedactMapPath -MapPath 'session1.redactmap.json'
    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$MapPath)

    $target = if ([System.IO.Path]::GetFileName($MapPath) -ceq $MapPath) { Join-Path (Join-Path (Get-RedactDataFolder) 'maps') $MapPath } else { $MapPath }
    $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($target)
    if (Test-RedactSyncedPath -Path $full) {
        Write-Warning 'The map path looks like a OneDrive, Dropbox, Google Drive or iCloud folder. A map holds original values; keep it in a local, unsynced folder.'
    }
    $full
}

function Read-RedactMap {
    <#
    .SYNOPSIS
        Reads and validates a version 1 map file.
    .DESCRIPTION
        Returns Counters (type -> n) and Entries (Token, Type, Original). Any parse or shape problem gives one
        generic error that never quotes the file; an entry that is a secret is rejected.
    .PARAMETER Path
        Full path of the map file.
    .EXAMPLE
        (Read-RedactMap -Path $path).Entries
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw (Get-RedactErrorRecord -ErrorId 'RedactOutput.MapNotFound' -Message 'The file given by -MapPath was not found.')
    }
    $counters = @{}
    $entries = [System.Collections.Generic.List[object]]::new()
    try {
        $doc = [System.Text.Json.JsonDocument]::Parse([System.IO.File]::ReadAllText($Path))
        try {
            $root = $doc.RootElement
            $version = $root.GetProperty('version').GetInt32()
            foreach ($c in $root.GetProperty('counters').EnumerateObject()) { $counters[$c.Name] = $c.Value.GetInt32() }
            foreach ($e in $root.GetProperty('entries').EnumerateArray()) {
                $entries.Add([pscustomobject]@{ Token = $e.GetProperty('token').GetString(); Type = $e.GetProperty('type').GetString(); Original = $e.GetProperty('original').GetString() })
            }
        }
        finally { $doc.Dispose() }
    }
    catch { $version = 0 }
    if ($version -ne 1 -or $entries.Where({ -not $_.Token -or -not $_.Type -or $null -eq $_.Original }, 'First').Count -gt 0) {
        throw (Get-RedactErrorRecord -ErrorId 'RedactOutput.MapInvalid' -Message 'The map file is not a valid RedactOutput map (version 1).')
    }
    foreach ($e in $entries) { Assert-RedactNoSecret -Type $e.Type -Token $e.Token }
    [pscustomobject]@{ Counters = $counters; Entries = $entries }
}

function Import-RedactMap {
    <#
    .SYNOPSIS
        Loads a saved map into the session so numbering continues and known originals keep their tokens.
    .PARAMETER Session
        Session from New-RedactSession.
    .PARAMETER Path
        Full path of an existing map file.
    .EXAMPLE
        Import-RedactMap -Session $session -Path $path
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Fills an in-memory session only.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Session,
        [Parameter(Mandatory)][string]$Path
    )

    $map = Read-RedactMap -Path $Path
    $counters = $map.Counters
    $numbered = Get-RedactRegex -Pattern '^\[(.+)-([0-9]+)\]$'
    foreach ($e in $map.Entries) {
        if (-not $Session.Maps.TryAdd("$($e.Type)|$(Get-RedactKey -Type $e.Type -Original $e.Original)", $e.Token)) { continue }
        $Session.Entries.Add($e)
        # The counter is the highest number seen, whatever the file's counters say, so a new token can never collide.
        $m = $numbered.Match($e.Token)
        if ($m.Success -and [int]$m.Groups[2].Value -gt $counters[$m.Groups[1].Value]) { $counters[$m.Groups[1].Value] = [int]$m.Groups[2].Value }
    }
    foreach ($type in $counters.Keys) { $Session.Counters[$type] = $counters[$type] }
}

function New-RedactPrivateFile {
    # Creates an empty file that only the current user can access, before any content is written to it.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Callers confirm; this creates the private temp file.')]
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$LiteralPath)

    if ($IsWindows) {
        [System.IO.File]::Create($LiteralPath).Dispose()
        $acl = [System.Security.AccessControl.FileSecurity]::new()
        $acl.SetAccessRuleProtection($true, $false)
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.WindowsIdentity]::GetCurrent().User, 'FullControl', 'Allow'))
        Set-Acl -LiteralPath $LiteralPath -AclObject $acl
        return
    }
    if (-not [System.IO.FileStreamOptions].GetProperty('UnixCreateMode')) {
        throw (Get-RedactErrorRecord -ErrorId 'RedactOutput.NeedsNewerPowerShell' -Message 'Writing a map file on Linux or macOS needs PowerShell 7.3 or later (owner-only file mode).')
    }
    [System.IO.FileStream]::new($LiteralPath, [System.IO.FileStreamOptions]@{ Mode = 'CreateNew'; Access = 'Write'; UnixCreateMode = 'UserRead, UserWrite' }).Dispose()
}

function Save-RedactMap {
    <#
    .SYNOPSIS
        Writes the session's entries and counters as a version 1 map file, atomically and owner-only.
    .DESCRIPTION
        A temp file in the same folder is created with the owner-only ACL (Windows) or mode 600 (Linux/macOS)
        before any content is written, then moved over the target. Loaded entries come first, unchanged, so a
        reused map only grows. Callers confirm (ShouldProcess) and call this only after a successful run.
    .PARAMETER Session
        Session whose Entries and Counters are saved.
    .PARAMETER Path
        Full path of the map file.
    .EXAMPLE
        Save-RedactMap -Session $session -Path $path
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'The caller confirms with ShouldProcess before calling.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Session,
        [Parameter(Mandatory)][string]$Path
    )

    foreach ($e in $Session.Entries) { Assert-RedactNoSecret -Type $e.Type -Token $e.Token }
    $counters = [ordered]@{}
    foreach ($type in ($Session.Counters.Keys | Sort-Object)) { $counters[$type] = $Session.Counters[$type] }
    $json = [ordered]@{
        version  = 1
        counters = $counters
        entries  = @($Session.Entries | ForEach-Object { [ordered]@{ token = $_.Token; type = $_.Type; original = $_.Original } })
    } | ConvertTo-Json -Depth 5

    $folder = [System.IO.Path]::GetDirectoryName($Path)
    [void][System.IO.Directory]::CreateDirectory($folder)
    $temp = [System.IO.Path]::Combine($folder, ".redactmap-$([guid]::NewGuid().ToString('N')).tmp")
    try {
        New-RedactPrivateFile -LiteralPath $temp
        [System.IO.File]::WriteAllText($temp, $json + "`n", [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::Move($temp, $Path, $true)
    }
    finally { if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force } }
}

#endregion
