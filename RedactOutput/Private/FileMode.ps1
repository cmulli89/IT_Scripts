# File mode for Protect-Output: the input plan (files and folders), output naming and safety, and the
# read-redact-write cycle for one file.

#region Plan

function Get-RedactFolderFile {
    # Files under a directory, hidden ones included (.env). Reparse points (links), earlier *.redacted.* outputs and
    # VCS folders (.git, .svn, .hg) are skipped.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Directory,
        [switch]$Recurse
    )

    foreach ($item in (Get-ChildItem -LiteralPath $Directory -Force)) {
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { continue }
        if ($item.PSIsContainer) { if ($Recurse -and $item.Name -notin '.git', '.svn', '.hg') { Get-RedactFolderFile -Directory $item.FullName -Recurse } }
        elseif ($item.Name -notlike '*.redacted.*') { $item }
    }
}

function Get-RedactRealPath {
    # Full path with a symbolic link resolved, so a link to the input cannot be used as the output.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Path)

    $full = [System.IO.Path]::GetFullPath($Path)
    $target = if (Test-Path -LiteralPath $full -PathType Leaf) { [System.IO.FileInfo]::new($full).ResolveLinkTarget($true) }
    if ($target) { $target.FullName } else { $full }
}

function Test-RedactSamePath {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$Left,
        [Parameter(Mandatory)][string]$Right
    )

    $comparison = if ($IsWindows) { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }
    [string]::Equals((Get-RedactRealPath -Path $Left), (Get-RedactRealPath -Path $Right), $comparison)
}

function Resolve-RedactOutputPath {
    # <base>.redacted<ext> next to the input, or under -OutDir (keeping the folder structure); -OutFile names it outright.
    # Refuses an output that resolves to the input.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][object]$Entry,
        [string]$OutDir,
        [string]$OutFile
    )

    $in = $Entry.Input
    $provider = $ExecutionContext.SessionState.Path
    $out = if ($OutFile) { $provider.GetUnresolvedProviderPathFromPSPath($OutFile) }
    else {
        $name = '{0}.redacted{1}' -f [System.IO.Path]::GetFileNameWithoutExtension($in), [System.IO.Path]::GetExtension($in)
        $folder = if ($OutDir) { [System.IO.Path]::Combine($provider.GetUnresolvedProviderPathFromPSPath($OutDir), [System.IO.Path]::GetDirectoryName($Entry.Relative)) } else { [System.IO.Path]::GetDirectoryName($in) }
        [System.IO.Path]::Combine($folder, $name)
    }
    $out = $provider.GetUnresolvedProviderPathFromPSPath($out)
    if (Test-RedactSamePath -Left $out -Right $in) {
        throw (Get-RedactErrorRecord -ErrorId 'RedactOutput.OutputIsInput' -Message "The output path for '$($Entry.Relative)' is the input file; the input is never modified.")
    }
    $out
}

function Get-RedactFilePlan {
    # One { Input; Relative; Folder; OutPath } per file to process; refuses an output that is an input before any file is written.
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[object]])]
    param(
        [string[]]$Path,
        [string[]]$LiteralPath,
        [switch]$Recurse,
        [string[]]$Include = '*',
        [string]$OutDir,
        [string]$OutFile
    )

    $roots = if ($LiteralPath) { Resolve-Path -LiteralPath $LiteralPath -ErrorAction Stop } else { Resolve-Path -Path $Path -ErrorAction Stop }
    $plan = [System.Collections.Generic.List[object]]::new()
    foreach ($root in $roots) {
        $item = Get-Item -LiteralPath $root.ProviderPath -Force
        if (-not $item.PSIsContainer) {
            $plan.Add([pscustomobject]@{ Input = $item.FullName; Relative = $item.Name; Folder = $false; OutPath = $null })
            continue
        }
        foreach ($file in (Get-RedactFolderFile -Directory $item.FullName -Recurse:$Recurse)) {
            $name = $file.Name
            if (@($Include).Where({ $name -like $_ }, 'First').Count -eq 0) { continue }
            $plan.Add([pscustomobject]@{ Input = $file.FullName; Relative = [System.IO.Path]::GetRelativePath($item.FullName, $file.FullName); Folder = $true; OutPath = $null })
        }
    }
    if ($OutFile -and $plan.Count -ne 1) { throw (Get-RedactErrorRecord -ErrorId 'RedactOutput.OutFileNeedsOneInput' -Message '-OutFile needs exactly one input file.') }
    foreach ($entry in $plan) { $entry.OutPath = Resolve-RedactOutputPath -Entry $entry -OutDir $OutDir -OutFile $OutFile }
    , $plan
}

#endregion

#region One file

function Invoke-RedactFile {
    <#
    .SYNOPSIS
        Reads one planned file, redacts it, and writes <base>.redacted<ext>.
    .DESCRIPTION
        Text-mode files above LargeFileThresholdMB stream in chunks; everything else is redacted in memory.
        The engine always runs first, so -Strict throws before the output exists. -WhatIf (inherited from the
        caller) runs the engine, reports counts and writes nothing. Returns a RedactOutput.Result, or nothing for
        a skipped binary file.
    .PARAMETER Entry
        Plan entry from Get-RedactFilePlan.
    .PARAMETER Session
        Session shared by the run; its counts are reset for each file.
    .PARAMETER SkipBinary
        Warn and skip a binary file instead of failing.
    .PARAMETER Encoding
        Forces the encoding for reading and writing.
    .PARAMETER Head
        Keep only the first N lines of line-oriented input.
    .PARAMETER Tail
        Keep only the last N lines of line-oriented input.
    .PARAMETER LargeFileThresholdMB
        Text-mode files larger than this stream chunk by chunk.
    .PARAMETER Strict
        Throw if the residual scan finds anything.
    .PARAMETER NoAudit
        Do not append an audit row.
    .PARAMETER AuditPath
        Audit CSV to append to.
    .EXAMPLE
        Invoke-RedactFile -Entry $entry -Session $session
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][object]$Entry,
        [Parameter(Mandatory)][object]$Session,
        [switch]$SkipBinary,
        [string]$Encoding,
        [int]$Head,
        [int]$Tail,
        [int]$LargeFileThresholdMB = 50,
        [switch]$Strict,
        [switch]$NoAudit,
        [string]$AuditPath
    )

    if (-not $Entry.OutPath) { throw (Get-RedactErrorRecord -ErrorId 'RedactOutput.NoOutputPath' -Message "No output path was planned for '$($Entry.Relative)'.") }
    $path = $Entry.Input
    $type = Get-RedactFileType -Path $path
    $stream = $type -in 'text', 'script' -and -not ($Head -or $Tail) -and ([System.IO.FileInfo]::new($path).Length -gt $LargeFileThresholdMB * 1MB)
    $file = if ($type -eq 'binary') { [pscustomobject]@{ IsBinary = $true } }
    elseif ($stream) { Get-RedactEncoding -LiteralPath $path -Encoding $Encoding }
    else { Read-RedactFile -LiteralPath $path -Encoding $Encoding }
    if ($file.IsBinary) {
        if (-not $SkipBinary) { throw (Get-RedactBinaryError -Path $path) }
        Write-Warning "Skipped binary file: $($Entry.Relative)"
        return
    }

    Reset-RedactCount -Session $Session
    $write = $PSCmdlet.ShouldProcess($Entry.OutPath, 'Write redacted file')
    $outFolder = [System.IO.Path]::GetDirectoryName($Entry.OutPath)
    $temp = if ($stream -and $write) { [System.IO.Path]::Combine($outFolder, ".redact-$([guid]::NewGuid().ToString('N')).tmp") }
    try {
        if ($stream) {
            if ($temp) { [void][System.IO.Directory]::CreateDirectory($outFolder) }
            Invoke-RedactStream -InputPath $path -File $file -Session $Session -OutputPath $temp
        }
        else {
            if ($type -eq 'text') { $type = Get-RedactFileType -Path $path -Text $file.Text }
            $text = Select-RedactLine -Text $file.Text -Type $type -Head $Head -Tail $Tail
            $redacted = Invoke-RedactContent -Text $text -Type $type -Session $Session
            [void](Find-RedactResidual -Text $redacted -Session $Session)
        }
        Confirm-RedactFinding -Session $Session -Strict:$Strict -Source $Entry.Relative
        if ($write) {
            [void][System.IO.Directory]::CreateDirectory($outFolder)
            if ($stream) { [System.IO.File]::Move($temp, $Entry.OutPath, $true) }
            else { Write-RedactFile -LiteralPath $Entry.OutPath -Text $redacted -Encoding $file.Encoding -HasBom:$file.HasBom }
            if (-not $NoAudit) {
                $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
                Write-RedactAudit -Session $Session -InputSource path -InputSha256 $hash -OutputPath $Entry.OutPath -Strict:$Strict -AuditPath $AuditPath
            }
        }
        else { Write-RedactSummary -Session $Session }
    }
    finally { if ($temp -and (Test-Path -LiteralPath $temp)) { Remove-Item -LiteralPath $temp -Force } }

    $counts = [ordered]@{}
    foreach ($label in $Session.Counts.Keys) { if ($Session.Counts[$label] -gt 0) { $counts[$label] = $Session.Counts[$label] } }
    [pscustomobject]@{
        PSTypeName       = 'RedactOutput.Result'
        Path             = $path
        OutPath          = $Entry.OutPath
        DetectedType     = $type
        Encoding         = $file.Encoding.WebName + $(if ($file.HasBom) { ' (BOM)' })
        Counts           = $counts
        ResidualWarnings = $Session.Findings.Count
    }
}

#endregion
