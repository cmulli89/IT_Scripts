BeforeAll {
    . $PSScriptRoot/TestHelpers.ps1

    function Initialize-TestMapDir {
        $dir = Join-Path $TestDrive "map-$([guid]::NewGuid().ToString('N'))"
        New-Item -ItemType Directory -Path $dir | Out-Null
        $dir
    }

    # Runs the pipeline path with a map; the text never leaves the test.
    function Invoke-TestMapRun {
        param([Parameter(Mandatory)][string]$Text, [Parameter(Mandatory)][string]$MapPath, [hashtable]$Extra = @{})
        $Text | Protect-Output -MapPath $MapPath -NoAudit -WarningAction SilentlyContinue @Extra
    }

    function Read-TestMap {
        param([Parameter(Mandatory)][string]$Path)
        Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable
    }

    # The serialized lines of the entries block, one string per line.
    function Get-TestEntryLine {
        param([Parameter(Mandatory)][string]$Path)
        $lines = @(Get-Content -LiteralPath $Path)
        $start = [array]::IndexOf($lines, '  "entries": [') + 1
        $end = [array]::LastIndexOf($lines, '  ]') - 1
        @($lines[$start..$end] | ForEach-Object { $_.TrimEnd(',') })
    }

    $script:Jwt = Get-TestJwt
    $script:HostA = 'WS-1234'
    $script:HostB = 'WS-5678'
}

AfterAll { Remove-Item -Path Env:REDACTOUTPUT_CONFIG_DIR -ErrorAction SilentlyContinue }

Describe 'Map file' -Tag 'Unit' {
    It 'has the version 1 shape and holds no secret and no secret token' {
        $map = Join-Path (Initialize-TestMapDir) 'run.redactmap.json'
        $text = "host $script:HostA ip 192.0.2.5`npassword=FakeValue01`nbearer $script:Jwt`n"
        $out = Invoke-TestMapRun -Text $text -MapPath $map
        $out.Contains('[secret:') | Should -BeTrue -Because 'the run must have redacted secrets'
        $raw = Get-Content -LiteralPath $map -Raw
        $raw.Contains('[secret:') | Should -BeFalse
        $raw.Contains('FakeValue01') | Should -BeFalse
        $raw.Contains($script:Jwt.Split('.')[2]) | Should -BeFalse
        $data = Read-TestMap -Path $map
        $data.version | Should -Be 1
        $data.counters['host'] | Should -Be 1
        $data.counters['ip-pub'] | Should -Be 1
        @($data.entries).Count | Should -Be 2
        @($data.entries | Where-Object { $_.token -eq '[host-01]' -and $_.type -eq 'host' -and $_.original -eq $script:HostA }).Count | Should -Be 1
        @($data.entries | Where-Object { $_.type -eq 'secret' }).Count | Should -Be 0
    }

    It 'reuses a map: numbering continues, known originals keep their tokens, existing entries stay byte-identical' {
        $map = Join-Path (Initialize-TestMapDir) 'reuse.redactmap.json'
        $first = Invoke-TestMapRun -Text "a $script:HostA" -MapPath $map
        $first | Should -Be 'a [host-01]'
        $before = Get-TestEntryLine -Path $map
        $second = Invoke-TestMapRun -Text "b $script:HostB and $($script:HostA.ToLowerInvariant())" -MapPath $map
        $second | Should -Be 'b [host-02] and [host-01]'
        $after = Get-TestEntryLine -Path $map
        $after.Count | Should -BeGreaterThan $before.Count
        ($after[0..($before.Count - 1)] -join "`n") | Should -BeExactly ($before -join "`n")
        (Read-TestMap -Path $map).counters['host'] | Should -Be 2
    }

    It 'continues numbering from the entries even when the counters in the file are wrong' {
        $map = Join-Path (Initialize-TestMapDir) 'counters.redactmap.json'
        Invoke-TestMapRun -Text $script:HostA -MapPath $map | Out-Null
        $json = (Get-Content -LiteralPath $map -Raw) -replace '"host": 1', '"host": 0'
        Set-Content -LiteralPath $map -Value $json
        Invoke-TestMapRun -Text $script:HostB -MapPath $map | Should -Be '[host-02]'
    }

    It 'keeps aliases (a NetBIOS name shares its domain token) across runs' {
        $map = Join-Path (Initialize-TestMapDir) 'alias.redactmap.json'
        Invoke-TestMapRun -Text 'jdoe@ad.contoso.example' -MapPath $map | Out-Null
        Invoke-TestMapRun -Text 'CONTOSO\jdoe' -MapPath $map | Should -Be '[domain-01]\[user-01]'
    }

    It 'writes no map with -WhatIf and none when -Strict finds a residual' {
        $dir = Initialize-TestMapDir
        $map = Join-Path $dir 'none.redactmap.json'
        Invoke-TestMapRun -Text $script:HostA -MapPath $map -Extra @{ WhatIf = $true } 6>$null | Out-Null
        Test-Path -LiteralPath $map | Should -BeFalse
        $ErrorActionPreference = 'Continue'
        $residual = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Fixtures/residual.txt') -Raw
        $caught = $false
        try { Invoke-TestMapRun -Text "$script:HostA`n$residual" -MapPath $map -Extra @{ Strict = $true } 2>$null | Out-Null } catch { $caught = $true }
        $caught | Should -BeTrue
        Test-Path -LiteralPath $map | Should -BeFalse
        @(Get-ChildItem -LiteralPath $dir -Force).Count | Should -Be 0
    }

    It 'writes no map in file mode with -WhatIf, and writes one after a real run' {
        $dir = Initialize-TestMapDir
        $in = Join-Path $dir 'in.txt'
        Set-Content -LiteralPath $in -Value "x $script:HostA"
        $map = Join-Path $dir 'file.redactmap.json'
        Protect-Output -LiteralPath $in -MapPath $map -NoAudit -WhatIf 6>$null | Out-Null
        Test-Path -LiteralPath $map | Should -BeFalse
        Protect-Output -LiteralPath $in -MapPath $map -NoAudit
        (Read-TestMap -Path $map).entries[0].token | Should -Be '[host-01]'
    }

    It 'writes no map when the run fails before any output' {
        $dir = Initialize-TestMapDir
        $map = Join-Path $dir 'fail.redactmap.json'
        { Protect-Output -LiteralPath (Join-Path $dir 'missing.txt') -MapPath $map -NoAudit } | Should -Throw
        Test-Path -LiteralPath $map | Should -BeFalse
    }

    It 'creates the folder, leaves no temp file, and puts a bare file name in the default maps folder' {
        $map = Join-Path (Initialize-TestMapDir) 'deep/er/m.redactmap.json'
        Invoke-TestMapRun -Text $script:HostA -MapPath $map | Out-Null
        @(Get-ChildItem -LiteralPath (Split-Path $map) -Force).Name | Should -Be 'm.redactmap.json'
        InModuleScope RedactOutput {
            $expected = Join-Path (Join-Path (Get-RedactDataFolder) 'maps') 's.redactmap.json'
            Resolve-RedactMapPath -MapPath 's.redactmap.json' | Should -Be $expected
        }
    }

    It 'creates the map with mode 600, also when it replaces an existing map' -Skip:$IsWindows {
        $map = Join-Path (Initialize-TestMapDir) 'mode.redactmap.json'
        Invoke-TestMapRun -Text $script:HostA -MapPath $map | Out-Null
        ((Get-Item -LiteralPath $map).UnixFileMode -eq 'UserRead, UserWrite') | Should -BeTrue
        [System.IO.File]::SetUnixFileMode($map, 'UserRead, UserWrite, GroupRead, OtherRead')
        Invoke-TestMapRun -Text $script:HostB -MapPath $map | Out-Null
        ((Get-Item -LiteralPath $map).UnixFileMode -eq 'UserRead, UserWrite') | Should -BeTrue
    }

    It 'has inheritance disabled and exactly one ACE for the current user' -Tag 'Windows' -Skip:(-not $IsWindows) {
        $map = Join-Path (Initialize-TestMapDir) 'acl.redactmap.json'
        Invoke-TestMapRun -Text $script:HostA -MapPath $map | Out-Null
        $acl = Get-Acl -LiteralPath $map
        $acl.AreAccessRulesProtected | Should -BeTrue
        $rules = @($acl.Access)
        $rules.Count | Should -Be 1
        $rules[0].IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) | Should -Be ([System.Security.Principal.WindowsIdentity]::GetCurrent().User)
        $rules[0].FileSystemRights.ToString() | Should -Be 'FullControl'
    }

    It 'never lets a secret into a map and rejects a map file that holds one' {
        InModuleScope RedactOutput {
            $s = New-RedactSession -Config (Get-RedactConfig)
            { Get-RedactToken -Session $s -Type secret -Original 'x' } | Should -Throw '*never stored in a map*'
            { Add-RedactAlias -Session $s -Type domain -Original 'x' -Token '[secret:jwt]' } | Should -Throw '*never stored in a map*'
            $s.Entries.Count | Should -Be 0
            $path = Join-Path $TestDrive 'bad.redactmap.json'
            Set-Content -LiteralPath $path -Value '{"version":1,"counters":{},"entries":[{"token":"[secret:jwt]","type":"jwt","original":"FakeValue01"}]}'
            { Read-RedactMap -Path $path } | Should -Throw '*never stored in a map*'
        }
    }

    It 'gives one generic error for an invalid map and never quotes the file' {
        InModuleScope RedactOutput {
            $path = Join-Path $TestDrive 'junk.redactmap.json'
            Set-Content -LiteralPath $path -Value '{"version":2,"entries":"FakeValue01"}'
            $caught = try { Read-RedactMap -Path $path } catch { $_ }
            $caught.Exception.Message | Should -Be 'The map file is not a valid RedactOutput map (version 1).'
            { Read-RedactMap -Path (Join-Path $TestDrive 'absent.json') } | Should -Throw '*-MapPath was not found*'
        }
    }

    It 'warns without naming the path when the map is under a synced folder' {
        $dir = Initialize-TestMapDir
        $root = Join-Path $dir 'SyncRoot'
        $folders = @{ $root = 'OneDrive' }
        $folders[(Join-Path $dir 'Dropbox')] = $null
        $folders[(Join-Path $dir 'Google Drive')] = $null
        $folders[(Join-Path $dir 'iCloudDrive')] = $null
        $saved = $env:OneDrive
        try {
            $env:OneDrive = $root
            foreach ($folder in $folders.Keys) {
                $map = Join-Path $folder 'w.redactmap.json'
                $warning = $null
                $script:HostA | Protect-Output -MapPath $map -NoAudit -WarningVariable warning -WarningAction SilentlyContinue | Out-Null
                @($warning).Count | Should -Be 1 -Because "$folder should warn"
                $warning[0].Message.Contains($dir) | Should -BeFalse
                $warning[0].Message | Should -Match 'OneDrive, Dropbox, Google Drive or iCloud'
            }
        }
        finally { $env:OneDrive = $saved }
    }

    It 'does not warn for an ordinary folder' {
        $warning = $null
        $script:HostA | Protect-Output -MapPath (Join-Path (Initialize-TestMapDir) 'ok.redactmap.json') -NoAudit -WarningVariable warning | Out-Null
        @($warning).Count | Should -Be 0
    }
}

Describe 'Restore-RedactedText' -Tag 'Unit' {
    It 'round-trips identifier-only text exactly' {
        $map = Join-Path (Initialize-TestMapDir) 'rt.redactmap.json'
        $text = "host $script:HostA at 192.0.2.5 and 10.1.2.3/24`nmail jdoe@contoso.example, id 11111111-2222-3333-4444-555555555555`nsvc-example on \\fileserver\projects`n"
        $redacted = Invoke-TestMapRun -Text $text -MapPath $map
        $redacted.Contains('jdoe') | Should -BeFalse
        $restored = Restore-RedactedText -Text $redacted -MapPath $map
        ($restored -ceq $text) | Should -BeTrue
    }

    It 'leaves secret tokens as they are and reports their count' {
        $map = Join-Path (Initialize-TestMapDir) 'sec.redactmap.json'
        $redacted = Invoke-TestMapRun -Text "host $script:HostA`npassword=FakeValue01`nbearer $script:Jwt" -MapPath $map
        $all = @(Restore-RedactedText -Text $redacted -MapPath $map -Verbose 4>&1)
        $verbose = @($all.Where({ $_ -is [System.Management.Automation.VerboseRecord] }))
        $restored = @($all.Where({ $_ -is [string] }))[0]
        $restored.Contains($script:HostA) | Should -BeTrue
        $restored.Contains('[secret:') | Should -BeTrue
        $restored.Contains('FakeValue01') | Should -BeFalse
        $verbose.Message | Should -Be '2 secret token(s) left as is.'
    }

    It 'replaces longest tokens first in a single pass, without rescanning restored text' {
        $path = Join-Path (Initialize-TestMapDir) 'long.redactmap.json'
        InModuleScope RedactOutput -Parameters @{ Path = $path } {
            $s = New-RedactSession -Config (Get-RedactConfig)
            foreach ($i in 1..101) { $null = Get-RedactToken -Session $s -Type host -Original "ws-$i" }
            $null = Get-RedactToken -Session $s -Type term-x -Original '[host-02]'
            Save-RedactMap -Session $s -Path $Path
        }
        Restore-RedactedText -Text '[host-01] [host-10] [host-100] [host-101] [term-x-01] [host-102]' -MapPath $path | Should -BeExactly 'ws-1 ws-10 ws-100 ws-101 [host-02] [host-102]'
    }

    It 'restores from a file with -OutputPath, keeping encoding and BOM, and honors -WhatIf and -Force' {
        $dir = Initialize-TestMapDir
        $map = Join-Path $dir 'f.redactmap.json'
        $redacted = Invoke-TestMapRun -Text "host $script:HostA" -MapPath $map
        $in = Join-Path $dir 'reply.txt'
        [System.IO.File]::WriteAllText($in, "r $redacted`r`n", [System.Text.UTF8Encoding]::new($true))
        $out = Join-Path $dir 'reply.restored.txt'
        Restore-RedactedText -Path $in -MapPath $map -OutputPath $out -WhatIf 6>$null
        Test-Path -LiteralPath $out | Should -BeFalse
        Restore-RedactedText -Path $in -MapPath $map -OutputPath $out
        $bytes = [System.IO.File]::ReadAllBytes($out)
        $bytes[0..2] -join ',' | Should -Be '239,187,191'
        [System.IO.File]::ReadAllText($out) | Should -BeExactly "r host $script:HostA`r`n"
        { Restore-RedactedText -Path $in -MapPath $map -OutputPath $out } | Should -Throw '*Use -Force*'
        { Restore-RedactedText -Path $in -MapPath $map -OutputPath $in -Force } | Should -Throw '*is the input file*'
        Restore-RedactedText -Path $in -MapPath $map -OutputPath $out -Force
        Test-Path -LiteralPath $out | Should -BeTrue
    }

    It 'writes text input to -OutputPath and returns nothing' {
        $dir = Initialize-TestMapDir
        $map = Join-Path $dir 't.redactmap.json'
        $redacted = Invoke-TestMapRun -Text $script:HostA -MapPath $map
        $out = Join-Path $dir 'sub/t.txt'
        $result = Restore-RedactedText -Text $redacted -MapPath $map -OutputPath $out
        $result | Should -BeNullOrEmpty
        [System.IO.File]::ReadAllText($out) | Should -BeExactly $script:HostA
    }

    It 'fails on a missing map without writing anything' {
        $out = Join-Path (Initialize-TestMapDir) 'o.txt'
        { Restore-RedactedText -Text '[host-01]' -MapPath (Join-Path $TestDrive 'absent.redactmap.json') -OutputPath $out } | Should -Throw '*-MapPath was not found*'
        Test-Path -LiteralPath $out | Should -BeFalse
    }
}

Describe 'Get-RedactionMap' -Tag 'Unit' {
    BeforeAll {
        $script:ListMap = Join-Path (Initialize-TestMapDir) 'list.redactmap.json'
        Invoke-TestMapRun -Text "$script:HostA $script:HostB 192.0.2.5`nCONTOSO\jdoe ad.contoso.example" -MapPath $script:ListMap | Out-Null
    }

    It 'lists token, type and count ordered by type, and never the originals by default' {
        $rows = @(Get-RedactionMap -MapPath $script:ListMap)
        ($rows | Get-Member -MemberType NoteProperty).Name -join ',' | Should -Be 'Count,Token,Type'
        $rows.Count | Should -BeGreaterThan 3
        @($rows | Where-Object { $_.Token -eq '[host-02]' -and $_.Type -eq 'host' -and $_.Count -eq 1 }).Count | Should -Be 1
        @($rows | Where-Object { $_.Type -eq 'domain' })[0].Count | Should -Be 2
        ($rows.Type -join ',') | Should -Be (($rows.Type | Sort-Object) -join ',')
        $dump = ($rows | ConvertTo-Json -Depth 3) + ($rows | Out-String)
        foreach ($original in $script:HostA, $script:HostB, '192.0.2.5', 'jdoe', 'contoso') { $dump.Contains($original) | Should -BeFalse -Because 'originals stay hidden' }
    }

    It 'adds the originals with -ShowOriginal' {
        $rows = @(Get-RedactionMap -MapPath $script:ListMap -ShowOriginal)
        @($rows | Where-Object { $_.Token -eq '[host-01]' }).Original | Should -Be $script:HostA
        (@($rows | Where-Object { $_.Type -eq 'domain' }).Original -split ', ').Count | Should -Be 2
    }
}
