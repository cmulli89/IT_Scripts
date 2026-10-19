BeforeDiscovery {
    $script:HasGit = [bool](Get-Command -Name git -ErrorAction Ignore)
}

BeforeAll {
    . $PSScriptRoot/TestHelpers.ps1
    $script:Pwsh = (Get-Process -Id $PID).Path
    $script:Entropic = 'k9Zq3XvB7mT2wLp8Rj5HcN1yD6sGa4UfE0'

    function Read-TestJsonFile {
        param([Parameter(Mandatory)][string]$Path)
        Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable
    }
}

AfterAll { Remove-Item -Path Env:REDACTOUTPUT_CONFIG_DIR -ErrorAction SilentlyContinue }

Describe 'Invoke-RedactedCommand' -Tag 'Unit' {
    It 'captures output, errors, warnings, a throw and native stderr, all redacted' {
        $pwsh = $script:Pwsh
        $block = {
            'out WS-1111'
            Write-Error 'err WS-2222'
            Write-Warning 'warn WS-3333'
            & $pwsh -NoProfile -Command "[Console]::Error.WriteLine('native WS-4444')"
            throw 'thrown WS-5555'
        }
        $out = Invoke-RedactedCommand -ScriptBlock $block -NoAudit -WarningAction SilentlyContinue
        foreach ($n in 1111, 2222, 3333, 4444, 5555) { $out.Contains("WS-$n") | Should -BeFalse -Because "WS-$n must be redacted" }
        # An error record also shows the line of the command, so tokens repeat; count the distinct ones.
        @([regex]::Matches($out, '\[host-0[1-5]\]').Value | Sort-Object -Unique).Count | Should -Be 5
        $out.Contains('WARNING: warn') | Should -BeTrue
        $out.Contains('native') | Should -BeTrue
        $out.Contains('thrown') | Should -BeTrue
    }

    It 'keeps a table together and survives a caller with -ErrorAction Stop' {
        $out = Invoke-RedactedCommand -ScriptBlock { [pscustomobject]@{ Name = 'a'; Host = 'WS-1111' }; [pscustomobject]@{ Name = 'b'; Host = 'WS-2222' }; Write-Error 'x' } -NoAudit -ErrorAction Stop
        ([regex]::Matches($out, 'Name')).Count | Should -Be 1
        $out.Contains('WS-1111') | Should -BeFalse
    }

    It 'redacts secrets in command output and reports the command audit source' {
        $audit = Join-Path $TestDrive 'command-audit.csv'
        $out = Invoke-RedactedCommand -ScriptBlock { 'password=FakeValue01' } -AuditPath $audit
        $out.Contains('FakeValue01') | Should -BeFalse
        $out.Contains('[secret:') | Should -BeTrue
        (Import-Csv -LiteralPath $audit).input_source | Should -Be 'command'
    }

    It '-OutFile writes the redacted text, returns nothing and needs -Force to overwrite' {
        $file = Join-Path $TestDrive 'command-out.txt'
        $result = Invoke-RedactedCommand -ScriptBlock { 'host WS-1111' } -OutFile $file -NoAudit
        $result | Should -BeNullOrEmpty
        (Get-Content -LiteralPath $file -Raw).Trim() | Should -Be 'host [host-01]'
        $ErrorActionPreference = 'Continue'
        { Invoke-RedactedCommand -ScriptBlock { 'again' } -OutFile $file -NoAudit } | Should -Throw '*-Force*'
        Invoke-RedactedCommand -ScriptBlock { 'again' } -OutFile $file -Force -NoAudit
        (Get-Content -LiteralPath $file -Raw).Trim() | Should -Be 'again'
    }

    It '-Preview prints only redacted text and writes no map, audit or clipboard' {
        Mock Set-RedactClipboard -ModuleName RedactOutput {}
        $map = Join-Path $TestDrive 'preview.redactmap.json'
        $audit = Join-Path $TestDrive 'preview-audit.csv'
        $records = Invoke-RedactedCommand -ScriptBlock { 'host WS-1111 password=FakeValue01' } -Preview -MapPath $map -AuditPath $audit 6>&1
        @($records | Where-Object { $_ -isnot [System.Management.Automation.InformationRecord] }).Count | Should -Be 0
        $shown = ($records | ForEach-Object { [string]$_ }) -join ''
        $shown.Contains('[host-01]') | Should -BeTrue
        $shown.Contains('WS-1111') | Should -BeFalse
        $shown.Contains('FakeValue01') | Should -BeFalse
        Test-Path -LiteralPath $map | Should -BeFalse
        Test-Path -LiteralPath $audit | Should -BeFalse
        Should -Invoke Set-RedactClipboard -ModuleName RedactOutput -Times 0 -Exactly
    }

    It '-Clipboard writes the redacted text to the clipboard once and returns nothing' {
        Mock Set-RedactClipboard -ModuleName RedactOutput {}
        $result = Invoke-RedactedCommand -ScriptBlock { 'host WS-1111' } -Clipboard -NoAudit
        $result | Should -BeNullOrEmpty
        Should -Invoke Set-RedactClipboard -ModuleName RedactOutput -Times 1 -Exactly -ParameterFilter { $Text -ceq 'host [host-01]' }
    }

    It '-WhatIf writes nothing and -Strict throws before the clipboard or map is touched' {
        Mock Set-RedactClipboard -ModuleName RedactOutput {}
        $map = Join-Path $TestDrive 'cmd-strict.redactmap.json'
        Invoke-RedactedCommand -ScriptBlock { 'host WS-1111' } -Clipboard -MapPath $map -NoAudit -WhatIf 6>$null | Should -BeNullOrEmpty
        $ErrorActionPreference = 'Continue'
        $caught = $false
        try { Invoke-RedactedCommand -ScriptBlock { "host WS-1111 value $script:Entropic" } -Clipboard -MapPath $map -NoAudit -Strict 2>$null 3>$null } catch { $caught = $true }
        $caught | Should -BeTrue
        Test-Path -LiteralPath $map | Should -BeFalse
        Should -Invoke Set-RedactClipboard -ModuleName RedactOutput -Times 0 -Exactly
    }

    It 'reuses the map helpers: a saved map restores the command output' {
        $map = Join-Path $TestDrive 'cmd.redactmap.json'
        $out = Invoke-RedactedCommand -ScriptBlock { 'host WS-1111' } -MapPath $map -NoAudit
        $out | Should -Be 'host [host-01]'
        Restore-RedactedText -Text $out -MapPath $map | Should -Be 'host WS-1111'
    }
}

Describe 'Clipboard' -Tag 'Unit' {
    It 'Protect-Output -Clipboard redacts the clipboard text and writes it back, input_source clipboard' {
        Mock Get-RedactClipboard -ModuleName RedactOutput { 'host WS-1111 password=FakeValue01' }
        Mock Set-RedactClipboard -ModuleName RedactOutput {}
        $audit = Join-Path $TestDrive 'clip-audit.csv'
        $result = Protect-Output -Clipboard -AuditPath $audit
        $result | Should -BeNullOrEmpty
        Should -Invoke Set-RedactClipboard -ModuleName RedactOutput -Times 1 -Exactly -ParameterFilter {
            $Text.Contains('[host-01]') -and $Text.Contains('[secret:') -and -not $Text.Contains('WS-1111') -and -not $Text.Contains('FakeValue01')
        }
        (Import-Csv -LiteralPath $audit).input_source | Should -Be 'clipboard'
    }

    It 'Protect-Output -Clipboard -Preview shows tokens and writes nothing' {
        Mock Get-RedactClipboard -ModuleName RedactOutput { 'host WS-1111' }
        Mock Set-RedactClipboard -ModuleName RedactOutput {}
        $audit = Join-Path $TestDrive 'clip-preview-audit.csv'
        $records = Protect-Output -Clipboard -Preview -AuditPath $audit 6>&1
        (($records | ForEach-Object { [string]$_ }) -join '').Contains('[host-01]') | Should -BeTrue
        Test-Path -LiteralPath $audit | Should -BeFalse
        Should -Invoke Set-RedactClipboard -ModuleName RedactOutput -Times 0 -Exactly
    }

    It 'Protect-Output -Clipboard -Strict throws before the clipboard or map is written' {
        Mock Get-RedactClipboard -ModuleName RedactOutput { "host WS-1111 value $script:Entropic" }
        Mock Set-RedactClipboard -ModuleName RedactOutput {}
        $map = Join-Path $TestDrive 'clip-strict.redactmap.json'
        $ErrorActionPreference = 'Continue'
        $caught = $false
        try { Protect-Output -Clipboard -Strict -MapPath $map -NoAudit 2>$null 3>$null } catch { $caught = $true }
        $caught | Should -BeTrue
        Test-Path -LiteralPath $map | Should -BeFalse
        Should -Invoke Set-RedactClipboard -ModuleName RedactOutput -Times 0 -Exactly
    }

    It 'Protect-Output -Clipboard -WhatIf leaves the clipboard alone' {
        Mock Get-RedactClipboard -ModuleName RedactOutput { 'host WS-1111' }
        Mock Set-RedactClipboard -ModuleName RedactOutput {}
        Protect-Output -Clipboard -NoAudit -WhatIf 6>$null
        Should -Invoke Set-RedactClipboard -ModuleName RedactOutput -Times 0 -Exactly
    }

    It 'fails on <Name> without echoing anything' -ForEach @(
        @{ Name = 'an empty clipboard'; Value = '' }
        @{ Name = 'a clipboard without text'; Value = $null }
        @{ Name = 'a whitespace clipboard'; Value = "  `n " }
    ) {
        Mock Get-RedactClipboardTool -ModuleName RedactOutput { 'builtin' }
        Mock Get-Clipboard -ModuleName RedactOutput { $Value }.GetNewClosure()
        $err = $null
        try { Protect-Output -Clipboard -NoAudit } catch { $err = $_ }
        $err.FullyQualifiedErrorId | Should -Match 'ClipboardEmpty'
    }

    It 'Restore-RedactedText -Clipboard restores the clipboard text in place' {
        $map = Join-Path $TestDrive 'clip-restore.redactmap.json'
        'host WS-1111' | Protect-Output -MapPath $map -NoAudit | Out-Null
        Mock Get-RedactClipboard -ModuleName RedactOutput { 'reply about [host-01]' }
        Mock Set-RedactClipboard -ModuleName RedactOutput {}
        Restore-RedactedText -Clipboard -MapPath $map | Should -BeNullOrEmpty
        Should -Invoke Set-RedactClipboard -ModuleName RedactOutput -Times 1 -Exactly -ParameterFilter { $Text -ceq 'reply about WS-1111' }
    }

    It 'names xclip or wl-clipboard on Linux when no tool exists' -Skip:(-not $IsLinux) {
        Mock Get-Command -ModuleName RedactOutput { $null }
        $err = $null
        try { Protect-Output -Clipboard -NoAudit } catch { $err = $_ }
        $err.Exception.Message | Should -Be 'Clipboard on Linux needs xclip or wl-clipboard'
        $err = $null
        try { Protect-Output -Clipboard -NoAudit } catch { $err = $_ }
        $err.FullyQualifiedErrorId | Should -Match 'ClipboardTool'
    }

    It 'uses the built-in cmdlets on Linux when xclip exists' -Skip:(-not $IsLinux) {
        Mock Get-Command -ModuleName RedactOutput { [pscustomobject]@{ Name = $Name } } -ParameterFilter { $Name -eq 'xclip' }
        Mock Get-Clipboard -ModuleName RedactOutput { 'host WS-1111' }
        Mock Set-Clipboard -ModuleName RedactOutput {}
        Mock Invoke-RedactWlClipboard -ModuleName RedactOutput {}
        Protect-Output -Clipboard -NoAudit
        Should -Invoke Set-Clipboard -ModuleName RedactOutput -Times 1 -Exactly -ParameterFilter { $Value -ceq 'host [host-01]' }
        Should -Invoke Invoke-RedactWlClipboard -ModuleName RedactOutput -Times 0 -Exactly
    }

    It 'calls wl-paste and wl-copy on Linux without xclip but with wl-clipboard' -Skip:(-not $IsLinux) {
        Mock Get-Command -ModuleName RedactOutput { $null } -ParameterFilter { $Name -eq 'xclip' }
        Mock Get-Command -ModuleName RedactOutput { [pscustomobject]@{ Name = $Name } } -ParameterFilter { $Name -in 'wl-copy', 'wl-paste' }
        Mock Get-Clipboard -ModuleName RedactOutput { throw 'must not be used' }
        Mock Set-Clipboard -ModuleName RedactOutput { throw 'must not be used' }
        Mock Invoke-RedactWlClipboard -ModuleName RedactOutput { if (-not $Write) { 'host WS-1111' } }
        Protect-Output -Clipboard -NoAudit
        Should -Invoke Invoke-RedactWlClipboard -ModuleName RedactOutput -Times 1 -Exactly -ParameterFilter { -not $Write }
        Should -Invoke Invoke-RedactWlClipboard -ModuleName RedactOutput -Times 1 -Exactly -ParameterFilter { $Write -and $Text -ceq 'host [host-01]' }
    }

    It 'needs both wl-copy and wl-paste, and a failed wl-clipboard call names nothing' -Skip:(-not $IsLinux) {
        Mock Get-Command -ModuleName RedactOutput { $null } -ParameterFilter { $Name -in 'xclip', 'wl-paste' }
        Mock Get-Command -ModuleName RedactOutput { [pscustomobject]@{ Name = $Name } } -ParameterFilter { $Name -eq 'wl-copy' }
        $err = $null
        try { InModuleScope RedactOutput { Get-RedactClipboard } } catch { $err = $_ }
        $err.Exception.Message | Should -Be 'Clipboard on Linux needs xclip or wl-clipboard'
        Mock Get-Command -ModuleName RedactOutput { [pscustomobject]@{ Name = $Name } } -ParameterFilter { $Name -in 'wl-copy', 'wl-paste' }
        Mock Invoke-RedactWlClipboard -ModuleName RedactOutput { throw 'CANARY-native-detail' }
        $err = $null
        try { InModuleScope RedactOutput { Set-RedactClipboard -Text 'x' } } catch { $err = $_ }
        $err.Exception.Message | Should -Be 'The clipboard could not be written.'
    }
}

Describe 'New-RedactionConfig' -Tag 'Unit' {
    BeforeEach { $script:Target = Join-Path $TestDrive "new-$([guid]::NewGuid().ToString('N')).json" }

    It 'writes the given keys, folds the tenant prefix and the shorthand entries, and loads back through the config loader' {
        New-RedactionConfig -Path $script:Target -InternalDomains 'ad.contoso.example' -NetbiosDomain 'CONTOSO=ad.contoso.example' `
            -HostPattern 'WS-[0-9]{3,}', @{ regex = 'LT-[0-9]{3,}'; minLength = 7 } -ResourcePrefix 'rg-contoso-' -TenantPrefix 'contoso' `
            -ExtraTerm 'Project Placeholder=proj' -Username 'svc-example' -IpMode KeepPrivate -SidKeepRid $false | Out-Null
        $data = Read-TestJsonFile -Path $script:Target
        $data.internalDomains | Should -Be @('ad.contoso.example')
        $data.netbiosDomains[0].netbios | Should -Be 'CONTOSO'
        $data.hostPatterns.Count | Should -Be 2
        $data.hostPatterns[0].minLength | Should -Be 6
        $data.resourcePrefixes | Should -Be @('rg-contoso-', 'contoso')
        $data.extraTerms[0].label | Should -Be 'proj'
        $data.ipMode | Should -Be 'KeepPrivate'
        $data.sidKeepRid | Should -BeFalse
        $data.ContainsKey('hostList') | Should -BeFalse
        $config = InModuleScope RedactOutput -Parameters @{ Path = $script:Target } { Get-RedactConfig -ConfigPath $Path }
        $config.usernames | Should -Be @('svc-example')
    }

    It 'keeps a single value as a JSON array' {
        New-RedactionConfig -Path $script:Target -HostList 'one-host' | Out-Null
        (Get-Content -LiteralPath $script:Target -Raw) | Should -Match '"hostList":\s*\[\s*"one-host"\s*\]'
    }

    It 'refuses to overwrite without -Force and replaces with it, without reading the old file' {
        Set-Content -LiteralPath $script:Target -Value 'OLD'
        { New-RedactionConfig -Path $script:Target -HostList 'a-host' } | Should -Throw '*-Force*'
        (Get-Content -LiteralPath $script:Target -Raw).Trim() | Should -Be 'OLD'
        New-RedactionConfig -Path $script:Target -HostList 'a-host' -Force | Out-Null
        (Read-TestJsonFile -Path $script:Target).hostList | Should -Be @('a-host')
    }

    It '-WhatIf writes nothing' {
        New-RedactionConfig -Path $script:Target -HostList 'a-host' -WhatIf 6>$null | Out-Null
        Test-Path -LiteralPath $script:Target | Should -BeFalse
    }

    It 'refuses an invalid regex, naming key and index only, and writes nothing' {
        $err = $null
        try { New-RedactionConfig -Path $script:Target -HostPattern 'WS-[0-9]{3,}', 'CANARY[0-9' } catch { $err = $_ }
        $err.Exception.Message | Should -Be 'Config rejected: hostPatterns[1] rejected: does not compile.'
        $err.Exception.Message.Contains('CANARY') | Should -BeFalse
        Test-Path -LiteralPath $script:Target | Should -BeFalse
    }

    It 'rejects shorthand that has no label by key and index' {
        $err = $null
        try { New-RedactionConfig -Path $script:Target -ExtraTerm 'CANARY-NO-LABEL' } catch { $err = $_ }
        $err.Exception.Message | Should -Be 'Config rejected: extraTerms[0] rejected: needs term, label.'
    }

    It 'prompts when no parameters are given in an interactive session and never echoes the answers' {
        Mock Test-RedactInteractive -ModuleName RedactOutput { $true }
        Mock Read-Host -ModuleName RedactOutput {
            switch -Wildcard ($Prompt) {
                'Internal domains*' { 'ad.contoso.example, contoso.example' }
                'NetBIOS domain name*' { 'CONTOSO' }
                'FQDN*' { 'ad.contoso.example' }
                'Desktop*' { 'WS-[0-9]{3,}' }
                'Server*' { 'SRV-[A-Z]{2,4}[0-9]{2,}' }
                'Tenant*' { 'contoso' }
                default { '' }
            }
        }
        $stream = New-RedactionConfig -Path $script:Target 6>&1 5>&1 4>&1 3>&1 | Out-String
        $data = Read-TestJsonFile -Path $script:Target
        $data.internalDomains.Count | Should -Be 2
        $data.netbiosDomains[0].fqdn | Should -Be 'ad.contoso.example'
        $data.hostPatterns.Count | Should -Be 2
        $data.resourcePrefixes | Should -Be @('contoso')
        $data.ContainsKey('usernames') | Should -BeFalse
        $stream.Contains('WS-[0-9]') | Should -BeFalse
    }

    It 'fails with no parameters in a non-interactive session' {
        Mock Test-RedactInteractive -ModuleName RedactOutput { $false }
        { New-RedactionConfig -Path $script:Target } | Should -Throw '*not interactive*'
    }

    It 'warns when the file sits in a git repository that does not ignore it' -Skip:(-not $script:HasGit) {
        $repo = Join-Path $TestDrive "repo-$([guid]::NewGuid().ToString('N'))"
        New-Item -ItemType Directory -Path $repo | Out-Null
        git -C $repo init -q
        $file = Join-Path $repo 'redact.config.local.json'
        $null = New-RedactionConfig -Path $file -HostList 'a-host' -WarningVariable w -WarningAction SilentlyContinue
        @($w).Count | Should -Be 1
        $w[0].Message | Should -Match 'not covered by \.gitignore'
        $w[0].Message.Contains('a-host') | Should -BeFalse
    }

    It 'stays quiet when .gitignore covers the file, and outside a repository' -Skip:(-not $script:HasGit) {
        $repo = Join-Path $TestDrive "repo-$([guid]::NewGuid().ToString('N'))"
        New-Item -ItemType Directory -Path $repo | Out-Null
        git -C $repo init -q
        Set-Content -LiteralPath (Join-Path $repo '.gitignore') -Value 'redact.config.local.json'
        $null = New-RedactionConfig -Path (Join-Path $repo 'redact.config.local.json') -HostList 'a-host' -WarningVariable w -WarningAction SilentlyContinue
        @($w).Count | Should -Be 0
        InModuleScope RedactOutput -Parameters @{ Path = $script:Target } { Test-RedactGitIgnored -Path $Path } | Should -BeNullOrEmpty
    }
}
