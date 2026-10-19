# Pester scopes discovery data to the Describe below; the analyzer cannot see that usage.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'rejectCases is consumed by -ForEach during Pester discovery.')]
param()

BeforeDiscovery {
    $rejectCases = @(
        @{ Name = 'a nested quantifier'; Key = 'hostPatterns'; Entry = @{ regex = '(CANARYa+)+'; minLength = 6 }; Index = 1; Reason = 'nested quantifier' }
        @{ Name = 'a nested star'; Key = 'hostPatterns'; Entry = @{ regex = '(CANARY.*)*'; minLength = 6 }; Index = 1; Reason = 'nested quantifier' }
        @{ Name = 'a pattern shorter than 3 characters'; Key = 'hostPatterns'; Entry = @{ regex = 'ab'; minLength = 6 }; Index = 1; Reason = 'too short' }
        @{ Name = 'a pattern that does not compile'; Key = 'hostPatterns'; Entry = @{ regex = 'CANARY[0-9'; minLength = 6 }; Index = 1; Reason = 'does not compile' }
        @{ Name = 'a short pattern with no digit class'; Key = 'hostPatterns'; Entry = @{ regex = 'CANARY[a-z]{3,}'; minLength = 3 }; Index = 1; Reason = 'needs minLength >= 4 or a digit class' }
        @{ Name = 'a pattern that exceeds the regex time limit on the probe string'; Key = 'hostPatterns'; Entry = @{ regex = '(a|aa)+$'; minLength = 4 }; Index = 1; Reason = 'exceeded the regex time limit' }
        @{ Name = 'a nested quantifier in deviceSerialPatterns'; Key = 'deviceSerialPatterns'; Entry = '(CANARY[0-9]+)+'; Index = 1; Reason = 'nested quantifier' }
    )
}

BeforeAll {
    . $PSScriptRoot/TestHelpers.ps1
    $script:Keep = "graph.microsoft.us 00000000-0000-0000-0000-000000000000 00000003-0000-0000-c000-000000000000 127.0.0.1 git@github.com 255.255.255.0"
}

AfterAll { Remove-Item -Path Env:REDACTOUTPUT_CONFIG_DIR -ErrorAction SilentlyContinue }

Describe 'Config defaults and layering' -Tag 'Unit' {
    BeforeEach {
        $script:Dir = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:Dir | Out-Null
        $env:REDACTOUTPUT_CONFIG_DIR = $script:Dir
    }
    AfterEach { $env:REDACTOUTPUT_CONFIG_DIR = $script:ConfigDir }

    It 'has a default for every key' {
        $c = InModuleScope RedactOutput { Get-RedactConfig }
        foreach ($key in 'internalDomains', 'netbiosDomains', 'hostPatterns', 'hostList', 'resourcePrefixes', 'usernames', 'extraTerms', 'guidAllowlist', 'publicHostAllowlist', 'publicDomains', 'ipAllowlist', 'secretNames', 'nonSecretNames', 'deviceSerialPatterns') {
            @($c[$key]).Count | Should -Be 0 -Because "$key defaults to an empty list"
        }
        $c['ipMode'] | Should -Be 'Classify'
        $c['pathMode'] | Should -Be 'UserOnly'
        $c['sidKeepRid'] | Should -BeTrue
        $c['categories'].Count | Should -Be 0
    }

    It 'applies built-in < sample < local < -ConfigPath < -Override for the stage 2 keys' {
        '{"internalDomains":["sample.example"],"ipMode":"KeepPrivate","pathMode":"Full","sidKeepRid":false,"categories":{"guid":false,"ipv4":false}}' | Set-Content (Join-Path $script:Dir 'redact.config.sample.json')
        '{"internalDomains":["local.example"],"ipMode":"Keep","hostList":["h1"],"categories":{"ipv4":true}}' | Set-Content (Join-Path $script:Dir 'redact.config.local.json')
        $extra = Join-Path $TestDrive 'layer3.json'
        '{"ipMode":"Classify","hostList":["h2"],"usernames":["u3"]}' | Set-Content $extra
        $c = InModuleScope RedactOutput -Parameters @{ Extra = $extra } {
            Get-RedactConfig -ConfigPath $Extra -Override @{ usernames = @('u4'); sidKeepRid = $true }
        }
        $c['internalDomains'] | Should -Be @('local.example')
        $c['ipMode'] | Should -Be 'Classify'
        $c['pathMode'] | Should -Be 'Full'
        $c['hostList'] | Should -Be @('h2')
        $c['usernames'] | Should -Be @('u4')
        $c['sidKeepRid'] | Should -BeTrue
        $c['categories']['guid'] | Should -BeFalse
        $c['categories']['ipv4'] | Should -BeTrue
    }

    It 'keeps built-in allowlists when config tries to empty them' {
        $cfg = Write-TestConfig -Data @{ publicHostAllowlist = @(); guidAllowlist = @(); ipAllowlist = @(); publicDomains = @() }
        $out = Invoke-TestRedact -ConfigPath $cfg -Text $script:Keep
        $out -ceq $script:Keep | Should -BeTrue
    }

    It 'lets config extend the host, GUID, IP and public domain allowlists, plus guid-allowlist.txt' {
        $extraGuid = 'aaaaaaaa-1111-2222-3333-444444444444'
        $fileGuid = 'bbbbbbbb-1111-2222-3333-444444444444'
        $dropped = 'cccccccc-1111-2222-3333-444444444444'
        Set-Content -LiteralPath (Join-Path $script:Dir 'guid-allowlist.txt') -Value @('# comment', '', "$($fileGuid.ToUpper()) # upper-case with a comment")
        $cfg = Write-TestConfig -Data @{ guidAllowlist = @($extraGuid); publicHostAllowlist = @('*.example.net'); ipAllowlist = @('198.51.100.53'); publicDomains = @('partner.example') }
        $text = "$extraGuid $fileGuid $dropped svc.example.net 198.51.100.53 198.51.100.54 a@partner.example"
        $out = Invoke-TestRedact -ConfigPath $cfg -Text $text
        $out | Should -BeExactly "$extraGuid $fileGuid [guid-01] svc.example.net 198.51.100.53 [ip-pub-01] [user-01]@partner.example"
    }
}

Describe 'Config validation' -Tag 'Unit' {
    It 'rejects <Name> naming the key and index, never the pattern' -ForEach $rejectCases {
        $good = @{ regex = 'WS-[0-9]{3,}'; minLength = 6 }
        $data = @{ $Key = @($(if ($Key -eq 'hostPatterns') { $good } else { 'PF[0-9]{4}' }), $Entry) }
        $cfg = Write-TestConfig -Data $data
        $err = $null
        try { 'text' | Protect-Output -NoAudit -ConfigPath $cfg } catch { $err = $_ }
        $err | Should -Not -BeNullOrEmpty
        $err.FullyQualifiedErrorId | Should -Match 'RedactOutput.ConfigInvalid'
        $err.Exception.Message | Should -Be "Config rejected: $Key[$Index] rejected: $Reason."
        $err.Exception.Message.Contains('CANARY') | Should -BeFalse
        $err.Exception.Message.Contains('(a|aa)') | Should -BeFalse
    }

    It 'rejects an entry without its required fields and an unknown enum value' {
        $err = $null
        try { 'x' | Protect-Output -NoAudit -ConfigPath (Write-TestConfig -Data @{ extraTerms = @(@{ term = 'Alpha' }) }) } catch { $err = $_ }
        $err.Exception.Message | Should -Be 'Config rejected: extraTerms[0] rejected: needs term, label.'
        $err = $null
        try { 'x' | Protect-Output -NoAudit -ConfigPath (Write-TestConfig -Data @{ ipMode = 'Bogus' }) } catch { $err = $_ }
        $err.Exception.Message | Should -Be 'Config rejected: ipMode must be one of: Classify, KeepPrivate, Keep.'
    }

    It 'accepts the committed sample config' {
        { InModuleScope RedactOutput { Get-RedactConfig } } | Should -Not -Throw
    }
}

Describe 'Config switches' -Tag 'Unit' {
    It 'categories.<label>=false disables that identifier rule only' {
        $cfg = Write-TestConfig -Data @{ categories = @{ guid = $false } }
        $out = Invoke-TestRedact -ConfigPath $cfg -Text "11111111-2222-3333-4444-555555555555 198.51.100.7`napi_token=FakeValue01"
        $out | Should -BeExactly "11111111-2222-3333-4444-555555555555 [ip-pub-01]`napi_token=[secret:kv]"
    }

    It 'cannot disable secret rules through categories' {
        $cfg = Write-TestConfig -Data @{ categories = @{ kv = $false; jwt = $false; secret = $false } }
        (Invoke-TestRedact -ConfigPath $cfg -Text 'api_token=FakeValue01') | Should -BeExactly 'api_token=[secret:kv]'
    }

    It 'ipMode KeepPrivate keeps private addresses and Keep turns IPv4 and IPv6 off' {
        $text = '10.20.30.40 198.51.100.7 2001:db8::10'
        (Invoke-TestRedact -ConfigPath (Write-TestConfig -Data @{ ipMode = 'KeepPrivate' }) -Text $text) | Should -BeExactly '10.20.30.40 [ip-pub-01] [ip6-01]'
        (Invoke-TestRedact -ConfigPath (Write-TestConfig -Data @{ ipMode = 'Keep' }) -Text $text) | Should -BeExactly $text
    }

    It 'pathMode Full tokenizes non-system folders, Keep turns the rule off, UserOnly is the default' {
        $text = 'C:\Users\jdoe\Projects\app\bin and C:\Windows\System32 and /opt/app/data'
        (Invoke-TestRedact -ConfigPath (Write-TestConfig -Data @{ pathMode = 'Full' }) -Text $text) | Should -BeExactly 'C:\Users\[user-01]\[path-01]\[path-02]\bin and C:\Windows\System32 and /opt/[path-02]/[path-03]'
        (Invoke-TestRedact -ConfigPath (Write-TestConfig -Data @{ pathMode = 'Keep' }) -Text $text) | Should -BeExactly $text
        (Invoke-TestRedact -Text $text) | Should -BeExactly 'C:\Users\[user-01]\Projects\app\bin and C:\Windows\System32 and /opt/app/data'
    }

    It 'pathMode Full is idempotent and leaves URL paths and resource IDs to their own rules' {
        $cfg = Write-TestConfig -Data @{ pathMode = 'Full' }
        $text = "C:\Users\jdoe\Projects\app and /opt/app/data and https://example.invalid/api/v1/items`n/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg1"
        $once = Invoke-TestRedact -ConfigPath $cfg -Text $text
        $once | Should -BeExactly "C:\Users\[user-01]\[path-01]\[path-02] and /opt/[path-02]/[path-03] and https://example.invalid/api/v1/items`n/subscriptions/[sub-01]/resourceGroups/[rg-01]"
        (Invoke-TestRedact -ConfigPath $cfg -Text $once) -ceq $once | Should -BeTrue
        @($once | Test-RedactionResidual -ConfigPath $cfg).Count | Should -Be 0
    }

    It 'sidKeepRid=false replaces the whole SID' {
        $cfg = Write-TestConfig -Data @{ sidKeepRid = $false }
        (Invoke-TestRedact -ConfigPath $cfg -Text 'S-1-5-21-1111111111-2222222222-3333333333-512') | Should -BeExactly '[sid-dom-01]'
    }

    It 'matches config literals literally and longest first' {
        $cfg = Write-TestConfig -Data @{ usernames = @('svc.(x)'); hostList = @('srv', 'srv-long') }
        (Invoke-TestRedact -ConfigPath $cfg -Text 'run svc.(x) and svcZ(x) on srv-long and srv') | Should -BeExactly 'run [user-01] and svcZ(x) on [host-01] and [host-02]'
    }

    It 'keeps per-label counters for extra terms and sanitizes labels' {
        $cfg = Write-TestConfig -Data @{ extraTerms = @(@{ term = 'Alpha'; label = 'Proj-A' }, @{ term = 'Beta'; label = 'proja' }, @{ term = 'Gamma'; label = 'site' }) }
        (Invoke-TestRedact -ConfigPath $cfg -Text 'Alpha Beta Gamma alpha') | Should -BeExactly '[term-proja-01] [term-proja-02] [term-site-01] [term-proja-01]'
    }
}

Describe 'Audit header rotation' -Tag 'Unit' {
    It 'renames an audit file whose header differs and starts a new one' {
        $folder = Join-Path $TestDrive 'audit-rotation'
        New-Item -ItemType Directory -Path $folder | Out-Null
        $audit = Join-Path $folder 'audit.csv'
        Set-Content -LiteralPath $audit -Value @('timestamp_utc,operator', '2024-01-01T00:00:00Z,someone')
        $null = 'api_token=FakeValue01' | Protect-Output -AuditPath $audit
        $null = 'password=FakeValue02' | Protect-Output -AuditPath $audit
        $rotated = @(Get-ChildItem -LiteralPath $folder -Filter 'audit-*.csv')
        $rotated.Count | Should -Be 1
        $rotated[0].Name | Should -Match '^audit-[0-9]{14}\.csv$'
        (Get-Content -LiteralPath $rotated[0].FullName).Count | Should -Be 2
        $rows = @(Import-Csv -LiteralPath $audit)
        $rows.Count | Should -Be 2
        $rows[0].PSObject.Properties.Name | Should -Contain 'upn'
        $rows[0].PSObject.Properties.Name | Should -Contain 'kv'
        $rows[0].kv | Should -Be '1'
    }
}
