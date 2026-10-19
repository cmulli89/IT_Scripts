# Pester scopes discovery data to the Describe below; the analyzer cannot see that usage.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'ruleCases and keepCases are consumed by -ForEach during Pester discovery.')]
param()

BeforeDiscovery {
    $guid = '11111111-2222-3333-4444-555555555555'
    $thumb = '0123456789abcdef0123456789abcdef01234567'
    $ruleCases = @(
        @{ Name = 'I01 guid'; Text = "id $guid end"; Gone = @($guid); Want = @('id [guid-01] end') }
        @{ Name = 'I01 braced guid keeps the braces'; Text = "key {$guid}"; Gone = @($guid); Want = @('key {[guid-01]}') }
        @{ Name = 'I01 keyed unhyphenated guid'; Text = '"deviceId":"0123456789abcdef0123456789abcdef"'; Gone = @('0123456789abcdef0123456789abcdef'); Want = @('"deviceId":"[guid-01]"') }
        @{ Name = 'I02 SID keeps the RID'; Text = 'sid S-1-5-21-1111111111-2222222222-3333333333-512 end'; Gone = @('1111111111', '2222222222'); Want = @('sid S-1-5-21-[sid-dom-01]-512 end') }
        @{ Name = 'I02 cloud SID'; Text = 'S-1-12-1-1111111111-2222222222-3333333333-4444444444'; Gone = @('1111111111', '4444444444'); Want = @('[sid-cloud-01]') }
        @{ Name = 'I03 UPN'; Text = 'mail jdoe@contoso.example now'; Gone = @('jdoe', 'contoso'); Want = @('mail [user-01]@[domain-01] now') }
        @{ Name = 'I03 guest UPN'; Text = 'jdoe_partner.example#EXT#@tenant.onmicrosoft.us'; Gone = @('jdoe', 'partner', 'tenant.onmicrosoft'); Want = @('[user-01]_[domain-01]#EXT#@[tenant-01].onmicrosoft.us') }
        @{ Name = 'I03 public domain keeps the domain, git and noreply local parts stay'; Text = 'jdoe@gmail.com git@github.com no-reply@microsoft.com'; Gone = @('jdoe'); Want = @('[user-01]@gmail.com git@github.com no-reply@microsoft.com') }
        @{ Name = 'I04 onmicrosoft tenant'; Text = 'sign in as x@contoso.onmicrosoft.com or contoso.onmicrosoft.us'; Gone = @('contoso'); Want = @('[tenant-01].onmicrosoft.us') }
        @{ Name = 'I04 sharepoint tenant'; Text = 'https://contoso-my.sharepoint.us/personal/x and https://contoso.sharepoint.us/sites/y'; Gone = @('contoso'); Want = @('https://[tenant-01]-my.sharepoint.us/personal/x and https://[tenant-01].sharepoint.us/sites/y') }
        @{ Name = 'I05 internal FQDN and bare domain'; Text = 'srv.sub.ad.contoso.example and ad.contoso.example'; Gone = @('srv', 'contoso'); Want = @('[host-01].[domain-01] and [domain-02]') }
        @{ Name = 'I05 distinguished name'; Text = 'CN=John Smith,OU=Staff,CN=Users,DC=ad,DC=contoso,DC=example'; Gone = @('John', 'Staff', 'contoso'); Want = @('CN=[name-01],OU=[ou-01],CN=Users,DC=[domain-01]') }
        @{ Name = 'I06 host patterns and computer accounts'; Text = 'WS-1234 and LT-5678$ and srv-ab01 and dkr-77'; Gone = @('1234', '5678', 'ab01', '77'); Want = @('[host-01] and [host-02]$ and [host-03] and [host-04]') }
        @{ Name = 'I06 host list'; Text = 'connect host-placeholder now'; Gone = @('placeholder'); Want = @('connect [host-01] now') }
        @{ Name = 'I07 IPv4 with CIDR'; Text = '10.20.30.40/24 and 198.51.100.7 and 10.20.30.40'; Gone = @('10.20.30', '198.51'); Want = @('[ip-priv-01]/24 and [ip-pub-01] and [ip-priv-01]') }
        @{ Name = 'I08 IPv6 keeps ::1'; Text = 'fe80::1c2b:3d4e:5f60:7182%12 and 2001:db8::10 and ::1'; Gone = @('1c2b', 'db8'); Want = @('[ip6-01] and [ip6-02] and ::1') }
        @{ Name = 'I09 MAC, all-ff stays'; Text = '00-15-5D-01-02-03 and 0015.5d01.0203 and ff:ff:ff:ff:ff:ff'; Gone = @('5D-01', '5d01'); Want = @('[mac-01] and [mac-02] and ff:ff:ff:ff:ff:ff') }
        @{ Name = 'I10 resource ID'; Text = "/subscriptions/$guid/resourceGroups/rg-contoso-prod/providers/Microsoft.KeyVault/vaults/kv-contoso-main/keys/k1 and bare $guid"; Gone = @($guid, 'contoso', 'k1'); Want = @('/subscriptions/[sub-01]/resourceGroups/[rg-01]/providers/Microsoft.KeyVault/vaults/[res-01]/keys/[res-02] and bare [sub-01]') }
        @{ Name = 'I10 keeps locations'; Text = "/subscriptions/$guid/providers/Microsoft.Compute/locations/usgovarizona/vmSizes"; Gone = @($guid); Want = @('/providers/Microsoft.Compute/locations/usgovarizona/vmSizes') }
        @{ Name = 'I10 bare names from resourcePrefixes'; Text = 'rg-contoso-prod and kv-contoso-main and st-contosodata'; Gone = @('contoso'); Want = @('[rg-01] and [res-01] and [res-02]') }
        @{ Name = 'I11 tenant-specific Azure host, first label only'; Text = 'https://contosostore.blob.core.usgovcloudapi.net/c and kv-contoso-main.vault.usgovcloudapi.net and management.usgovcloudapi.net'; Gone = @('contosostore', 'kv-contoso'); Want = @('https://[res-01].blob.core.usgovcloudapi.net/c and [res-02].vault.usgovcloudapi.net and management.usgovcloudapi.net') }
        @{ Name = 'I11 app service host'; Text = 'https://myapp.scm.azurewebsites.us/'; Gone = @('myapp'); Want = @('https://[res-01].scm.azurewebsites.us/') }
        @{ Name = 'I12 thumbprint needs cert context'; Text = "Thumbprint: $thumb`ncommit $thumb"; Gone = @(); Want = @('Thumbprint: [thumb-01]', "commit $thumb") }
        @{ Name = 'I12 serial numbers'; Text = 'SerialNumber : PF1ABC123 and ServiceTag=5CD1234XYZ'; Gone = @('PF1ABC123', '5CD1234XYZ'); Want = @('SerialNumber : [serial-01]', 'ServiceTag=[serial-02]') }
        @{ Name = 'I12 device serial pattern from config'; Text = 'device PF9XYZ12345 here'; Gone = @('PF9XYZ12345'); Want = @('device [serial-01] here') }
        @{ Name = 'I13 UNC raw and JSON-escaped, admin shares and device paths stay'; Text = 'a \\fileserver\projects\x.txt b \\fileserver\IPC$ c \\\\fileserver\\projects d \\?\C:\x \\.\pipe\x'; Gone = @('projects'); Want = @('a \\[host-01]\[share-01]\x.txt b \\[host-01]\IPC$ c \\\\[host-01]\\[share-01] d \\?\C:\x \\.\pipe\x') }
        @{ Name = 'I14 profile paths, system profiles stay'; Text = 'C:\Users\jdoe\AppData and C:\\Users\\jdoe\\x and /home/jdoe/.ssh and /Users/jdoe C:\Users\Public\x /root/x C:\Users\Default\y'; Gone = @('jdoe'); Want = @('C:\Users\[user-01]\AppData and C:\\Users\\[user-01]\\x and /home/[user-01]/.ssh and /Users/[user-01] C:\Users\Public\x /root/x C:\Users\Default\y') }
        @{ Name = 'I15 DOMAIN\user, computer accounts and well-known names'; Text = 'CONTOSO\jdoe CONTOSO\WS-1234$ CONTOSO\Domain Admins NT AUTHORITY\SYSTEM BUILTIN\Administrators'; Gone = @('CONTOSO', 'jdoe', '1234'); Want = @('[domain-01]\[user-01] [domain-01]\[host-01]$ [domain-01]\Domain Admins NT AUTHORITY\SYSTEM BUILTIN\Administrators') }
        @{ Name = 'I16 usernames from config'; Text = 'run as svc-example today'; Gone = @('svc-example'); Want = @('run as [user-01] today') }
        @{ Name = 'I16 person fields in JSON text'; Text = '{"givenName":"Jane","surname":"Doe","mobilePhone":"+1 555 0100","businessPhones":["+1 555 0101","+1 555 0102"],"employeeId":"E12345"}'; Gone = @('Jane', '555', 'E12345'); Want = @('{"givenName":"[name-01]","surname":"[name-02]","mobilePhone":"[phone-01]","businessPhones":["[phone-02]","[phone-03]"],"employeeId":"[emp-01]"}') }
        @{ Name = 'I17 extra terms'; Text = 'about Project Placeholder and building 7'; Gone = @('Placeholder', 'building'); Want = @('about [term-proj-01] and [term-site-01]') }
    )
    $keepCases = @(
        @{ Name = 'version strings'; Text = "build 10.0.19045.1`nversion 10.1.2.3`nVer: 192.0.2.4`nv1.2.3.4" }
        @{ Name = 'DisplayVersion value with four valid octets'; Text = 'DisplayVersion : 10.0.190.45' }
        @{ Name = 'Format-List padded DisplayVersion'; Text = 'DisplayVersion          : 10.0.190.45' }
        @{ Name = 'KEY=value ProductVersion'; Text = 'ProductVersion=10.2.3.4' }
        @{ Name = 'JSON displayVersion'; Text = '{"displayVersion": "10.0.190.45"}' }
        @{ Name = 'OSBuildNumber'; Text = 'OSBuildNumber : 10.0.190.45' }
        @{ Name = 'lowercase fileversion and YAML version'; Text = "fileversion: 1.2.3.4`nversion: 1.2.3.4" }
        @{ Name = 'camel-case and snake-case ver keys'; Text = "AgentVer = 10.2.3.4`napp_ver=10.2.3.4" }
        @{ Name = 'git SHAs without certificate context'; Text = 'commit 0123456789abcdef0123456789abcdef01234567' }
        @{ Name = 'PasswordLastSet and KeyVaultName fields'; Text = "PasswordLastSet : 1/1/2024`nKeyVaultName : kv-fake" }
        @{ Name = 'timestamps'; Text = "12:34:56`n2024-01-01 09:41:07,123" }
        @{ Name = 'English words against host patterns'; Text = 'Workstation Server Wsus WS-12 LT-9 ws vm' }
        @{ Name = 'keep-listed IPv4 addresses'; Text = '127.0.0.1 0.0.0.0 255.255.255.255 169.254.1.1 224.0.0.251 255.255.255.0 0.0.0.255 168.63.129.16 169.254.169.254' }
        @{ Name = 'well-known SIDs'; Text = 'S-1-5-18 S-1-5-19 S-1-5-20 S-1-5-32-544 S-1-1-0 S-1-5-11 S-1-5-80-1234567890' }
        @{ Name = 'allowlisted GUIDs and endpoints'; Text = "00000000-0000-0000-0000-000000000000 00000003-0000-0000-c000-000000000000 62e90394-69f5-4237-9190-012177145e10 04b07795-8ddb-461a-bbee-02f9e1bf7b46 graph.microsoft.us login.microsoftonline.us" }
        @{ Name = 'system profile folders'; Text = 'C:\Users\Public C:\Users\Default\x /root/.bashrc' }
        @{ Name = 'device and UNC admin paths'; Text = '\\?\C:\Windows \\.\pipe\name \\127.0.0.1\C$' }
        @{ Name = 'unkeyed 32-hex and 40-hex values'; Text = "checksum 0123456789abcdef0123456789abcdef`nsha 0123456789abcdef0123456789abcdef01234567" }
    )
}

BeforeAll {
    . $PSScriptRoot/TestHelpers.ps1
    $script:Neighbors = "graph.microsoft.us`nlogin.microsoftonline.us`n00000000-0000-0000-0000-000000000000`n00000003-0000-0000-c000-000000000000`nS-1-5-18`nusgovvirginia`nENABLE_SIGNUP=false"
}

AfterAll { Remove-Item -Path Env:REDACTOUTPUT_CONFIG_DIR -ErrorAction SilentlyContinue }

Describe 'I01-I17 identifier rules' -Tag 'Unit' {
    It '<Name>: replaces the value with the right token shape and keeps allowlisted neighbors' -ForEach $ruleCases {
        $out = Invoke-TestRedact -Text "$script:Neighbors`n$Text"
        foreach ($value in $Gone) { $out.Contains($value) | Should -BeFalse -Because "$Name must redact '$value'" }
        foreach ($expected in $Want) { $out.Contains($expected) | Should -BeTrue -Because "$Name must produce '$expected'" }
        foreach ($kept in $script:Neighbors.Split("`n")) { $out.Contains($kept) | Should -BeTrue -Because "'$kept' must survive in $Name" }
    }

    It 'leaves <Name> untouched' -ForEach $keepCases {
        (Invoke-TestRedact -Text $Text) -ceq $Text | Should -BeTrue
    }

    It 'tokenizes the IPv4 address on <Name>' -ForEach @(
        @{ Name = 'IPAddress key'; Text = 'IPAddress : 10.1.2.3' }
        @{ Name = 'Server key'; Text = 'Server : 192.0.2.10' }
        @{ Name = 'vpn word'; Text = 'vpn 10.1.2.3' }
        @{ Name = 'version keyword earlier on the line'; Text = 'version 2 server 10.1.2.3' }
    ) {
        $out = Invoke-TestRedact -Text $Text
        $out.Contains('.2.3') -or $out.Contains('.2.10') | Should -BeFalse
        $out -match '\[ip-(priv|pub)-01\]' | Should -BeTrue
    }

    It 'raises no residual finding for version values' {
        { "DisplayVersion          : 10.0.190.45`nProductVersion=10.2.3.4`n" | Protect-Output -NoAudit -Strict -WarningAction SilentlyContinue } | Should -Not -Throw
    }

    It 'tokenizes a tenant GUID in a login URL path and keeps the host' {
        $out = Invoke-TestRedact -Text 'https://login.microsoftonline.us/11111111-2222-3333-4444-555555555555/oauth2/v2.0/token'
        $out | Should -BeExactly 'https://login.microsoftonline.us/[guid-01]/oauth2/v2.0/token'
    }

    It 'maps a text-mode phone list and ignores empty person values' {
        $out = Invoke-TestRedact -Text '{"givenName":"","mobilePhone":"","businessPhones":[]}'
        $out | Should -BeExactly '{"givenName":"","mobilePhone":"","businessPhones":[]}'
    }
}

Describe 'Endpoint allowlist' -Tag 'Unit' {
    It 'matches on label boundaries only' {
        InModuleScope RedactOutput {
            $s = New-RedactSession -Config (Get-RedactConfig)
            foreach ($name in 'graph.microsoft.us', 'a.b.microsoft.us', 'LOGIN.MICROSOFTONLINE.US', 'github.com', 'aka.ms', 'x.usgovcloudapi.net') {
                (Test-RedactPublicHost -Name $name -Session $s) | Should -BeTrue -Because "$name is allowlisted"
            }
            foreach ($name in 'evilmicrosoft.us', 'x.microsoft.us.example', 'microsoft.us', 'www.github.com', 'contoso.example') {
                (Test-RedactPublicHost -Name $name -Session $s) | Should -BeFalse -Because "$name is not allowlisted"
            }
        }
    }

    It 'does not keep look-alike hosts in text (they stay visible to identifier rules)' {
        $cfg = Write-TestConfig -Data @{ hostList = @('evilmicrosoft.us', 'x.microsoft.us.example') }
        $out = Invoke-TestRedact -ConfigPath $cfg -Text 'evilmicrosoft.us x.microsoft.us.example graph.microsoft.us'
        $out | Should -BeExactly '[host-01] [host-02] graph.microsoft.us'
    }

    It 'does not mask a host that follows @ (the email rule decides by publicDomains)' {
        $out = Invoke-TestRedact -Text 'jdoe@graph.microsoft.us jdoe@contoso.example'
        $out | Should -BeExactly '[user-01]@graph.microsoft.us [user-01]@[domain-01]'
    }

    It 'scans paths and queries under allowlisted hosts' {
        $out = Invoke-TestRedact -Text 'https://graph.microsoft.us/v1.0/users/jdoe@contoso.example?ip=198.51.100.7'
        $out | Should -BeExactly 'https://graph.microsoft.us/v1.0/users/[user-01]@[domain-01]?ip=[ip-pub-01]'
    }
}

Describe 'Consistency across forms' -Tag 'Unit' {
    It 'gives one person one user token across UPN, DOMAIN\user, profile paths and /home' {
        $out = Invoke-TestRedact -Text 'jdoe@contoso.example CONTOSO\jdoe C:\Users\jdoe.CONTOSO /home/jdoe JDoe@Contoso.Example'
        $out | Should -BeExactly '[user-01]@[domain-01] [domain-02]\[user-01] C:\Users\[user-01] /home/[user-01] [user-01]@[domain-01]'
    }

    It 'gives one machine one host token across names, FQDN, UNC and computer accounts' {
        $out = Invoke-TestRedact -Text 'WS-1234 WS-1234.ad.contoso.example \\WS-1234\data CONTOSO\WS-1234$ ws-1234'
        $out | Should -BeExactly '[host-01] [host-01].[domain-01] \\[host-01]\[share-01] [domain-01]\[host-01]$ [host-01]'
    }

    It 'gives a DN CN value that is a host or user the shared token, with the DN first or last' {
        $dn = 'CN=WS-1234,OU=Laptops,DC=ad,DC=contoso,DC=example'
        $hostForms = '\\WS-1234\data WS-1234.ad.contoso.example'
        (Invoke-TestRedact -Text "$dn $hostForms") | Should -BeExactly 'CN=[host-01],OU=[ou-01],DC=[domain-01] \\[host-01]\[share-01] [host-01].[domain-01]'
        (Invoke-TestRedact -Text "$hostForms $dn") | Should -BeExactly '\\[host-01]\[share-01] [host-01].[domain-01] CN=[host-01],OU=[ou-01],DC=[domain-01]'
        (Invoke-TestRedact -Text "jdoe@contoso.example CN=jdoe,DC=ad,DC=contoso,DC=example CN=svc-example,DC=ad,DC=contoso,DC=example CN=John Smith,DC=ad,DC=contoso,DC=example") |
            Should -BeExactly '[user-01]@[domain-01] CN=[user-01],DC=[domain-02] CN=[user-02],DC=[domain-02] CN=[name-01],DC=[domain-02]'
    }

    It 'gives a NetBIOS name and its FQDN one domain token, in either order' {
        (Invoke-TestRedact -Text 'CONTOSO\jdoe ad.contoso.example CONTOSO') | Should -BeExactly '[domain-01]\[user-01] [domain-01] [domain-01]'
        (Invoke-TestRedact -Text 'ad.contoso.example CONTOSO\jdoe') | Should -BeExactly '[domain-01] [domain-01]\[user-01]'
    }

    It 'shares the res token between I10 names and I11 hosts, and the sub token with bare GUIDs' {
        $out = Invoke-TestRedact -Text '/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/kv-contoso-main and kv-contoso-main.vault.usgovcloudapi.net {11111111-2222-3333-4444-555555555555}'
        $out | Should -BeExactly '/subscriptions/[sub-01]/resourceGroups/[rg-01]/providers/Microsoft.KeyVault/vaults/[res-01] and [res-01].vault.usgovcloudapi.net {[sub-01]}'
    }

    It 'uses one token for the same original and the next number for a new one' {
        $out = Invoke-TestRedact -Text '198.51.100.7 203.0.113.9 198.51.100.7'
        $out | Should -BeExactly '[ip-pub-01] [ip-pub-02] [ip-pub-01]'
    }
}

Describe 'Tokens and maps' -Tag 'Unit' {
    It 'pads counters to two digits and grows to three past 99' {
        InModuleScope RedactOutput {
            $s = New-RedactSession -Config (Get-RedactConfig)
            $tokens = foreach ($i in 1..101) { Get-RedactToken -Session $s -Type host -Original "h$i" }
            $tokens[0] | Should -Be '[host-01]'
            $tokens[98] | Should -Be '[host-99]'
            $tokens[99] | Should -Be '[host-100]'
        }
    }

    It 'normalizes names to lower case, GUIDs without braces, and keeps other types as is' {
        InModuleScope RedactOutput {
            $s = New-RedactSession -Config (Get-RedactConfig)
            (Get-RedactToken -Session $s -Type user -Original 'JDoe') | Should -Be (Get-RedactToken -Session $s -Type user -Original 'jdoe')
            (Get-RedactToken -Session $s -Type guid -Original '{AAAAAAAA-2222-3333-4444-555555555555}') | Should -Be (Get-RedactToken -Session $s -Type guid -Original 'aaaaaaaa-2222-3333-4444-555555555555')
            (Get-RedactToken -Session $s -Type guid -Original 'aaaaaaaa222233334444555555555555') | Should -Be '[guid-01]'
            (Get-RedactToken -Session $s -Type mac -Original 'AA:BB:CC:DD:EE:FF') | Should -Not -Be (Get-RedactToken -Session $s -Type mac -Original 'aa:bb:cc:dd:ee:ff')
            (Get-RedactToken -Session $s -Type 'term-proj' -Original 'Alpha') | Should -Be '[term-proj-01]'
            (Get-RedactToken -Session $s -Type 'term-proj' -Original 'ALPHA') | Should -Be '[term-proj-01]'
        }
    }

    It 'records every new token and alias in Session.Entries, never a secret' {
        InModuleScope RedactOutput {
            $s = New-RedactSession -Config (Get-RedactConfig)
            $token = Get-RedactToken -Session $s -Type domain -Original 'ad.contoso.example'
            Add-RedactAlias -Session $s -Type domain -Original 'CONTOSO' -Token $token
            Add-RedactAlias -Session $s -Type domain -Original 'contoso' -Token '[domain-99]'
            (Get-RedactToken -Session $s -Type domain -Original 'Contoso') | Should -Be '[domain-01]'
            $s.Entries.Count | Should -Be 2
            $s.Entries[1].Token | Should -Be '[domain-01]'
            $s.Entries[1].Type | Should -Be 'domain'
            $null = Invoke-RedactText -Text 'password=FakeValue01' -Session $s
            $s.Entries.Count | Should -Be 2
        }
    }
}

Describe 'Sentinel restore' -Tag 'Unit' {
    It 'restores sentinels nested inside replacements, with a pass cap' {
        InModuleScope RedactOutput {
            $store = [System.Collections.Generic.List[string]]::new()
            $store.Add('inner')
            $store.Add((ConvertTo-RedactSentinel -Index 0) + '-outer')
            (Restore-RedactSentinel -Text ('<' + (ConvertTo-RedactSentinel -Index 1) + '>') -Store $store) | Should -Be '<inner-outer>'
            $store.Add((ConvertTo-RedactSentinel -Index 2))
            $loop = Restore-RedactSentinel -Text (ConvertTo-RedactSentinel -Index 2) -Store $store
            $loop.Length | Should -BeGreaterThan 0
        }
    }
}

Describe 'Residual check for identifiers and config literals' -Tag 'Unit' {
    It 'reports identifier categories without values' {
        $f = @('jdoe@contoso.example 198.51.100.7' | Test-RedactionResidual)
        ($f.Category | Sort-Object -Unique) -join ',' | Should -Be 'fqdn,ipv4,upn'
        $f[0].PSObject.Properties.Name -join ',' | Should -Be 'Category,Line,Column,Length'
    }

    It 'reports a config literal that no rule could replace, by config key' {
        $f = @("line one`nhost xcontoso.example and Project Placeholder-x and svc-example2" | Test-RedactionResidual)
        $f.Where({ $_.Category -eq 'internalDomains' }).Count | Should -Be 1
        $f.Where({ $_.Category -eq 'internalDomains' })[0].Line | Should -Be 2
        $f.Where({ $_.Category -eq 'internalDomains' })[0].Column | Should -Be 7
        $f.Category | Should -Contain 'extraTerms'
        $f.Category | Should -Contain 'usernames'
    }

    It 'finds nothing in redacted output, the mask hides allowlisted hosts from later rules' {
        $out = Invoke-TestRedact -Text "jdoe@contoso.example WS-1234 10.20.30.40 graph.microsoft.us"
        @($out | Test-RedactionResidual).Count | Should -Be 0
    }
}

Describe 'Fixtures and idempotency' -Tag 'Unit' {
    It 'redacts the sample dump, leaves nothing behind and is idempotent' {
        $text = (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Fixtures/sample-dump.txt') -Raw).TrimEnd()
        $once = Invoke-TestRedact -Text $text
        foreach ($value in 'jdoe', 'contoso', 'WS-1234', '10.20.30', '198.51.100', '1111111111', 'FakePassw0rd01', '11111111-2222', 'sql-contoso-01', 'kv-contoso-main', 'rg-contoso-prod', 'E12345', '5D-01-02-03', '1c2b:3d4e') {
            $once.Contains($value) | Should -BeFalse -Because "sample dump must redact '$value'"
        }
        foreach ($kept in 'graph.microsoft.us', 'login.microsoftonline.us', 'usgovvirginia', 'ENABLE_SIGNUP=false', '00000003-0000-0000-c000-000000000000', 'S-1-5-18', 'S-1-5-32-544', 'S-1-1-0', '255.255.255.0', 'CN=[name-01]', 'NT AUTHORITY\SYSTEM') {
            $once.Contains($kept) | Should -BeTrue -Because "sample dump must keep '$kept'"
        }
        (Invoke-TestRedact -Text $once) -ceq $once | Should -BeTrue
        @($once | Test-RedactionResidual).Count | Should -Be 0
    }

    It 'passes -Strict on the clean fixture without changing it' {
        $text = (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Fixtures/clean.txt') -Raw).TrimEnd()
        $out = $text | Protect-Output -Strict -NoAudit
        $out -ceq $text | Should -BeTrue
    }

    It 'fails -Strict on the planted-residual fixture' {
        $text = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Fixtures/residual.txt') -Raw
        { $text | Protect-Output -Strict -NoAudit } | Should -Throw '*residual finding*'
        @($text | Test-RedactionResidual).Category | Should -Be @('high-entropy')
    }
}
