# Pester scopes discovery data to the Describe below; the analyzer cannot see that usage.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'ruleCases is consumed by -ForEach during Pester discovery.')]
param()

BeforeDiscovery {
    $jwt = 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJmYWtlLXN1YmplY3QifQ.ZmFrZS1zaWduYXR1cmU'
    $hex64 = 'ab12' * 12
    $begin = '-----BEGIN ' + 'RSA PRIVATE KEY-----'
    $end = '-----END ' + 'RSA PRIVATE KEY-----'
    $storageKey = ('A1b2C3d4' * 10) + 'E5f6G7=='
    $ruleCases = @(
        @{ Name = 'S01 pem-key'; Label = 'pem-key'; Text = "before`n$begin`nFAKEFAKE0000`nFAKEFAKE1111`n$end`nafter"; Secret = 'FAKEFAKE0000'; Keep = @('before', 'after') }
        @{ Name = 'S16 dpapi'; Label = 'dpapi'; Text = "blob: 01000000d08c9ddf0115d1118c7a00c04fc297eb$hex64"; Secret = $hex64; Keep = @('blob: ') }
        @{ Name = 'S02 jwt'; Label = 'jwt'; Text = "jwt text $jwt end"; Secret = 'ZmFrZS1zaWduYXR1cmU'; Keep = @('jwt text ', ' end') }
        @{ Name = 'S07 url-cred (user:pass)'; Label = 'url-cred'; Text = 'url postgresql://appuser:FakePassw0rd@db.contoso.example:5432/x'; Secret = 'FakePassw0rd'; Keep = @('postgresql://', '@[host-01].[domain-01]:5432/x') }
        @{ Name = 'S07 url-cred (token-only userinfo)'; Label = 'url-cred'; Text = 'clone https://AbCdEfGhIjKlMnOpQrStUvWx@dev.contoso.example/repo.git'; Secret = 'AbCdEfGhIjKlMnOpQrStUvWx'; Keep = @('https://', '@[host-01].[domain-01]/repo.git') }
        @{ Name = 'S03 auth-header (Bearer)'; Label = 'auth-header'; Text = 'Authorization: Bearer abcdefghij0123456789ABCDEF'; Secret = 'abcdefghij0123456789ABCDEF'; Keep = @('Authorization: Bearer ') }
        @{ Name = 'S03 auth-header (Proxy Basic)'; Label = 'auth-header'; Text = 'Proxy-Authorization: Basic dXNlcjpGYWtlUGFzcw=='; Secret = 'dXNlcjpGYWtlUGFzcw'; Keep = @('Proxy-Authorization: Basic ') }
        @{ Name = 'S03 auth-header (bare Bearer)'; Label = 'auth-header'; Text = 'sent Bearer abcdefghij0123456789ABCDEF today'; Secret = 'abcdefghij0123456789ABCDEF'; Keep = @('sent Bearer ', ' today') }
        @{ Name = 'S05 connstr (Password)'; Label = 'connstr'; Text = 'Server=tcp:db.contoso.example;Database=app;Password=FakePassw0rd;User Id=app'; Secret = 'FakePassw0rd'; Keep = @('Server=tcp:[host-01].[domain-01];Database=app;Password=', ';User Id=app') }
        @{ Name = 'S05 connstr (AccountKey)'; Label = 'connstr'; Text = "DefaultEndpointsProtocol=https;AccountName=fakeacct;AccountKey=$storageKey;EndpointSuffix=core.usgovcloudapi.net"; Secret = 'A1b2C3d4A1b2'; Keep = @('AccountName=fakeacct;AccountKey=', ';EndpointSuffix=core.usgovcloudapi.net') }
        @{ Name = 'S06 sas-sig'; Label = 'sas-sig'; Text = 'https://fakeacct.blob.core.usgovcloudapi.net/c/b?sv=2020-08-04&sp=r&se=2030-01-01T00%3A00%3A00Z&st=2020-01-01&sig=FAKE%2Bsig%2Fvalue%3D'; Secret = 'FAKE%2Bsig'; Keep = @('sv=2020-08-04', 'sp=r', 'se=2030-01-01T00%3A00%3A00Z', 'st=2020-01-01', '&sig=') }
        @{ Name = 'S11 git-token (GitLab)'; Label = 'git-token'; Text = 'glab glpat-abcdefghij0123456789 end'; Secret = 'abcdefghij0123456789'; Keep = @('glab ', ' end') }
        @{ Name = 'S11 git-token (GitLab runner)'; Label = 'git-token'; Text = 'runner GR1348941abcdefghij0123456789 end'; Secret = 'abcdefghij0123456789'; Keep = @('runner ', ' end') }
        @{ Name = 'S11 git-token (GitHub)'; Label = 'git-token'; Text = ('gh ghp_' + ('aB3dE' * 8) + ' end'); Secret = 'aB3dEaB3dE'; Keep = @('gh ', ' end') }
        @{ Name = 'S11 git-token (GitHub fine-grained)'; Label = 'git-token'; Text = ('gh github_pat_' + ('aB3dE' * 12) + ' end'); Secret = 'aB3dEaB3dE'; Keep = @('gh ', ' end') }
        @{ Name = 'S10 api-key (sk-)'; Label = 'api-key'; Text = 'key sk-FAKEFAKEFAKEFAKEFAKE01 end'; Secret = 'FAKEFAKEFAKEFAKEFAKE01'; Keep = @('key ', ' end') }
        @{ Name = 'S10 api-key (sk-proj-)'; Label = 'api-key'; Text = 'key sk-proj-FAKEFAKEFAKEFAKEFAKE01 end'; Secret = 'FAKEFAKEFAKEFAKEFAKE01'; Keep = @('key ', ' end') }
        @{ Name = 'S09 entra-secret'; Label = 'entra-secret'; Text = ('cred fak7Q~' + ('AbCdEfGhIj' * 3) + '01 end'); Secret = 'AbCdEfGhIjAbCdEfGhIj'; Keep = @('cred ', ' end') }
        @{ Name = 'S08 storage-key'; Label = 'storage-key'; Text = "blobkey $storageKey end"; Secret = 'A1b2C3d4A1b2C3d4'; Keep = @('blobkey ', ' end') }
        @{ Name = 'S13 bitlocker'; Label = 'bitlocker'; Text = 'recovery 123456-234567-345678-456789-567890-678901-789012-890123 end'; Secret = '123456-234567'; Keep = @('recovery ', ' end') }
        @{ Name = 'S15 ntlm (pair)'; Label = 'ntlm'; Text = 'dump aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 end'; Secret = 'aad3b435b51404ee'; Keep = @('dump ', ' end') }
        @{ Name = 'S15 ntlm (keyed NT hash)'; Label = 'ntlm'; Text = 'NTHash: 31d6cfe0d16ae931b73c59d7e0c089c0'; Secret = '31d6cfe0d16ae931'; Keep = @('NTHash: ') }
        @{ Name = 'S14 laps (legacy attribute)'; Label = 'laps'; Text = "ms-Mcs-AdmPwd : FakeLapsPass!9`nms-Mcs-AdmPwdExpirationTime : 133000000000000000"; Secret = 'FakeLapsPass!9'; Keep = @('ms-Mcs-AdmPwd : ', 'ms-Mcs-AdmPwdExpirationTime : 133000000000000000') }
        @{ Name = 'S14 laps (Windows LAPS attribute)'; Label = 'laps'; Text = "msLAPS-Password : FakeLapsPass!9`nmsLAPS-PasswordExpirationTime : 133000000000000000"; Secret = 'FakeLapsPass!9'; Keep = @('msLAPS-Password : ', 'msLAPS-PasswordExpirationTime : 133000000000000000') }
        @{ Name = 'S14 laps (JSON p field)'; Label = 'laps'; Text = '{"n":"Administrator","t":"1d8c0ffee1234567","p":"FakeLapsPass!9"}'; Secret = 'FakeLapsPass!9'; Keep = @('{"n":"Administrator","t":"1d8c0ffee1234567","p":"', '"}') }
        @{ Name = 'S12 duo-skey'; Label = 'duo-skey'; Text = ('duo_skey = ' + ('aB3dE' * 8)); Secret = 'aB3dEaB3dE'; Keep = @('duo_skey = ') }
    )
}

BeforeAll {
    . $PSScriptRoot/TestHelpers.ps1
    $script:Neighbors = "graph.microsoft.us`nlogin.microsoftonline.us`nENABLE_SIGNUP=false"
}

AfterAll { Remove-Item -Path Env:REDACTOUTPUT_CONFIG_DIR -ErrorAction SilentlyContinue }

Describe 'S01-S16 secret rules' -Tag 'Unit' {
    It '<Name>: removes the value, adds [secret:<Label>], keeps the structure and allowlisted neighbors' -ForEach $ruleCases {
        $out = Invoke-TestRedact -Text "$script:Neighbors`n$Text"
        $out.Contains($Secret) | Should -BeFalse -Because "$Name must redact the value"
        $out.Contains("[secret:$Label]") | Should -BeTrue -Because "$Name must emit its own label"
        foreach ($kept in $Keep + @('graph.microsoft.us', 'login.microsoftonline.us', 'ENABLE_SIGNUP=false')) {
            $out.Contains($kept) | Should -BeTrue -Because "'$kept' must survive in $Name"
        }
    }

    It 'S01 without an END line redacts to the end of the input' {
        $out = Invoke-TestRedact -Text ("head`n" + (Get-TestPem -NoEnd) + "`ntail line")
        $out.Contains('FAKEFAKE') | Should -BeFalse
        $out.Contains('tail line') | Should -BeFalse
        $out.StartsWith("head`n[secret:pem-key]") | Should -BeTrue
    }

    It 'S01 does not match certificates or public keys' {
        $text = "-----BEGIN CERTIFICATE-----`nMIIFAKE`n-----END CERTIFICATE-----`n-----BEGIN PUBLIC KEY-----`nMIIFAKE`n-----END PUBLIC KEY-----"
        (Invoke-TestRedact -Text $text) -ceq $text | Should -BeTrue
    }

    It 'S02 wins the label over S03 when a JWT follows Bearer' {
        $out = Invoke-TestRedact -Text "Authorization: Bearer $(Get-TestJwt)"
        $out | Should -BeExactly 'Authorization: Bearer [secret:jwt]'
    }

    It 'S07 leaves ssh://git@host untouched' {
        $out = Invoke-TestRedact -Text 'git clone ssh://git@git.contoso.example/team/repo.git'
        $out | Should -BeExactly 'git clone ssh://git@[domain-01]/team/repo.git'
    }

    It 'S15 never touches a bare 32-hex value' {
        $text = 'checksum 31d6cfe0d16ae931b73c59d7e0c089c0'
        (Invoke-TestRedact -Text $text) -ceq $text | Should -BeTrue
    }

    It 'S14 leaves unrelated JSON p fields alone' {
        $text = '{"p":"keep-this","q":1}'
        (Invoke-TestRedact -Text $text) -ceq $text | Should -BeTrue
    }

    It 'S05 keeps variable references and empty values' {
        $text = "Password=`$env:DB_PW`nPwd=`nPassword=****"
        (Invoke-TestRedact -Text $text) -ceq $text | Should -BeTrue
    }
}

Describe 'S04 secret-named key/value' -Tag 'Unit' {
    It 'redacts env, INI, YAML and PowerShell table lines and keeps names and quotes' {
        $text = "export WEBUI_SECRET_KEY=FakeValue01`nAPI_TOKEN=`"fake value 02`"`nclient_secret = FakeValue03`npassword: FakeValue04`nPassword : FakeValue05"
        $out = Invoke-TestRedact -Text $text
        foreach ($v in 'FakeValue01', 'fake value 02', 'FakeValue03', 'FakeValue04', 'FakeValue05') { $out.Contains($v) | Should -BeFalse }
        $out | Should -BeExactly "export WEBUI_SECRET_KEY=[secret:kv]`nAPI_TOKEN=`"[secret:kv]`"`nclient_secret = [secret:kv]`npassword: [secret:kv]`nPassword : [secret:kv]"
    }

    It 'redacts JSON string properties, including escaped quotes' {
        $out = Invoke-TestRedact -Text '{"clientSecret": "Fake\"Value06", "name": "keep-me", "password":"FakeValue07"}'
        $out | Should -BeExactly '{"clientSecret": "[secret:kv]", "name": "keep-me", "password":"[secret:kv]"}'
    }

    It 'redacts NAME=VALUE inside JSON strings (docker inspect Env) and leaves other entries' {
        $out = Invoke-TestRedact -Text '"Env": ["WEBUI_SECRET_KEY=FakeValue08","ENABLE_SIGNUP=false","MODE=prod"]'
        $out | Should -BeExactly '"Env": ["WEBUI_SECRET_KEY=[secret:kv]","ENABLE_SIGNUP=false","MODE=prod"]'
    }

    It 'redacts PowerShell secret parameters, quoted or not, and skips variables' {
        $text = "Connect-Thing -ClientSecret FakeValue09 -User bob`nConnect-Thing -Password 'Fake Value 10'`nConnect-Thing -Token `$env:TOKEN -Key `$key -ApiKey `$(Get-Key)"
        $out = Invoke-TestRedact -Text $text
        $out | Should -BeExactly "Connect-Thing -ClientSecret [secret:kv] -User bob`nConnect-Thing -Password '[secret:kv]'`nConnect-Thing -Token `$env:TOKEN -Key `$key -ApiKey `$(Get-Key)"
    }

    It 'redacts XML elements, unattend Password/Value and attributes, and the output stays well-formed' {
        $xml = '<r><ApiKey>FakeValue11</ApiKey><Password><Value>FakeValue12</Value><PlainText>true</PlainText></Password><add secretName="FakeValue13" other="x"/></r>'
        $out = Invoke-TestRedact -Text $xml
        foreach ($v in 'FakeValue11', 'FakeValue12', 'FakeValue13') { $out.Contains($v) | Should -BeFalse }
        $out.Contains('<PlainText>true</PlainText>') | Should -BeTrue
        $out.Contains('other="x"') | Should -BeTrue
        { [xml]$out } | Should -Not -Throw
    }

    It 'skips empty, null-ish, mask and variable values and already-tokenized values' {
        $text = "password=`nsecret=`$null`ntoken=null`napikey=true`nkey=false`npwd=none`npassword=****`nsecret=`$env:X`ntoken=`$(Get-Token)`nkey=`$myKey`npassword: [secret:jwt]"
        (Invoke-TestRedact -Text $text) -ceq $text | Should -BeTrue
    }

    It 'leaves non-secret deny-list names untouched' {
        $text = "PasswordLastSet : 1/1/2024`nKeyVaultName : kv-fake`nKeyType: RSA`nTokenType : Bearer`nPasswordNeverExpires : False`nmsLAPS-PasswordExpirationTime : 133000000000000000"
        (Invoke-TestRedact -Text $text) -ceq $text | Should -BeTrue
    }

    It 'treats the bare name Key as a non-secret name (registry Format-List) and still tokenizes the GUID' {
        $out = Invoke-TestRedact -Text 'Key : HKEY_LOCAL_MACHINE\SOFTWARE\Example\{11111111-2222-3333-4444-555555555555}'
        $out | Should -BeExactly 'Key : HKEY_LOCAL_MACHINE\SOFTWARE\Example\{[guid-01]}'
    }

    It 'still redacts every longer name that contains key' {
        $names = 'ApiKey', 'AccessKey', 'AccountKey', 'client_key', 'SecretKey', 'KEY_FILE'
        foreach ($name in $names) {
            foreach ($separator in ' : ', '=') {
                $out = Invoke-TestRedact -Text "$name$($separator)FakeValue16"
                $out.Contains('FakeValue16') | Should -BeFalse -Because "$name must stay a secret name"
            }
        }
    }

    It 'no longer redacts an XML attribute named key, and a bare key= line is left to the S17 residual scan' {
        $xml = '<add key="Setting" value="x"/>'
        (Invoke-TestRedact -Text $xml) -ceq $xml | Should -BeTrue
        $line = 'key=' + 'k9Zq3XvB7mT2wLp8Rj5HcN1yD6sGa4UfE0Qw7Xe2'
        (Invoke-TestRedact -Text $line) -ceq $line | Should -BeTrue
        $f = @($line | Test-RedactionResidual)
        $f.Count | Should -Be 1
        $f[0].Category | Should -Be 'high-entropy'
    }

    It 'extends the deny-list and name list from config, case-insensitively' {
        $cfg = Write-TestConfig -Data @{ nonSecretNames = @('MyKeyName'); secretNames = @('badge_pin') }
        $out = Invoke-TestRedact -ConfigPath $cfg -Text "mykeyname=visible`nBADGE_PIN=FakeValue14`nMyKeyOther=FakeValue15"
        $out | Should -BeExactly "mykeyname=visible`nBADGE_PIN=[secret:kv]`nMyKeyOther=[secret:kv]"
    }

    It 'reports the specific label before kv when both apply' {
        $out = Invoke-TestRedact -Text 'OPENAI_API_KEY=sk-FAKEFAKEFAKEFAKEFAKE01'
        $out | Should -BeExactly 'OPENAI_API_KEY=[secret:api-key]'
    }
}

Describe 'bash redact() fixture' -Tag 'Unit' {
    It 'redacts the env fixture, leaves ENABLE_SIGNUP alone and tokenizes the internal WEBUI_URL host' {
        $text = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Fixtures/bash-env.env') -Raw
        $out = Invoke-TestRedact -Text $text.TrimEnd()
        foreach ($v in 'FAKEFAKEFAKEFAKEFAKE01', 'FakeSecretValue0123', 'FakePassw0rd', 'FakeOauthValue0123', 'FakeLowerCaseValue0123') {
            $out.Contains($v) | Should -BeFalse -Because 'fixture secrets must be redacted'
        }
        $expected = @(
            'OPENAI_API_KEYS=[secret:api-key];[secret:api-key]'
            'WEBUI_SECRET_KEY=[secret:kv]'
            'DATABASE_URL=postgresql://[secret:url-cred]@db:5432/x'
            'OAUTH_CLIENT_SECRET=[secret:kv]'
            'openai_api_key=[secret:kv]'
            'ENABLE_SIGNUP=false'
            'WEBUI_URL=https://[host-01].[domain-01]'
        ) -join "`n"
        $out -ceq $expected | Should -BeTrue
    }
}

Describe 'S17 high-entropy residual' -Tag 'Unit' {
    BeforeAll { $script:Entropic = 'k9Zq3XvB7mT2wLp8Rj5HcN1yD6sGa4UfE0' }

    It 'never changes the text but Test-RedactionResidual reports category, line, column and length' {
        $text = "line one`nvalue $script:Entropic end"
        (Invoke-TestRedact -Text $text) -ceq $text | Should -BeTrue
        $f = @($text | Test-RedactionResidual)
        $f.Count | Should -Be 1
        $f[0].Category | Should -Be 'high-entropy'
        $f[0].Line | Should -Be 2
        $f[0].Column | Should -Be 7
        $f[0].Length | Should -Be $script:Entropic.Length
        $f[0].PSObject.Properties.Name -join ',' | Should -Be 'Category,Line,Column,Length'
    }

    It 'counts GUID and 32/40/64-hex values as hash-like, not as findings' {
        $text = "00000000-0000-0000-0000-000000000000`n31d6cfe0d16ae931b73c59d7e0c089c0`n" + ('a1b2c3d4e5' * 4) + "`n" + ('a1b2c3d4e5f60718' * 4)
        @($text | Test-RedactionResidual).Count | Should -Be 0
        InModuleScope RedactOutput -Parameters @{ Text = $text } {
            $s = New-RedactSession -Config (Get-RedactConfig)
            [void](Find-RedactResidual -Text $Text -Session $s)
            $s.HashLike | Should -Be 4
        }
    }

    It 'reads a file with -Path and adds a Path property' {
        $file = Join-Path $TestDrive 'residual.txt'
        Set-Content -LiteralPath $file -Value "x $script:Entropic y"
        $f = @(Test-RedactionResidual -LiteralPath $file)
        $f.Count | Should -Be 1
        $f[0].Path | Should -Be $file
    }

    It 'finds nothing in clean text' {
        @('just a plain sentence with graph.microsoft.us in it' | Test-RedactionResidual).Count | Should -Be 0
    }

    It 'finds an unredacted secret-named value and a redacted result is clean' {
        $text = 'db_password=FakeValue16'
        @($text | Test-RedactionResidual | ForEach-Object Category) | Should -Be @('kv')
        @((Invoke-TestRedact -Text $text) | Test-RedactionResidual).Count | Should -Be 0
    }
}

Describe 'Engine behavior' -Tag 'Unit' {
    It 'leaves existing tokens alone, including digits and hex inside them' {
        $text = 'see [guid-03] [ip-priv-01]/24 [sid-dom-01] [secret:jwt] [term-PROJECT-02] and [host-12].[domain-01]'
        (Invoke-TestRedact -Text $text) -ceq $text | Should -BeTrue
    }

    It 'is idempotent over a multi-secret fixture' {
        $fixture = @(
            (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Fixtures/bash-env.env') -Raw)
            Get-TestPem
            "Authorization: Bearer $(Get-TestJwt)"
            'Server=x;Password=FakePassw0rd;'
            '{"clientSecret": "FakeValue17", "Env": ["A_TOKEN=FakeValue18"]}'
            "ms-Mcs-AdmPwd : FakeLapsPass!9"
        ) -join "`n"
        $once = Invoke-TestRedact -Text $fixture
        $twice = Invoke-TestRedact -Text $once
        $twice -ceq $once | Should -BeTrue
        $once.Contains('FakePassw0rd') | Should -BeFalse
    }

    It 'preserves CRLF line endings and the final newline' {
        $text = "db_password=FakeValue19`r`nname=keep`r`n"
        (Invoke-TestRedact -Text $text) -ceq "db_password=[secret:kv]`r`nname=keep`r`n" | Should -BeTrue
    }

    It 'redacts several matches per line and across lines' {
        $out = Invoke-TestRedact -Text "a ghp_$('aB3dE' * 8) b ghp_$('cD4eF' * 8) c`nsk-FAKEFAKEFAKEFAKEFAKE01"
        $out | Should -BeExactly "a [secret:git-token] b [secret:git-token] c`n[secret:api-key]"
    }

    It 'builds every regex with Compiled, CultureInvariant and a 2 second timeout' {
        InModuleScope RedactOutput {
            $r = New-RedactRegex -Pattern 'a' -IgnoreCase
            $r.MatchTimeout.TotalSeconds | Should -Be 2
            $r.Options.HasFlag([System.Text.RegularExpressions.RegexOptions]::Compiled) | Should -BeTrue
            $r.Options.HasFlag([System.Text.RegularExpressions.RegexOptions]::CultureInvariant) | Should -BeTrue
            $r.Options.HasFlag([System.Text.RegularExpressions.RegexOptions]::IgnoreCase) | Should -BeTrue
            (New-RedactRegex -Pattern 'a').Options.HasFlag([System.Text.RegularExpressions.RegexOptions]::IgnoreCase) | Should -BeFalse
        }
    }

    It 'orders the secret rules as specified' {
        InModuleScope RedactOutput {
            (@(Get-RedactSecretRule).Label -join ',') | Should -Be 'pem-key,dpapi,jwt,url-cred,auth-header,connstr,sas-sig,git-token,api-key,entra-secret,storage-key,bitlocker,ntlm,laps,duo-skey,kv'
        }
    }

    It 'converts offsets to 1-based line and column' {
        InModuleScope RedactOutput {
            $p = ConvertTo-LineColumn -Text "ab`ncde`nf" -Offset 4
            $p.Line | Should -Be 2
            $p.Column | Should -Be 2
            (ConvertTo-LineColumn -Text 'abc' -Offset 0).Column | Should -Be 1
        }
    }

    It 'throws naming only the rule when a regex times out' {
        InModuleScope RedactOutput {
            $rule = @{ Id = 'SXX'; Label = 'slow'; Regex = [regex[]]@([regex]::new('(a+)+$', 'None', [timespan]::FromMilliseconds(20))) }
            $s = New-RedactSession -Config (Get-RedactConfig)
            $err = $null
            try { Get-RedactSpan -Text (('a' * 40) + '!') -Rule $rule -Session $s } catch { $err = $_ }
            $err | Should -Not -BeNullOrEmpty
            $err.Exception.Message | Should -Be 'Rule SXX exceeded the regex time limit.'
        }
    }
}

Describe 'Protect-Output behavior' -Tag 'Unit' {
    It 'renders non-string objects with Out-String and redacts them' {
        $out = [pscustomobject]@{ Name = 'app'; Id = 1; Owner = 'ops'; Region = 'one'; ApiKey = 'FakeValue20' } | Protect-Output -NoAudit
        $out.Contains('FakeValue20') | Should -BeFalse
        $out.Contains('[secret:kv]') | Should -BeTrue
    }

    It 'joins pipeline strings with newlines into one output string' {
        $out = @('a=1', 'db_password=FakeValue21') | Protect-Output -NoAudit
        $out | Should -BeExactly "a=1`ndb_password=[secret:kv]"
    }

    It 'emits one warning per residual finding without the value' {
        $text = "ok`nvalue $script:Entropic"
        $null = $text | Protect-Output -NoAudit -WarningVariable w -WarningAction SilentlyContinue
        @($w).Count | Should -Be 1
        $w[0].Message | Should -Be 'Residual high-entropy at line 2, column 7, length 34'
    }

    It '-Strict throws on a planted residual and writes no audit row' {
        $audit = Join-Path $TestDrive 'strict-audit.csv'
        { "value $script:Entropic" | Protect-Output -Strict -AuditPath $audit } | Should -Throw '*residual finding*'
        Test-Path -LiteralPath $audit | Should -BeFalse
    }

    It '-Strict does not throw on clean redacted input' {
        { 'password=FakeValue22' | Protect-Output -Strict -NoAudit } | Should -Not -Throw
    }

    It '-WhatIf emits no text, writes no audit file and reports counts only' {
        $audit = Join-Path $TestDrive 'whatif-audit.csv'
        $info = & { 'db_password=FakeValue23' | Protect-Output -WhatIf -AuditPath $audit } 6>&1
        @($info | Where-Object { $_ -isnot [System.Management.Automation.InformationRecord] }).Count | Should -Be 0
        $joined = ($info | ForEach-Object { "$_" }) -join "`n"
        $joined.Contains('kv: 1') | Should -BeTrue
        $joined.Contains('FakeValue23') | Should -BeFalse
        Test-Path -LiteralPath $audit | Should -BeFalse
    }

    It 'rejects a missing -ConfigPath file without echoing anything' {
        { 'x' | Protect-Output -NoAudit -ConfigPath (Join-Path $TestDrive 'nope.json') } | Should -Throw '*-ConfigPath*'
    }
}

Describe 'Audit log' -Tag 'Unit' {
    It 'writes a stable header, one row per run and never a secret value' {
        $audit = Join-Path $TestDrive 'sub/audit.csv'
        $null = 'db_password=FakeValue24' | Protect-Output -AuditPath $audit
        $null = 'token=FakeValue25' | Protect-Output -AuditPath $audit -Strict
        $raw = Get-Content -LiteralPath $audit
        $raw.Count | Should -Be 3
        $labels = InModuleScope RedactOutput { (New-RedactSession -Config (Get-RedactConfig)).Counts.Keys }
        $expected = @('timestamp_utc', 'operator', 'input_source', 'input_sha256', 'output_path') + $labels + @('residual_findings', 'strict')
        $rows = Import-Csv -LiteralPath $audit
        $rows.Count | Should -Be 2
        ($rows[0].PSObject.Properties.Name -join ',') | Should -Be ($expected -join ',')
        $rows[0].kv | Should -Be '1'
        $rows[0].input_source | Should -Be 'pipeline'
        $rows[0].input_sha256.Length | Should -Be 64
        $rows[0].strict | Should -Be 'False'
        $rows[1].strict | Should -Be 'True'
        $joined = $raw -join "`n"
        $joined.Contains('FakeValue24') | Should -BeFalse
        $joined.Contains('FakeValue25') | Should -BeFalse
    }

    It '-NoAudit writes nothing' {
        $audit = Join-Path $TestDrive 'noaudit.csv'
        $null = 'password=FakeValue26' | Protect-Output -NoAudit -AuditPath $audit
        Test-Path -LiteralPath $audit | Should -BeFalse
    }
}

Describe 'Config layering' -Tag 'Unit' {
    BeforeEach {
        $script:Dir = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:Dir | Out-Null
        $env:REDACTOUTPUT_CONFIG_DIR = $script:Dir
    }
    AfterEach { $env:REDACTOUTPUT_CONFIG_DIR = $script:ConfigDir }

    It 'applies defaults < sample < local < -ConfigPath < -Override; arrays replace, categories merge' {
        '{"secretNames":["a"],"nonSecretNames":["n1"],"categories":{"x":true,"y":true}}' | Set-Content (Join-Path $script:Dir 'redact.config.sample.json')
        '{"secretNames":["b"],"categories":{"y":false}}' | Set-Content (Join-Path $script:Dir 'redact.config.local.json')
        $extra = Join-Path $TestDrive 'layer3.json'
        '{"secretNames":["c"],"_comment":"ignored","categories":{"z":true}}' | Set-Content $extra
        $result = InModuleScope RedactOutput -Parameters @{ Extra = $extra } {
            Get-RedactConfig -ConfigPath $Extra -Override @{ nonSecretNames = @('o') }
        }
        $result['secretNames'] | Should -Be @('c')
        $result['nonSecretNames'] | Should -Be @('o')
        $result['categories']['x'] | Should -BeTrue
        $result['categories']['y'] | Should -BeFalse
        $result['categories']['z'] | Should -BeTrue
        $result.ContainsKey('_comment') | Should -BeFalse
    }

    It 'returns defaults when no config files exist' {
        $result = InModuleScope RedactOutput { Get-RedactConfig }
        @($result['secretNames']).Count | Should -Be 0
        @($result['nonSecretNames']).Count | Should -Be 0
    }

    It 'names the layer, not the content, when a file is malformed' {
        '{ "secretNames": [ CANARYCONTENT' | Set-Content (Join-Path $script:Dir 'redact.config.local.json')
        $err = $null
        try { InModuleScope RedactOutput { Get-RedactConfig } } catch { $err = $_ }
        $err | Should -Not -BeNullOrEmpty
        $err.Exception.Message.Contains("'local'") | Should -BeTrue
        $err.Exception.Message.Contains('CANARYCONTENT') | Should -BeFalse
    }
}
