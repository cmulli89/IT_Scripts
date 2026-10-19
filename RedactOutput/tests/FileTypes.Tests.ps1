BeforeAll {
    . $PSScriptRoot/TestHelpers.ps1
    $script:Fixtures = Join-Path $PSScriptRoot 'Fixtures'
    $script:In = Join-Path $TestDrive 'in'
    New-Item -ItemType Directory -Path $script:In -Force | Out-Null

    # Fixtures are copied first, so outputs never land in the repo.
    function Copy-TestFixture {
        param([Parameter(Mandatory)][string]$Name)
        Copy-Item -LiteralPath (Join-Path $script:Fixtures $Name) -Destination $script:In -Force
        Join-Path $script:In $Name
    }

    function Write-TestFile {
        param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][byte[]]$Byte)
        $path = Join-Path $script:In $Name
        [System.IO.File]::WriteAllBytes($path, $Byte)
        $path
    }

    # Runs the file path quietly; returns the Result object.
    function Invoke-TestFile {
        param([Parameter(Mandatory)][string]$Path, [hashtable]$Extra = @{})
        Protect-Output -LiteralPath $Path -NoAudit -PassThru -Force -WarningAction SilentlyContinue @Extra
    }

    function Read-TestText {
        param([Parameter(Mandatory)][string]$Path)
        [System.IO.File]::ReadAllText($Path)
    }

    function Get-TestJsonShape {
        param($Node, [string]$Path = '$')
        if ($Node -is [System.Collections.IDictionary]) { foreach ($k in $Node.Keys) { Get-TestJsonShape -Node $Node[$k] -Path "$Path.$k" } }
        elseif ($Node -is [System.Collections.IList]) {
            "$Path[]=$($Node.Count)"
            for ($i = 0; $i -lt $Node.Count; $i++) { Get-TestJsonShape -Node $Node[$i] -Path "$Path[$i]" }
        }
        else { $Path }
    }

    function ConvertTo-TestRegHex {
        param([Parameter(Mandatory)][string]$Text)
        $bytes = [System.Text.Encoding]::Unicode.GetBytes($Text + [char]0)
        $pairs = foreach ($b in $bytes) { $b.ToString('x2') }
        $lines = for ($i = 0; $i -lt $pairs.Count; $i += 12) { ($pairs[$i..([math]::Min($i + 11, $pairs.Count - 1))] -join ',') }
        $lines -join ",\`r`n  "
    }
}

AfterAll { Remove-Item -Path Env:REDACTOUTPUT_CONFIG_DIR -ErrorAction SilentlyContinue }

Describe 'JSON' -Tag 'Unit' {
    BeforeAll {
        $script:JsonPath = Copy-TestFixture -Name 'graph-users.json'
        $script:JsonResult = Invoke-TestFile -Path $script:JsonPath
        $script:JsonText = Read-TestText -Path $script:JsonResult.OutPath
        $script:JsonOut = $script:JsonText | ConvertFrom-Json -AsHashtable
    }

    It 'writes <base>.redacted<ext> that parses and keeps key paths and array lengths' {
        $script:JsonResult.OutPath | Should -Be (Join-Path $script:In 'graph-users.redacted.json')
        $script:JsonResult.DetectedType | Should -Be 'json'
        $inData = Get-Content -LiteralPath $script:JsonPath -Raw | ConvertFrom-Json -AsHashtable
        $inData.Remove('byDevice')
        $outData = $script:JsonText | ConvertFrom-Json -AsHashtable
        $outData.Remove('byDevice')
        (Get-TestJsonShape -Node $outData) -join '|' | Should -Be ((Get-TestJsonShape -Node $inData) -join '|')
    }

    It 'replaces every string under a secret-named property and keeps booleans' {
        $passwordProfile = $script:JsonOut['value'][0]['passwordProfile']
        $passwordProfile['password'] | Should -Be '[secret:kv]'
        $passwordProfile['notes'] -join ',' | Should -Be '[secret:kv],[secret:kv]'
        $passwordProfile['forceChangePasswordNextSignIn'] | Should -BeTrue
        $script:JsonOut['value'][0]['keyCredentials'][0]['displayName'] | Should -Be '[secret:kv]'
        $script:JsonText.Contains('FakePassw0rd') | Should -BeFalse
    }

    It 'tokenizes displayName only in an object that has userPrincipalName or mail' {
        $script:JsonOut['value'][0]['displayName'] | Should -Match '^\[name-[0-9]{2}\]$'
        $script:JsonOut['value'][1]['displayName'] | Should -Be 'Helpdesk Team'
        $script:JsonOut['value'][0]['givenName'] | Should -Match '^\[name-[0-9]{2}\]$'
        $script:JsonOut['value'][0]['businessPhones'].Count | Should -Be 2
        $script:JsonOut['value'][0]['businessPhones'][0] | Should -Match '^\[phone-[0-9]{2}\]$'
        $script:JsonOut['value'][0]['employeeId'] | Should -Match '^\[emp-[0-9]{2}\]$'
    }

    It 'tokenizes values and property names, keeps first-party GUIDs and allowlisted endpoints' {
        $script:JsonOut['value'][0]['userPrincipalName'] | Should -Be '[user-01]@[domain-01]'
        $script:JsonOut['value'][1]['id'] | Should -Be '00000003-0000-0000-c000-000000000000'
        $script:JsonOut['value'][0]['endpoint'] | Should -Match '^https://login\.microsoftonline\.us/\[guid-[0-9]{2}\]/oauth2/v2\.0/token$'
        @($script:JsonOut['byDevice'].Keys)[0] | Should -Match '^\[guid-[0-9]{2}\]$'
        $script:JsonText.Contains('22222222-3333-4444-5555-666666666666') | Should -BeFalse
    }

    It 'tokenizes displayName only when userPrincipalName or mail is a non-empty string' {
        $path = Join-Path $script:In 'names.json'
        Set-Content -LiteralPath $path -Value '[{"displayName":"Printers","mail":null},{"displayName":"Lab","mail":"","userPrincipalName":null},{"displayName":"Jane Q","mail":"jane.q@contoso.example"},{"displayName":"Sam R","userPrincipalName":"sam.r@contoso.example"}]'
        $out = (Read-TestText -Path (Invoke-TestFile -Path $path).OutPath) | ConvertFrom-Json
        $out[0].displayName | Should -Be 'Printers'
        $out[1].displayName | Should -Be 'Lab'
        $out[2].displayName | Should -Match '^\[name-[0-9]{2}\]$'
        $out[3].displayName | Should -Match '^\[name-[0-9]{2}\]$'
    }

    It 'round-trips dates, large integers, decimals and key order unchanged' {
        $path = Join-Path $script:In 'fidelity.json'
        $json = '{"zeta":1,"createdDateTime":"2026-03-04T05:06:07+02:00","big":12345678901234567890123,"price":1.10,"alpha":[0.5,"2026-03-04T05:06:07.1230000Z"],"mid":null}'
        Set-Content -LiteralPath $path -Value $json
        $out = Read-TestText -Path (Invoke-TestFile -Path $path).OutPath
        foreach ($kept in '"createdDateTime": "2026-03-04T05:06:07+02:00"', '"big": 12345678901234567890123', '"price": 1.10', '"2026-03-04T05:06:07.1230000Z"', '"mid": null') {
            $out.Contains($kept) | Should -BeTrue -Because "$kept must survive unchanged"
        }
        $out.IndexOf('"zeta"') | Should -BeLessThan $out.IndexOf('"createdDateTime"')
        $out.IndexOf('"createdDateTime"') | Should -BeLessThan $out.IndexOf('"alpha"')
        $piped = ([pscustomobject]@{ when = '2026-03-04T05:06:07+02:00'; n = 1.10 }) | Protect-Output -As Json -NoAudit
        $piped.Contains('2026-03-04T05:06:07+02:00') | Should -BeTrue
    }

    It 'keeps a single-element top-level array an array' {
        $path = Join-Path $script:In 'one.json'
        Set-Content -LiteralPath $path -Value '[ { "mail": "a.b@contoso.example" } ]'
        $out = Read-TestText -Path (Invoke-TestFile -Path $path).OutPath
        ($out | ConvertFrom-Json -NoEnumerate) -is [System.Array] | Should -BeTrue
        $out.Contains('contoso.example') | Should -BeFalse
    }

    It 'falls back to text with a warning that names the type, never the content' {
        $path = Join-Path $script:In 'broken.json'
        Set-Content -LiteralPath $path -Value '{ "password": "FakeBrokenPass1", '
        $warnings = $null
        $result = Protect-Output -LiteralPath $path -NoAudit -PassThru -Force -WarningVariable warnings -WarningAction SilentlyContinue
        ($warnings -join '|') | Should -Match 'Could not parse the input as json'
        ($warnings -join '|').Contains('FakeBrokenPass1') | Should -BeFalse
        (Read-TestText -Path $result.OutPath).Contains('FakeBrokenPass1') | Should -BeFalse
    }

    It 'is idempotent' {
        $second = Invoke-TestFile -Path $script:JsonResult.OutPath -Extra @{ OutFile = (Join-Path $script:In 'twice.json') }
        (Read-TestText -Path $second.OutPath) | Should -Be $script:JsonText
    }
}

Describe 'JSONL' -Tag 'Unit' {
    It 'keeps one record per line with the same count and terminators' {
        $path = Copy-TestFixture -Name 'events.jsonl'
        $raw = (Read-TestText -Path $path).TrimEnd() -replace "`r?`n", "`r`n"
        [System.IO.File]::WriteAllText($path, $raw + "`r`n")
        $out = Read-TestText -Path (Invoke-TestFile -Path $path).OutPath
        $lines = $out -split "`r`n"
        $lines.Count | Should -Be 4
        $lines[3] | Should -Be ''
        ($out -split "`n").Count | Should -Be 4
        { $lines[0] | ConvertFrom-Json } | Should -Not -Throw
        $lines[0].Contains('FakeSecretValue123') | Should -BeFalse
        $lines[0].Contains('[secret:kv]') | Should -BeTrue
        $lines[1] | Should -Match '^plain text line from host \[host-[0-9]{2}\] with no JSON$'
        $lines[2].Contains('192.0.2.10') | Should -BeFalse
    }
}

Describe 'CSV and TSV' -Tag 'Unit' {
    BeforeAll {
        $script:CsvPath = Copy-TestFixture -Name 'users.csv'
        $script:CsvOut = Read-TestText -Path (Invoke-TestFile -Path $script:CsvPath).OutPath
    }

    It 'copies the header byte for byte' {
        $header = (Read-TestText -Path $script:CsvPath) -split "`n" | Select-Object -First 1
        ($script:CsvOut -split "`n" | Select-Object -First 1) | Should -BeExactly $header
    }

    It 'keeps column counts and quoted commas, and replaces the secret-named column' {
        $in = Get-Content -LiteralPath $script:CsvPath -Raw | ConvertFrom-Csv
        $out = $script:CsvOut | ConvertFrom-Csv
        @($out).Count | Should -Be @($in).Count
        @($out[0].PSObject.Properties).Count | Should -Be 4
        $out[0].Name | Should -Be 'Example, Jane'
        $out[0].'Api Key' | Should -Be '[secret:kv]'
        $out[1].'Api Key' | Should -Be ''
        $out[0].Email | Should -Be '[user-01]@[domain-01]'
        $out[0].Notes | Should -Be 'said "hello" to [host-01]'
        $script:CsvOut.Contains('FakeKeyValue123') | Should -BeFalse
    }

    It 'keeps embedded newlines, a missing final newline and sniffs the delimiter' {
        $path = Join-Path $script:In 'semi.csv'
        [System.IO.File]::WriteAllText($path, "a;pwd;c`r`n1;FakeSemiPass1;`"two`r`nlines`"`r`n2;;x")
        $out = Read-TestText -Path (Invoke-TestFile -Path $path).OutPath
        $out | Should -Be "a;pwd;c`r`n1;[secret:kv];`"two`r`nlines`"`r`n2;;x"
    }

    It 'handles .tsv with tab as the delimiter' {
        $path = Join-Path $script:In 'data.tsv'
        [System.IO.File]::WriteAllText($path, "host`tpassword`nWS-1234`tFakeTabPass1`n")
        $result = Invoke-TestFile -Path $path
        $result.DetectedType | Should -Be 'tsv'
        Read-TestText -Path $result.OutPath | Should -Be "host`tpassword`n[host-01]`t[secret:kv]`n"
    }

    It 'falls back to text with a warning for ragged rows and duplicate headers' {
        foreach ($case in @{ Name = 'ragged.csv'; Text = "a,b,c`n1,2`n" }, @{ Name = 'dupe.csv'; Text = "a,A`n1,2`n" }) {
            $path = Join-Path $script:In $case.Name
            [System.IO.File]::WriteAllText($path, $case.Text)
            $warnings = $null
            $null = Protect-Output -LiteralPath $path -NoAudit -Force -WarningVariable warnings -WarningAction SilentlyContinue
            ($warnings -join '|') | Should -Match 'Could not parse the input as csv'
        }
    }
}

Describe 'XML' -Tag 'Unit' {
    It 'keeps a gpresult-like document well-formed and replaces secret-named values' {
        $path = Copy-TestFixture -Name 'gpresult-like.xml'
        $out = Read-TestText -Path (Invoke-TestFile -Path $path).OutPath
        { [xml]$out } | Should -Not -Throw
        foreach ($secret in 'FakeProxyPass1', 'FakeAddValue1', 'FakeCdataValue1') { $out.Contains($secret) | Should -BeFalse -Because 'secret-named XML values are redacted' }
        $out.Contains('<KeyUsage>DigitalSignature</KeyUsage>') | Should -BeTrue
        $out.Contains('ad.contoso.example') | Should -BeFalse
        $out.Contains('S-1-5-21-1111111111') | Should -BeFalse
        $out.Contains('Name="ProxyPassword"') | Should -BeTrue
    }

    It 'replaces unattend passwords and keeps the document well-formed' {
        $path = Copy-TestFixture -Name 'unattend-like.xml'
        $out = Read-TestText -Path (Invoke-TestFile -Path $path).OutPath
        { [xml]$out } | Should -Not -Throw
        $out.Contains('FakeAutoLogon1') | Should -BeFalse
        $out.Contains('FakeAdminPass1') | Should -BeFalse
        $out.Contains('<Username>installer</Username>') | Should -BeTrue
        ([xml]$out).unattend.settings.component.AutoLogon.Password.Value | Should -Be '[secret:kv]'
    }
}

Describe 'key=value files' -Tag 'Unit' {
    It 'redacts credentials in comments and list items as well as plain lines' {
        $path = Copy-TestFixture -Name 'app.yaml'
        $out = Read-TestText -Path (Invoke-TestFile -Path $path).OutPath
        foreach ($secret in 'FakeCommentPass1', 'FakeYamlPass1', 'FakeListKey1') { $out.Contains($secret) | Should -BeFalse -Because 'keyvalue files redact comments and list items' }
        $out.Contains('  # password: [secret:kv]') | Should -BeTrue
        $out.Contains('  - api_key: [secret:kv]') | Should -BeTrue
        $out.Contains('- name: example') | Should -BeTrue
    }

    It 'treats a .env file like the bash redact() fixture requires' {
        $path = Copy-TestFixture -Name 'bash-env.env'
        $result = Invoke-TestFile -Path $path
        $result.DetectedType | Should -Be 'keyvalue'
        $out = Read-TestText -Path $result.OutPath
        $out.Contains('ENABLE_SIGNUP=false') | Should -BeTrue
    }
}

Describe '.reg dumps' -Tag 'Unit' {
    BeforeAll {
        $lines = @(
            'Windows Registry Editor Version 5.00'
            ''
            '[HKEY_LOCAL_MACHINE\SOFTWARE\Contoso]'
            '"Name"="demo"'
            '"Password"="FakeRegPass1"'
            '"Path"=hex(2):' + (ConvertTo-TestRegHex -Text 'C:\Tools\ws-1234.ad.contoso.example\bin')
            '"Setting"=hex(2):' + (ConvertTo-TestRegHex -Text 'password=FakeHexPass1')
            '"Plain"=hex(2):' + (ConvertTo-TestRegHex -Text 'C:\Windows\System32')
            '"Blob"=hex:01,02,03'
            ''
        )
        $script:RegBenignHex = ConvertTo-TestRegHex -Text 'C:\Windows\System32'
        $script:RegHostHex = ConvertTo-TestRegHex -Text 'ws-1234'
        $content = $lines -join "`r`n"
        $path = Write-TestFile -Name 'export.reg' -Byte ([byte[]](0xFF, 0xFE) + [System.Text.Encoding]::Unicode.GetBytes($content))
        $script:RegResult = Invoke-TestFile -Path $path
        $script:RegBytes = [System.IO.File]::ReadAllBytes($script:RegResult.OutPath)
        $script:RegOut = [System.Text.Encoding]::Unicode.GetString($script:RegBytes, 2, $script:RegBytes.Length - 2)
    }

    It 'keeps the UTF-16LE BOM and CRLF' {
        $script:RegResult.DetectedType | Should -Be 'reg'
        $script:RegResult.Encoding | Should -Be 'utf-16 (BOM)'
        $script:RegBytes[0] | Should -Be 0xFF
        $script:RegBytes[1] | Should -Be 0xFE
        ($script:RegOut -split "`n").Count - 1 | Should -Be (($script:RegOut -split "`r`n").Count - 1)
    }

    It 'replaces a REG_SZ secret' {
        $script:RegOut.Contains('FakeRegPass1') | Should -BeFalse
        $script:RegOut.Contains('"Password"="[secret:kv]"') | Should -BeTrue
    }

    It 'replaces a hex(2) value that holds an internal host with its token and one that holds a secret with [secret:reg-hex]' {
        $script:RegOut.Contains('77,00,73,00,2d,00') | Should -BeFalse
        $script:RegOut | Should -Match '"Path"=hex\(2\):\[host-[0-9]{2}\]'
        $script:RegOut.Contains('"Setting"=hex(2):[secret:reg-hex]') | Should -BeTrue
    }

    It 'leaves a hex value that no rule changes untouched' {
        $script:RegOut.Contains($script:RegBenignHex) | Should -BeTrue
        $script:RegOut.Contains('"Blob"=hex:01,02,03') | Should -BeTrue
    }
}

Describe 'HTML' -Tag 'Unit' {
    It 'warns with a count of base64 data URIs and redacts the text' {
        $path = Copy-TestFixture -Name 'page.html'
        $warnings = $null
        $result = Protect-Output -LiteralPath $path -NoAudit -PassThru -Force -WarningVariable warnings -WarningAction SilentlyContinue
        $result.DetectedType | Should -Be 'html'
        ($warnings -join '|') | Should -Match '1 base64 data: URI'
        (Read-TestText -Path $result.OutPath).Contains('contoso.example') | Should -BeFalse
    }
}

Describe 'Encoding and line endings' -Tag 'Unit' {
    It 'keeps a UTF-8 BOM' {
        $bytes = [byte[]](0xEF, 0xBB, 0xBF) + [System.Text.Encoding]::UTF8.GetBytes("user jane.example@contoso.example`r`n")
        $result = Invoke-TestFile -Path (Write-TestFile -Name 'bom8.txt' -Byte $bytes)
        $out = [System.IO.File]::ReadAllBytes($result.OutPath)
        ($out[0..2] -join ',') | Should -Be '239,187,191'
        $out[3] | Should -Not -Be 0xEF
        $result.Encoding | Should -Be 'utf-8 (BOM)'
    }

    It 'keeps UTF-8 without a BOM and non-ASCII text' {
        $text = "caf$([char]0x00E9) user jane.example@contoso.example"
        $result = Invoke-TestFile -Path (Write-TestFile -Name 'nobom8.txt' -Byte ([System.Text.Encoding]::UTF8.GetBytes($text)))
        $out = [System.IO.File]::ReadAllBytes($result.OutPath)
        $out[0] | Should -Be ([byte][char]'c')
        (Read-TestText -Path $result.OutPath).StartsWith("caf$([char]0x00E9) user ") | Should -BeTrue
        $result.Encoding | Should -Be 'utf-8'
    }

    It 'round-trips UTF-16BE and UTF-32LE with their BOMs' {
        $text = "user jane.example@contoso.example`r`n"
        $be = [byte[]](0xFE, 0xFF) + [System.Text.Encoding]::BigEndianUnicode.GetBytes($text)
        $le32 = [byte[]](0xFF, 0xFE, 0, 0) + [System.Text.UTF32Encoding]::new($false, $false).GetBytes($text)
        $outBe = [System.IO.File]::ReadAllBytes((Invoke-TestFile -Path (Write-TestFile -Name 'be.txt' -Byte $be)).OutPath)
        $out32 = [System.IO.File]::ReadAllBytes((Invoke-TestFile -Path (Write-TestFile -Name 'u32.txt' -Byte $le32)).OutPath)
        ($outBe[0..1] -join ',') | Should -Be '254,255'
        ($out32[0..3] -join ',') | Should -Be '255,254,0,0'
        [System.Text.Encoding]::BigEndianUnicode.GetString($outBe, 2, $outBe.Length - 2).Contains('contoso') | Should -BeFalse
    }

    It 'decodes invalid UTF-8 as Windows-1252 with a warning' {
        $bytes = [System.Text.Encoding]::ASCII.GetBytes('caf') + [byte[]](0xE9) + [System.Text.Encoding]::ASCII.GetBytes(" user jane.example@contoso.example`n")
        $path = Write-TestFile -Name 'cp1252.txt' -Byte $bytes
        $warnings = $null
        $result = Protect-Output -LiteralPath $path -NoAudit -PassThru -Force -WarningVariable warnings -WarningAction SilentlyContinue
        ($warnings -join '|') | Should -Match 'decoded as Windows-1252'
        $result.Encoding | Should -Be 'windows-1252'
        [System.IO.File]::ReadAllBytes($result.OutPath)[3] | Should -Be 0xE9
    }

    It 'refuses BOM-less UTF-16 and suggests -Encoding Unicode, which then works' {
        $path = Write-TestFile -Name 'utf16.txt' -Byte ([System.Text.Encoding]::Unicode.GetBytes("user jane.example@contoso.example`r`nsecond line`r`n"))
        { Protect-Output -LiteralPath $path -NoAudit } | Should -Throw '*-Encoding Unicode*'
        $result = Invoke-TestFile -Path $path -Extra @{ Encoding = 'Unicode' }
        $bytes = [System.IO.File]::ReadAllBytes($result.OutPath)
        $bytes[0] | Should -Not -Be 0xFF
        [System.Text.Encoding]::Unicode.GetString($bytes).Contains('contoso') | Should -BeFalse
    }

    It 'refuses a binary file with the hint, by extension and by NUL sniffing' {
        $byExtension = Write-TestFile -Name 'archive.zip' -Byte ([byte[]](0x50, 0x4B, 3, 4))
        $bySniff = Write-TestFile -Name 'blob.dat' -Byte ([byte[]](1, 0, 2, 0, 0, 0, 7, 9, 0, 0, 0, 255, 0, 0))
        { Protect-Output -LiteralPath $byExtension -NoAudit } | Should -Throw '*Get-WinEvent -LogName System -MaxEvents 500*| redact*'
        { Protect-Output -LiteralPath $bySniff -NoAudit } | Should -Throw '*binary file*'
    }

    It 'preserves mixed CRLF/LF and a missing final newline byte for byte when nothing matches' {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes("first line`r`nsecond line`nthird line`r`nlast line without newline")
        $path = Write-TestFile -Name 'mixed.txt' -Byte $bytes
        $result = Invoke-TestFile -Path $path
        (Get-FileHash -LiteralPath $result.OutPath).Hash | Should -Be (Get-FileHash -LiteralPath $path).Hash
    }

    It 'redacts lines without changing their own terminators' {
        $path = Write-TestFile -Name 'eol.txt' -Byte ([System.Text.Encoding]::UTF8.GetBytes("a jane.example@contoso.example`r`nb`nc jane.example@contoso.example"))
        Read-TestText -Path (Invoke-TestFile -Path $path).OutPath | Should -Be "a [user-01]@[domain-01]`r`nb`nc [user-01]@[domain-01]"
    }
}

Describe 'Test-RedactionResidual on files' -Tag 'Unit' {
    It 'reads UTF-16 files with a BOM and reports findings without values' {
        $text = 'note k9Zq3XvB7mT2wLp8Rj5HcN1yD6sGa4UfE0 left behind'
        $path = Write-TestFile -Name 'scan16.txt' -Byte ([byte[]](0xFF, 0xFE) + [System.Text.Encoding]::Unicode.GetBytes($text))
        $found = @(Test-RedactionResidual -LiteralPath $path)
        $found.Count | Should -BeGreaterThan 0
        $found[0].Path | Should -Be $path
        ($found | ConvertTo-Json -Compress).Contains('k9Zq3XvB7mT2') | Should -BeFalse
    }

    It 'reports a binary file as an error and continues' {
        $path = Write-TestFile -Name 'scan.bin' -Byte ([byte[]](1, 0, 2, 0, 0, 0, 7, 9, 0, 0, 0, 255, 0, 0))
        $errors = $null
        $null = Test-RedactionResidual -LiteralPath $path -ErrorVariable errors -ErrorAction SilentlyContinue
        @($errors).Count | Should -Be 1
    }
}

Describe 'Output safety and folder mode' -Tag 'Unit' {
    It 'refuses an output that is the input, even through a symbolic link' {
        $path = Join-Path $script:In 'same.txt'
        Set-Content -LiteralPath $path -Value 'jane.example@contoso.example'
        { Protect-Output -LiteralPath $path -OutFile $path -Force -NoAudit } | Should -Throw '*is the input file*'
        if (-not $IsWindows) {
            $link = Join-Path $script:In 'link.txt'
            New-Item -ItemType SymbolicLink -Path $link -Target $path | Out-Null
            { Protect-Output -LiteralPath $path -OutFile $link -Force -NoAudit } | Should -Throw '*is the input file*'
        }
        (Get-Content -LiteralPath $path -Raw).Contains('contoso.example') | Should -BeTrue
    }

    It 'refuses an existing output without -Force and overwrites it with -Force' {
        $path = Join-Path $script:In 'exists.txt'
        Set-Content -LiteralPath $path -Value 'jane.example@contoso.example'
        $out = Join-Path $script:In 'exists.redacted.txt'
        Set-Content -LiteralPath $out -Value 'old'
        { Protect-Output -LiteralPath $path -NoAudit } | Should -Throw '*1 output file(s) already exist*-Force*'
        (Get-Content -LiteralPath $out -Raw).Trim() | Should -Be 'old'
        Protect-Output -LiteralPath $path -NoAudit -Force
        (Get-Content -LiteralPath $out -Raw).Contains('contoso.example') | Should -BeFalse
    }

    It 'never modifies the input' {
        $path = Join-Path $script:In 'keep.txt'
        Set-Content -LiteralPath $path -Value 'jane.example@contoso.example'
        $before = (Get-FileHash -LiteralPath $path).Hash
        Invoke-TestFile -Path $path | Out-Null
        (Get-FileHash -LiteralPath $path).Hash | Should -Be $before
    }

    It 'processes a folder with -Recurse and -Include, skips *.redacted.*, links and binary files, and uses -OutDir' {
        $root = Join-Path $TestDrive 'tree'
        New-Item -ItemType Directory -Path (Join-Path $root 'sub') -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $root 'a.log') -Value 'host WS-1234 up'
        Set-Content -LiteralPath (Join-Path $root 'sub/b.log') -Value 'host WS-5678 up'
        Set-Content -LiteralPath (Join-Path $root 'c.txt') -Value 'host WS-9999 up'
        Set-Content -LiteralPath (Join-Path $root 'old.redacted.log') -Value 'host WS-1111 up'
        [System.IO.File]::WriteAllBytes((Join-Path $root 'x.zip'), [byte[]](0x50, 0x4B, 3, 4))
        [System.IO.File]::WriteAllBytes((Join-Path $root 'raw.log'), [byte[]](1, 0, 2, 0, 0, 0, 7, 9, 0, 0, 0, 255, 0, 0))
        $outDir = Join-Path $TestDrive 'tree-out'
        $warnings = $null
        $results = @(Protect-Output -Path $root -Recurse -Include '*.log', '*.zip' -OutDir $outDir -NoAudit -PassThru -WarningVariable warnings -WarningAction SilentlyContinue)
        @($results.Path | ForEach-Object { Split-Path $_ -Leaf } | Sort-Object) -join ',' | Should -Be 'a.log,b.log'
        Test-Path -LiteralPath (Join-Path $outDir 'a.redacted.log') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $outDir 'sub/b.redacted.log') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $outDir 'old.redacted.redacted.log') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $outDir 'c.redacted.txt') | Should -BeFalse
        ($warnings -join '|') | Should -Match 'Skipped binary file: x\.zip'
        ($warnings -join '|') | Should -Match 'Skipped binary file: raw\.log'
        (Get-Content -LiteralPath (Join-Path $outDir 'sub/b.redacted.log') -Raw) | Should -Match '\[host-[0-9]{2}\]'
        Test-Path -LiteralPath (Join-Path $root 'a.redacted.log') | Should -BeFalse
    }

    It 'works with a relative . path and skips .git, .svn and .hg folders but not hidden files' {
        $root = Join-Path $TestDrive 'relative'
        foreach ($dir in 'sub/.git', 'sub/.svn', '.hg') { New-Item -ItemType Directory -Path (Join-Path $root $dir) -Force | Out-Null }
        Set-Content -LiteralPath (Join-Path $root 'p.json') -Value '{"a":"WS-1234"}'
        Set-Content -LiteralPath (Join-Path $root '.env') -Value 'API_TOKEN=FakeEnvToken1'
        Set-Content -LiteralPath (Join-Path $root 'sub/t.csv') -Value "a,b`n1,2"
        foreach ($vcs in 'sub/.git/HEAD', 'sub/.svn/entries', '.hg/store') { Set-Content -LiteralPath (Join-Path $root $vcs) -Value 'ref: x' }
        Push-Location -LiteralPath $root
        try {
            $errors = $null
            Protect-Output -Path . -Recurse -NoAudit -ErrorVariable errors
            @($errors).Count | Should -Be 0
        }
        finally { Pop-Location }
        $made = @(Get-ChildItem -LiteralPath $root -Recurse -Force -File -Filter '*.redacted*' | ForEach-Object { [System.IO.Path]::GetRelativePath($root, $_.FullName).Replace('\', '/') } | Sort-Object)
        $made -join ',' | Should -Be '.redacted.env,p.redacted.json,sub/t.redacted.csv'
    }

    Context 'pre-existing outputs in folder mode' {
        BeforeEach {
            $script:Exist = Join-Path $TestDrive "exist-$([guid]::NewGuid().ToString('N'))"
            foreach ($dir in 'sub/.git') { New-Item -ItemType Directory -Path (Join-Path $script:Exist $dir) -Force | Out-Null }
            Set-Content -LiteralPath (Join-Path $script:Exist 'p.json') -Value '{"a":"WS-1234"}'
            Set-Content -LiteralPath (Join-Path $script:Exist 'x.reg') -Value "Windows Registry Editor Version 5.00`n"
            Set-Content -LiteralPath (Join-Path $script:Exist 'sub/t.csv') -Value "a,b`n1,2"
            Set-Content -LiteralPath (Join-Path $script:Exist 'sub/.git/HEAD') -Value 'ref: x'
            foreach ($old in 'p.redacted.json', 'x.redacted.reg', 'sub/t.redacted.csv') { Set-Content -LiteralPath (Join-Path $script:Exist $old) -Value 'old' }
        }

        It 'stops with one terminating error and writes nothing, even with -ErrorAction Continue' {
            $ErrorActionPreference = 'Continue'
            $before = @(Get-ChildItem -LiteralPath $script:Exist -Recurse -Force -File | ForEach-Object { "$($_.FullName)|$($_.Length)" } | Sort-Object)
            $errors = $null
            $caught = $null
            Push-Location -LiteralPath $script:Exist
            try { Protect-Output -Path . -Recurse -NoAudit -ErrorVariable errors 2>$null 3>$null }
            catch { $caught = $_ }
            finally { Pop-Location }
            @($errors).Count | Should -Be 1
            $caught | Should -Not -BeNullOrEmpty
            $caught.Exception.Message | Should -Match "^3 output file\(s\) already exist \(first: '(p\.json|x\.reg|sub[/\\]t\.csv)'\)\. Use -Force to overwrite\.$"
            @(Get-ChildItem -LiteralPath $script:Exist -Recurse -Force -File | ForEach-Object { "$($_.FullName)|$($_.Length)" } | Sort-Object) | Should -Be $before
        }

        It 'carries a non-empty, value-free message in the recorded error' {
            $ErrorActionPreference = 'Continue'
            $errors = $null
            Push-Location -LiteralPath $script:Exist
            try { Protect-Output -Path . -Recurse -NoAudit -ErrorVariable errors 2>$null 3>$null } catch { $null = $_ }
            finally { Pop-Location }
            @($errors).Count | Should -Be 1
            # For a terminating error ErrorVariable holds the wrapping exception, whose .Exception is empty by design.
            $pattern = "^3 output file\(s\) already exist \(first: '[^']+'\)\. Use -Force to overwrite\.$"
            $errors[0].Message | Should -Match $pattern
            $errors[0].ErrorRecord.Exception.Message | Should -Match $pattern
            $errors[0].ErrorRecord.Exception.Message.Contains('WS-1234') | Should -BeFalse
        }

        It 'overwrites the outputs with -Force and reports no errors' {
            $ErrorActionPreference = 'Continue'
            $errors = $null
            Push-Location -LiteralPath $script:Exist
            try { Protect-Output -Path . -Recurse -NoAudit -Force -ErrorVariable errors 2>$null 3>$null }
            finally { Pop-Location }
            @($errors).Count | Should -Be 0
            (Get-Content -LiteralPath (Join-Path $script:Exist 'p.redacted.json') -Raw).Contains('old') | Should -BeFalse
            (Get-Content -LiteralPath (Join-Path $script:Exist 'sub/t.redacted.csv') -Raw) | Should -Match 'a,b'
        }
    }

    It 'stops before writing under -ErrorAction Continue for -Strict, in file and pipeline mode' {
        $ErrorActionPreference = 'Continue'
        $path = Copy-TestFixture -Name 'residual.txt'
        $caught = $false
        try { Protect-Output -LiteralPath $path -Strict -NoAudit 2>$null 3>$null } catch { $caught = $true }
        $caught | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:In 'residual.redacted.txt') | Should -BeFalse
        $emitted = $null
        $caught = $false
        try { $emitted = Get-Content -LiteralPath $path -Raw | Protect-Output -Strict -NoAudit 2>$null 3>$null } catch { $caught = $true }
        $caught | Should -BeTrue
        $emitted | Should -BeNullOrEmpty
    }

    It 'shares tokens across the files of one run' {
        $root = Join-Path $TestDrive 'shared'
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $root 'one.log') -Value 'a WS-1234 b'
        Set-Content -LiteralPath (Join-Path $root 'two.log') -Value 'c WS-5678 d WS-1234'
        Protect-Output -Path $root -NoAudit
        (Get-Content -LiteralPath (Join-Path $root 'one.redacted.log') -Raw).Trim() | Should -Be 'a [host-01] b'
        (Get-Content -LiteralPath (Join-Path $root 'two.redacted.log') -Raw).Trim() | Should -Be 'c [host-02] d [host-01]'
    }

    It 'emits nothing without -PassThru and a RedactOutput.Result with it' {
        $path = Join-Path $script:In 'result.txt'
        Set-Content -LiteralPath $path -Value 'jane.example@contoso.example WS-1234'
        @(Protect-Output -LiteralPath $path -NoAudit -Force).Count | Should -Be 0
        $result = Invoke-TestFile -Path $path
        $result.PSObject.TypeNames[0] | Should -Be 'RedactOutput.Result'
        $result.Path | Should -Be $path
        $result.DetectedType | Should -Be 'text'
        $result.Counts['upn'] | Should -Be 1
        $result.Counts['host'] | Should -Be 1
        $result.ResidualWarnings | Should -Be 0
    }

    It 'writes an audit row per file with counts and the input hash' {
        $path = Join-Path $script:In 'audited.txt'
        Set-Content -LiteralPath $path -Value 'jane.example@contoso.example'
        $audit = Join-Path $TestDrive 'audit-files.csv'
        Protect-Output -LiteralPath $path -Force -AuditPath $audit -WarningAction SilentlyContinue
        $row = Import-Csv -LiteralPath $audit
        $row.input_source | Should -Be 'path'
        $row.input_sha256 | Should -Be (Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()
        $row.upn | Should -Be '1'
        (Get-Content -LiteralPath $audit -Raw).Contains('jane.example') | Should -BeFalse
    }
}

Describe '-Head, -Tail, -As Json, -WhatIf and -Strict' -Tag 'Unit' {
    It 'trims files to the first and last lines with an omitted marker' {
        $path = Join-Path $script:In 'long.log'
        Set-Content -LiteralPath $path -Value (1..10 | ForEach-Object { "line $_" })
        $out = Read-TestText -Path (Invoke-TestFile -Path $path -Extra @{ Head = 2; Tail = 3 }).OutPath
        ($out -split "`r?`n" | Where-Object { $_ }) -join '|' | Should -Be 'line 1|line 2|... [5 lines omitted] ...|line 8|line 9|line 10'
    }

    It 'trims pipeline input the same way' {
        $out = (1..6 | ForEach-Object { "row $_" }) | Protect-Output -Head 1 -NoAudit
        $out | Should -Be "row 1`n... [5 lines omitted] ..."
        ((1..6 | ForEach-Object { "row $_" }) | Protect-Output -Tail 2 -NoAudit) | Should -Be "... [4 lines omitted] ...`nrow 5`nrow 6"
    }

    It 'ignores -Head and -Tail with a warning for structured types' {
        $path = Join-Path $script:In 'struct.json'
        Set-Content -LiteralPath $path -Value '{"a":1,"b":2,"c":3}'
        $warnings = $null
        $result = Protect-Output -LiteralPath $path -Head 1 -NoAudit -PassThru -Force -WarningVariable warnings -WarningAction SilentlyContinue
        ($warnings -join '|') | Should -Match '-Head/-Tail ignored for json'
        (Read-TestText -Path $result.OutPath) | Should -Not -Match 'omitted'
    }

    It 'renders pipeline objects as JSON with -As Json and applies the JSON rules' {
        $objects = [pscustomobject]@{ user = 'jane.example@contoso.example'; password = 'FakePipePass1'; n = 3 }
        $out = $objects | Protect-Output -As Json -NoAudit
        $parsed = $out | ConvertFrom-Json
        $parsed.password | Should -Be '[secret:kv]'
        $parsed.user | Should -Be '[user-01]@[domain-01]'
        $parsed.n | Should -Be 3
        $out.Contains('FakePipePass1') | Should -BeFalse
    }

    It '-WhatIf creates no output file and no audit file' {
        $path = Join-Path $script:In 'whatif.txt'
        Set-Content -LiteralPath $path -Value 'jane.example@contoso.example'
        $audit = Join-Path $TestDrive 'audit-whatif.csv'
        Protect-Output -LiteralPath $path -AuditPath $audit -WhatIf *>$null
        Test-Path -LiteralPath (Join-Path $script:In 'whatif.redacted.txt') | Should -BeFalse
        Test-Path -LiteralPath $audit | Should -BeFalse
    }

    It '-Strict with a residual finding throws and creates no file' {
        $path = Copy-TestFixture -Name 'residual.txt'
        { Protect-Output -LiteralPath $path -Strict -NoAudit } | Should -Throw '*-Strict*'
        Test-Path -LiteralPath (Join-Path $script:In 'residual.redacted.txt') | Should -BeFalse
    }

    It '-Strict also leaves no output or temp file on the large-file path' {
        $path = Join-Path $script:In 'strict-big.txt'
        Copy-Item -LiteralPath (Join-Path $script:Fixtures 'residual.txt') -Destination $path
        { Protect-Output -LiteralPath $path -Strict -NoAudit -LargeFileThresholdMB 0 } | Should -Throw '*-Strict*'
        @(Get-ChildItem -LiteralPath $script:In -Force -Filter 'strict-big*').Count | Should -Be 1
        @(Get-ChildItem -LiteralPath $script:In -Force -Filter '.redact-*').Count | Should -Be 0
    }

    It 'never writes a matched value to any stream' {
        $path = Join-Path $script:In 'canary.txt'
        Set-Content -LiteralPath $path -Value "password=FakeCanaryPass1`nnote k9Zq3XvB7mT2wLp8Rj5HcN1yD6sGa4UfE0 here`nuser jane.example@contoso.example"
        $all = Protect-Output -LiteralPath $path -NoAudit -Force -PassThru -Verbose *>&1 | Out-String
        $all.Contains('FakeCanaryPass1') | Should -BeFalse
        $all.Contains('k9Zq3XvB7mT2') | Should -BeFalse
        $all.Contains('jane.example') | Should -BeFalse
    }
}

Describe 'Large-file path' -Tag 'Unit' {
    It 'gives the same output and counts as the in-memory path for a small file' {
        $path = Join-Path $script:In 'pem-small.log'
        $text = "start jane.example@contoso.example`r`n$(Get-TestPem)`r`nmiddle WS-1234`r`nend jane.example@contoso.example`r`n"
        [System.IO.File]::WriteAllText($path, $text)
        $memory = Invoke-TestFile -Path $path -Extra @{ OutFile = (Join-Path $script:In 'pem-memory.log') }
        $stream = Invoke-TestFile -Path $path -Extra @{ OutFile = (Join-Path $script:In 'pem-stream.log'); LargeFileThresholdMB = 0 }
        (Get-FileHash -LiteralPath $stream.OutPath).Hash | Should -Be (Get-FileHash -LiteralPath $memory.OutPath).Hash
        ($stream.Counts | ConvertTo-Json -Compress) | Should -Be ($memory.Counts | ConvertTo-Json -Compress)
        $stream.Counts['pem-key'] | Should -Be 1
        (Read-TestText -Path $stream.OutPath).Contains('FAKEFAKE') | Should -BeFalse
    }

    It 'keeps a private key whole across a chunk boundary and offsets residual line numbers' {
        $filler = '2026-01-15 10:00:00 INFO heartbeat ok' + "`r`n"
        $count = [int][math]::Floor((1MB - 40) / $filler.Length)
        $sb = [System.Text.StringBuilder]::new()
        $null = $sb.Append($filler * $count).Append("user jane.example@contoso.example`r`n").Append((Get-TestPem)).Append("`r`n")
        $null = $sb.Append('2026-01-15 10:00:01 INFO more').Append("`r`n").Append("note k9Zq3XvB7mT2wLp8Rj5HcN1yD6sGa4UfE0 left`r`n")
        $path = Join-Path $script:In 'pem-big.log'
        [System.IO.File]::WriteAllText($path, $sb.ToString())
        $memory = Invoke-TestFile -Path $path -Extra @{ OutFile = (Join-Path $script:In 'big-memory.log') }
        $stream = Invoke-TestFile -Path $path -Extra @{ OutFile = (Join-Path $script:In 'big-stream.log'); LargeFileThresholdMB = 0 }
        (Get-FileHash -LiteralPath $stream.OutPath).Hash | Should -Be (Get-FileHash -LiteralPath $memory.OutPath).Hash
        $stream.Counts['pem-key'] | Should -Be 1
        $stream.ResidualWarnings | Should -Be $memory.ResidualWarnings
        $streamWarnings = $null
        $memoryWarnings = $null
        $null = Protect-Output -LiteralPath $path -NoAudit -Force -OutFile (Join-Path $script:In 'big-w1.log') -LargeFileThresholdMB 0 -WarningVariable streamWarnings -WarningAction SilentlyContinue
        $null = Protect-Output -LiteralPath $path -NoAudit -Force -OutFile (Join-Path $script:In 'big-w2.log') -WarningVariable memoryWarnings -WarningAction SilentlyContinue
        @($streamWarnings) -join '|' | Should -Be (@($memoryWarnings) -join '|')
        @($memoryWarnings).Count | Should -BeGreaterThan 0
    }
}
