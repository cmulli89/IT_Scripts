BeforeAll {
    . $PSScriptRoot/TestHelpers.ps1
    $script:Pwsh = (Get-Process -Id $PID).Path
    $script:Wrapper = Join-Path $script:ModuleRoot 'redact.ps1'
    $script:Fixture = Join-Path $PSScriptRoot 'Fixtures'

    # Runs redact.ps1 in a child pwsh (the config dir comes from the environment); returns exit code, stdout and stderr.
    # -File does not bind piped stdin to the script's parameters, so pipeline input goes through -Command.
    function Invoke-TestWrapper {
        param([string[]]$Arguments, [string]$InputText)
        $stderr = Join-Path $TestDrive "stderr-$([guid]::NewGuid().ToString('N')).txt"
        $stdout = if ($PSBoundParameters.ContainsKey('InputText')) {
            & $script:Pwsh -NoProfile -Command "'$InputText' | & '$script:Wrapper' $($Arguments -join ' '); exit `$LASTEXITCODE" 2>$stderr
        }
        else { & $script:Pwsh -NoProfile -File $script:Wrapper @Arguments 2>$stderr }
        [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $stdout -join "`n"; Error = (Get-Content -LiteralPath $stderr -Raw) }
    }
}

AfterAll { Remove-Item -Path Env:REDACTOUTPUT_CONFIG_DIR -ErrorAction SilentlyContinue }

Describe 'redact.ps1 exit codes' -Tag 'Unit' {
    BeforeEach { $script:OutDir = Join-Path $TestDrive "out-$([guid]::NewGuid().ToString('N'))" }

    It 'exits 0 for a clean file with -Strict' {
        (Invoke-TestWrapper -Arguments '-Path', (Join-Path $script:Fixture 'clean.txt'), '-Strict', '-NoAudit', '-OutDir', $script:OutDir).ExitCode | Should -Be 0
        Test-Path -LiteralPath (Join-Path $script:OutDir 'clean.redacted.txt') | Should -BeTrue
    }

    It 'exits 1 for residual findings without -Strict and still writes the output' {
        $run = Invoke-TestWrapper -Arguments '-Path', (Join-Path $script:Fixture 'residual.txt'), '-NoAudit', '-OutDir', $script:OutDir
        $run.ExitCode | Should -Be 1
        Test-Path -LiteralPath (Join-Path $script:OutDir 'residual.redacted.txt') | Should -BeTrue
    }

    It 'exits 2 for residual findings with -Strict and writes nothing' {
        $run = Invoke-TestWrapper -Arguments '-Path', (Join-Path $script:Fixture 'residual.txt'), '-Strict', '-NoAudit', '-OutDir', $script:OutDir
        $run.ExitCode | Should -Be 2
        $run.Error | Should -Match '-Strict'
        Test-Path -LiteralPath $script:OutDir | Should -BeFalse
    }

    It 'exits 2 for an invalid config without printing the pattern' {
        $bad = Write-TestConfig -Name 'wrapper-bad.config.json' -Data @{ hostPatterns = @(@{ regex = 'CANARY[0-9'; minLength = 6 }) }
        $run = Invoke-TestWrapper -Arguments '-Path', (Join-Path $script:Fixture 'clean.txt'), '-ConfigPath', $bad, '-NoAudit', '-OutDir', $script:OutDir
        $run.ExitCode | Should -Be 2
        $run.Error | Should -Match 'Config rejected'
        ($run.Error + $run.Output).Contains('CANARY') | Should -BeFalse
    }

    It 'exits 2 for a binary file' {
        $bin = Join-Path $TestDrive 'wrapper.zip'
        [System.IO.File]::WriteAllBytes($bin, [byte[]](80, 75, 3, 4, 0, 0, 0, 0))
        (Invoke-TestWrapper -Arguments '-Path', $bin, '-NoAudit', '-OutDir', $script:OutDir).ExitCode | Should -Be 2
    }

    It 'redacts pipeline input to stdout and exits 0' {
        $run = Invoke-TestWrapper -Arguments '-NoAudit' -InputText 'host WS-1111'
        $run.ExitCode | Should -Be 0
        $run.Output | Should -Be 'host [host-01]'
    }

    It 'passes -WhatIf through: nothing is written' {
        $run = Invoke-TestWrapper -Arguments '-Path', (Join-Path $script:Fixture 'clean.txt'), '-NoAudit', '-OutDir', $script:OutDir, '-WhatIf'
        $run.ExitCode | Should -Be 0
        Test-Path -LiteralPath $script:OutDir | Should -BeFalse
    }
}
