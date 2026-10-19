# Canary values (a config term used as extra term and host, a secret, a planted residual) must not appear in any stream,
# the audit CSV, an error message or the redacted output. Failure messages name the canary, never print text.

BeforeAll {
    . $PSScriptRoot/TestHelpers.ps1
    $script:Canary = [ordered]@{
        term     = 'CanaryHost-Zq7'
        secret   = 'CanarySecretValue9Zq'
        residual = 'k9Zq3XvB7mT2wLp8Rj5HcN1yD6sGa4UfE0'
    }
    $script:Config = Write-TestConfig -Name 'canary.config.json' -Data @{
        extraTerms = @(@{ term = $script:Canary.term; label = 'canary' })
        hostList   = @($script:Canary.term)
    }
    $script:Clean = "connect to $($script:Canary.term) 192.0.2.10`npassword=$($script:Canary.secret)`nok"
    $script:Planted = "$script:Clean`nvalue $($script:Canary.residual)"

    # Runs the block in this scope (dot-sourced) so -ErrorVariable/-WarningVariable/-InformationVariable land here, with
    # every stream merged; returns all of it as one string, plus the audit file when there is one.
    function Get-TestLeakText {
        param([Parameter(Mandatory)][scriptblock]$Run, [string]$AuditPath)
        $ErrorActionPreference = 'Continue'
        $common = @{ Verbose = $true; ErrorVariable = 'ev'; WarningVariable = 'wv'; InformationVariable = 'iv' }
        $caught = $null
        $merged = @(try { . $Run $common *>&1 } catch { $caught = $_ })
        $parts = @($merged | Out-String -Width 4096) + @($ev | Out-String) + @($wv | Out-String) + @($iv | Out-String)
        if ($caught) { $parts += $caught.Exception.Message, ($caught | Out-String) }
        if ($AuditPath -and (Test-Path -LiteralPath $AuditPath)) { $parts += Get-Content -LiteralPath $AuditPath -Raw }
        $parts -join "`n"
    }

    function Assert-TestNoCanary {
        param([Parameter(Mandatory)][string]$Text, [string[]]$Except = @())
        foreach ($name in $script:Canary.Keys) {
            if ($name -in $Except) { continue }
            $Text.IndexOf($script:Canary[$name], [StringComparison]::OrdinalIgnoreCase) -ge 0 | Should -BeFalse -Because "the '$name' canary must not appear"
        }
    }
}

AfterAll { Remove-Item -Path Env:REDACTOUTPUT_CONFIG_DIR -ErrorAction SilentlyContinue }

Describe 'No value leaves the module' -Tag 'Unit' {
    BeforeEach { $script:Audit = Join-Path $TestDrive "audit-$([guid]::NewGuid().ToString('N')).csv" }

    It 'Protect-Output on pipeline text, with -Verbose' {
        $text = Get-TestLeakText -AuditPath $script:Audit -Run { param($c) $script:Clean | Protect-Output -ConfigPath $script:Config -AuditPath $script:Audit @c }
        Assert-TestNoCanary -Text $text -Except 'residual'
        $text.Contains('[term-canary-01]') | Should -BeTrue -Because 'the run must have redacted the term'
        Test-Path -LiteralPath $script:Audit | Should -BeTrue
    }

    It 'Protect-Output on a file, with -Verbose and -PassThru' {
        $in = Join-Path $TestDrive 'canary-in.txt'
        Set-Content -LiteralPath $in -Value $script:Clean
        $outDir = Join-Path $TestDrive 'canary-out'
        $text = Get-TestLeakText -AuditPath $script:Audit -Run { param($c) Protect-Output -LiteralPath $in -OutDir $outDir -ConfigPath $script:Config -AuditPath $script:Audit -PassThru @c }
        Assert-TestNoCanary -Text $text
        $written = Get-Content -LiteralPath (Join-Path $outDir 'canary-in.redacted.txt') -Raw
        Assert-TestNoCanary -Text $written
    }

    It 'Protect-Output -Strict with a residual: the error, streams and audit hold no value' {
        $text = Get-TestLeakText -AuditPath $script:Audit -Run { param($c) $script:Planted | Protect-Output -ConfigPath $script:Config -Strict -AuditPath $script:Audit @c }
        $text.Contains('-Strict') | Should -BeTrue -Because 'the run must have failed on the residual'
        Assert-TestNoCanary -Text $text
        Test-Path -LiteralPath $script:Audit | Should -BeFalse
    }

    It 'Protect-Output without -Strict reports the residual by position only' {
        $text = Get-TestLeakText -AuditPath $script:Audit -Run { param($c) $script:Planted | Protect-Output -ConfigPath $script:Config -AuditPath $script:Audit @c }
        $text | Should -Match 'Residual .* at line [0-9]+, column [0-9]+, length [0-9]+'
        Assert-TestNoCanary -Text $text -Except 'residual'
        # The residual is report-only (never mutated), so it stays in the output; it must not be in the audit row or messages.
        (Get-Content -LiteralPath $script:Audit -Raw).Contains($script:Canary.residual) | Should -BeFalse
    }

    It 'Protect-Output -WhatIf' {
        $text = Get-TestLeakText -AuditPath $script:Audit -Run { param($c) $script:Clean | Protect-Output -ConfigPath $script:Config -AuditPath $script:Audit -WhatIf @c }
        Assert-TestNoCanary -Text $text
        Test-Path -LiteralPath $script:Audit | Should -BeFalse
    }

    # A thrown exception is also kept by PowerShell itself in $Error and -ErrorVariable (the command's own record, as for any
    # caught exception), so the throw here carries no canary; the canary goes through output and Write-Error.
    It 'Invoke-RedactedCommand, including a canary in an error record' {
        $text = Get-TestLeakText -AuditPath $script:Audit -Run {
            param($c)
            Invoke-RedactedCommand -ScriptBlock { "host $($script:Canary.term)"; Write-Error "failed for $($script:Canary.term)"; "password=$($script:Canary.secret)"; throw 'boom' } `
                -ConfigPath $script:Config -AuditPath $script:Audit @c
        }
        Assert-TestNoCanary -Text $text
        $text.Contains('[term-canary-01]') | Should -BeTrue
    }

    It 'Test-RedactionResidual on unredacted text reports positions only' {
        $text = Get-TestLeakText -Run { param($c) Test-RedactionResidual -Text $script:Planted -ConfigPath $script:Config @c }
        $text | Should -Match 'Category'
        Assert-TestNoCanary -Text $text
    }

    It 'a config with an invalid regex holding a canary is rejected without echoing it' {
        $bad = Write-TestConfig -Name 'bad-canary.config.json' -Data @{ hostPatterns = @(@{ regex = "$($script:Canary.term)[0-9"; minLength = 6 }) }
        $text = Get-TestLeakText -Run { param($c) 'x' | Protect-Output -ConfigPath $bad -NoAudit @c }
        $text.Contains('Config rejected') | Should -BeTrue
        Assert-TestNoCanary -Text $text
    }
}
