BeforeAll {
    . $PSScriptRoot/TestHelpers.ps1
    $script:RepoRoot = Split-Path -Path $script:ModuleRoot -Parent
}

AfterAll { Remove-Item -Path Env:REDACTOUTPUT_CONFIG_DIR -ErrorAction SilentlyContinue }

Describe 'Static checks' -Tag 'Static' {
    It 'has only ASCII bytes in every text file (reports file and line only)' {
        $extensions = '*.ps1', '*.psm1', '*.psd1', '*.json', '*.md', '*.txt', '*.csv', '*.xml', '*.env', '.gitignore'
        $files = @(Get-ChildItem -Path $script:ModuleRoot -Recurse -File -Include $extensions)
        $files += Get-Item -LiteralPath (Join-Path $script:RepoRoot '.claude/settings.json')
        $offenders = foreach ($file in $files) {
            $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
            $line = 1
            $reported = $false
            foreach ($b in $bytes) {
                if ($b -eq 10) { $line++ }
                elseif ($b -gt 127 -and -not $reported) { "$($file.FullName):$line"; $reported = $true }
            }
        }
        @($offenders).Count | Should -Be 0 -Because "non-ASCII found at: $(@($offenders) -join ', ')"
    }

    It 'parses every script, module and manifest without errors' {
        $files = Get-ChildItem -Path $script:ModuleRoot -Recurse -File -Include '*.ps1', '*.psm1', '*.psd1'
        $errors = foreach ($file in $files) {
            $parseErrors = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$parseErrors)
            foreach ($e in $parseErrors) { "$($file.Name):$($e.Extent.StartLineNumber): $($e.ErrorId)" }
        }
        @($errors).Count | Should -Be 0 -Because "parse errors: $(@($errors) -join '; ')"
    }

    It 'passes Test-ModuleManifest' {
        { Test-ModuleManifest -Path (Join-Path $script:ModuleRoot 'RedactOutput.psd1') -ErrorAction Stop } | Should -Not -Throw
    }

    It 'exports exactly the manifest functions and the redact alias' {
        $module = Get-Module RedactOutput
        ($module.ExportedFunctions.Keys | Sort-Object) -join ',' | Should -Be 'Protect-Output,Test-RedactionResidual'
        (Get-Alias redact).Definition | Should -Be 'Protect-Output'
    }

    It 'uses explicit character classes instead of \d and \w in the pattern table' {
        $source = Get-Content -LiteralPath (Join-Path $script:ModuleRoot 'Private/Patterns.ps1') -Raw
        [regex]::IsMatch($source, '\\[dwDW]') | Should -BeFalse
    }
}
