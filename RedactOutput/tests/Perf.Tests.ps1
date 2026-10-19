# The elapsed time is reported to the host so a Perf run shows it.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Reports the measured time; no values.')]
param()

BeforeAll {
    . $PSScriptRoot/TestHelpers.ps1

    # Benign log lines with one identifier line per 20 (user, IP, host or GUID, all synthetic).
    function Write-TestLog {
        param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][long]$Bytes)
        $writer = [System.IO.StreamWriter]::new($Path, $false, [System.Text.UTF8Encoding]::new($false))
        $random = [random]::new(7)
        $i = 0
        try {
            while ($writer.BaseStream.Position -lt $Bytes) {
                $sb = [System.Text.StringBuilder]::new()
                for ($k = 0; $k -lt 1000; $k++) {
                    $i++
                    $stamp = '2026-01-15 10:{0:D2}:{1:D2}.{2:D3}' -f ($i % 60), ($i % 59), ($i % 1000)
                    if ($i % 20 -eq 0) {
                        $line = switch ($i % 80) {
                            0 { "$stamp INFO sign-in for user$($random.Next(99999))@contoso.example accepted" }
                            20 { "$stamp WARN client 192.0.2.$($random.Next(1, 255)) rejected" }
                            40 { "$stamp INFO connected to WS-$($random.Next(1000, 9999)) over tunnel" }
                            default { "$stamp DEBUG object $([guid]::NewGuid()) refreshed" }
                        }
                    }
                    else { $line = "$stamp INFO [worker-$($i % 8)] processed batch $($random.Next(100000)) in $($random.Next(900)) ms (queue depth $($random.Next(40)))" }
                    [void]$sb.Append($line).Append("`r`n")
                }
                $writer.Write($sb.ToString())
                $writer.Flush()
            }
        }
        finally { $writer.Dispose() }
    }
}

AfterAll { Remove-Item -Path Env:REDACTOUTPUT_CONFIG_DIR -ErrorAction SilentlyContinue }

Describe 'Large input' -Tag 'Perf' {
    It 'redacts a 50 MB synthetic log within the time budget' {
        $log = Join-Path $TestDrive 'big.log'
        Write-TestLog -Path $log -Bytes 50MB
        (Get-Item -LiteralPath $log).Length | Should -BeGreaterThan 50MB
        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        $result = Protect-Output -LiteralPath $log -NoAudit -PassThru -WarningAction SilentlyContinue
        $watch.Stop()
        Write-Host ('50 MB log redacted in {0:N1} s' -f $watch.Elapsed.TotalSeconds)
        $result.Counts['upn'] | Should -BeGreaterThan 0
        $watch.Elapsed.TotalSeconds | Should -BeLessThan 120
    }
}
