# Dot-sourced by every test file from BeforeAll. Imports the module fresh and points config at TestDrive,
# so tests never read the real local config.

$script:ModuleRoot = Split-Path -Path $PSScriptRoot -Parent
Import-Module (Join-Path $script:ModuleRoot 'RedactOutput.psd1') -Force

$script:ConfigDir = Join-Path $TestDrive 'config'
New-Item -ItemType Directory -Path $script:ConfigDir -Force | Out-Null
Copy-Item -Path (Join-Path $script:ModuleRoot 'config/redact.config.sample.json') -Destination $script:ConfigDir
$env:REDACTOUTPUT_CONFIG_DIR = $script:ConfigDir

function Invoke-TestRedact {
    param([Parameter(Mandatory)][string]$Text, [string]$ConfigPath)
    $params = @{ NoAudit = $true; WarningAction = 'SilentlyContinue' }
    if ($ConfigPath) { $params['ConfigPath'] = $ConfigPath }
    $Text | Protect-Output @params
}

function Write-TestConfig {
    param([Parameter(Mandatory)][hashtable]$Data, [string]$Name = 'test.config.json')
    $path = Join-Path $TestDrive $Name
    $Data | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path
    $path
}

function ConvertTo-TestBase64Url {
    param([Parameter(Mandatory)][string]$Value)
    [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Value)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Get-TestJwt {
    $header = ConvertTo-TestBase64Url '{"alg":"none"}'
    $payload = ConvertTo-TestBase64Url '{"sub":"fake-subject"}'
    "$header.$payload.ZmFrZS1zaWduYXR1cmU"
}

# Assemble shaped-but-fake values at run time so no token-shaped literal sits in the repo.
function Get-TestPem {
    param([switch]$NoEnd)
    $lines = @('-----BEGIN ' + 'RSA PRIVATE KEY-----', 'FAKEFAKEFAKEFAKE0000', 'FAKEFAKEFAKEFAKE1111')
    if (-not $NoEnd) { $lines += '-----END ' + 'RSA PRIVATE KEY-----' }
    $lines -join "`n"
}
