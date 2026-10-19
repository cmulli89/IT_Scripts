# RedactOutput

A PowerShell 7 module that scrubs secrets and environment identifiers out of text before it leaves your boundary:
script output, Graph JSON, gpresult, registry dumps, logs, .env files, CSV exports, Az/az output, Linux command
output and source files. The typical use is redacting before pasting into a commercial AI chat that is not
authorized for CUI.

- Secrets (keys, tokens, passwords, connection strings, PEM blocks, ...) become `[secret:type]`. They are never
  correlated and never stored in a map.
- Identifiers (GUIDs, users, hosts, domains, IPs, SIDs, Azure resource IDs, ...) become stable `[type-NN]` tokens:
  the same original always gets the same token, so the redacted text can still be reasoned about.
- Public Government endpoints (`graph.microsoft.us`, `login.microsoftonline.us`, `*.usgovcloudapi.net`, ...) stay
  readable. Tenant-specific labels on them do not.

Requirements: PowerShell 7.2+ on Windows or Linux (writing a map file on Linux needs 7.3+; on Windows map ACLs work
on 7.2+). Clipboard on Linux needs `xclip` or wl-clipboard.

## Install

Copy or clone this library, then either add its folder to `$env:PSModulePath` (so `Import-Module RedactOutput`
works) or import the manifest by path:

```powershell
Import-Module C:\Scripts\RedactOutput\RedactOutput.psd1
```

Profile snippet (`$PROFILE`), importing the module and setting the `redact` alias:

```powershell
Import-Module C:\Scripts\RedactOutput\RedactOutput.psd1
Set-Alias -Name redact -Value Protect-Output
```

Importing has no side effects. Without importing, `.\redact.ps1` at the module root does the same job (see Exit codes).

## Fill in your local config

Your organization's values (domains, NetBIOS name, host naming patterns, resource prefixes, usernames, tenant
prefix, project terms) live only in `config/redact.config.local.json`, which is git-ignored. Create it with:

```powershell
New-RedactionConfig                      # asks for each item
New-RedactionConfig -InternalDomains ad.contoso.example, contoso.example `
    -NetbiosDomain 'CONTOSO=ad.contoso.example' -HostPattern 'WS-[0-9]{3,}', 'LT-[0-9]{3,}' `
    -ResourcePrefix 'rg-contoso-' -ExtraTerm 'Project Placeholder=proj'
```

It validates the result like the loader does (a bad regex is reported by key and index, never by value), refuses to
overwrite without `-Force`, never reads an existing file, and checks `git check-ignore`, warning if the file is not
covered by `.gitignore`. See `config/redact.config.sample.json` for every key and what to put in it. Layering,
lowest to highest: built-in defaults, sample, local, `-ConfigPath`, parameters. Built-in allowlists cannot be removed.

## Usage

```powershell
Get-Something | redact                              # pipeline
redact -Clipboard                                   # copy -> redact -> paste
redact -Path .\dump.json                            # file, structure-aware; writes dump.redacted.json
redact -Path .\logs -Recurse -Include *.log,*.json  # folder
Invoke-RedactedCommand { gpresult /r } -Clipboard   # run, capture all streams (errors too), redact
```

Useful switches: `-Preview` (show, write nothing), `-WhatIf` (run the engine, report counts, write nothing),
`-OutDir`, `-Force`, `-PassThru`, `-Head`/`-Tail`, `-As Json`, `-ConfigPath`. Files are never modified; the output is
`<name>.redacted<ext>` next to the input or under `-OutDir`.

## Clipboard workflow

1. Copy the text.
2. `redact -Clipboard -Preview` shows the redacted text with tokens highlighted (secrets red, identifiers cyan) and
   writes nothing. Skim it.
3. `redact -Clipboard` replaces the clipboard with the redacted text. Paste.

`Invoke-RedactedCommand { ... } -Clipboard` does the same for command output. An empty or non-text clipboard is an
error. On Linux install `xclip` or wl-clipboard.

## Map and restore workflow

```powershell
Get-Something | redact -MapPath session1.redactmap.json      # tokens stay stable across the session
# ...paste the redacted text, get a reply that mentions [host-02]...
Restore-RedactedText -Clipboard -MapPath session1.redactmap.json   # reply -> originals, locally
Get-RedactionMap -MapPath session1.redactmap.json                  # tokens and counts (-ShowOriginal for values)
```

A bare map name goes to the per-user maps folder (`%LOCALAPPDATA%\RedactOutput\maps`, Linux
`~/.local/share/RedactOutput/maps`). Reusing a map continues its numbering. A map holds the original values: keep it
local (it is created owner-only), never in a synced folder (OneDrive, Dropbox, ...; a warning is given), never share it.
Restored text contains originals, so use it locally only. Secrets are never in a map.

## Strict mode, exit codes and audit

After redaction every result is rescanned for anything that still looks sensitive (rule matches, secret-named
pairs, high-entropy strings, your config literals). By default each finding is a warning with category, line,
column and length only. With `-Strict` any finding throws before anything is written (file, clipboard, map or audit).

`redact.ps1` exit codes: `0` clean, `1` residual findings reported (non-strict), `2` error (a `-Strict` finding, bad
config, binary file, bad parameters).

An audit row is appended per run to `%LOCALAPPDATA%\RedactOutput\audit.csv` (Linux
`~/.local/share/RedactOutput/audit.csv`; `-AuditPath` moves it, `-NoAudit` skips it): timestamp, operator,
input_source (path, pipeline, clipboard, command), input SHA-256, output path, a count per category, residual
findings, strict. Never values. `Test-RedactionResidual` rescans text or a file on demand and only reports.

## File types

| Type | Handling |
|---|---|
| .txt .log .out, unknown text | whole-text pass, then line-based |
| .json, .jsonl | structure-aware; secret-named properties replaced; output still parses |
| .csv .tsv | quote-aware; header and quoting kept byte for byte |
| .xml .wsb | text mode; secret-named elements and attributes; stays well-formed |
| .env .ini .conf .properties .yaml .yml | `KEY=value` and `key: value`; quotes and comments kept |
| .reg | UTF-16LE BOM and CRLF kept; `hex:` payloads scanned |
| .ps1 .psm1 .psd1 .sh .py, .html | text mode |
| binary (.zip .evtx .xlsx .docx .pdf, images) | refused with a hint; skipped in folder mode |

Encoding, BOM and each line's own line ending are kept. A UTF-16 file without a BOM needs `-Encoding Unicode`.

## Config keys

| Key | Purpose |
|---|---|
| `internalDomains`, `netbiosDomains` | AD and UPN domains; NetBIOS name with its FQDN |
| `hostPatterns`, `hostList` | host naming regexes (with `minLength`); exact host names |
| `resourcePrefixes` | Azure resource and resource group prefixes (a tenant prefix goes here too) |
| `usernames`, `extraTerms` | explicit users; project, contract, site terms (`term`, `label`) |
| `guidAllowlist`, `publicHostAllowlist`, `ipAllowlist`, `publicDomains` | extra values to keep verbatim |
| `ipMode`, `pathMode`, `sidKeepRid` | `Classify`/`KeepPrivate`/`Keep`; `UserOnly`/`Full`/`Keep`; keep SID RIDs |
| `categories` | per-category on/off (secret rules cannot be disabled) |
| `secretNames`, `nonSecretNames`, `deviceSerialPatterns` | extend the secret-name rule, its deny-list, serial formats |

## Limits

Regex redaction removes secrets and environment identifiers. It cannot recognize CUI in free text: document
contents, technical data, contract details and similar. Do not pipe such content through it and assume the result
is safe to share. Rare false positives (for example base64 SHA-512 digests treated as storage keys) and false
negatives (identifiers your config does not know about) are possible. Always skim `-Preview` before pasting.
