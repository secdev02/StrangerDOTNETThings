[CmdletBinding()]
param(
    [string]$OutputMarkdown = (Join-Path $PSScriptRoot 'Wsh-Com-Catalog.md'),
    [ValidateSet('Both','x64','x86')]
    [string]$Architecture = 'Both',
    [int]$TimeoutSeconds = 4,
    [string[]]$IncludePattern = @('*'),
    [string[]]$ExcludePattern = @(),
    [switch]$IncludeFailures,
    [string]$ActCtxManifest,
    [string[]]$ActCtxProgId = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-PatternMatch {
    param([string]$Value, [string[]]$Patterns)
    foreach ($p in $Patterns) { if ($Value -like $p) { return $true } }
    return $false
}

function Get-ProgIdRecords {
    $roots = @(
        @{ Name='HKCR'; Path='Registry::HKEY_CLASSES_ROOT' }
    )

    $seen = @{}
    foreach ($root in $roots) {
        Get-ChildItem -Path ($root.Path + '\*') -ErrorAction SilentlyContinue | ForEach-Object {
            $progId = $_.PSChildName
            if ($progId -notmatch '^.+\..+$') { return }
            if (-not (Test-PatternMatch $progId $IncludePattern)) { return }
            if ($ExcludePattern.Count -gt 0 -and (Test-PatternMatch $progId $ExcludePattern)) { return }

            $clsid = $null
            try { $clsid = (Get-ItemProperty -LiteralPath ($_.PSPath + '\CLSID') -ErrorAction Stop).'(default)' } catch {}
            if (-not $clsid) { return }
            if ($seen.ContainsKey($progId)) { return }
            $seen[$progId] = $true

            $clsidPath = "Registry::HKEY_CLASSES_ROOT\CLSID\$clsid"
            $description = $null
            $inproc = $null
            $localServer = $null
            $threading = $null
            $typeLib = $null
            $versionIndependentProgId = $null

            try { $description = (Get-ItemProperty -LiteralPath $clsidPath -ErrorAction Stop).'(default)' } catch {}
            try {
                $p = Get-ItemProperty -LiteralPath ($clsidPath + '\InprocServer32') -ErrorAction Stop
                $inproc = $p.'(default)'
                $threading = $p.ThreadingModel
            } catch {}
            try { $localServer = (Get-ItemProperty -LiteralPath ($clsidPath + '\LocalServer32') -ErrorAction Stop).'(default)' } catch {}
            try { $typeLib = (Get-ItemProperty -LiteralPath ($clsidPath + '\TypeLib') -ErrorAction Stop).'(default)' } catch {}
            try { $versionIndependentProgId = (Get-ItemProperty -LiteralPath ($clsidPath + '\VersionIndependentProgID') -ErrorAction Stop).'(default)' } catch {}

            [pscustomobject]@{
                ProgID = $progId
                CLSID = [string]$clsid
                Description = [string]$description
                InprocServer32 = [string]$inproc
                LocalServer32 = [string]$localServer
                ThreadingModel = [string]$threading
                TypeLib = [string]$typeLib
                VersionIndependentProgID = [string]$versionIndependentProgId
            }
        }
    }
}

function Invoke-CscriptProbe {
    param(
        [string]$Cscript,
        [string]$Script,
        [string[]]$Arguments,
        [int]$Timeout
    )

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $Cscript
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true

    $allArgs = @('//nologo', ('"' + $Script + '"')) + ($Arguments | ForEach-Object { '"' + ($_ -replace '"','\"') + '"' })
    $psi.Arguments = ($allArgs -join ' ')

    $p = [System.Diagnostics.Process]::new()
    $p.StartInfo = $psi
    $null = $p.Start()

    if (-not $p.WaitForExit($Timeout * 1000)) {
        try { $p.Kill() } catch {}
        return [pscustomobject]@{ Success=$false; TimedOut=$true; ExitCode=$null; Output='TIMEOUT'; Error='' }
    }

    $out = $p.StandardOutput.ReadToEnd().Trim()
    $err = $p.StandardError.ReadToEnd().Trim()
    return [pscustomobject]@{ Success=($p.ExitCode -eq 0); TimedOut=$false; ExitCode=$p.ExitCode; Output=$out; Error=$err }
}

function Escape-Md([string]$s) {
    if ($null -eq $s) { return '' }
    return ($s -replace '\|','\|') -replace "`r?`n", ' '
}

function Get-CuratedExample {
    param([string]$ProgID)

    switch -Wildcard ($ProgID) {
        'Scripting.FileSystemObject' {
@'
```javascript
var fso = new ActiveXObject("Scripting.FileSystemObject");
WScript.Echo("Windows folder: " + fso.GetSpecialFolder(0));
```

This is a simple, read-only example. `GetSpecialFolder(0)` returns the Windows folder.
'@
        }
        'WScript.Shell' {
@'
```javascript
var shell = new ActiveXObject("WScript.Shell");
WScript.Echo("TEMP=" + shell.ExpandEnvironmentStrings("%TEMP%"));
```

This example only expands an environment variable and does not start a process or modify the registry.
'@
        }
        'Shell.Application' {
@'
```javascript
var shell = new ActiveXObject("Shell.Application");
WScript.Echo("Shell.Application created successfully");
```

`Shell.Application` exposes Windows Shell automation. The catalog intentionally limits the example to activation because many methods perform actions in Explorer or the shell.
'@
        }
        'MSXML2.DOMDocument*' {
@'
```javascript
var xml = new ActiveXObject("PROGID_HERE");
xml.async = false;
xml.loadXML("<root><item>demo</item></root>");
WScript.Echo(xml.documentElement.nodeName);
```

Replace `PROGID_HERE` with the ProgID shown in this section. This parses an in-memory XML string only.
'@
        }
        'Microsoft.XMLDOM' {
@'
```javascript
var xml = new ActiveXObject("Microsoft.XMLDOM");
xml.async = false;
xml.loadXML("<root><item>demo</item></root>");
WScript.Echo(xml.documentElement.nodeName);
```
'@
        }
        'ADODB.Stream' {
@'
```javascript
var s = new ActiveXObject("ADODB.Stream");
s.Type = 2; // text
s.Charset = "utf-8";
s.Open();
s.WriteText("hello from WSH");
s.Position = 0;
WScript.Echo(s.ReadText());
s.Close();
```

The example uses only an in-memory stream; it does not read or write a file.
'@
        }
        'WbemScripting.SWbemLocator' {
@'
```javascript
var locator = new ActiveXObject("WbemScripting.SWbemLocator");
var svc = locator.ConnectServer(".", "root\\cimv2");
WScript.Echo("Connected to local WMI namespace root\\cimv2");
```

This connects to the local WMI service but does not execute a query or change configuration.
'@
        }
        'Microsoft.Windows.ActCtx' {
@'
```javascript
var act = new ActiveXObject("Microsoft.Windows.ActCtx");
act.Manifest = "C:\\Path\\To\\component.manifest";
var obj = act.CreateObject("Vendor.Component");
WScript.Echo("Created object through an activation context");
```

`Microsoft.Windows.ActCtx` is the WSH-accessible bridge for registration-free COM. The manifest must declare the COM class/ProgID being activated.
'@
        }
        default {
@'
```javascript
var obj = new ActiveXObject("PROGID_HERE");
WScript.Echo("Created: PROGID_HERE");
```

The discovery pass verified activation only. No method is called here because arbitrary registered COM classes can expose state-changing, interactive, privileged, or application-specific methods.
'@
        }
    }
}

$probeJs = Join-Path $PSScriptRoot 'Probe-ProgId.js'
$actCtxJs = Join-Path $PSScriptRoot 'Probe-ActCtx.js'

$targets = @()
if ($Architecture -in @('Both','x64')) {
    $p = Join-Path $env:WINDIR 'System32\cscript.exe'
    if (Test-Path $p) { $targets += [pscustomobject]@{ Arch='x64'; Cscript=$p } }
}
if ($Architecture -in @('Both','x86')) {
    $p = Join-Path $env:WINDIR 'SysWOW64\cscript.exe'
    if (Test-Path $p) { $targets += [pscustomobject]@{ Arch='x86'; Cscript=$p } }
}

$records = @(Get-ProgIdRecords | Sort-Object ProgID)
$results = New-Object System.Collections.Generic.List[object]

Write-Host "Found $($records.Count) candidate ProgIDs. Testing activation with cscript.exe..."
foreach ($r in $records) {
    foreach ($t in $targets) {
        Write-Progress -Activity 'Testing WSH COM activation' -Status "$($t.Arch): $($r.ProgID)" -PercentComplete 0
        $probe = Invoke-CscriptProbe -Cscript $t.Cscript -Script $probeJs -Arguments @($r.ProgID) -Timeout $TimeoutSeconds
        $results.Add([pscustomobject]@{
            Arch=$t.Arch; ProgID=$r.ProgID; CLSID=$r.CLSID; Description=$r.Description;
            InprocServer32=$r.InprocServer32; LocalServer32=$r.LocalServer32;
            ThreadingModel=$r.ThreadingModel; TypeLib=$r.TypeLib;
            VersionIndependentProgID=$r.VersionIndependentProgID;
            Success=$probe.Success; TimedOut=$probe.TimedOut; ProbeOutput=$probe.Output
        })
    }
}
Write-Progress -Activity 'Testing WSH COM activation' -Completed

$actResults = @()
if ($ActCtxManifest -and $ActCtxProgId.Count -gt 0) {
    foreach ($pid in $ActCtxProgId) {
        foreach ($t in $targets) {
            $probe = Invoke-CscriptProbe -Cscript $t.Cscript -Script $actCtxJs -Arguments @($ActCtxManifest, $pid) -Timeout $TimeoutSeconds
            $actResults += [pscustomobject]@{ Arch=$t.Arch; ProgID=$pid; Success=$probe.Success; TimedOut=$probe.TimedOut; ProbeOutput=$probe.Output }
        }
    }
}

$ok = @($results | Where-Object Success)
$uniqueOk = @($ok | Group-Object ProgID | Sort-Object Name)

$sb = [System.Text.StringBuilder]::new()
$null = $sb.AppendLine('# WSH / JScript COM Activation Catalog')
$null = $sb.AppendLine('')
$null = $sb.AppendLine('Generated from the local machine by `Generate-WshComCatalog.ps1`. A ProgID appears in the main catalog only if a real `cscript.exe` process successfully instantiated it with `new ActiveXObject(ProgID)`.')
$null = $sb.AppendLine('')
$null = $sb.AppendLine('> **Important:** Successful activation does not mean every method is safe or Automation-compatible. Discovery intentionally performs activation only. The examples below either use a deliberately read-only demonstration for known objects or stop after object creation.')
$null = $sb.AppendLine('')
$null = $sb.AppendLine('## Summary')
$null = $sb.AppendLine('')
$null = $sb.AppendLine("- Candidate registered ProgIDs: $($records.Count)")
$null = $sb.AppendLine("- Successful architecture-specific activations: $($ok.Count)")
$tick = [char]96
$null = $sb.AppendLine("- Unique ProgIDs callable by at least one tested ${tick}cscript.exe${tick}: $($uniqueOk.Count)")
$null = $sb.AppendLine('')
$null = $sb.AppendLine('## Callable ProgIDs')
$null = $sb.AppendLine('')
$null = $sb.AppendLine('| ProgID | x64 | x86 | CLSID | Description | Server |')
$null = $sb.AppendLine('|---|:---:|:---:|---|---|---|')
foreach ($g in $uniqueOk) {
    $rows = @($g.Group)
    $base = $rows[0]
    $x64 = if ($rows | Where-Object { $_.Arch -eq 'x64' -and $_.Success }) {'Yes'} else {'No'}
    $x86 = if ($rows | Where-Object { $_.Arch -eq 'x86' -and $_.Success }) {'Yes'} else {'No'}
    $server = if ($base.InprocServer32) { $base.InprocServer32 } elseif ($base.LocalServer32) { $base.LocalServer32 } else { '' }
    $null = $sb.AppendLine("| $tick$(Escape-Md $g.Name)$tick | $x64 | $x86 | $tick$(Escape-Md $base.CLSID)$tick | $(Escape-Md $base.Description) | $tick$(Escape-Md $server)$tick |")
}

$null = $sb.AppendLine('')
$null = $sb.AppendLine('## Per-object examples')
$null = $sb.AppendLine('')
foreach ($g in $uniqueOk) {
    $rows = @($g.Group)
    $base = $rows[0]
    $arches = @($rows | Where-Object Success | Select-Object -ExpandProperty Arch) -join ', '
    $null = $sb.AppendLine("### $($g.Name)")
    $null = $sb.AppendLine('')
    $null = $sb.AppendLine("- **CLSID:** $tick$($base.CLSID)$tick")
    if ($base.Description) { $null = $sb.AppendLine("- **Description:** $(Escape-Md $base.Description)") }
    $null = $sb.AppendLine("- **Verified with:** $arches ${tick}cscript.exe${tick}")
    if ($base.InprocServer32) { $null = $sb.AppendLine("- **In-proc server:** $tick$($base.InprocServer32)$tick") }
    if ($base.LocalServer32) { $null = $sb.AppendLine("- **Local server:** $tick$($base.LocalServer32)$tick") }
    if ($base.ThreadingModel) { $null = $sb.AppendLine("- **Threading model:** $tick$($base.ThreadingModel)$tick") }
    if ($base.TypeLib) { $null = $sb.AppendLine("- **Type library:** $tick$($base.TypeLib)$tick") }
    $null = $sb.AppendLine('')

    $ex = Get-CuratedExample -ProgID $g.Name
    $ex = $ex.Replace('PROGID_HERE', $g.Name.Replace('"','\\"'))
    $null = $sb.AppendLine($ex.Trim())
    $null = $sb.AppendLine('')
}

if ($actResults.Count -gt 0) {
    $null = $sb.AppendLine('## ACTCTX / registration-free COM results')
    $null = $sb.AppendLine('')
    $null = $sb.AppendLine("Manifest: $tick$ActCtxManifest$tick")
    $null = $sb.AppendLine('')
    $null = $sb.AppendLine('| ProgID | Architecture | Result |')
    $null = $sb.AppendLine('|---|---|---|')
    foreach ($a in $actResults) {
        $state = if ($a.Success) {'Success'} elseif ($a.TimedOut) {'Timeout'} else {'Failed'}
        $null = $sb.AppendLine("| $tick$($a.ProgID)$tick | $($a.Arch) | $state |")
    }
    $null = $sb.AppendLine('')
}

if ($IncludeFailures) {
    $null = $sb.AppendLine('## Failed / timed-out activations')
    $null = $sb.AppendLine('')
    $null = $sb.AppendLine('| ProgID | Architecture | Result | Probe output |')
    $null = $sb.AppendLine('|---|---|---|---|')
    foreach ($r in ($results | Where-Object { -not $_.Success } | Sort-Object ProgID,Arch)) {
        $state = if ($r.TimedOut) {'Timeout'} else {'Failed'}
        $null = $sb.AppendLine("| $tick$($r.ProgID)$tick | $($r.Arch) | $state | $tick$(Escape-Md $r.ProbeOutput)$tick |")
    }
    $null = $sb.AppendLine('')
}

$null = $sb.AppendLine('## Generic WSH invocation patterns')
$null = $sb.AppendLine('')
$null = $sb.AppendLine('```javascript')
$null = $sb.AppendLine('var obj = new ActiveXObject("Vendor.Component");')
$null = $sb.AppendLine('WScript.Echo("created");')
$null = $sb.AppendLine('```')
$null = $sb.AppendLine('')
$null = $sb.AppendLine('Equivalent WSH factory form:')
$null = $sb.AppendLine('')
$null = $sb.AppendLine('```javascript')
$null = $sb.AppendLine('var obj = WScript.CreateObject("Vendor.Component");')
$null = $sb.AppendLine('```')
$null = $sb.AppendLine('')
$null = $sb.AppendLine('Registration-free COM using an activation context:')
$null = $sb.AppendLine('')
$null = $sb.AppendLine('```javascript')
$null = $sb.AppendLine('var act = new ActiveXObject("Microsoft.Windows.ActCtx");')
$null = $sb.AppendLine('act.Manifest = "C:\\Path\\To\\component.manifest";')
$null = $sb.AppendLine('var obj = act.CreateObject("Vendor.Component");')
$null = $sb.AppendLine('```')

[IO.File]::WriteAllText($OutputMarkdown, $sb.ToString(), [Text.UTF8Encoding]::new($false))
$csv = [IO.Path]::ChangeExtension($OutputMarkdown, '.csv')
$results | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csv
Write-Host "Markdown: $OutputMarkdown"
Write-Host "CSV:      $csv"
