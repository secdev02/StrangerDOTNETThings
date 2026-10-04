# WSH COM Catalog Generator

This toolkit answers a machine-specific question: **which registered COM ProgIDs can this computer actually instantiate from Windows Script Host JScript using `cscript.exe`?**

It does not assume that a ProgID is usable merely because a registry key exists. Each candidate is tested in a separate `cscript.exe` process. This matters because 32-bit and 64-bit registration, missing dependencies, licensing, COM security, and server startup can all change the result.

## Files

- `Generate-WshComCatalog.ps1` — enumerates registered ProgIDs, tests x64/x86 WSH activation, and emits Markdown + CSV.
- `Probe-ProgId.js` — minimal JScript activation probe used by the PowerShell orchestrator.
- `Probe-ActCtx.js` — registration-free COM probe using `Microsoft.Windows.ActCtx`.

## Basic use

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Generate-WshComCatalog.ps1 -Architecture Both -IncludeFailures
```

Outputs:

```text
Wsh-Com-Catalog.md
Wsh-Com-Catalog.csv
```

The Markdown contains:

1. a summary table of every ProgID that actually activated;
2. x64/x86 status;
3. CLSID and server metadata;
4. one JScript example per successful ProgID;
5. deliberately read-only examples for several common automation objects;
6. optional failure/timeout details.

## Reduce the scan

A machine can have hundreds or thousands of ProgIDs. Use wildcard filters:

```powershell
.\Generate-WshComCatalog.ps1 \
  -IncludePattern 'System.*','Microsoft.*','Scripting.*','WbemScripting.*','MSXML2.*'
```

Exclude known application families:

```powershell
.\Generate-WshComCatalog.ps1 \
  -ExcludePattern 'Excel.*','Word.*','Outlook.*'
```

## x64 versus x86

```powershell
.\Generate-WshComCatalog.ps1 -Architecture x64
.\Generate-WshComCatalog.ps1 -Architecture x86
```

The script explicitly tests:

```text
%WINDIR%\System32\cscript.exe   (64-bit on 64-bit Windows)
%WINDIR%\SysWOW64\cscript.exe  (32-bit)
```

## ACTCTX / registration-free COM

If you have a side-by-side manifest, you can test one or more ProgIDs through `Microsoft.Windows.ActCtx`:

```powershell
.\Generate-WshComCatalog.ps1 \
  -ActCtxManifest 'C:\Lab\component.manifest' \
  -ActCtxProgId 'Vendor.Component','Vendor.OtherComponent'
```

The underlying JScript pattern is:

```javascript
var act = new ActiveXObject("Microsoft.Windows.ActCtx");
act.Manifest = "C:\\Lab\\component.manifest";
var obj = act.CreateObject("Vendor.Component");
```

Activation contexts permit COM classes described by a manifest to be activated without ordinary COM registration.

## Why the generated examples are conservative

Instantiation itself can have side effects for some COM servers, so each object is tested in a separate process with a timeout. The discovery pass **does not automatically invoke arbitrary methods**. For well-known objects the generated Markdown includes a small read-only example. For everything else it documents verified activation and gives the minimal `ActiveXObject` call.

If you want a second pass that extracts `ITypeInfo` / type-library methods and generates method signatures for Automation-compatible classes, that can be layered on top of this catalog.

## Windows download security

If Windows marks the extracted scripts as downloaded from the Internet, run this once from the extracted folder:

```powershell
Get-ChildItem -Recurse -File | Unblock-File
```

Then run the generator normally.
