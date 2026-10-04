#requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$Register
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSEdition -ne 'Desktop') {
    throw "Use Windows PowerShell 5.1 (powershell.exe)."
}

$out = Join-Path $PSScriptRoot 'Sample'
New-Item -ItemType Directory -Path $out -Force | Out-Null

$dll = Join-Path $out 'SimpleMessage.dll'
$tlb = Join-Path $out 'SimpleMessage.tlb'

Remove-Item $dll,$tlb -Force -ErrorAction SilentlyContinue

$src = @'
using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows.Forms;

[assembly: ComVisible(false)]
[assembly: TypeLibVersion(1,0)]
[assembly: AssemblyVersion("1.0.0.0")]

namespace DemoTypeLib
{
    [ComVisible(true)]
    [Guid("6215EB35-D540-4BD7-9428-AD298BBA44AA")]
    [InterfaceType(ComInterfaceType.InterfaceIsDual)]
    public interface IHelloMessage
    {
        [DispId(1)]
        string Name { get; set; }

        [DispId(2)]
        string Message { get; set; }

        [DispId(3)]
        void ShowMessage();
    }

    [ComVisible(true)]
    [Guid("17C23391-C543-4A11-88D1-675C652250D1")]
    [ProgId("DemoTypeLib.SimpleMessage")]
    [ClassInterface(ClassInterfaceType.None)]
    [ComDefaultInterface(typeof(IHelloMessage))]
    public class SimpleMessage : IHelloMessage
    {
        public SimpleMessage()
        {
            Name = "TLB Research Kit";
            Message = "Hello from the sample COM object.";
        }

        public string Name { get; set; }
        public string Message { get; set; }

        public void ShowMessage()
        {
            MessageBox.Show(
                Message ?? "",
                String.IsNullOrEmpty(Name) ? "SimpleMessage" : Name,
                MessageBoxButtons.OK,
                MessageBoxIcon.Information
            );
        }
    }

    [ComVisible(false)]
    public sealed class ExportSink : ITypeLibExporterNotifySink
    {
        public void ReportEvent(ExporterEventKind eventKind, int eventCode, string eventMsg)
        {
            Console.WriteLine("[TypeLib] " + eventMsg);
        }

        public object ResolveRef(Assembly assembly)
        {
            return null;
        }
    }
}
'@

Add-Type `
    -TypeDefinition $src `
    -Language CSharp `
    -ReferencedAssemblies System.Windows.Forms.dll `
    -OutputAssembly $dll `
    -OutputType Library

$asm = [Reflection.Assembly]::LoadFrom($dll)
$converter = New-Object Runtime.InteropServices.TypeLibConverter
$sinkType = $asm.GetType('DemoTypeLib.ExportSink', $true)
$sink = [Activator]::CreateInstance($sinkType)

$null = $converter.ConvertAssemblyToTypeLib(
    $asm,
    $tlb,
    [Runtime.InteropServices.TypeLibExporterFlags]::None,
    $sink
)

Write-Host "Created:"
Write-Host "  $dll"
Write-Host "  $tlb"

if ($Register) {
    $framework = if ([Environment]::Is64BitProcess) {
        Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319'
    } else {
        Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319'
    }

    $regasm = Join-Path $framework 'RegAsm.exe'

    if (-not (Test-Path -LiteralPath $regasm)) {
        throw "RegAsm.exe was not found at: $regasm"
    }

    Write-Host ""
    Write-Host "Registering COM class using:"
    Write-Host "  $regasm"

    & $regasm $dll /codebase "/tlb:$tlb"

    if ($LASTEXITCODE -ne 0) {
        throw "RegAsm exited with code $LASTEXITCODE"
    }

    Write-Host ""
    Write-Host "COM registration completed."
    Write-Host "ProgID: DemoTypeLib.SimpleMessage"
}
