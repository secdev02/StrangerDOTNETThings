#requires -Version 5.1
$ErrorActionPreference = 'Stop'

$sampleTlb = Join-Path $PSScriptRoot 'Sample\SimpleMessage.tlb'

if (-not (Test-Path -LiteralPath $sampleTlb)) {
    throw "Run .\New-SampleTypeLib.ps1 first."
}

Write-Host "=== INSPECTION ==="
$r = & (Join-Path $PSScriptRoot 'Inspect-Tlb.ps1') -Path $sampleTlb

$r.Types |
    Select-Object Index, Name, TypeKind, Guid, FunctionCount |
    Format-Table -AutoSize

Write-Host ""
Write-Host "=== ACTIVATION RESEARCH ==="

$activation = & (Join-Path $PSScriptRoot 'Invoke-TlbResearch.ps1') -Path $sampleTlb

$activation.Coclasses |
    Select-Object CoclassName, CLSID, ProgID, ActivationSucceeded, ActivationError |
    Format-Table -AutoSize

Write-Host ""
Write-Host "If ActivationSucceeded is False, rebuild/register the sample with:"
Write-Host "  .\New-SampleTypeLib.ps1 -Register"
Write-Host ""
Write-Host "Then invoke the zero-argument sample method with:"
Write-Host "  .\Invoke-TlbResearch.ps1 -Path .\Sample\SimpleMessage.tlb -InvokeSafeZeroArg"
