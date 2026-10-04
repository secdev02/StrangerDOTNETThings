#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Path,

    [switch]$InvokeSafeZeroArg,

    [string]$JsonPath,

    [string]$CsvPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$inspectScript = Join-Path $PSScriptRoot 'Inspect-Tlb.ps1'

if (-not (Test-Path -LiteralPath $inspectScript)) {
    throw "Inspect-Tlb.ps1 must be in the same directory."
}

$tlb = & $inspectScript -Path $Path

$denyPattern = '(?i)(delete|remove|erase|destroy|kill|terminate|shutdown|restart|reboot|execute|exec|run|shellexecute|navigate|open|send|mail|write|save|create|add|insert|update|commit|apply|connect|disconnect|install|uninstall|register|unregister|format|clear|reset|stop|start|launch|download|upload|move|copy|rename|print|publish)'

function Get-ProgIdFromClsid {
    param([guid]$Clsid)

    $paths = @(
        "Registry::HKEY_CLASSES_ROOT\CLSID\$($Clsid.ToString('B'))\ProgID",
        "Registry::HKEY_CLASSES_ROOT\Wow6432Node\CLSID\$($Clsid.ToString('B'))\ProgID"
    )

    foreach ($p in $paths) {
        try {
            if (Test-Path -LiteralPath $p) {
                $v = (Get-Item -LiteralPath $p).GetValue('')
                if ($v) {
                    return [string]$v
                }
            }
        }
        catch {}
    }

    return $null
}

$results = @()

foreach ($coclass in @($tlb.Types | Where-Object TypeKind -eq 'TKIND_COCLASS')) {

    $clsid = [guid]$coclass.Guid
    $progId = Get-ProgIdFromClsid -Clsid $clsid

    $activationSucceeded = $false
    $activationError = $null
    $obj = $null
    $invocations = @()

    try {
        $comType = [type]::GetTypeFromCLSID($clsid, $true)
        $obj = [Activator]::CreateInstance($comType)
        $activationSucceeded = $true

        if ($InvokeSafeZeroArg) {
            $candidateMembers = @()

            foreach ($impl in @($coclass.ImplementedInterfaces)) {
                $iface = $tlb.Types |
                    Where-Object Name -eq $impl.Name |
                    Select-Object -First 1

                if ($null -ne $iface) {
                    $candidateMembers += @(
                        $iface.Members |
                        Where-Object {
                            $_.InvokeKind -eq 'INVOKE_FUNC' -and
                            $_.ParameterCount -eq 0
                        }
                    )
                }
            }

            if ($candidateMembers.Count -eq 0) {
                $candidateMembers += @(
                    $coclass.Members |
                    Where-Object {
                        $_.InvokeKind -eq 'INVOKE_FUNC' -and
                        $_.ParameterCount -eq 0
                    }
                )
            }

            foreach ($m in @($candidateMembers | Sort-Object Name -Unique)) {

                if ([string]::IsNullOrWhiteSpace($m.Name)) {
                    continue
                }

                if ($m.Name -match $denyPattern) {
                    $invocations += [pscustomobject]@{
                        Method = $m.Name
                        Status = 'SkippedByDenylist'
                        Result = $null
                        Error  = $null
                    }
                    continue
                }

                try {
                    $flags = [Reflection.BindingFlags]::InvokeMethod -bor
                             [Reflection.BindingFlags]::Public -bor
                             [Reflection.BindingFlags]::Instance

                    $value = $obj.GetType().InvokeMember(
                        $m.Name,
                        $flags,
                        $null,
                        $obj,
                        @()
                    )

                    $invocations += [pscustomobject]@{
                        Method = $m.Name
                        Status = 'Invoked'
                        Result = if ($null -eq $value) { $null } else { [string]$value }
                        Error  = $null
                    }
                }
                catch {
                    $invocations += [pscustomobject]@{
                        Method = $m.Name
                        Status = 'InvocationFailed'
                        Result = $null
                        Error  = $_.Exception.Message
                    }
                }
            }
        }
    }
    catch {
        $activationError = $_.Exception.Message
    }
    finally {
        if ($null -ne $obj -and [Runtime.InteropServices.Marshal]::IsComObject($obj)) {
            try {
                [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($obj)
            }
            catch {}
        }
    }

    $methodCount = 0
    foreach ($impl in @($coclass.ImplementedInterfaces)) {
        $iface = $tlb.Types |
            Where-Object Name -eq $impl.Name |
            Select-Object -First 1

        if ($null -ne $iface) {
            $methodCount += @($iface.Members).Count
        }
    }

    $results += [pscustomobject]@{
        TypeLibrary          = $tlb.Name
        CoclassName          = $coclass.Name
        CLSID                = $coclass.Guid
        ProgID               = $progId
        ActivationSucceeded  = $activationSucceeded
        ActivationError      = $activationError
        ImplementedInterfaces= @($coclass.ImplementedInterfaces)
        DescribedMemberCount = $methodCount
        Invocations          = $invocations
    }
}

$report = [pscustomobject]@{
    TypeLibrary = [pscustomobject]@{
        Path    = $tlb.Path
        Name    = $tlb.Name
        Guid    = $tlb.Guid
        Version = "$($tlb.MajorVersion).$($tlb.MinorVersion)"
    }
    InvocationEnabled = [bool]$InvokeSafeZeroArg
    Coclasses         = $results
}

if ($JsonPath) {
    $report |
        ConvertTo-Json -Depth 12 |
        Set-Content -LiteralPath $JsonPath -Encoding UTF8
}

if ($CsvPath) {
    $flat = foreach ($r in $results) {
        [pscustomobject]@{
            TypeLibrary         = $r.TypeLibrary
            CoclassName         = $r.CoclassName
            CLSID               = $r.CLSID
            ProgID              = $r.ProgID
            ActivationSucceeded = $r.ActivationSucceeded
            ActivationError     = $r.ActivationError
            Interfaces          = ($r.ImplementedInterfaces.Name -join '; ')
            InvocationSummary   = (
                $r.Invocations |
                ForEach-Object { "$($_.Method):$($_.Status)" }
            ) -join '; '
        }
    }

    $flat | Export-Csv -LiteralPath $CsvPath -NoTypeInformation
}

$report
