#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Path,

    [string]$JsonPath,

    [string]$CsvPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSEdition -ne 'Desktop') {
    throw "Use Windows PowerShell 5.1 (powershell.exe)."
}

if (-not ('TlbNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;

public static class TlbNative
{
    public enum REGKIND
    {
        REGKIND_DEFAULT  = 0,
        REGKIND_REGISTER = 1,
        REGKIND_NONE     = 2
    }

    [DllImport("oleaut32.dll", CharSet=CharSet.Unicode, PreserveSig=false)]
    public static extern void LoadTypeLibEx(
        string szFile,
        REGKIND regkind,
        out ITypeLib typeLib);
}
'@
}

function Get-TlbDoc {
    param(
        [Parameter(Mandatory=$true)]
        [System.Runtime.InteropServices.ComTypes.ITypeInfo]$TypeInfo,

        [int]$MemId = -1
    )

    $name = $null
    $doc = $null
    $ctx = 0
    $help = $null

    try {
        $TypeInfo.GetDocumentation(
            $MemId,
            [ref]$name,
            [ref]$doc,
            [ref]$ctx,
            [ref]$help
        )
    }
    catch {
        $name = $null
        $doc = $null
    }

    [pscustomobject]@{
        Name = $name
        Description = $doc
    }
}

function Get-MemberNames {
    param(
        [Parameter(Mandatory=$true)]
        [System.Runtime.InteropServices.ComTypes.ITypeInfo]$TypeInfo,

        [Parameter(Mandatory=$true)]
        [int]$MemId,

        [int]$MaxNames = 32
    )

    $names = New-Object string[] $MaxNames
    $count = 0

    try {
        $TypeInfo.GetNames($MemId, $names, $MaxNames, [ref]$count)

        if ($count -gt 0) {
            return @($names[0..($count - 1)])
        }
    }
    catch {}

    return @()
}

$resolved = (Resolve-Path -LiteralPath $Path).Path
$typeLib = $null

[TlbNative]::LoadTypeLibEx(
    $resolved,
    [TlbNative+REGKIND]::REGKIND_NONE,
    [ref]$typeLib
)

try {
    $libName = $null
    $libDoc = $null
    $libHelpContext = 0
    $libHelpFile = $null

    $typeLib.GetDocumentation(
        -1,
        [ref]$libName,
        [ref]$libDoc,
        [ref]$libHelpContext,
        [ref]$libHelpFile
    )

    $libAttrPtr = [IntPtr]::Zero

    try {
        $typeLib.GetLibAttr([ref]$libAttrPtr)

        $libAttr = [Runtime.InteropServices.Marshal]::PtrToStructure(
            $libAttrPtr,
            [type][System.Runtime.InteropServices.ComTypes.TYPELIBATTR]
        )

        $types = @()
        $typeCount = $typeLib.GetTypeInfoCount()

        for ($i = 0; $i -lt $typeCount; $i++) {
            $ti = $null

            try {
                $typeLib.GetTypeInfo($i, [ref]$ti)

                $typeKind = [System.Runtime.InteropServices.ComTypes.TYPEKIND]0
                $typeLib.GetTypeInfoType($i, [ref]$typeKind)

                $typeAttrPtr = [IntPtr]::Zero

                try {
                    $ti.GetTypeAttr([ref]$typeAttrPtr)

                    $ta = [Runtime.InteropServices.Marshal]::PtrToStructure(
                        $typeAttrPtr,
                        [type][System.Runtime.InteropServices.ComTypes.TYPEATTR]
                    )

                    $td = Get-TlbDoc -TypeInfo $ti

                    $members = @()

                    for ($f = 0; $f -lt $ta.cFuncs; $f++) {
                        $funcPtr = [IntPtr]::Zero

                        try {
                            $ti.GetFuncDesc($f, [ref]$funcPtr)

                            $fd = [Runtime.InteropServices.Marshal]::PtrToStructure(
                                $funcPtr,
                                [type][System.Runtime.InteropServices.ComTypes.FUNCDESC]
                            )

                            $names = @(Get-MemberNames -TypeInfo $ti -MemId $fd.memid)
                            $memberName = if ($names.Count -gt 0) {
                                $names[0]
                            } else {
                                (Get-TlbDoc -TypeInfo $ti -MemId $fd.memid).Name
                            }

                            $paramNames = @()
                            if ($names.Count -gt 1) {
                                $paramNames = @($names[1..($names.Count - 1)])
                            }

                            $members += [pscustomobject]@{
                                TypeName          = $td.Name
                                TypeGuid          = $ta.guid.ToString("B")
                                TypeKind          = $typeKind.ToString()
                                Name              = $memberName
                                MemId             = $fd.memid
                                InvokeKind        = $fd.invkind.ToString()
                                FunctionKind      = $fd.funckind.ToString()
                                CallConvention    = $fd.callconv.ToString()
                                ParameterCount    = [int]$fd.cParams
                                OptionalParameters= [int]$fd.cParamsOpt
                                ParameterNames    = $paramNames
                                VTableOffset      = [int]$fd.oVft
                                FunctionFlags     = $fd.wFuncFlags.ToString()
                            }
                        }
                        finally {
                            if ($funcPtr -ne [IntPtr]::Zero) {
                                $ti.ReleaseFuncDesc($funcPtr)
                            }
                        }
                    }

                    $implemented = @()

                    for ($x = 0; $x -lt $ta.cImplTypes; $x++) {
                        try {
                            $href = 0
                            $ti.GetRefTypeOfImplType($x, [ref]$href)

                            $refTi = $null
                            $ti.GetRefTypeInfo($href, [ref]$refTi)

                            try {
                                $rd = Get-TlbDoc -TypeInfo $refTi

                                $flags = 0
                                $ti.GetImplTypeFlags($x, [ref]$flags)

                                $implemented += [pscustomobject]@{
                                    Name  = $rd.Name
                                    Flags = $flags
                                }
                            }
                            finally {
                                if ($null -ne $refTi) {
                                    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($refTi)
                                }
                            }
                        }
                        catch {}
                    }

                    $types += [pscustomobject]@{
                        Index                 = $i
                        Name                  = $td.Name
                        Description           = $td.Description
                        Guid                  = $ta.guid.ToString("B")
                        TypeKind              = $typeKind.ToString()
                        MajorVersion          = [int]$ta.wMajorVerNum
                        MinorVersion          = [int]$ta.wMinorVerNum
                        FunctionCount         = [int]$ta.cFuncs
                        VariableCount         = [int]$ta.cVars
                        ImplementedTypeCount  = [int]$ta.cImplTypes
                        TypeFlags             = $ta.wTypeFlags.ToString()
                        ImplementedInterfaces = $implemented
                        Members               = $members
                    }
                }
                finally {
                    if ($typeAttrPtr -ne [IntPtr]::Zero) {
                        $ti.ReleaseTypeAttr($typeAttrPtr)
                    }
                }
            }
            finally {
                if ($null -ne $ti) {
                    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($ti)
                }
            }
        }

        $result = [pscustomobject]@{
            Path         = $resolved
            Name         = $libName
            Description  = $libDoc
            Guid         = $libAttr.guid.ToString("B")
            MajorVersion = [int]$libAttr.wMajorVerNum
            MinorVersion = [int]$libAttr.wMinorVerNum
            LCID         = [int]$libAttr.lcid
            SysKind      = $libAttr.syskind.ToString()
            LibraryFlags = $libAttr.wLibFlags.ToString()
            TypeCount    = $typeCount
            Types        = $types
        }

        if ($JsonPath) {
            $result |
                ConvertTo-Json -Depth 10 |
                Set-Content -LiteralPath $JsonPath -Encoding UTF8
        }

        if ($CsvPath) {
            $flat = foreach ($t in $types) {
                if ($t.Members.Count -eq 0) {
                    [pscustomobject]@{
                        TypeName       = $t.Name
                        TypeGuid       = $t.Guid
                        TypeKind       = $t.TypeKind
                        MemberName     = $null
                        MemId          = $null
                        InvokeKind     = $null
                        ParameterCount = $null
                        VTableOffset   = $null
                    }
                }
                else {
                    foreach ($m in $t.Members) {
                        [pscustomobject]@{
                            TypeName       = $t.Name
                            TypeGuid       = $t.Guid
                            TypeKind       = $t.TypeKind
                            MemberName     = $m.Name
                            MemId          = $m.MemId
                            InvokeKind     = $m.InvokeKind
                            ParameterCount = $m.ParameterCount
                            VTableOffset   = $m.VTableOffset
                        }
                    }
                }
            }

            $flat | Export-Csv -LiteralPath $CsvPath -NoTypeInformation
        }

        $result
    }
    finally {
        if ($libAttrPtr -ne [IntPtr]::Zero) {
            $typeLib.ReleaseTLibAttr($libAttrPtr)
        }
    }
}
finally {
    if ($null -ne $typeLib) {
        [void][Runtime.InteropServices.Marshal]::ReleaseComObject($typeLib)
    }
}
