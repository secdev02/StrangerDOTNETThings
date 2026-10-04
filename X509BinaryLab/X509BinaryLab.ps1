#requires -Version 7.4
<#
.SYNOPSIS
  X509BinaryLab - dependency-free X.509 DER construction and validation toolkit.
.DESCRIPTION
  Builds X.509 v3 certificates from DER primitives so callers can control the
  TBSCertificate at the byte level while still using built-in .NET crypto for
  signing. Designed for interoperability and negative-testing labs.

  No NuGet modules, OpenSSL, BouncyCastle, certreq.exe, or third-party binaries.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:X509BinaryLabVersion = '1.0.0'

function Join-ByteArray {
    param([Parameter(ValueFromRemainingArguments=$true)][object[]]$Parts)
    $ms = [System.IO.MemoryStream]::new()
    try {
        foreach ($part in $Parts) {
            if ($null -eq $part) { continue }
            [byte[]]$b = $part
            $ms.Write($b, 0, $b.Length)
        }
        return $ms.ToArray()
    } finally { $ms.Dispose() }
}

function ConvertTo-DerLength {
    param([Parameter(Mandatory)][int]$Length)
    if ($Length -lt 0) { throw 'DER length cannot be negative.' }
    if ($Length -lt 128) { return [byte[]]@([byte]$Length) }
    $tmp = [System.Collections.Generic.List[byte]]::new()
    $n = [uint64]$Length
    while ($n -gt 0) { $tmp.Insert(0, [byte]($n -band 0xFF)); $n = $n -shr 8 }
    return Join-ByteArray ([byte[]]@([byte](0x80 -bor $tmp.Count))) ([byte[]]$tmp.ToArray())
}

function New-DerTlv {
    param([Parameter(Mandatory)][byte]$Tag, [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Value)
    return Join-ByteArray ([byte[]]@($Tag)) (ConvertTo-DerLength $Value.Length) $Value
}
function New-DerSequence { param([Parameter(ValueFromRemainingArguments=$true)][object[]]$Items) New-DerTlv 0x30 (Join-ByteArray @Items) }
function New-DerSet      { param([Parameter(ValueFromRemainingArguments=$true)][object[]]$Items) New-DerTlv 0x31 (Join-ByteArray @Items) }
function New-DerNull     { New-DerTlv 0x05 ([byte[]]@()) }
function New-DerOctetString { param([byte[]]$Bytes) New-DerTlv 0x04 $Bytes }
function New-DerBoolean  { param([bool]$Value) New-DerTlv 0x01 ([byte[]]@($(if($Value){0xFF}else{0x00}))) }
function New-DerUtf8String { param([string]$Value) New-DerTlv 0x0C ([Text.Encoding]::UTF8.GetBytes($Value)) }
function New-DerIa5String { param([string]$Value) New-DerTlv 0x16 ([Text.Encoding]::ASCII.GetBytes($Value)) }

function Convert-HexToBytes {
    param([Parameter(Mandatory)][string]$Hex)
    $h = ($Hex -replace '[^0-9A-Fa-f]', '')
    if (($h.Length % 2) -ne 0) { $h = '0' + $h }
    $out = [byte[]]::new($h.Length / 2)
    for ($i=0; $i -lt $out.Length; $i++) { $out[$i] = [Convert]::ToByte($h.Substring($i*2,2),16) }
    return $out
}
function Convert-BytesToHex { param([byte[]]$Bytes) (($Bytes | ForEach-Object { $_.ToString('X2') }) -join '') }

function New-DerIntegerUnsigned {
    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes)
    $i = 0
    while ($i -lt ($Bytes.Length - 1) -and $Bytes[$i] -eq 0) { $i++ }
    [byte[]]$v = if ($Bytes.Length -eq 0) { @(0) } else { $Bytes[$i..($Bytes.Length-1)] }
    if (($v[0] -band 0x80) -ne 0) { $v = Join-ByteArray ([byte[]]@(0)) $v }
    return New-DerTlv 0x02 $v
}
function New-DerInteger {
    param([Parameter(Mandatory)][long]$Value)
    if ($Value -lt 0) { throw 'This helper only accepts non-negative integers.' }
    if ($Value -eq 0) { return New-DerTlv 0x02 ([byte[]]@(0)) }
    $tmp = [System.Collections.Generic.List[byte]]::new()
    [uint64]$n = $Value
    while ($n -gt 0) { $tmp.Insert(0,[byte]($n -band 0xFF)); $n = $n -shr 8 }
    return New-DerIntegerUnsigned $tmp.ToArray()
}

function New-DerOid {
    param([Parameter(Mandatory)][string]$Oid)
    $arcs = $Oid.Split('.') | ForEach-Object { [uint64]$_ }
    if ($arcs.Count -lt 2 -or $arcs[0] -gt 2 -or ($arcs[0] -lt 2 -and $arcs[1] -gt 39)) { throw "Invalid OID: $Oid" }
    $bytes = [System.Collections.Generic.List[byte]]::new()
    $bytes.Add([byte](40*$arcs[0] + $arcs[1]))
    if ($arcs.Count -gt 2) { foreach ($arc in $arcs[2..($arcs.Count-1)]) {
        $stack = [System.Collections.Generic.List[byte]]::new()
        [uint64]$n = $arc
        $stack.Insert(0,[byte]($n -band 0x7F)); $n = $n -shr 7
        while ($n -gt 0) { $stack.Insert(0,[byte](0x80 -bor ($n -band 0x7F))); $n = $n -shr 7 }
        $bytes.AddRange($stack)
    } }
    return New-DerTlv 0x06 $bytes.ToArray()
}

function New-DerBitString {
    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes, [ValidateRange(0,7)][int]$UnusedBits=0)
    if ($Bytes.Length -eq 0 -and $UnusedBits -ne 0) { throw 'Empty BIT STRING must have zero unused bits.' }
    if ($Bytes.Length -gt 0 -and $UnusedBits -gt 0) {
        $mask = (1 -shl $UnusedBits) - 1
        if (($Bytes[-1] -band $mask) -ne 0) { throw 'Non-zero unused bits are not DER canonical.' }
    }
    return New-DerTlv 0x03 (Join-ByteArray ([byte[]]@([byte]$UnusedBits)) $Bytes)
}

function New-DerContextExplicit { param([ValidateRange(0,30)][int]$Number,[byte[]]$InnerDer) New-DerTlv ([byte](0xA0 + $Number)) $InnerDer }
function New-DerContextPrimitive { param([ValidateRange(0,30)][int]$Number,[byte[]]$Value) New-DerTlv ([byte](0x80 + $Number)) $Value }

function New-DerTime {
    param([Parameter(Mandatory)][DateTimeOffset]$Time)
    $utc = $Time.ToUniversalTime()
    if ($utc.Year -ge 1950 -and $utc.Year -le 2049) {
        return New-DerTlv 0x17 ([Text.Encoding]::ASCII.GetBytes($utc.ToString('yyMMddHHmmssZ',[Globalization.CultureInfo]::InvariantCulture)))
    }
    return New-DerTlv 0x18 ([Text.Encoding]::ASCII.GetBytes($utc.ToString('yyyyMMddHHmmssZ',[Globalization.CultureInfo]::InvariantCulture)))
}

function New-X509AlgorithmIdentifier {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Oid,
        [byte[]]$ParametersDer,
        [switch]$OmitParameters
    )
    if ($OmitParameters) { return New-DerSequence (New-DerOid $Oid) }
    if ($PSBoundParameters.ContainsKey('ParametersDer')) { return New-DerSequence (New-DerOid $Oid) $ParametersDer }
    return New-DerSequence (New-DerOid $Oid) (New-DerNull)
}

function Get-HashOid {
    param([ValidateSet('SHA256','SHA384','SHA512')][string]$Hash)
    switch ($Hash) { 'SHA256' {'2.16.840.1.101.3.4.2.1'} 'SHA384' {'2.16.840.1.101.3.4.2.2'} 'SHA512' {'2.16.840.1.101.3.4.2.3'} }
}

function New-RsaPssParameters {
    param([ValidateSet('SHA256','SHA384','SHA512')][string]$Hash='SHA256',[int]$SaltLength=0)
    if ($SaltLength -eq 0) { $SaltLength = switch($Hash){'SHA256'{32}'SHA384'{48}'SHA512'{64}} }
    $hashAI = New-X509AlgorithmIdentifier -Oid (Get-HashOid $Hash)
    $mgf1AI = New-X509AlgorithmIdentifier -Oid '1.2.840.113549.1.1.8' -ParametersDer $hashAI
    return New-DerSequence (New-DerContextExplicit 0 $hashAI) (New-DerContextExplicit 1 $mgf1AI) (New-DerContextExplicit 2 (New-DerInteger $SaltLength))
}

function Get-X509SignatureAlgorithmIdentifier {
    param([Parameter(Mandatory)][ValidateSet('RSA-SHA256','RSA-SHA384','RSA-SHA512','RSA-PSS-SHA256','RSA-PSS-SHA384','RSA-PSS-SHA512','ECDSA-SHA256','ECDSA-SHA384','ECDSA-SHA512')][string]$Algorithm)
    switch ($Algorithm) {
        'RSA-SHA256' { New-X509AlgorithmIdentifier '1.2.840.113549.1.1.11' }
        'RSA-SHA384' { New-X509AlgorithmIdentifier '1.2.840.113549.1.1.12' }
        'RSA-SHA512' { New-X509AlgorithmIdentifier '1.2.840.113549.1.1.13' }
        'RSA-PSS-SHA256' { New-X509AlgorithmIdentifier '1.2.840.113549.1.1.10' -ParametersDer (New-RsaPssParameters SHA256) }
        'RSA-PSS-SHA384' { New-X509AlgorithmIdentifier '1.2.840.113549.1.1.10' -ParametersDer (New-RsaPssParameters SHA384) }
        'RSA-PSS-SHA512' { New-X509AlgorithmIdentifier '1.2.840.113549.1.1.10' -ParametersDer (New-RsaPssParameters SHA512) }
        'ECDSA-SHA256' { New-X509AlgorithmIdentifier '1.2.840.10045.4.3.2' -OmitParameters }
        'ECDSA-SHA384' { New-X509AlgorithmIdentifier '1.2.840.10045.4.3.3' -OmitParameters }
        'ECDSA-SHA512' { New-X509AlgorithmIdentifier '1.2.840.10045.4.3.4' -OmitParameters }
    }
}

function Get-X509NamedCurve {
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateSet('P256','P384','P521')][string]$Curve)

    $propertyName = switch ($Curve) { 'P256' {'nistP256'} 'P384' {'nistP384'} 'P521' {'nistP521'} }
    $oid = switch ($Curve) { 'P256' {'1.2.840.10045.3.1.7'} 'P384' {'1.3.132.0.34'} 'P521' {'1.3.132.0.35'} }

    # PowerShell does not consistently resolve ECCurve.NamedCurves across
    # Windows PowerShell and PowerShell 7. Resolve the nested type via reflection.
    $namedCurvesType = [Security.Cryptography.ECCurve].GetNestedType('NamedCurves')
    if ($null -ne $namedCurvesType) {
        $prop = $namedCurvesType.GetProperty($propertyName, [Reflection.BindingFlags]'Public,Static')
        if ($null -ne $prop) { return $prop.GetValue($null, $null) }
    }

    $createFromOid = [Security.Cryptography.ECCurve].GetMethod('CreateFromOid', [type[]]@([Security.Cryptography.Oid]))
    if ($null -ne $createFromOid) {
        return $createFromOid.Invoke($null, @([Security.Cryptography.Oid]::new($oid)))
    }

    $createFromFriendlyName = [Security.Cryptography.ECCurve].GetMethod('CreateFromFriendlyName', [type[]]@([string]))
    if ($null -ne $createFromFriendlyName) {
        return $createFromFriendlyName.Invoke($null, @($propertyName))
    }

    throw "This runtime cannot construct the named EC curve $Curve ($oid)."
}

function Convert-EcdsaP1363ToDer {
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$Signature)
    if (($Signature.Length % 2) -ne 0 -or $Signature.Length -eq 0) { throw 'Invalid IEEE-P1363 ECDSA signature length.' }
    $half = [int]($Signature.Length / 2)
    $r = [byte[]]::new($half); $s = [byte[]]::new($half)
    [Array]::Copy($Signature, 0, $r, 0, $half)
    [Array]::Copy($Signature, $half, $s, 0, $half)
    return New-DerSequence (New-DerIntegerUnsigned $r) (New-DerIntegerUnsigned $s)
}

function Convert-EcdsaDerToP1363 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$SignatureDer,[Parameter(Mandatory)][int]$FieldBytes)
    $outer = Read-DerNode $SignatureDer 0 $SignatureDer.Length
    if ($outer.Tag -ne 0x30 -or $outer.End -ne $SignatureDer.Length) { throw 'ECDSA signature is not a DER SEQUENCE.' }
    $rNode = Read-DerNode $SignatureDer $outer.ValueOffset $outer.End
    $sNode = Read-DerNode $SignatureDer $rNode.End $outer.End
    if ($rNode.Tag -ne 0x02 -or $sNode.Tag -ne 0x02) { throw 'ECDSA signature must contain two INTEGER values.' }
    $result = [byte[]]::new($FieldBytes * 2)
    foreach ($pair in @(@($rNode,0), @($sNode,$FieldBytes))) {
        $node=$pair[0]; $dest=[int]$pair[1]
        $v=[byte[]]::new($node.Length); [Array]::Copy($SignatureDer,$node.ValueOffset,$v,0,$node.Length)
        while ($v.Length -gt 1 -and $v[0] -eq 0) { $v = $v[1..($v.Length-1)] }
        if ($v.Length -gt $FieldBytes) { throw 'ECDSA INTEGER is larger than the target field size.' }
        [Array]::Copy($v,0,$result,$dest + $FieldBytes - $v.Length,$v.Length)
    }
    return $result
}

function Export-X509Pkcs8PrivateKey {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Key)

    $m = $Key.GetType().GetMethod('ExportPkcs8PrivateKey', [Type[]]@())
    if ($null -ne $m) { return [byte[]]$m.Invoke($Key, @()) }

    # Windows PowerShell / .NET Framework fallback for CNG-backed keys.
    if ($Key.PSObject.Properties.Name -contains 'Key' -and $null -ne $Key.Key) {
        $blobFormat = [Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob
        return [byte[]]$Key.Key.Export($blobFormat)
    }

    return $null
}

function Test-X509EcdsaSignature {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Key,
        [Parameter(Mandatory)][byte[]]$Data,
        [Parameter(Mandatory)][byte[]]$SignatureDer,
        [Parameter(Mandatory)][Security.Cryptography.HashAlgorithmName]$HashAlgorithm
    )
    $fmtType = 'System.Security.Cryptography.DSASignatureFormat' -as [type]
    if ($null -ne $fmtType) {
        $m = $Key.GetType().GetMethods() | Where-Object {
            $_.Name -eq 'VerifyData' -and $_.GetParameters().Count -eq 4 -and $_.GetParameters()[3].ParameterType.FullName -eq $fmtType.FullName
        } | Select-Object -First 1
        if ($null -ne $m) {
            $fmt = [Enum]::Parse($fmtType, 'Rfc3279DerSequence')
            return [bool]$m.Invoke($Key, @($Data,$SignatureDer,$HashAlgorithm,$fmt))
        }
    }
    $fieldBytes = $Key.ExportParameters($false).Q.X.Length
    $raw = Convert-EcdsaDerToP1363 -SignatureDer $SignatureDer -FieldBytes $fieldBytes
    return [bool]$Key.VerifyData($Data,$raw,$HashAlgorithm)
}

function New-X509Key {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('RSA','ECDSA-P256','ECDSA-P384','ECDSA-P521')][string]$Algorithm,
        [ValidateRange(2048,16384)][int]$RsaKeySize=3072
    )
    switch ($Algorithm) {
        'RSA' { return [Security.Cryptography.RSA]::Create($RsaKeySize) }
        'ECDSA-P256' { return [Security.Cryptography.ECDsa]::Create((Get-X509NamedCurve P256)) }
        'ECDSA-P384' { return [Security.Cryptography.ECDsa]::Create((Get-X509NamedCurve P384)) }
        'ECDSA-P521' { return [Security.Cryptography.ECDsa]::Create((Get-X509NamedCurve P521)) }
    }
}
function Get-X509SubjectPublicKeyInfo { param([Parameter(Mandatory)]$Key) [byte[]]$Key.ExportSubjectPublicKeyInfo() }

function New-X509RsaSubjectPublicKeyInfo {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ModulusHex,[uint32]$Exponent=65537)
    $mod = Convert-HexToBytes $ModulusHex
    $expBytes = [BitConverter]::GetBytes($Exponent); [Array]::Reverse($expBytes)
    while ($expBytes.Length -gt 1 -and $expBytes[0] -eq 0) { $expBytes = $expBytes[1..($expBytes.Length-1)] }
    $rsaPub = New-DerSequence (New-DerIntegerUnsigned $mod) (New-DerIntegerUnsigned $expBytes)
    $alg = New-X509AlgorithmIdentifier '1.2.840.113549.1.1.1'
    return New-DerSequence $alg (New-DerBitString $rsaPub)
}

function New-X509EcSubjectPublicKeyInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CurveOid,
        [Parameter(Mandatory)][string]$UncompressedPointHex
    )
    $point = Convert-HexToBytes $UncompressedPointHex
    if ($point.Length -lt 2 -or $point[0] -ne 0x04) { throw 'EC point must be ANSI X9.62 uncompressed form beginning with 04.' }
    $alg = New-X509AlgorithmIdentifier -Oid '1.2.840.10045.2.1' -ParametersDer (New-DerOid $CurveOid)
    return New-DerSequence $alg (New-DerBitString $point)
}

function New-X509Extension {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Oid,[Parameter(Mandatory)][byte[]]$ValueDer,[bool]$Critical=$false)
    $parts = @((New-DerOid $Oid))
    if ($Critical) { $parts += ,(New-DerBoolean $true) }
    $parts += ,(New-DerOctetString $ValueDer)
    return [pscustomobject]@{ PSTypeName='X509BinaryLab.Extension'; Oid=$Oid; Critical=$Critical; ValueDer=$ValueDer; ExtensionDer=(New-DerSequence @parts) }
}

function New-X509BasicConstraintsExtension {
    param([bool]$CertificateAuthority=$false,[Nullable[int]]$PathLength,[bool]$Critical=$true)
    $items=@(); if($CertificateAuthority){$items += ,(New-DerBoolean $true)}; if($null -ne $PathLength){$items += ,(New-DerInteger $PathLength.Value)}
    New-X509Extension '2.5.29.19' (New-DerSequence @items) $Critical
}

function New-X509KeyUsageExtension {
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateSet('digitalSignature','nonRepudiation','keyEncipherment','dataEncipherment','keyAgreement','keyCertSign','cRLSign','encipherOnly','decipherOnly')][string[]]$Usage,[bool]$Critical=$true)
    $positions=@{digitalSignature=0;nonRepudiation=1;keyEncipherment=2;dataEncipherment=3;keyAgreement=4;keyCertSign=5;cRLSign=6;encipherOnly=7;decipherOnly=8}
    $max=($Usage | ForEach-Object {$positions[$_]} | Measure-Object -Maximum).Maximum
    $count=[Math]::Floor($max/8)+1; $bytes=[byte[]]::new($count)
    foreach($u in $Usage){$p=$positions[$u];$bytes[[Math]::Floor($p/8)] = $bytes[[Math]::Floor($p/8)] -bor (0x80 -shr ($p%8))}
    $used=($max%8)+1; $unused=(8-$used)%8
    New-X509Extension '2.5.29.15' (New-DerBitString $bytes $unused) $Critical
}

function New-X509ExtendedKeyUsageExtension {
    param([Parameter(Mandatory)][string[]]$Oid,[bool]$Critical=$false)
    $items=@($Oid | ForEach-Object { New-DerOid $_ })
    New-X509Extension '2.5.29.37' (New-DerSequence @items) $Critical
}

function Get-X509SubjectKeyIdentifierBytes {
    param([Parameter(Mandatory)][byte[]]$SubjectPublicKeyInfo)
    $outer=Read-DerNode $SubjectPublicKeyInfo 0 $SubjectPublicKeyInfo.Length
    if($outer.Tag -ne 0x30 -or $outer.End -ne $SubjectPublicKeyInfo.Length){throw 'SPKI is not a single DER SEQUENCE.'}
    $p=$outer.ValueOffset
    $alg=Read-DerNode $SubjectPublicKeyInfo $p $outer.End; $p=$alg.End
    $bits=Read-DerNode $SubjectPublicKeyInfo $p $outer.End
    if($alg.Tag -ne 0x30 -or $bits.Tag -ne 0x03 -or $bits.End -ne $outer.End){throw 'SPKI does not contain AlgorithmIdentifier + subjectPublicKey BIT STRING.'}
    if($bits.Length -lt 1 -or $SubjectPublicKeyInfo[$bits.ValueOffset] -ne 0){throw 'SPKI subjectPublicKey has unsupported unused bits.'}
    [byte[]]$keyBits = if($bits.Length -eq 1){@()}else{$SubjectPublicKeyInfo[($bits.ValueOffset+1)..($bits.End-1)]}
    $sha1=[Security.Cryptography.SHA1]::Create(); try{return [byte[]]$sha1.ComputeHash($keyBits)}finally{$sha1.Dispose()}
}
function New-X509SubjectKeyIdentifierExtension {
    param([Parameter(Mandatory)][byte[]]$SubjectPublicKeyInfo,[bool]$Critical=$false)
    $id=Get-X509SubjectKeyIdentifierBytes $SubjectPublicKeyInfo
    New-X509Extension '2.5.29.14' (New-DerOctetString $id) $Critical
}
function New-X509AuthorityKeyIdentifierExtension {
    param([Parameter(Mandatory)][byte[]]$KeyIdentifier,[bool]$Critical=$false)
    New-X509Extension '2.5.29.35' (New-DerSequence (New-DerContextPrimitive 0 $KeyIdentifier)) $Critical
}

function New-X509GeneralNameDer {
    param([Parameter(Mandatory)][ValidateSet('DNS','URI','Email','IP')][string]$Type,[Parameter(Mandatory)][string]$Value)
    switch($Type){
        'DNS' { New-DerContextPrimitive 2 ([Text.Encoding]::ASCII.GetBytes($Value)) }
        'URI' { New-DerContextPrimitive 6 ([Text.Encoding]::ASCII.GetBytes($Value)) }
        'Email' { New-DerContextPrimitive 1 ([Text.Encoding]::ASCII.GetBytes($Value)) }
        'IP' { New-DerContextPrimitive 7 ([Net.IPAddress]::Parse($Value).GetAddressBytes()) }
    }
}
function New-X509SubjectAltNameExtension {
    param([string[]]$DnsName,[string[]]$IpAddress,[string[]]$Uri,[string[]]$Email,[bool]$Critical=$false)
    $n=@(); foreach($v in $DnsName){$n+=,(New-X509GeneralNameDer DNS $v)};foreach($v in $IpAddress){$n+=,(New-X509GeneralNameDer IP $v)};foreach($v in $Uri){$n+=,(New-X509GeneralNameDer URI $v)};foreach($v in $Email){$n+=,(New-X509GeneralNameDer Email $v)}
    if($n.Count -eq 0){throw 'At least one SAN value is required.'}
    New-X509Extension '2.5.29.17' (New-DerSequence @n) $Critical
}

function New-X509AuthorityInformationAccessExtension {
    param([string[]]$OcspUri,[string[]]$CaIssuersUri,[bool]$Critical=$false)
    $a=@(); foreach($u in $OcspUri){$a+=,(New-DerSequence (New-DerOid '1.3.6.1.5.5.7.48.1') (New-X509GeneralNameDer URI $u))}; foreach($u in $CaIssuersUri){$a+=,(New-DerSequence (New-DerOid '1.3.6.1.5.5.7.48.2') (New-X509GeneralNameDer URI $u))}
    if($a.Count -eq 0){throw 'At least one AIA URI is required.'}
    New-X509Extension '1.3.6.1.5.5.7.1.1' (New-DerSequence @a) $Critical
}
function New-X509CrlDistributionPointsExtension {
    param([Parameter(Mandatory)][string[]]$Uri,[bool]$Critical=$false)
    $points=@(); foreach($u in $Uri){$gn=New-X509GeneralNameDer URI $u; $fullName=New-DerContextExplicit 0 $gn; $dpName=New-DerContextExplicit 0 $fullName; $points+=,(New-DerSequence $dpName)}
    New-X509Extension '2.5.29.31' (New-DerSequence @points) $Critical
}

function New-X509SerialNumber {
    param([ValidateRange(1,20)][int]$Bytes=20)
    $b=[byte[]]::new($Bytes); [Security.Cryptography.RandomNumberGenerator]::Fill($b); $b[0]=$b[0]-band 0x7F
    if(($b | Where-Object {$_ -ne 0}).Count -eq 0){$b[-1]=1}; return $b
}

function Invoke-X509Sign {
    param([Parameter(Mandatory)][byte[]]$Data,[Parameter(Mandatory)]$Signer,[Parameter(Mandatory)][string]$SignatureAlgorithm)
    $hash = if($SignatureAlgorithm -match 'SHA256$'){'SHA256'}elseif($SignatureAlgorithm -match 'SHA384$'){'SHA384'}else{'SHA512'}
    $hn=[Security.Cryptography.HashAlgorithmName]::$hash
    if($SignatureAlgorithm -like 'RSA-PSS-*') { return [byte[]]$Signer.SignData($Data,$hn,[Security.Cryptography.RSASignaturePadding]::Pss) }
    if($SignatureAlgorithm -like 'RSA-*') { return [byte[]]$Signer.SignData($Data,$hn,[Security.Cryptography.RSASignaturePadding]::Pkcs1) }
    if($SignatureAlgorithm -like 'ECDSA-*') {
        $fmtType = 'System.Security.Cryptography.DSASignatureFormat' -as [type]
        if ($null -ne $fmtType) {
            $m = $Signer.GetType().GetMethods() | Where-Object {
                $_.Name -eq 'SignData' -and $_.GetParameters().Count -eq 3 -and $_.GetParameters()[2].ParameterType.FullName -eq $fmtType.FullName
            } | Select-Object -First 1
            if ($null -ne $m) {
                $fmt = [Enum]::Parse($fmtType, 'Rfc3279DerSequence')
                return [byte[]]$m.Invoke($Signer, @($Data,$hn,$fmt))
            }
        }
        # Legacy ECDsa.SignData returns IEEE-P1363 r||s; X.509 needs RFC 3279 DER.
        return (Convert-EcdsaP1363ToDer -Signature ([byte[]]$Signer.SignData($Data,$hn)))
    }
    throw "Unsupported built-in signer algorithm: $SignatureAlgorithm"
}

function New-X509CertificateDer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Subject,
        [Parameter(Mandatory)][string]$Issuer,
        [Parameter(Mandatory)][byte[]]$SubjectPublicKeyInfo,
        [Parameter(Mandatory)]$Signer,
        [Parameter(Mandatory)][ValidateSet('RSA-SHA256','RSA-SHA384','RSA-SHA512','RSA-PSS-SHA256','RSA-PSS-SHA384','RSA-PSS-SHA512','ECDSA-SHA256','ECDSA-SHA384','ECDSA-SHA512')][string]$SignatureAlgorithm,
        [DateTimeOffset]$NotBefore=[DateTimeOffset]::UtcNow.AddMinutes(-5),
        [DateTimeOffset]$NotAfter=[DateTimeOffset]::UtcNow.AddYears(1),
        [byte[]]$SerialNumber=(New-X509SerialNumber),
        [object[]]$Extension=@(),
        [ValidateRange(1,3)][int]$Version=3,
        [byte[]]$IssuerUniqueId,
        [byte[]]$SubjectUniqueId,
        [ValidateSet('Strict','AsnOnly','None')][string]$Validation='Strict'
    )
    if($NotAfter -le $NotBefore){throw 'NotAfter must be later than NotBefore.'}
    if($SerialNumber.Length -lt 1 -or $SerialNumber.Length -gt 20){throw 'RFC 5280 serial number must be 1..20 octets.'}
    $sigAI=Get-X509SignatureAlgorithmIdentifier $SignatureAlgorithm
    $issuerDer=[Security.Cryptography.X509Certificates.X500DistinguishedName]::new($Issuer).RawData
    $subjectDer=[Security.Cryptography.X509Certificates.X500DistinguishedName]::new($Subject).RawData
    $t=@()
    if($Version -ne 1){$t+=,(New-DerContextExplicit 0 (New-DerInteger ($Version-1)))}
    $t+=,(New-DerIntegerUnsigned $SerialNumber)
    $t+=,$sigAI
    $t+=,$issuerDer
    $t+=,(New-DerSequence (New-DerTime $NotBefore) (New-DerTime $NotAfter))
    $t+=,$subjectDer
    $t+=,$SubjectPublicKeyInfo
    if($PSBoundParameters.ContainsKey('IssuerUniqueId')){$t+=,(New-DerTlv 0x81 (Join-ByteArray ([byte[]]@(0)) $IssuerUniqueId))}
    if($PSBoundParameters.ContainsKey('SubjectUniqueId')){$t+=,(New-DerTlv 0x82 (Join-ByteArray ([byte[]]@(0)) $SubjectUniqueId))}
    if($Extension.Count -gt 0){
        if($Version -ne 3){throw 'Extensions require X.509 v3.'}
        $extDer=@($Extension | ForEach-Object { if($_.PSObject.Properties.Name -contains 'ExtensionDer'){[byte[]]$_.ExtensionDer}else{[byte[]]$_} })
        $t+=,(New-DerContextExplicit 3 (New-DerSequence @extDer))
    }
    $tbs=New-DerSequence @t
    $signature=Invoke-X509Sign $tbs $Signer $SignatureAlgorithm
    $cert=New-DerSequence $tbs $sigAI (New-DerBitString $signature)
    if($Validation -ne 'None'){ $r=Test-X509CertificateDer -CertificateDer $cert -Mode $Validation; if(-not $r.Valid){throw "Certificate validation failed: $($r.Errors -join '; ')"} }
    [pscustomobject]@{PSTypeName='X509BinaryLab.Certificate';Version=$script:X509BinaryLabVersion;CertificateDer=$cert;TbsCertificateDer=$tbs;Signature=$signature;SignatureAlgorithm=$SignatureAlgorithm;SerialHex=(Convert-BytesToHex $SerialNumber);Subject=$Subject;Issuer=$Issuer}
}

function New-X509SelfSignedCertificate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Subject,
        [ValidateSet('RSA','ECDSA-P256','ECDSA-P384','ECDSA-P521')][string]$KeyAlgorithm='RSA',
        [int]$RsaKeySize=3072,
        [string]$SignatureAlgorithm,
        [DateTimeOffset]$NotBefore=[DateTimeOffset]::UtcNow.AddMinutes(-5),
        [DateTimeOffset]$NotAfter=[DateTimeOffset]::UtcNow.AddYears(1),
        [object[]]$Extension=@(),
        [ValidateSet('Strict','AsnOnly','None')][string]$Validation='Strict'
    )
    $key=New-X509Key $KeyAlgorithm $RsaKeySize
    if(-not $SignatureAlgorithm){$SignatureAlgorithm=if($KeyAlgorithm -eq 'RSA'){'RSA-PSS-SHA256'}elseif($KeyAlgorithm -eq 'ECDSA-P384'){'ECDSA-SHA384'}elseif($KeyAlgorithm -eq 'ECDSA-P521'){'ECDSA-SHA512'}else{'ECDSA-SHA256'}}
    try {
        $spki=Get-X509SubjectPublicKeyInfo $key
        $c=New-X509CertificateDer -Subject $Subject -Issuer $Subject -SubjectPublicKeyInfo $spki -Signer $key -SignatureAlgorithm $SignatureAlgorithm -NotBefore $NotBefore -NotAfter $NotAfter -Extension $Extension -Validation $Validation
        $pkcs8 = Export-X509Pkcs8PrivateKey $key; if ($null -ne $pkcs8) { $c | Add-Member -NotePropertyName PrivateKeyPkcs8 -NotePropertyValue ([byte[]]$pkcs8) }
        return $c
    } finally { $key.Dispose() }
}

function New-X509CertificateFromTbsDer {
    [CmdletBinding(DefaultParameterSetName='BuiltIn')]
    param(
        [Parameter(Mandatory)][byte[]]$TbsCertificateDer,
        [Parameter(Mandatory)][byte[]]$SignatureAlgorithmIdentifierDer,
        [Parameter(Mandatory,ParameterSetName='BuiltIn')]$Signer,
        [Parameter(Mandatory,ParameterSetName='BuiltIn')][ValidateSet('RSA-SHA256','RSA-SHA384','RSA-SHA512','RSA-PSS-SHA256','RSA-PSS-SHA384','RSA-PSS-SHA512','ECDSA-SHA256','ECDSA-SHA384','ECDSA-SHA512')][string]$SignatureAlgorithm,
        [Parameter(Mandatory,ParameterSetName='External')][scriptblock]$ExternalSigner,
        [ValidateSet('Strict','AsnOnly','None')][string]$Validation='Strict'
    )
    $t=Test-DerEncoding $TbsCertificateDer
    if(-not $t.Valid -and $Validation -ne 'None'){throw "TBS DER validation failed: $($t.Errors -join '; ')"}
    $sig = if($PSCmdlet.ParameterSetName -eq 'External') { [byte[]](& $ExternalSigner $TbsCertificateDer) } else { Invoke-X509Sign $TbsCertificateDer $Signer $SignatureAlgorithm }
    if($null -eq $sig -or $sig.Length -eq 0){throw 'Signer returned an empty signature.'}
    $cert=New-DerSequence $TbsCertificateDer $SignatureAlgorithmIdentifierDer (New-DerBitString $sig)
    if($Validation -ne 'None'){$r=Test-X509CertificateDer $cert $Validation;if(-not$r.Valid){throw "Certificate validation failed: $($r.Errors -join '; ')"}}
    [pscustomobject]@{PSTypeName='X509BinaryLab.Certificate';Version=$script:X509BinaryLabVersion;CertificateDer=$cert;TbsCertificateDer=$TbsCertificateDer;Signature=$sig;SignatureAlgorithmIdentifierDer=$SignatureAlgorithmIdentifierDer}
}

function Read-DerNode {
    param([byte[]]$Data,[int]$Offset=0,[int]$Limit=-1)
    if($Limit -lt 0){$Limit=$Data.Length}
    if($Offset -ge $Limit){throw 'Unexpected end of DER.'}
    $start=$Offset; $tag=$Data[$Offset++]; if(($tag -band 0x1F) -eq 0x1F){throw 'High-tag-number form is not supported by this validator.'}
    if($Offset -ge $Limit){throw 'Missing DER length.'}; $lb=$Data[$Offset++];
    if($lb -eq 0x80){throw 'Indefinite length is BER, not DER.'}
    if(($lb -band 0x80) -eq 0){$len=$lb}else{$n=$lb -band 0x7F;if($n -eq 0 -or $n -gt 4){throw 'Invalid DER length-of-length.'};if($Offset+$n -gt $Limit){throw 'Truncated DER length.'};if($Data[$Offset] -eq 0){throw 'Non-minimal DER length.'};$len=0;for($i=0;$i-lt$n;$i++){$len=($len-shl 8)-bor $Data[$Offset++]};if($len -lt 128){throw 'Long-form length used for short value.'}}
    $valueOffset=$Offset;$end=$Offset+$len;if($end -gt $Limit){throw 'DER value exceeds containing object.'}
    [pscustomobject]@{Tag=[byte]$tag;Start=$start;HeaderLength=$valueOffset-$start;Length=$len;ValueOffset=$valueOffset;End=$end;Encoded=$Data[$start..($end-1)]}
}

function Test-DerEncoding {
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$Der)
    $errors=[Collections.Generic.List[string]]::new()
    function Walk([byte[]]$d,[int]$s,[int]$e){
        $o=$s
        while($o -lt $e){
            try{$n=Read-DerNode $d $o $e}catch{$errors.Add($_.Exception.Message);return}
            if($n.Tag -eq 0x02 -and $n.Length -gt 1){$v=$n.ValueOffset;if($d[$v] -eq 0 -and ($d[$v+1]-band 0x80)-eq 0){$errors.Add("Non-minimal INTEGER at offset $($n.Start).")};if($d[$v]-eq 0xFF -and ($d[$v+1]-band 0x80)-ne 0){$errors.Add("Non-minimal negative INTEGER at offset $($n.Start).")}}
            if($n.Tag -eq 0x03){if($n.Length -lt 1){$errors.Add("Invalid BIT STRING at offset $($n.Start).") }else{$u=$d[$n.ValueOffset];if($u -gt 7){$errors.Add("Invalid BIT STRING unused-bit count at offset $($n.Start).")};if($n.Length -gt 1 -and $u -gt 0){$mask=(1-shl$u)-1;if(($d[$n.End-1]-band$mask)-ne 0){$errors.Add("Non-zero unused BIT STRING bits at offset $($n.Start).")}}}}
            if(($n.Tag -band 0x20) -ne 0){Walk $d $n.ValueOffset $n.End}
            $o=$n.End
        }
        if($o -ne $e){$errors.Add("DER child boundary mismatch at offset $o.")}
    }
    Walk $Der 0 $Der.Length
    [pscustomobject]@{Valid=($errors.Count -eq 0);Errors=$errors.ToArray()}
}

function Test-X509CertificateDer {
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$CertificateDer,[ValidateSet('Strict','AsnOnly')][string]$Mode='Strict')
    $errors=[Collections.Generic.List[string]]::new(); $d=Test-DerEncoding $CertificateDer; foreach($e in $d.Errors){$errors.Add($e)}
    try{$outer=Read-DerNode $CertificateDer 0 $CertificateDer.Length;if($outer.Tag -ne 0x30){$errors.Add('Certificate outer object is not a SEQUENCE.')};if($outer.End -ne $CertificateDer.Length){$errors.Add('Trailing bytes after certificate.')};$p=$outer.ValueOffset;$a=Read-DerNode $CertificateDer $p $outer.End;$p=$a.End;$b=Read-DerNode $CertificateDer $p $outer.End;$p=$b.End;$c=Read-DerNode $CertificateDer $p $outer.End;$p=$c.End;if($p -ne $outer.End){$errors.Add('Certificate must contain exactly three top-level fields.')};if($a.Tag -ne 0x30){$errors.Add('tbsCertificate is not a SEQUENCE.')};if($b.Tag -ne 0x30){$errors.Add('signatureAlgorithm is not a SEQUENCE.')};if($c.Tag -ne 0x03){$errors.Add('signatureValue is not a BIT STRING.')}}catch{$errors.Add("X.509 structural parse failed: $($_.Exception.Message)")}
    if($Mode -eq 'Strict'){
        try{$cert=[Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificateDer);$null=$cert.Subject;$cert.Dispose()}catch{$errors.Add("Platform X.509 parser rejected certificate: $($_.Exception.Message)")}
    }
    [pscustomobject]@{Valid=($errors.Count -eq 0);Mode=$Mode;Errors=$errors.ToArray()}
}

function Export-X509BinaryLabArtifact {
    [CmdletBinding()]
    param([Parameter(Mandatory,ValueFromPipeline)]$Certificate,[Parameter(Mandatory)][string]$Path,[switch]$Pem,[switch]$PrivateKeyPem)
    process{
        $full=[IO.Path]::GetFullPath($Path);$dir=[IO.Path]::GetDirectoryName($full);if($dir -and -not(Test-Path $dir)){New-Item -ItemType Directory -Path $dir -Force|Out-Null}
        if($Pem){$body=[Convert]::ToBase64String([byte[]]$Certificate.CertificateDer,[Base64FormattingOptions]::InsertLineBreaks);[IO.File]::WriteAllText($full,"-----BEGIN CERTIFICATE-----`n$body`n-----END CERTIFICATE-----`n",[Text.Encoding]::ASCII)}else{[IO.File]::WriteAllBytes($full,[byte[]]$Certificate.CertificateDer)}
        if($PrivateKeyPem){if(-not($Certificate.PSObject.Properties.Name -contains 'PrivateKeyPkcs8')){throw 'Certificate object has no exported private key.'};$k=[Convert]::ToBase64String([byte[]]$Certificate.PrivateKeyPkcs8,[Base64FormattingOptions]::InsertLineBreaks);$kp=[IO.Path]::ChangeExtension($full,'.key.pem');[IO.File]::WriteAllText($kp,"-----BEGIN PRIVATE KEY-----`n$k`n-----END PRIVATE KEY-----`n",[Text.Encoding]::ASCII)}
        Get-Item $full
    }
}

function Get-X509BinaryLabCapability {
    $runtime=[Environment]::Version
    [pscustomobject]@{
        PowerShell=$PSVersionTable.PSVersion.ToString(); DotNet=$runtime.ToString();
        RSA=$true; RSA_PSS=$true; ECDSA_P256_P384_P521=$true;
        RawSPKI=$true; RawExtensions=$true; ManualDER=$true;
        MLDsaNative=([type]::GetType('System.Security.Cryptography.MLDsa, System.Security.Cryptography') -ne $null);
        SlhDsaNative=([type]::GetType('System.Security.Cryptography.SlhDsa, System.Security.Cryptography') -ne $null);
        Note='ML-DSA/SLH-DSA are runtime/platform-gated. Raw SPKI and externally produced signature bytes can still be modeled by extending the generic DER helpers.'
    }
}
