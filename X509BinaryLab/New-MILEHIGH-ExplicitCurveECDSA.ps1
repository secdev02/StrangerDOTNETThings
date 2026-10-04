#requires -Version 7.4
<#+
.SYNOPSIS
  Creates a DER-valid ECDSA X.509 certificate whose SubjectPublicKeyInfo uses
  explicit ANSI X9.62 / SEC1 prime-field curve parameters (specifiedCurve).

.DESCRIPTION
  MILEHIGH test-vector example. By default the explicit domain parameters are
  the NIST P-256 / secp256r1 values, but they are encoded as a full
  SpecifiedECDomain SEQUENCE instead of the usual named-curve OID.

  This is deliberately an interoperability / negative-testing certificate.
  RFC 5480 requires PKIX certificates to use namedCurve and says specifiedCurve
  MUST NOT be used in PKIX. The DER itself can still be valid.

  All explicit domain fields are parameters so a test suite can mutate them.
  If you change the domain away from P-256, the generated P-256 key and point
  may no longer belong to that domain. That is useful for parser/validator
  negative tests, but it is not a coherent production certificate.
#>
[CmdletBinding()]
param(
    [string]$Subject = 'CN=MILEHIGH Explicit Curve Test,O=MILEHIGH X509 Lab,L=Denver,ST=Colorado,C=US',
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'out'),

    # ANSI X9.62 prime-field curve parameters. Defaults are secp256r1 / P-256.
    [string]$PrimeHex = 'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF',
    [string]$AHex     = 'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC',
    [string]$BHex     = '5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B',
    [string]$GxHex    = '6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296',
    [string]$GyHex    = '4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5',
    [string]$OrderHex = 'FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551',
    [uint32]$Cofactor = 1,
    [string]$SeedHex  = 'C49D360886E704936A6678E1139D26B7819F7E90',

    [switch]$OmitSeed,
    [switch]$AllowIncoherentParameters
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Flat-folder loader: keep X509BinaryLab.ps1 beside this script.
. (Join-Path $PSScriptRoot 'X509BinaryLab.ps1')

function Assert-FixedHexLength {
    param([string]$Name, [string]$Hex, [int]$Bytes)
    $clean = $Hex -replace '[^0-9A-Fa-f]', ''
    if ($clean.Length -ne ($Bytes * 2)) {
        throw "$Name must be exactly $Bytes bytes ($($Bytes*2) hex digits); got $($clean.Length/2) bytes."
    }
}

function New-MileHighSpecifiedPrimeCurveParameters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PrimeHex,
        [Parameter(Mandatory)][string]$AHex,
        [Parameter(Mandatory)][string]$BHex,
        [Parameter(Mandatory)][string]$GxHex,
        [Parameter(Mandatory)][string]$GyHex,
        [Parameter(Mandatory)][string]$OrderHex,
        [Parameter(Mandatory)][uint32]$Cofactor,
        [string]$SeedHex,
        [switch]$OmitSeed
    )

    # X9.62 prime-field OID: 1.2.840.10045.1.1
    $fieldId = New-DerSequence `
        (New-DerOid '1.2.840.10045.1.1') `
        (New-DerIntegerUnsigned (Convert-HexToBytes $PrimeHex))

    $curveParts = @(
        (New-DerOctetString (Convert-HexToBytes $AHex)),
        (New-DerOctetString (Convert-HexToBytes $BHex))
    )
    if (-not $OmitSeed -and $SeedHex) {
        $curveParts += ,(New-DerBitString (Convert-HexToBytes $SeedHex))
    }
    $curve = New-DerSequence @curveParts

    $basePoint = Join-ByteArray `
        ([byte[]]@(0x04)) `
        (Convert-HexToBytes $GxHex) `
        (Convert-HexToBytes $GyHex)

    # SpecifiedECDomain ::= SEQUENCE {
    #   version INTEGER(1), fieldID, curve, base ECPoint(OCTET STRING),
    #   order INTEGER, cofactor INTEGER OPTIONAL, hash AlgorithmIdentifier OPTIONAL }
    return New-DerSequence `
        (New-DerInteger 1) `
        $fieldId `
        $curve `
        (New-DerOctetString $basePoint) `
        (New-DerIntegerUnsigned (Convert-HexToBytes $OrderHex)) `
        (New-DerInteger $Cofactor)
}

function New-MileHighExplicitEcSpki {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$SpecifiedCurveDer,
        [Parameter(Mandatory)][byte[]]$Qx,
        [Parameter(Mandatory)][byte[]]$Qy
    )

    # id-ecPublicKey = 1.2.840.10045.2.1
    $algorithmIdentifier = New-X509AlgorithmIdentifier `
        -Oid '1.2.840.10045.2.1' `
        -ParametersDer $SpecifiedCurveDer

    $publicPoint = Join-ByteArray ([byte[]]@(0x04)) $Qx $Qy
    return New-DerSequence $algorithmIdentifier (New-DerBitString $publicPoint)
}

# P-256 uses 32-byte field elements. Keeping this strict prevents accidental
# loss of leading-zero octets in explicit field elements.
foreach ($entry in @(
    @('PrimeHex',$PrimeHex), @('AHex',$AHex), @('BHex',$BHex),
    @('GxHex',$GxHex), @('GyHex',$GyHex), @('OrderHex',$OrderHex)
)) { Assert-FixedHexLength $entry[0] $entry[1] 32 }

$defaultFingerprint = @(
    'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF',
    'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC',
    '5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B',
    '6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296',
    '4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5',
    'FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551'
) -join ':'
$actualFingerprint = @($PrimeHex,$AHex,$BHex,$GxHex,$GyHex,$OrderHex) | ForEach-Object { ($_ -replace '[^0-9A-Fa-f]','').ToUpperInvariant() }
$actualFingerprint = $actualFingerprint -join ':'
$parametersAreDefaultP256 = ($actualFingerprint -eq $defaultFingerprint -and $Cofactor -eq 1)

if (-not $parametersAreDefaultP256 -and -not $AllowIncoherentParameters) {
    throw @"
You changed one or more explicit domain parameters. This example generates its
private/public key with the platform P-256 implementation, so mutated domain
parameters may no longer describe that key.

Re-run with -AllowIncoherentParameters if this is intentional for a negative
parser/validator test vector.
"@
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$key = [Security.Cryptography.ECDsa]::Create((Get-X509NamedCurve P256))
try {
    $public = $key.ExportParameters($false)

    $specifiedCurveDer = New-MileHighSpecifiedPrimeCurveParameters `
        -PrimeHex $PrimeHex -AHex $AHex -BHex $BHex `
        -GxHex $GxHex -GyHex $GyHex -OrderHex $OrderHex `
        -Cofactor $Cofactor -SeedHex $SeedHex -OmitSeed:$OmitSeed

    $spki = New-MileHighExplicitEcSpki `
        -SpecifiedCurveDer $specifiedCurveDer `
        -Qx $public.Q.X -Qy $public.Q.Y

    $extensions = @(
        (New-X509BasicConstraintsExtension -CertificateAuthority:$false -Critical:$true),
        (New-X509KeyUsageExtension -Usage digitalSignature -Critical:$true),
        (New-X509SubjectKeyIdentifierExtension -SubjectPublicKeyInfo $spki)
    )

    $cert = New-X509CertificateDer `
        -Subject $Subject `
        -Issuer $Subject `
        -SubjectPublicKeyInfo $spki `
        -Signer $key `
        -SignatureAlgorithm 'ECDSA-SHA256' `
        -NotBefore ([DateTimeOffset]::UtcNow.AddMinutes(-5)) `
        -NotAfter ([DateTimeOffset]::UtcNow.AddDays(30)) `
        -Extension $extensions `
        -Validation AsnOnly

    # Preserve the private key only as a separate PKCS#8 artifact for lab use.
    $pkcs8 = Export-X509Pkcs8PrivateKey $key
    if ($null -ne $pkcs8) { $cert | Add-Member -NotePropertyName PrivateKeyPkcs8 -NotePropertyValue ([byte[]]$pkcs8) -Force }

    $derPath = Join-Path $OutputDirectory 'MILEHIGH-explicit-curve-p256.der'
    $pemPath = Join-Path $OutputDirectory 'MILEHIGH-explicit-curve-p256.pem'
    $spkiPath = Join-Path $OutputDirectory 'MILEHIGH-explicit-curve-spki.der'
    $paramsPath = Join-Path $OutputDirectory 'MILEHIGH-explicit-curve-parameters.der'

    Export-X509BinaryLabArtifact -Certificate $cert -Path $derPath | Out-Null
    if ($cert.PSObject.Properties.Name -contains 'PrivateKeyPkcs8') {
        Export-X509BinaryLabArtifact -Certificate $cert -Path $pemPath -Pem -PrivateKeyPem | Out-Null
    } else {
        Export-X509BinaryLabArtifact -Certificate $cert -Path $pemPath -Pem | Out-Null
        Write-Warning 'This runtime cannot export the ECDSA private key as PKCS#8. Certificate generation continues without a .key.pem artifact.'
    }
    [IO.File]::WriteAllBytes($spkiPath, $spki)
    [IO.File]::WriteAllBytes($paramsPath, $specifiedCurveDer)

    $asnValidation = Test-X509CertificateDer -CertificateDer $cert.CertificateDer -Mode AsnOnly
    $signatureValid = Test-X509EcdsaSignature `
        -Key $key `
        -Data $cert.TbsCertificateDer `
        -SignatureDer $cert.Signature `
        -HashAlgorithm ([Security.Cryptography.HashAlgorithmName]::SHA256)

    $nativeAccepted = $false
    $nativeMessage = $null
    try {
        $native = [Security.Cryptography.X509Certificates.X509Certificate2]::new($cert.CertificateDer)
        try {
            $nativeAccepted = $true
            $nativeMessage = "Accepted: $($native.Subject)"
        } finally { $native.Dispose() }
    } catch {
        $nativeMessage = $_.Exception.Message
    }

    [pscustomobject]@{
        TestVector                 = 'MILEHIGH ExplicitCurve ECDSA P-256'
        ParametersMatchP256        = $parametersAreDefaultP256
        DerValid                   = $asnValidation.Valid
        DerValidationErrors        = ($asnValidation.Errors -join '; ')
        EcdsaSignatureValid        = $signatureValid
        PlatformX509ParserAccepted = $nativeAccepted
        PlatformX509ParserMessage  = $nativeMessage
        CertificateDer             = $derPath
        CertificatePem             = $pemPath
        PrivateKeyPem              = if ($cert.PSObject.Properties.Name -contains 'PrivateKeyPkcs8') { [IO.Path]::ChangeExtension($pemPath, '.key.pem') } else { $null }
        SubjectPublicKeyInfoDer     = $spkiPath
        SpecifiedCurveDer          = $paramsPath
    } | Format-List
}
finally {
    $key.Dispose()
}
