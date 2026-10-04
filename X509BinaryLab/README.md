# MILEHIGH

**5,280 feet of X.509 control.**

MILEHIGH is named for Denver’s mile-high identity: **5,280 feet equals one statute mile**. The name fits the project’s goal—giving a test suite precise, low-level control over the full X.509 certificate structure.

`X509BinaryLab.ps1` is the MILEHIGH dependency-free PowerShell 7.4+ toolkit for constructing X.509 certificates at the DER/ASN.1 level for interoperability, parser, PKI, and negative-test suites.

It does **not** shell out to OpenSSL, `certreq.exe`, BouncyCastle, NuGet packages, or other third-party components. Cryptographic signing uses the .NET runtime that ships underneath PowerShell. Certificate layout and common extensions are assembled from DER primitives so you can inspect and override the exact bytes being signed.

## What it supports

Fully built-in signing paths:

- RSA PKCS#1 v1.5 with SHA-256, SHA-384, SHA-512
- RSA-PSS with SHA-256, SHA-384, SHA-512 and explicit PSS parameters
- ECDSA P-256, P-384, P-521
- X.509 v1/v2/v3 layout
- Explicit serial-number bytes
- Explicit validity times and UTCTime/GeneralizedTime selection
- Explicit subject and issuer DNs
- Raw `SubjectPublicKeyInfo` injection
- Explicit RSA modulus/exponent SPKI construction
- Explicit EC named-curve OID + uncompressed point SPKI construction
- Issuer/subject unique IDs
- Arbitrary raw extensions
- Basic Constraints
- Key Usage
- Extended Key Usage
- Subject Alternative Name: DNS, IP, URI, email
- Subject Key Identifier
- Authority Key Identifier
- Authority Information Access: OCSP and CA Issuers
- CRL Distribution Points
- DER structural validation and platform X.509 parsing validation
- DER, PEM, and PKCS#8 private-key output

The toolkit exposes generic DER helpers as well, so test cases can construct fields that do not have a convenience wrapper.

## Runtime requirements

- PowerShell 7.4 or newer
- No external modules
- No third-party cryptographic provider

Check capabilities:

```powershell
. .\X509BinaryLab.ps1
Get-X509BinaryLabCapability
```

.NET 10 adds native APIs for ML-DSA and SLH-DSA, but those algorithms remain runtime/platform dependent. This release reports those capabilities rather than claiming portable support where the underlying runtime cannot actually create the keys. The low-level DER functions remain usable for modeling their X.509 structures or importing externally generated SPKI/signature material into a specialized test extension.

## Safety model

The default constructor uses `-Validation Strict`. Before returning a certificate it:

1. Checks DER definite/minimal lengths.
2. Checks INTEGER canonical encoding.
3. Checks BIT STRING unused-bit rules.
4. Checks the outer X.509 certificate structure.
5. Loads the result with the platform `X509Certificate2` parser.

For parser-fuzzing or deliberately unusual test vectors, select `-Validation AsnOnly` or `-Validation None` explicitly. This makes malformed or platform-rejected cases opt-in instead of accidental.

## Quick start: RSA-PSS self-signed certificate

```powershell
. .\X509BinaryLab.ps1

$extensions = @(
    New-X509BasicConstraintsExtension -CertificateAuthority $false
    New-X509KeyUsageExtension -Usage digitalSignature,keyEncipherment
    New-X509ExtendedKeyUsageExtension -Oid '1.3.6.1.5.5.7.3.1'   # serverAuth
    New-X509SubjectAltNameExtension -DnsName 'inventory.test','localhost' -IpAddress '127.0.0.1'
    New-X509AuthorityInformationAccessExtension `
        -OcspUri 'http://pki.test/ocsp' `
        -CaIssuersUri 'http://pki.test/issuer.cer'
    New-X509CrlDistributionPointsExtension -Uri 'http://pki.test/root.crl'
)

$cert = New-X509SelfSignedCertificate `
    -Subject 'CN=inventory.test,O=Lab,C=US' `
    -KeyAlgorithm RSA `
    -RsaKeySize 3072 `
    -SignatureAlgorithm RSA-PSS-SHA256 `
    -Extension $extensions

$cert | Export-X509BinaryLabArtifact -Path .\inventory.pem -Pem -PrivateKeyPem

Test-X509CertificateDer -CertificateDer $cert.CertificateDer -Mode Strict
```

## ECDSA example

```powershell
. .\X509BinaryLab.ps1

$cert = New-X509SelfSignedCertificate `
    -Subject 'CN=p384.test,O=Lab,C=US' `
    -KeyAlgorithm ECDSA-P384 `
    -SignatureAlgorithm ECDSA-SHA384 `
    -Extension @(
        New-X509BasicConstraintsExtension -CertificateAuthority $false
        New-X509KeyUsageExtension -Usage digitalSignature
        New-X509SubjectAltNameExtension -DnsName 'p384.test'
    )

$cert | Export-X509BinaryLabArtifact -Path .\p384.cer
```

## CA + leaf example

```powershell
. .\X509BinaryLab.ps1

$caKey = New-X509Key -Algorithm RSA -RsaKeySize 4096
$leafKey = New-X509Key -Algorithm ECDSA-P256

try {
    $caSpki = Get-X509SubjectPublicKeyInfo $caKey
    $caExtensions = @(
        New-X509BasicConstraintsExtension -CertificateAuthority $true -PathLength 1
        New-X509KeyUsageExtension -Usage keyCertSign,cRLSign
        New-X509SubjectKeyIdentifierExtension -SubjectPublicKeyInfo $caSpki
    )

    $ca = New-X509CertificateDer `
        -Subject 'CN=MILEHIGH Test Root CA,O=MILEHIGH Lab,C=US' `
        -Issuer  'CN=MILEHIGH Test Root CA,O=MILEHIGH Lab,C=US' `
        -SubjectPublicKeyInfo $caSpki `
        -Signer $caKey `
        -SignatureAlgorithm RSA-PSS-SHA384 `
        -NotAfter ([DateTimeOffset]::UtcNow.AddYears(10)) `
        -Extension $caExtensions

    # RFC 5280 method (1): SHA-1 over the subjectPublicKey BIT STRING contents.
    $caKeyId = Get-X509SubjectKeyIdentifierBytes $caSpki

    $leafSpki = Get-X509SubjectPublicKeyInfo $leafKey
    $leaf = New-X509CertificateDer `
        -Subject 'CN=field-device-001,O=Lab,C=US' `
        -Issuer  'CN=MILEHIGH Test Root CA,O=MILEHIGH Lab,C=US' `
        -SubjectPublicKeyInfo $leafSpki `
        -Signer $caKey `
        -SignatureAlgorithm RSA-PSS-SHA384 `
        -Extension @(
            New-X509BasicConstraintsExtension -CertificateAuthority $false
            New-X509KeyUsageExtension -Usage digitalSignature
            New-X509ExtendedKeyUsageExtension -Oid '1.3.6.1.5.5.7.3.2' # clientAuth
            New-X509AuthorityKeyIdentifierExtension -KeyIdentifier $caKeyId
            New-X509SubjectAltNameExtension -DnsName 'field-device-001.lab.test'
        )

    $ca   | Export-X509BinaryLabArtifact -Path .\root-ca.pem -Pem
    $leaf | Export-X509BinaryLabArtifact -Path .\leaf.pem -Pem
}
finally {
    $caKey.Dispose()
    $leafKey.Dispose()
}
```

## Supplying an exact RSA modulus

This is useful when the subject key must have exact public-key bytes for a parser or boundary test. The signing key can be separate.

```powershell
$spki = New-X509RsaSubjectPublicKeyInfo `
    -ModulusHex 'C34F...YOUR EXACT MODULUS...91' `
    -Exponent 65537

$issuerKey = New-X509Key -Algorithm RSA -RsaKeySize 3072
try {
    $cert = New-X509CertificateDer `
        -Subject 'CN=Exact Modulus Subject' `
        -Issuer  'CN=MILEHIGH Test Issuer' `
        -SubjectPublicKeyInfo $spki `
        -Signer $issuerKey `
        -SignatureAlgorithm RSA-SHA256 `
        -Validation Strict
} finally {
    $issuerKey.Dispose()
}
```

The public modulus is exact. A private key corresponding to that modulus is not magically reconstructed; the certificate is simply signed by the supplied issuer key, as normal CA-issued certificates are.

## Supplying an exact EC point and named curve

```powershell
$spki = New-X509EcSubjectPublicKeyInfo `
    -CurveOid '1.2.840.10045.3.1.7' `
    -UncompressedPointHex '04...X...Y...'
```

For standards-conformant Internet PKI certificates, named-curve identifiers should be used according to the applicable algorithm profile. If your test requires explicit or non-standard EC parameters, construct the entire SPKI with the generic DER helpers and pass it through `-SubjectPublicKeyInfo`.

## Arbitrary extension bytes

`ValueDer` is the DER value *inside* the extension's outer OCTET STRING.

```powershell
$customValue = New-DerSequence `
    (New-DerInteger 7) `
    (New-DerUtf8String 'test-vector')

$custom = New-X509Extension `
    -Oid '1.3.6.1.4.1.55555.1.7' `
    -Critical $false `
    -ValueDer $customValue
```

This lets a test suite control private extensions without changing the certificate builder.

## Exact serial numbers

```powershell
$serial = Convert-HexToBytes '00112233445566778899AABBCCDDEEFF'

$cert = New-X509CertificateDer `
    -Subject 'CN=Serial Test' `
    -Issuer  'CN=Issuer' `
    -SubjectPublicKeyInfo $spki `
    -Signer $issuerKey `
    -SignatureAlgorithm RSA-SHA256 `
    -SerialNumber $serial
```

RFC 5280 limits conforming serial numbers to at most 20 octets and requires them to be positive. The builder enforces the 20-octet limit and encodes the supplied bytes as an unsigned DER INTEGER.

## ASN.1 / DER validation

Validate any DER blob:

```powershell
$result = Test-DerEncoding -Der ([IO.File]::ReadAllBytes('.\certificate.cer'))
$result | Format-List
```

Validate a certificate structurally and with the native X.509 parser:

```powershell
$result = Test-X509CertificateDer `
    -CertificateDer ([IO.File]::ReadAllBytes('.\certificate.cer')) `
    -Mode Strict

if (-not $result.Valid) {
    $result.Errors
}
```

`Strict` validates DER and asks the platform X.509 parser to load the object. `AsnOnly` is appropriate for negative vectors whose purpose is to test whether another implementation rejects or tolerates an unusual certificate.

## Validation modes when generating

```powershell
-Validation Strict   # default; DER + X509Certificate2 parse
-Validation AsnOnly  # DER structure only
-Validation None     # explicitly opt out for mutation/fuzzing workflows
```

## Binary inspection

The returned object includes:

```powershell
$cert.CertificateDer      # complete Certificate DER
$cert.TbsCertificateDer   # exact bytes covered by the signature
$cert.Signature           # raw certificate signature bytes
$cert.SignatureAlgorithm
$cert.SerialHex
```

A useful regression assertion is therefore:

```powershell
[Convert]::ToHexString($cert.TbsCertificateDer)
```

Store that value alongside a test vector if you need byte-for-byte reproducibility.


## Full raw-TBSCertificate mode

When a test needs control beyond the convenience builder, construct the complete `TBSCertificate` yourself with the DER primitives and use `New-X509CertificateFromTbsDer`.

```powershell
# $tbs is the exact DER SEQUENCE you want signed.
$alg = Get-X509SignatureAlgorithmIdentifier 'RSA-PSS-SHA256'
$key = New-X509Key -Algorithm RSA
try {
    $cert = New-X509CertificateFromTbsDer `
        -TbsCertificateDer $tbs `
        -SignatureAlgorithmIdentifierDer $alg `
        -Signer $key `
        -SignatureAlgorithm RSA-PSS-SHA256
} finally { $key.Dispose() }
```

For algorithms not implemented by the local .NET runtime, an external signing callback can return the raw signature bytes while the module still owns the X.509 binary assembly and DER validation:

```powershell
$cert = New-X509CertificateFromTbsDer `
    -TbsCertificateDer $tbs `
    -SignatureAlgorithmIdentifierDer $algorithmIdentifierDer `
    -ExternalSigner { param([byte[]]$bytesToSign) Invoke-YourPlatformSigner $bytesToSign } `
    -Validation AsnOnly
```

No external signer is bundled or required for RSA/ECDSA. The callback exists so hardware-backed, future, or runtime-specific algorithms do not force a third-party dependency into this toolkit.

## Adding unsupported or future algorithms

The builder deliberately keeps algorithm identifiers and SPKI as independent DER values. To model a future/public-key algorithm:

1. Construct its `AlgorithmIdentifier` with `New-X509AlgorithmIdentifier` or the generic DER functions.
2. Construct its exact SPKI bytes.
3. Add a signer implementation that returns the raw X.509 `signatureValue` payload.
4. Keep the `tbsCertificate.signature` and outer `signatureAlgorithm` byte-identical.

This makes the certificate layer independent of a particular crypto provider while preserving a dependency-free default implementation.

## Important profile notes

- X.509 syntax validity and PKIX profile validity are different things. A certificate can be valid DER but violate RFC 5280 policy requirements.
- RSA-PSS parameters are encoded explicitly so the hash, MGF1 hash, and salt length are visible in the binary certificate.
- ECDSA certificate signatures are encoded as the RFC 3279 DER `SEQUENCE { r, s }`, not IEEE-P1363 concatenation.
- AIA and CRL Distribution Point URLs are metadata. This toolkit does not contact them.
- The SHA-1 use in the SKI helper is an identifier-generation convention, not a certificate signature algorithm. Certificate signatures default to SHA-256 or stronger.
- Do not install generated test roots into production trust stores.

## Standards references

- RFC 5280 — Internet X.509 Public Key Infrastructure Certificate and CRL Profile
- RFC 4055 — Additional Algorithms and Identifiers for RSA Cryptography (including RSASSA-PSS)
- RFC 5480 — Elliptic Curve Cryptography Subject Public Key Information
- RFC 3279 — Algorithms and Identifiers for the Internet X.509 PKI
- RFC 8410 — Ed25519/Ed448 X.509 algorithm identifiers
- FIPS 204 — ML-DSA

