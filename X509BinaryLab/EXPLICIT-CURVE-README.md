# MILEHIGH Explicit-Curve ECDSA Test

**MILEHIGH — 5,280 feet of X.509 control.**

This example creates an ECDSA X.509 v3 test certificate using the MILEHIGH binary X.509 library. Unlike a normal P-256 certificate, the `SubjectPublicKeyInfo.algorithm.parameters` field does **not** contain the named-curve OID for `prime256v1 / secp256r1`. Instead, it contains a complete explicit ANSI X9.62 `SpecifiedECDomain` structure.

The default values are the well-known P-256 domain parameters, so the mathematical curve is still P-256. What changes is the X.509 encoding: every field is written into ASN.1/DER explicitly so a test suite can inspect or mutate it byte-for-byte.

## Why this is a test vector

RFC 5480 defines `ECParameters` as a choice that historically includes `namedCurve`, `implicitCurve`, and `specifiedCurve`, but for Internet PKIX certificates it requires `namedCurve`; `implicitCurve` and `specifiedCurve` **MUST NOT** be used. Therefore this certificate is intentionally an interoperability / parser-validation test, not a certificate to deploy in a production PKI.

The example uses MILEHIGH `-Validation AsnOnly`. That verifies the DER structure without requiring the operating system's X.509 parser to accept the non-PKIX curve representation. The script separately tries the native `.NET X509Certificate2` parser and reports whether the current platform accepts or rejects it.

## What is encoded

The EC public-key `AlgorithmIdentifier` is:

```text
SEQUENCE
  OBJECT IDENTIFIER 1.2.840.10045.2.1       -- id-ecPublicKey
  SEQUENCE                                     -- SpecifiedECDomain
    INTEGER 1                                  -- ecdpVer1
    SEQUENCE                                   -- FieldID
      OBJECT IDENTIFIER 1.2.840.10045.1.1     -- prime-field
      INTEGER p
    SEQUENCE                                   -- Curve
      OCTET STRING a
      OCTET STRING b
      BIT STRING seed                          -- optional
    OCTET STRING 04 || Gx || Gy                -- base point G
    INTEGER n                                  -- subgroup order
    INTEGER h                                  -- cofactor
```

The outer `SubjectPublicKeyInfo.subjectPublicKey` BIT STRING contains:

```text
04 || Qx || Qy
```

where `Q` is the generated ECDSA public key.

## Default curve values

The script exposes these values as ordinary PowerShell parameters:

- `PrimeHex` — field prime `p`
- `AHex` — curve coefficient `a`
- `BHex` — curve coefficient `b`
- `GxHex`, `GyHex` — base-point coordinates
- `OrderHex` — subgroup order `n`
- `Cofactor` — `h`
- `SeedHex` — optional curve-generation seed

The defaults reproduce the P-256 / secp256r1 domain. They are explicit rather than represented by an OID.

## Run it

From the MILEHIGH repository:

```powershell
pwsh .\New-MILEHIGH-ExplicitCurveECDSA.ps1
```

The loader also supports copying the example one or two directories closer to `X509BinaryLab.ps1`.

To choose another output directory:

```powershell
pwsh .\New-MILEHIGH-ExplicitCurveECDSA.ps1 `
    -OutputDirectory C:\Temp\milehigh-curve-test
```

## Expected output

The script prints a result similar to:

```text
TestVector                 : MILEHIGH ExplicitCurve ECDSA P-256
ParametersMatchP256        : True
DerValid                   : True
EcdsaSignatureValid        : True
PlatformX509ParserAccepted : False
...
```

`PlatformX509ParserAccepted` is intentionally platform-dependent. Rejection does not mean the DER is malformed. It may mean the platform correctly enforces the RFC 5480 PKIX restriction against explicit curve parameters.

The output directory contains:

```text
MILEHIGH-explicit-curve-p256.der
MILEHIGH-explicit-curve-p256.pem
MILEHIGH-explicit-curve-p256.key.pem
MILEHIGH-explicit-curve-spki.der
MILEHIGH-explicit-curve-parameters.der
```

The separate SPKI and parameter files make it easy to feed the exact encodings to ASN.1 tooling or fuzzing/test harnesses.

## Mutating a curve parameter

For negative testing, change one of the explicit fields. For example, change the last byte of coefficient `b`:

```powershell
pwsh .\New-MILEHIGH-ExplicitCurveECDSA.ps1 `
    -BHex '5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604A' `
    -AllowIncoherentParameters
```

MILEHIGH will still construct canonical DER and sign the `TBSCertificate`, but the declared curve no longer matches the P-256 key used by the demo. That creates a useful deliberately inconsistent certificate for testing whether a parser merely accepts ASN.1 or actually validates EC domain/key consistency.

The safety switch is intentional: changed parameters are rejected unless `-AllowIncoherentParameters` is supplied.

## What the test validates

There are three distinct checks:

1. **DER validation** — `Test-X509CertificateDer -Mode AsnOnly` checks canonical DER and X.509 outer structure.
2. **Signature validation against the actual generated key** — `.NET ECDsa.VerifyData()` confirms that the ECDSA signature over the exact `TBSCertificate` bytes is correct.
3. **Native X.509 parser behavior** — the certificate is offered to `X509Certificate2`, and acceptance/rejection is recorded without making it a prerequisite for test-vector creation.

These checks are deliberately separate. A certificate can be perfectly valid DER while violating a PKIX profile rule, and a cryptographically valid signature does not prove that the subject's declared EC domain parameters are acceptable.

## Important limitation

This example uses the platform's P-256 implementation to generate the private key. It does **not** implement arbitrary elliptic-curve scalar multiplication in PowerShell. Therefore changing `p`, `a`, `b`, `G`, `n`, or `h` creates a structural/semantic negative test unless the values still describe the same P-256 domain.

That separation is deliberate: the MILEHIGH library controls the X.509/ASN.1 bytes, while private-key arithmetic remains in the built-in operating-system/.NET cryptographic provider.

## References

- RFC 5480 — *Elliptic Curve Cryptography Subject Public Key Information*
- RFC 5280 — *Internet X.509 Public Key Infrastructure Certificate and CRL Profile*
- ANSI X9.62 / SEC 1 — EC domain-parameter structures and point representation

Do not use an explicit-curve test certificate as a public Web PKI or production enterprise certificate. Use a normal named curve for standards-conforming PKIX deployment.
