# MILEHIGH References

MILEHIGH is a dependency-free PowerShell X.509 / ASN.1 testing library. The following standards define the structures and algorithms used by the examples.

## Core X.509 / ASN.1

- **RFC 5280 — Internet X.509 Public Key Infrastructure Certificate and CRL Profile**  
  https://www.rfc-editor.org/rfc/rfc5280
- **ITU-T X.690 — ASN.1 encoding rules: BER, CER and DER**  
  https://www.itu.int/rec/T-REC-X.690
- **ITU-T X.509 — Public-key and attribute certificate frameworks**  
  https://www.itu.int/rec/T-REC-X.509

## Elliptic Curve / ECDSA

- **RFC 5480 — Elliptic Curve Cryptography Subject Public Key Information**  
  https://www.rfc-editor.org/rfc/rfc5480
- **RFC 5758 — Internet X.509 PKI: Additional Algorithms and Identifiers for DSA and ECDSA**  
  https://www.rfc-editor.org/rfc/rfc5758
- **SEC 1 — Elliptic Curve Cryptography**  
  https://www.secg.org/sec1-v2.pdf
- **NIST FIPS 186-5 — Digital Signature Standard**  
  https://csrc.nist.gov/pubs/fips/186-5/final
- **NIST SP 800-186 — Recommendations for Discrete Logarithm-Based Cryptography: Elliptic Curve Domain Parameters**  
  https://csrc.nist.gov/pubs/sp/800/186/final

## RSA / RSA-PSS

- **RFC 8017 — PKCS #1: RSA Cryptography Specifications Version 2.2**  
  https://www.rfc-editor.org/rfc/rfc8017
- **RFC 4055 — Additional Algorithms and Identifiers for RSA Cryptography for use in X.509**  
  https://www.rfc-editor.org/rfc/rfc4055

## Microsoft / .NET implementation references

- **System.Security.Cryptography.X509Certificates**  
  https://learn.microsoft.com/dotnet/api/system.security.cryptography.x509certificates
- **ECDsa class**  
  https://learn.microsoft.com/dotnet/api/system.security.cryptography.ecdsa
- **RSA class**  
  https://learn.microsoft.com/dotnet/api/system.security.cryptography.rsa

## Explicit-curve test note

RFC 5480 defines the `specifiedCurve` ASN.1 form, but its PKIX profile requires `namedCurve` and says `specifiedCurve` MUST NOT be used in conforming PKIX certificates. MILEHIGH's explicit-parameter ECDSA example is therefore intended for parser, DER, interoperability, and negative-testing scenarios rather than normal public-PKI issuance.
