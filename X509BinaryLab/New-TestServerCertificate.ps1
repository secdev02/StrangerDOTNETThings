. (Join-Path $PSScriptRoot 'X509BinaryLab.ps1')

$ext = @(
    New-X509BasicConstraintsExtension -CertificateAuthority $false
    New-X509KeyUsageExtension -Usage digitalSignature,keyEncipherment
    New-X509ExtendedKeyUsageExtension -Oid '1.3.6.1.5.5.7.3.1'
    New-X509SubjectAltNameExtension -DnsName 'inventory.test','localhost' -IpAddress '127.0.0.1','::1'
    New-X509AuthorityInformationAccessExtension -OcspUri 'http://pki.test/ocsp' -CaIssuersUri 'http://pki.test/issuer.cer'
    New-X509CrlDistributionPointsExtension -Uri 'http://pki.test/root.crl'
)

$cert = New-X509SelfSignedCertificate -Subject 'CN=inventory.test,O=MILEHIGH,C=US' -KeyAlgorithm RSA -RsaKeySize 3072 -SignatureAlgorithm RSA-PSS-SHA256 -Extension $ext
$cert | Export-X509BinaryLabArtifact -Path "$PSScriptRoot\inventory.test.pem" -Pem -PrivateKeyPem
$cert | Select-Object Subject,Issuer,SerialHex,SignatureAlgorithm
