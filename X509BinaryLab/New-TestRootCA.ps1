. (Join-Path $PSScriptRoot 'X509BinaryLab.ps1')

$ext = @(
    New-X509BasicConstraintsExtension -CertificateAuthority $true -PathLength 1
    New-X509KeyUsageExtension -Usage keyCertSign,cRLSign
)

$cert = New-X509SelfSignedCertificate -Subject 'CN=MILEHIGH Test Root CA,O=MILEHIGH Lab,C=US' -KeyAlgorithm RSA -RsaKeySize 4096 -SignatureAlgorithm RSA-PSS-SHA384 -NotAfter ([DateTimeOffset]::UtcNow.AddYears(10)) -Extension $ext
$cert | Export-X509BinaryLabArtifact -Path "$PSScriptRoot\test-root-ca.pem" -Pem -PrivateKeyPem
