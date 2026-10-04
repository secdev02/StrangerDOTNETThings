param([Parameter(Mandatory)][string]$Path)
. (Join-Path $PSScriptRoot 'X509BinaryLab.ps1')

$bytes = [IO.File]::ReadAllBytes((Resolve-Path $Path))
if ([Text.Encoding]::ASCII.GetString($bytes,0,[Math]::Min($bytes.Length,32)) -match 'BEGIN CERTIFICATE') {
    $text = [Text.Encoding]::ASCII.GetString($bytes)
    $b64 = ($text -split "`r?`n" | Where-Object { $_ -notmatch '^-----' -and $_ }) -join ''
    $bytes = [Convert]::FromBase64String($b64)
}
Test-X509CertificateDer -CertificateDer $bytes -Mode Strict | Format-List
