param([string]$OpenSSL = 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe')
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
if (!(Test-Path -LiteralPath $OpenSSL)) { throw 'No se encontro OpenSSL.' }
foreach ($archivo in @('CA/ca.key', 'CA/ca.crt', 'CA/index.txt', 'CA/serial', 'CA/crlnumber')) {
    if (Test-Path -LiteralPath $archivo) { throw "Ya existe $archivo. No se sobrescribira la CA." }
}
New-Item -ItemType Directory -Force -Path CA/newcerts,evidencias | Out-Null
function Invoke-OpenSSL {
    param([string[]]$Argumentos)
    & $OpenSSL @Argumentos
    if ($LASTEXITCODE -ne 0) { throw "OpenSSL fallo: $($Argumentos[0])" }
}
Start-Transcript -Path evidencias/01-creacion-ca.txt -Append
try {
    Invoke-OpenSSL @('version')
    Invoke-OpenSSL @('genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:4096','-out','CA/ca.key')
    Invoke-OpenSSL @('req','-new','-x509','-key','CA/ca.key','-sha256','-days','3650','-config','openssl.cnf','-extensions','root_ca','-out','CA/ca.crt')
    New-Item -ItemType File -Path CA/index.txt | Out-Null
    Set-Content -Encoding ascii -Path CA/serial -Value '1000'
    Set-Content -Encoding ascii -Path CA/crlnumber -Value '1000'
    Invoke-OpenSSL @('verify','-x509_strict','-check_ss_sig','-CAfile','CA/ca.crt','CA/ca.crt')
    Invoke-OpenSSL @('ca','-config','openssl.cnf','-gencrl','-out','CA/ca.crl.pem','-batch')
    Invoke-OpenSSL @('crl','-in','CA/ca.crl.pem','-noout','-verify','-CAfile','CA/ca.crt')
    Invoke-OpenSSL @('x509','-in','CA/ca.crt','-noout','-subject','-issuer','-dates','-fingerprint','-sha256')
} finally {
    Stop-Transcript
}
