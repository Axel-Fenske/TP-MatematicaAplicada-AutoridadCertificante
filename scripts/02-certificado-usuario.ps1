param([string]$OpenSSL = 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe')
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
foreach ($archivo in @($OpenSSL, 'CA/ca.key', 'CA/ca.crt', 'CA/index.txt')) {
    if (!(Test-Path -LiteralPath $archivo)) { throw "Falta $archivo" }
}
foreach ($archivo in @('Usuario/usuario.key', 'Usuario/usuario.csr', 'Usuario/usuario.crt')) {
    if (Test-Path -LiteralPath $archivo) { throw "Ya existe $archivo. No se sobrescribira." }
}
function Invoke-OpenSSL {
    param([string[]]$Argumentos)
    Write-Host ('openssl ' + ($Argumentos -join ' '))
    & $OpenSSL @Argumentos
    if ($LASTEXITCODE -ne 0) { throw "OpenSSL fallo: $($Argumentos[0])" }
}
Start-Transcript -Path evidencias/02-certificado-usuario.txt -Append
try {
    Invoke-OpenSSL @('genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out','Usuario/usuario.key')
    Invoke-OpenSSL @('req','-new','-config','openssl.cnf','-key','Usuario/usuario.key','-out','Usuario/usuario.csr','-subj','/C=AR/O=UNLaM/OU=Alumnos/CN=Usuario UNLaM')
    Invoke-OpenSSL @('req','-in','Usuario/usuario.csr','-verify','-noout')
    Invoke-OpenSSL @('ca','-batch','-config','openssl.cnf','-extensions','usuario','-in','Usuario/usuario.csr','-out','Usuario/usuario.crt','-notext','-days','365')
    Invoke-OpenSSL @('verify','-x509_strict','-CAfile','CA/ca.crt','Usuario/usuario.crt')
    Invoke-OpenSSL @('x509','-in','Usuario/usuario.crt','-pubkey','-noout','-out','Usuario/usuario_publica.pem')
    Invoke-OpenSSL @('x509','-in','Usuario/usuario.crt','-noout','-subject','-issuer','-serial','-dates')
} finally {
    Stop-Transcript
}
