param([string]$OpenSSL = 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe')
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
foreach ($archivo in @('Servidor/servidor.key','Servidor/servidor.csr','Servidor/servidor.crt')) {
    if (Test-Path $archivo) { throw "Ya existe $archivo; no se sobrescribira." }
}
function Invoke-OpenSSL {
    param([string[]]$Argumentos)
    Write-Host ('openssl ' + ($Argumentos -join ' '))
    & $OpenSSL @Argumentos
    if ($LASTEXITCODE -ne 0) { throw 'Fallo OpenSSL.' }
}
Start-Transcript -Path evidencias/04-certificado-servidor.txt -Append
try {
    Invoke-OpenSSL @('genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out','Servidor/servidor.key')
    Invoke-OpenSSL @('req','-new','-config','openssl.cnf','-key','Servidor/servidor.key','-out','Servidor/servidor.csr','-subj','/C=AR/O=UNLaM/OU=Servidor Web/CN=criptografia-unlam.com')
    Invoke-OpenSSL @('ca','-batch','-config','openssl.cnf','-extensions','servidor','-in','Servidor/servidor.csr','-out','Servidor/servidor.crt','-notext','-days','365')
    Invoke-OpenSSL @('verify','-x509_strict','-purpose','sslserver','-verify_hostname','criptografia-unlam.com','-CAfile','CA/ca.crt','Servidor/servidor.crt')
    Invoke-OpenSSL @('x509','-in','Servidor/servidor.crt','-noout','-subject','-issuer','-dates','-ext','subjectAltName')
} finally { Stop-Transcript }
