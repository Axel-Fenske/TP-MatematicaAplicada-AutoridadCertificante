param([string]$OpenSSL = 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe')
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
foreach ($archivo in @($OpenSSL, 'Usuario/usuario.key', 'Usuario/usuario.crt', 'Usuario/usuario_publica.pem')) {
    if (!(Test-Path -LiteralPath $archivo)) { throw "Falta $archivo" }
}
function Invoke-OpenSSL {
    param([string[]]$Argumentos)
    Write-Host ('openssl ' + ($Argumentos -join ' '))
    & $OpenSSL @Argumentos
    if ($LASTEXITCODE -ne 0) { throw "OpenSSL fallo: $($Argumentos[0])" }
}
Start-Transcript -Path evidencias/03-prueba-firma.txt -Append
try {
    # Cada ejecucion usa una carpeta nueva para conservar las pruebas anteriores.
    $prueba = 'Usuario/prueba-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff')
    New-Item -ItemType Directory -Path $prueba | Out-Null
    $original = "$prueba/archivo.txt"
    $modificado = "$prueba/archivo-modificado.txt"
    $firma = "$prueba/archivo.sig"
    Set-Content -Encoding ascii -Path $original -Value 'Este archivo fue firmado digitalmente utilizando OpenSSL.'
    Copy-Item -LiteralPath $original -Destination $modificado
    Add-Content -Encoding ascii -Path $modificado -Value 'Esta linea se agrego despues de la firma.'
    Invoke-OpenSSL @('verify','-x509_strict','-CAfile','CA/ca.crt','Usuario/usuario.crt')
    Invoke-OpenSSL @('dgst','-sha256','-sign','Usuario/usuario.key','-out',$firma,$original)
    Write-Host 'PRUEBA 1: archivo original. Debe mostrar Verified OK.'
    Invoke-OpenSSL @('dgst','-sha256','-verify','Usuario/usuario_publica.pem','-signature',$firma,$original)
    Write-Host 'PRUEBA 2: archivo modificado. Debe mostrar Verification failure.'
    $resultado = & $OpenSSL dgst -sha256 -verify Usuario/usuario_publica.pem -signature $firma $modificado 2>&1
    $codigo = $LASTEXITCODE
    $resultado | ForEach-Object { Write-Host $_ }
    if ($codigo -eq 0 -or ($resultado -join "`n") -notmatch 'Verification failure') {
        throw 'No se obtuvo el rechazo de firma esperado.'
    }
    Invoke-OpenSSL @('dgst','-sha256',$original,$modificado)
    Write-Host "AMBAS PRUEBAS CORRECTAS. Archivos conservados en $prueba"
} finally {
    Stop-Transcript
}
