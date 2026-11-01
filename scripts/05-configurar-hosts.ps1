$ErrorActionPreference = 'Stop'
$archivo = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$contenido = Get-Content -LiteralPath $archivo
$entradas = @($contenido | Where-Object { ($_ -split '#',2)[0] -match '(^|\s)criptografia-unlam\.com(\s|$)' })
if ($entradas.Count -gt 0) {
    if ($entradas.Count -ne 1 -or $entradas[0] -notmatch '^\s*127\.0\.0\.1\s+criptografia-unlam\.com\s*(#.*)?$') {
        throw 'Existe una entrada para el dominio. Revisarla antes de modificar hosts.'
    }
} else {
    $copia = Join-Path (Split-Path $PSScriptRoot -Parent) ('evidencias/hosts-antes-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.txt')
    Copy-Item -LiteralPath $archivo -Destination $copia
    Add-Content -LiteralPath $archivo -Encoding ascii -Value "`r`n127.0.0.1 criptografia-unlam.com # TP Autoridad Certificante UNLaM"
}
