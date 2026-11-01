# Autoridad Certificante — Matemática Aplicada

## Requisitos confirmados
- Crear una CA raíz con OpenSSL.
- Emitir un certificado de usuario y uno para un dominio ficticio.
- Firmar un archivo con la clave privada y verificarlo con la pública.
- Demostrar verificación válida del original y fallo al modificarlo.
- Servir una página HTTPS y demostrar confianza en el navegador.
- Incorporar GUI para generar claves, mostrar la jerarquía e inspeccionar certificados.
- Incorporar revocación y comprobación de listas CRL.
- Entregar informe académico, diapositivas y demostración en vivo.

## Etapas
1. Preparar Python y OpenSSL.
2. Implementar CA con registro de emisiones y soporte de revocación.
3. Emitir certificados y probar firmas.
4. Preparar HTTPS local y confianza del navegador.
5. Incorporar interfaz gráfica y pruebas integradas.
6. Documentar resultados reales y preparar la defensa.

## Observaciones sobre los documentos
La consigna Word dice firmar con la clave pública: es un error conceptual.
Se firma con la privada y se verifica con la pública.
El PDF indica 25 minutos en el desarrollo y 15 en la rúbrica; confirmar con la cátedra.

## Organización
CA/: material y registro de la autoridad.
Usuario/: certificado y archivos para la prueba de firma.
Servidor/: certificado TLS.
Web/: página de demostración.
evidencias/: resultados y capturas.
scripts/: automatización reproducible.

Las claves privadas y los datos generados de la práctica no deben incorporarse al repositorio.
