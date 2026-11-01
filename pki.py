"""Operaciones de la práctica ejecutadas con OpenSSL, sin shell."""
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parent

class PKI:
    def __init__(self, root=ROOT):
        self.root = Path(root)
        self.openssl = os.environ.get('OPENSSL_EXE') or shutil.which('openssl') or r'C:\Program Files\OpenSSL-Win64\bin\openssl.exe'

    def run(self, *args, check=True):
        p = subprocess.run([self.openssl, *map(str, args)], cwd=self.root,
                           capture_output=True, text=True, encoding='utf-8', errors='replace',
                           timeout=90, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        output = (p.stdout + p.stderr).strip()
        if check and p.returncode:
            raise RuntimeError(output or 'OpenSSL no pudo completar la operación.')
        return p.returncode, output

    def certificates(self):
        items = [('CA raíz', self.root / 'CA/ca.crt', None, 'Raíz')]
        states = {}
        for line in (self.root / 'CA/index.txt').read_text().splitlines():
            cols = line.split('\t')
            if len(cols) >= 6:
                states[cols[3].lstrip('0').upper()] = {'V': 'Vigente', 'R': 'Revocado', 'E': 'Vencido'}.get(cols[0], cols[0])
        paths = list((self.root / 'Usuario').glob('*.crt')) + list((self.root / 'Usuario').glob('*/certificado.crt')) + list((self.root / 'Servidor').glob('*.crt'))
        for cert in paths:
            _, serial = self.run('x509', '-in', cert, '-noout', '-serial')
            state = states.get(serial.split('=')[-1].lstrip('0').upper(), 'Sin registro')
            if state == 'Vigente' and self.run('x509', '-in', cert, '-checkend', '0', '-noout', check=False)[0]:
                state = 'Vencido'
            key = cert.with_suffix('.key')
            _, subject = self.run('x509', '-in', cert, '-noout', '-subject', '-nameopt', 'utf8')
            name = subject.split('CN=')[-1].split('CN =')[-1].strip()
            items.append((name, cert, key if key.exists() else None, state))
        return items

    def inspect(self, cert):
        return self.run('x509', '-in', cert, '-noout', '-text')[1]

    def issue(self, name):
        name = name.strip()
        if not re.fullmatch(r'[\w .@-]{1,70}', name, re.UNICODE):
            raise ValueError('Usá entre 1 y 70 letras, números, espacios, puntos, @ o guiones.')
        folder = self.root / 'Usuario' / ('emitido-' + uuid.uuid4().hex[:12])
        folder.mkdir(parents=True)
        key, csr, cert = (folder / ('certificado.' + ext) for ext in ('key', 'csr', 'crt'))
        self.run('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', key)
        self.run('req', '-new', '-utf8', '-config', 'openssl.cnf', '-key', key, '-out', csr, '-subj', '/C=AR/O=UNLaM/CN=' + name)
        self.run('ca', '-batch', '-config', 'openssl.cnf', '-extensions', 'usuario', '-in', csr, '-out', cert, '-notext')
        self.run('verify', '-x509_strict', '-CAfile', 'CA/ca.crt', cert)
        return f'Certificado emitido para {name}.\nRSA de 2048 bits · Firma SHA-256\n{cert}'

    def chain(self, cert):
        self.run('ca', '-config', 'openssl.cnf', '-gencrl', '-out', 'CA/ca.crl.pem', '-batch')
        self.run('crl', '-in', 'CA/ca.crl.pem', '-verify', '-CAfile', 'CA/ca.crt', '-noout')
        code, out = self.run('verify', '-x509_strict', '-crl_check', '-CRLfile', 'CA/ca.crl.pem', '-CAfile', 'CA/ca.crt', cert, check=False)
        return code == 0, out

    def revoke(self, cert):
        if Path(cert).resolve() == (self.root / 'CA/ca.crt').resolve():
            raise ValueError('Esta demostración no revoca la CA raíz.')
        self.run('ca', '-config', 'openssl.cnf', '-revoke', cert, '-crl_reason', 'cessationOfOperation', '-batch')
        valid, out = self.chain(cert)
        if valid or 'certificate revoked' not in out:
            raise RuntimeError('No se confirmó la revocación:\n' + out)
        return 'CERTIFICADO REVOCADO\nLa CRL fue actualizada y OpenSSL rechazó el certificado.\n\n' + out

    def sign(self, cert, key, file, signature):
        valid, out = self.chain(cert)
        if not valid:
            raise ValueError('El certificado no es válido para firmar:\n' + out)
        if Path(signature).resolve() in {Path(p).resolve() for p in (cert, key, file)}:
            raise ValueError('La firma debe guardarse en un archivo separado.')
        # Evitar producir una firma con una clave que no corresponde al certificado.
        public_cert = self.run('x509', '-in', cert, '-pubkey', '-noout')[1]
        public_key = self.run('pkey', '-in', key, '-pubout')[1]
        if public_cert != public_key:
            raise ValueError('La clave privada no corresponde al certificado.')
        self.run('dgst', '-sha256', '-sign', key, '-out', signature, file)
        return 'FIRMA GENERADA\nSe firmó el hash SHA-256 con la clave privada.\nEl archivo original se conserva.\n\n' + str(signature)

    def verify(self, cert, file, signature):
        with tempfile.TemporaryDirectory() as tmp:
            public = Path(tmp) / 'public.pem'
            self.run('x509', '-in', cert, '-pubkey', '-noout', '-out', public)
            code, out = self.run('dgst', '-sha256', '-verify', public, '-signature', signature, file, check=False)
        if code and 'Verification failure' not in out:
            raise RuntimeError(out)
        trusted, chain = self.chain(cert)
        return ('FIRMA VÁLIDA: el contenido coincide.' if code == 0 else 'FIRMA INVÁLIDA: el archivo o la firma no coinciden.') + '\n\n' + ('CERTIFICADO VÁLIDO según la CA y la CRL.' if trusted else 'CERTIFICADO NO VÁLIDO según la CA y la CRL.') + '\n\n' + out + '\n\n' + chain

    def demo(self, cert, key):
        folder = self.root / 'Usuario' / ('demo-' + uuid.uuid4().hex[:10])
        folder.mkdir()
        original, altered, sig = [folder / s for s in ('original.txt', 'modificado.txt', 'archivo.sig')]
        original.write_text('Archivo original de la práctica.\n', encoding='utf-8')
        altered.write_bytes(original.read_bytes() + b'Contenido agregado.\n')
        self.sign(cert, key, original, sig)
        return '1. ARCHIVO ORIGINAL\n' + self.verify(cert, original, sig) + '\n\n2. ARCHIVO MODIFICADO\n' + self.verify(cert, altered, sig) + '\n\nArchivos: ' + str(folder)
