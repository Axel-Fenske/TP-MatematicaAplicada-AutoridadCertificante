"""Pruebas de integración con OpenSSL y una copia aislada de la CA."""
import shutil
import tempfile
import unittest
from pathlib import Path
from pki import PKI, ROOT

class LifecycleTest(unittest.TestCase):
    def test_issue_sign_tamper_revoke(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            shutil.copytree(ROOT / 'CA', root / 'CA')
            shutil.copy(ROOT / 'openssl.cnf', root / 'openssl.cnf')
            (root / 'Usuario').mkdir()
            (root / 'Servidor').mkdir()
            pki = PKI(root)
            pki.issue('Usuario de prueba')
            item = pki.certificates()[1]
            cert, key = item[1:3]
            self.assertTrue(pki.chain(cert)[0])
            original, altered, signature = [root / f for f in ('original.txt', 'alterado.txt', 'firma.sig')]
            original.write_bytes(b'Contenido original\n')
            altered.write_bytes(b'Contenido modificado\n')
            pki.sign(cert, key, original, signature)
            self.assertIn('FIRMA VÁLIDA:', pki.verify(cert, original, signature))
            self.assertIn('FIRMA INVÁLIDA:', pki.verify(cert, altered, signature))
            with self.assertRaises(ValueError):
                pki.sign(cert, key, original, original)
            self.assertEqual(original.read_bytes(), b'Contenido original\n')
            self.assertIn('CERTIFICADO REVOCADO', pki.revoke(cert))
            result = pki.verify(cert, original, signature)
            self.assertIn('FIRMA VÁLIDA:', result)
            self.assertIn('CERTIFICADO NO VÁLIDO', result)
            self.assertEqual(pki.certificates()[1][3], 'Revocado')
            with self.assertRaises(ValueError):
                pki.sign(cert, key, original, signature)
            with self.assertRaises(ValueError):
                pki.revoke(root / 'CA/ca.crt')
            with self.assertRaises(ValueError):
                pki.issue('usuario/CN=otro')

if __name__ == '__main__':
    unittest.main()
