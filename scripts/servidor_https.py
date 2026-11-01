"""Servidor de demostracion: expone exclusivamente la pagina en loopback."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import ssl

ROOT = Path(__file__).resolve().parent.parent

class Pagina(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path not in ('/', '/index.html'):
            self.send_error(404)
            return
        body = (ROOT / 'Web' / 'index.html').read_bytes()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

if __name__ == '__main__':
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(ROOT / 'Servidor/servidor.crt', ROOT / 'Servidor/servidor.key')
    server = ThreadingHTTPServer(('127.0.0.1', 8443), Pagina)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print('Servidor activo: https://criptografia-unlam.com:8443', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
