"""Interfaz de escritorio para el TP de Autoridad Certificante."""
import queue
import socket
import ssl
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import webbrowser
from datetime import datetime
from pki import PKI, ROOT

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('Autoridad Certificante · UNLaM')
        self.geometry('1140x780')
        self.minsize(920, 640)
        self.configure(bg='#eef3f7')
        self.pki = PKI()
        self.events = queue.Queue()
        self.busy = False
        self.server = None
        self.buttons = []
        self.items = {}
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure('TFrame', background='#eef3f7')
        style.configure('TLabel', background='#eef3f7', foreground='#183247', font=('Segoe UI', 10))
        style.configure('TButton', font=('Segoe UI', 10), padding=(12, 9))
        style.configure('Treeview', font=('Segoe UI', 10), rowheight=34)
        style.configure('Treeview.Heading', font=('Segoe UI', 10, 'bold'))
        header = tk.Frame(self, bg='#123348', padx=28, pady=20)
        header.pack(fill='x')
        tk.Label(header, text='UNLaM  /  MATEMÁTICA APLICADA', bg='#123348', fg='#78d9ca', font=('Segoe UI', 10, 'bold')).pack(anchor='w')
        tk.Label(header, text='Laboratorio de certificados y firmas', bg='#123348', fg='white', font=('Segoe UI', 23, 'bold')).pack(anchor='w')
        tk.Label(header, text='Emití un certificado, firmá un archivo y comprobá qué cambia cuando se modifica.', bg='#123348', fg='#dbe7f0', font=('Segoe UI', 10)).pack(anchor='w', pady=(6, 0))
        body = ttk.Frame(self, padding=22)
        body.pack(fill='both', expand=True)
        notebook = ttk.Notebook(body)
        notebook.pack(fill='x')
        certs, signatures, https = [ttk.Frame(notebook, padding=16) for _ in range(3)]
        for panel, title in zip((certs, signatures, https), ('1  Certificados y revocación', '2  Firmas de archivos', '3  Servidor HTTPS')):
            notebook.add(panel, text=title)
        ttk.Label(certs, text='La CA raíz firma los certificados de usuarios y del servidor. Seleccioná uno para inspeccionarlo.').pack(anchor='w', pady=(0, 10))
        self.tree = ttk.Treeview(certs, columns=('state',), height=5)
        self.tree.heading('#0', text='Jerarquía de confianza')
        self.tree.heading('state', text='Estado')
        self.tree.column('#0', width=700)
        self.tree.column('state', width=150)
        self.tree.pack(fill='x')
        actions = ttk.Frame(certs)
        actions.pack(fill='x', pady=(10, 0))
        self.button(actions, 'Emitir certificado', self.issue)
        self.button(actions, 'Inspeccionar', self.inspect)
        self.button(actions, 'Validar con CRL', self.validate)
        self.button(actions, 'Revocar', self.revoke)
        self.button(actions, 'Actualizar', lambda: self.work('Actualizando certificados', lambda: 'Listado actualizado.'))
        ttk.Label(signatures, text='Elegí el certificado del firmante. Su clave privada firma; su clave pública verifica.').pack(anchor='w')
        self.signer = ttk.Combobox(signatures, state='readonly', width=85)
        self.signer.pack(fill='x', pady=10)
        ttk.Label(signatures, text='La demostración crea un original y una copia alterada, sin modificar tus archivos.').pack(anchor='w', pady=6)
        row = ttk.Frame(signatures)
        row.pack(fill='x')
        self.button(row, 'Demostrar original vs. modificado', self.demo)
        self.button(row, 'Firmar archivo…', self.sign)
        self.button(row, 'Verificar archivo y firma…', self.verify)
        ttk.Label(signatures, text='Una firma válida comprueba integridad; también verificamos vigencia y revocación del certificado.').pack(anchor='w', pady=12)
        ttk.Label(https, text='https://criptografia-unlam.com:8443', font=('Segoe UI', 18, 'bold')).pack(anchor='w', pady=10)
        ttk.Label(https, text='Comprobá la conexión y abrí el navegador para inspeccionar el certificado del servidor.').pack(anchor='w')
        row = ttk.Frame(https)
        row.pack(fill='x', pady=14)
        self.button(row, 'Iniciar servidor', self.start_server)
        self.button(row, 'Comprobar HTTPS', lambda: self.work('Comprobando TLS', self.check_https))
        self.button(row, 'Abrir navegador', lambda: webbrowser.open('https://criptografia-unlam.com:8443'))
        ttk.Label(https, text='La comprobación usa nuestra CA explícitamente. La confianza del navegador se revisa en el propio navegador.').pack(anchor='w')
        bottom = ttk.Frame(body)
        bottom.pack(fill='x', pady=(14, 6))
        self.status = tk.StringVar(value='Listo. Seleccioná una operación para comenzar.')
        ttk.Label(bottom, textvariable=self.status, font=('Segoe UI', 10, 'bold')).pack(side='left')
        self.button(bottom, 'Guardar resultado…', self.save, side='right')
        self.output = tk.Text(body, wrap='word', bg='white', fg='#183247', font=('Consolas', 10), padx=16, pady=14, relief='flat', height=13)
        self.output.pack(fill='both', expand=True)
        self.show('BIENVENIDO\n\n1. En Certificados, creá un usuario o inspeccioná uno existente.\n2. En Firmas, ejecutá la demostración y compará ambos resultados.\n3. Revocá un certificado de prueba y volvé a verificar una firma.\n4. En HTTPS, abrí la página y revisá el certificado en el navegador.\n\nPodés guardar los resultados como evidencia para el informe.')
        self.protocol('WM_DELETE_WINDOW', self.close)
        self.after(100, self.poll)
        self.work('Cargando certificados', lambda: None)

    def button(self, parent, text, command, side='left'):
        b = ttk.Button(parent, text=text, command=command)
        b.pack(side=side, padx=(0, 7))
        self.buttons.append(b)

    def show(self, text):
        self.output.configure(state='normal')
        self.output.delete('1.0', 'end')
        self.output.insert('1.0', text)
        self.output.configure(state='disabled')

    def work(self, label, fn):
        if self.busy:
            return
        self.busy = True
        self.status.set(label + '…')
        for b in self.buttons:
            b.configure(state='disabled')
        def task():
            try:
                result = fn()
                self.events.put((True, result, self.pki.certificates()))
            except Exception as e:
                self.events.put((False, str(e), None))
        threading.Thread(target=task, daemon=True).start()

    def poll(self):
        try:
            ok, result, items = self.events.get_nowait()
            self.busy = False
            for b in self.buttons:
                b.configure(state='normal')
            self.status.set('Operación terminada. Revisá el resultado.' if ok else 'No se pudo completar la operación.')
            if result:
                self.show(result if ok else 'ERROR\n\n' + result)
            if items:
                self.populate(items)
        except queue.Empty:
            pass
        self.after(100, self.poll)

    def populate(self, items):
        selected = self.tree.selection()
        old = self.items.get(selected[0], (None, None))[1] if selected else None
        previous = self.signer.get()
        self.tree.delete(*self.tree.get_children())
        self.items = {}
        self.signers = {}
        for i, item in enumerate(items):
            name, cert, key, state = item
            iid = str(i)
            self.tree.insert('' if i == 0 else '0', 'end', iid=iid, text=name, values=(state,), open=True)
            self.items[iid] = item
            if cert == old:
                self.tree.selection_set(iid)
            if key and 'Usuario' in cert.parts:
                self.signers[f'{name} · {state} · {cert.parent.name}'] = item
        self.signer['values'] = list(self.signers)
        if previous in self.signers:
            self.signer.set(previous)
        elif self.signers:
            self.signer.current(0)

    def selected(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo('Seleccioná un certificado', 'Elegí un certificado en la jerarquía.')
            return None
        return self.items[selection[0]]

    def issue(self):
        name = simpledialog.askstring('Nuevo certificado de usuario', 'Nombre del titular:', parent=self)
        if name:
            self.work('Emitiendo certificado', lambda: self.pki.issue(name))

    def inspect(self):
        item = self.selected()
        if item:
            self.work('Leyendo certificado', lambda: self.pki.inspect(item[1]))

    def validate(self):
        item = self.selected()
        if item:
            self.work('Validando certificado y CRL', lambda: self.pki.chain(item[1])[1])

    def revoke(self):
        item = self.selected()
        if not item:
            return
        if item[3] in ('Raíz', 'Revocado'):
            messagebox.showinfo('Revocación', 'Seleccioná un certificado emitido que todavía no esté revocado.')
            return
        if messagebox.askyesno('Revocar certificado', f'¿Revocar el certificado de {item[0]}?\n\nLa revocación es permanente. Para seguir usándolo habrá que emitir otro certificado. Para la demostración, usá un usuario de prueba.'):
            self.work('Revocando certificado', lambda: self.pki.revoke(item[1]))

    def demo(self):
        item = self.signers.get(self.signer.get())
        if item:
            self.work('Firmando y comparando archivos', lambda: self.pki.demo(item[1], item[2]))

    def sign(self):
        item = self.signers.get(self.signer.get())
        if not item:
            return
        file = filedialog.askopenfilename(title='Elegí el archivo que querés firmar')
        if not file:
            return
        signature = filedialog.asksaveasfilename(title='Guardar firma separada', defaultextension='.sig', initialfile='archivo.sig')
        if signature:
            self.work('Firmando archivo', lambda: self.pki.sign(item[1], item[2], file, signature))

    def verify(self):
        item = self.signers.get(self.signer.get())
        if not item:
            return
        file = filedialog.askopenfilename(title='Elegí el archivo que querés verificar')
        if not file:
            return
        signature = filedialog.askopenfilename(title='Elegí la firma correspondiente', filetypes=[('Firma digital', '*.sig'), ('Todos', '*.*')])
        if signature:
            self.work('Verificando firma y certificado', lambda: self.pki.verify(item[1], file, signature))

    def check_https(self):
        ctx = ssl.create_default_context(cafile=str(ROOT / 'CA/ca.crt'))
        with socket.create_connection(('criptografia-unlam.com', 8443), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname='criptografia-unlam.com') as conn:
                version = conn.version()
                conn.sendall(b'GET / HTTP/1.0\r\nHost: criptografia-unlam.com\r\n\r\n')
                response = b''
                while chunk := conn.recv(8192):
                    response += chunk
                if not response.startswith(b'HTTP/1.0 200') or b'Autoridad Certificante' not in response:
                    raise RuntimeError('El servidor no devolvió la página esperada.')
        valid, detail = self.pki.chain(ROOT / 'Servidor/servidor.crt')
        return f'HTTPS RESPONDE\nProtocolo: {version}\nDominio y cadena TLS: verificados con nuestra CA.\nPágina: HTTP 200\nRevocación: {"certificado válido" if valid else "certificado rechazado"}\n\n{detail}\n\nAbrí el navegador para comprobar también su confianza en la CA.'

    def start_server(self):
        def start():
            try:
                return self.check_https()
            except OSError:
                self.server = subprocess.Popen([sys.executable, str(ROOT / 'scripts/servidor_https.py')], cwd=ROOT, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
                try:
                    self.server.wait(timeout=1)
                    raise RuntimeError('El servidor no pudo iniciarse. Revisá si el puerto 8443 está ocupado.')
                except subprocess.TimeoutExpired:
                    return self.check_https()
        self.work('Iniciando servidor local', start)

    def save(self):
        path = filedialog.asksaveasfilename(title='Guardar evidencia', initialdir=ROOT / 'evidencias', initialfile='resultado-' + datetime.now().strftime('%Y%m%d-%H%M%S') + '.txt', defaultextension='.txt')
        if path:
            try:
                from pathlib import Path
                Path(path).write_text(self.output.get('1.0', 'end'), encoding='utf-8')
                self.status.set('Resultado guardado.')
            except OSError as e:
                messagebox.showerror('No se pudo guardar', str(e))

    def close(self):
        if self.busy:
            messagebox.showinfo('Operación en curso', 'Esperá a que termine para cerrar la aplicación.')
            return
        if self.server and self.server.poll() is None:
            self.server.terminate()
        self.destroy()

if __name__ == '__main__':
    App().mainloop()
