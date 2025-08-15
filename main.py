# main.py
import os
import threading
import socket
import json
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.progressbar import ProgressBar
from kivy.properties import StringProperty, NumericProperty
from kivy.clock import Clock
from kivy.lang import Builder
from kivy.core.window import Window
from kivy.uix.behaviors import ButtonBehavior
from kivy.uix.label import Label
from plyer import filechooser
from encryption import encrypt_bytes, decrypt_bytes

HEADER_LEN_BYTES = 4
CHUNK_SIZE = 4096

KV = """
<GradientProgressBar@ProgressBar>:
    canvas.before:
        Color:
            rgba: 0.3,0.6,0.9,1
        Rectangle:
            pos: self.pos
            size: (self.width * self.value_normalized, self.height)

<HoverButton@ButtonBehavior+Label>:
    font_size: '16sp'
    color: 1,1,1,1
    canvas.before:
        Color:
            rgba: self.bg_color
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [12,]
    bg_color: 0.3,0.8,0.4,1
    original_color: 0.3,0.8,0.4,1

<RootWidget>:
    orientation: 'vertical'
    padding: 20
    spacing: 20

    canvas.before:
        Color:
            rgba: 0.95,0.95,0.97,1
        Rectangle:
            pos: self.pos
            size: self.size

    Label:
        text: "🔒 Secure File Share"
        font_size: '28sp'
        bold: True
        size_hint_y: None
        height: '50dp'
        color: 0.1,0.1,0.1,1

    BoxLayout:
        orientation: 'vertical'
        spacing: 15
        padding: 15
        canvas.before:
            Color:
                rgba: 1,1,1,1
            RoundedRectangle:
                pos: self.pos
                size: self.size
                radius: [15,]

        BoxLayout:
            spacing: 10
            size_hint_y: None
            height: '50dp'
            HoverButton:
                text: "📂 Select File"
                on_release: root.select_file()
                bg_color: 0.2,0.6,0.9,1
                original_color: 0.2,0.6,0.9,1
            Label:
                text: root.filename or "No file selected"
                font_size: '16sp'
                valign: 'middle'
                color: 0.1,0.1,0.1,1

        GridLayout:
            cols: 2
            row_default_height: '40dp'
            row_force_default: True
            spacing: 10

            Label:
                text: "IP Address:"
                size_hint_x: 0.3
                color: 0.1,0.1,0.1,1
            TextInput:
                id: ip_input
                text: root.ip
                multiline: False
                padding: [10,10,10,10]

            Label:
                text: "Port:"
                size_hint_x: 0.3
                color: 0.1,0.1,0.1,1
            TextInput:
                id: port_input
                text: str(root.port)
                multiline: False
                padding: [10,10,10,10]

            Label:
                text: "Password:"
                size_hint_x: 0.3
                color: 0.1,0.1,0.1,1
            TextInput:
                id: passwd_input
                password: True
                multiline: False
                padding: [10,10,10,10]

        BoxLayout:
            spacing: 10
            size_hint_y: None
            height: '50dp'
            HoverButton:
                text: "📤 Send File"
                on_release: root.start_send(ip_input.text, port_input.text, passwd_input.text)
                bg_color: 0.3,0.8,0.4,1
                original_color: 0.3,0.8,0.4,1
            HoverButton:
                text: "📥 Start Receiver"
                on_release: root.start_receiver(port_input.text, passwd_input.text)
                bg_color: 0.9,0.4,0.3,1
                original_color: 0.9,0.4,0.3,1
            HoverButton:
                text: "⛔ Cancel Transfer"
                on_release: root.cancel_transfer()
                bg_color: 0.9,0.9,0.1,1
                original_color: 0.9,0.9,0.1,1

    GradientProgressBar:
        id: progress
        max: 100
        value: root.progress
        size_hint_y: None
        height: '20dp'

    Label:
        text: root.status
        size_hint_y: None
        height: '60dp'
        font_size: '16sp'
        color: 0.1,0.1,0.1,1
"""

class RootWidget(BoxLayout):
    filename = StringProperty("")
    ip = StringProperty("127.0.0.1")
    port = NumericProperty(5000)
    status = StringProperty("Ready")
    progress = NumericProperty(0)
    selected_path = None
    cancel_flag = False

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        Window.bind(on_dropfile=self._on_file_drop)

    def _on_file_drop(self, window, file_path):
        path = file_path.decode("utf-8")
        if os.path.isfile(path):
            self.selected_path = path
            self.filename = os.path.basename(path)
            self.set_status(f"File selected via drag-and-drop: {self.filename}")

    def select_file(self):
        filechooser.open_file(on_selection=self._file_chosen)

    def _file_chosen(self, selection):
        if selection:
            self.selected_path = selection[0]
            self.filename = os.path.basename(self.selected_path)
            self.set_status(f"Selected {self.filename}")

    def cancel_transfer(self):
        self.cancel_flag = True
        self.set_status("Transfer cancelled")
        self.set_progress(0)

    def start_send(self, ip, port, password):
        self.cancel_flag = False
        if not self.selected_path:
            self.set_status("No file selected")
            return
        try:
            port = int(port)
        except:
            self.set_status("Invalid port")
            return
        if not password:
            self.set_status("Password required")
            return
        threading.Thread(target=self._send_thread, args=(ip, port, password), daemon=True).start()

    def start_receiver(self, port, password):
        self.cancel_flag = False
        try:
            port = int(port)
        except:
            self.set_status("Invalid port")
            return
        if not password:
            self.set_status("Password required")
            return
        threading.Thread(target=self._receiver_thread, args=(port, password), daemon=True).start()

    def set_status(self, text):
        Clock.schedule_once(lambda dt: setattr(self, "status", text))

    def set_progress(self, value):
        Clock.schedule_once(lambda dt: setattr(self, "progress", value))

    def _send_thread(self, ip, port, password, filepath=None):
        if not filepath:
            filepath = self.selected_path
        self.set_progress(0)
        self.set_status("Reading file...")
        with open(filepath, "rb") as f:
            data = f.read()
        if self.cancel_flag: return
        self.set_status("Encrypting...")
        enc = encrypt_bytes(data, password)
        if self.cancel_flag: return

        total_len = len(enc["ciphertext"])
        sent = 0
        header = {"filename": os.path.basename(filepath), "salt": enc["salt"], "nonce": enc["nonce"], "cipher_len": total_len}
        header_bytes = json.dumps(header).encode()
        self.set_status(f"Connecting to {ip}:{port}...")

        try:
            with socket.create_connection((ip, port), timeout=10) as sock:
                sock.sendall(len(header_bytes).to_bytes(HEADER_LEN_BYTES, "big"))
                sock.sendall(header_bytes)
                for i in range(0, total_len, CHUNK_SIZE):
                    if self.cancel_flag: 
                        self.set_status("Send cancelled")
                        return
                    chunk = enc["ciphertext"][i:i+CHUNK_SIZE]
                    sock.sendall(chunk)
                    sent += len(chunk)
                    self.set_progress(int(sent/total_len*100))
            self.set_status("File sent successfully")
            self.set_progress(100)
        except Exception as e:
            self.set_status(f"Send failed: {e}")
            self.set_progress(0)

    def _receiver_thread(self, port, password):
        self.set_progress(0)
        self.set_status(f"Listening on port {port}...")
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("0.0.0.0", port))
        server.listen(1)
        conn, addr = server.accept()
        with conn:
            self.set_status(f"Connected: {addr}")

            raw = conn.recv(HEADER_LEN_BYTES)
            header_len = int.from_bytes(raw, "big")

            header_bytes = b""
            while len(header_bytes) < header_len:
                if self.cancel_flag: 
                    self.set_status("Receive cancelled")
                    return
                header_bytes += conn.recv(header_len - len(header_bytes))
            header = json.loads(header_bytes.decode())

            ciphertext = b""
            remaining = header["cipher_len"]
            while remaining > 0:
                if self.cancel_flag: 
                    self.set_status("Receive cancelled")
                    return
                chunk = conn.recv(min(CHUNK_SIZE, remaining))
                if not chunk:
                    break
                ciphertext += chunk
                remaining -= len(chunk)
                self.set_progress(int((len(ciphertext)/header["cipher_len"])*100))

            self.set_status("Decrypting...")
            if self.cancel_flag: 
                self.set_status("Decryption cancelled")
                return
            plaintext = decrypt_bytes(ciphertext, password, header["salt"], header["nonce"])
            os.makedirs("received", exist_ok=True)
            out_path = os.path.join("received", header["filename"])
            with open(out_path, "wb") as f:
                f.write(plaintext)
            self.set_status(f"File saved to {out_path}")
            self.set_progress(100)

class SecureFileShareApp(App):
    def build(self):
        Builder.load_string(KV)
        return RootWidget()

if __name__ == "__main__":
    SecureFileShareApp().run()
