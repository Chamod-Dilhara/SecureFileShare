import socket
import json
from encryption import decrypt_bytes
import os

HEADER_LEN_BYTES = 4

def receive_file(port, password):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", port))
    server.listen(1)
    print(f"Listening on port {port}...")
    conn, addr = server.accept()
    print(f"Connected by {addr}")
    raw = conn.recv(HEADER_LEN_BYTES)
    header_len = int.from_bytes(raw, "big")
    header_bytes = conn.recv(header_len)
    header = json.loads(header_bytes.decode())
    ciphertext = conn.recv(header["cipher_len"])
    plaintext = decrypt_bytes(ciphertext, password, header["salt"], header["nonce"])
    os.makedirs("received", exist_ok=True)
    out_path = os.path.join("received", header["filename"])
    with open(out_path, "wb") as f:
        f.write(plaintext)
    print(f"File saved to {out_path}")
    conn.close()
