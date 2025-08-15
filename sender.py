import socket
import json
from encryption import encrypt_bytes

HEADER_LEN_BYTES = 4

def send_file(filepath, host, port, password):
    with open(filepath, "rb") as f:
        data = f.read()
    enc = encrypt_bytes(data, password)
    header = {
        "filename": filepath.split("/")[-1],
        "salt": enc["salt"],
        "nonce": enc["nonce"],
        "cipher_len": len(enc["ciphertext"])
    }
    header_bytes = json.dumps(header).encode()
    with socket.create_connection((host, port)) as sock:
        sock.sendall(len(header_bytes).to_bytes(HEADER_LEN_BYTES, "big"))
        sock.sendall(header_bytes)
        sock.sendall(enc["ciphertext"])
    print("File sent successfully")
