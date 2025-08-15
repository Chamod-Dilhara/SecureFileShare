# encryption.py
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def encrypt_bytes(data: bytes, password: str):
    salt = os.urandom(16)
    key = AESGCM.generate_key(bit_length=256)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    cipher = aes.encrypt(nonce, data, None)
    return {"ciphertext": cipher, "salt": salt, "nonce": nonce}

def decrypt_bytes(ciphertext: bytes, password: str, salt: bytes, nonce: bytes):
    key = AESGCM.generate_key(bit_length=256)
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, None)
