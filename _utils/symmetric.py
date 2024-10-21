# -*- coding: utf-8 -*-

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

__all__ = ['generate_aes_key', 'aes_encrypt', 'aes_decrypt']

def generate_aes_key():
    return os.urandom(32)  

def aes_encrypt(key, plaintext):
    # Encrypt the plaintext using AES in CBC mode with PKCS7 padding.
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = plaintext + b"\0" * (16 - len(plaintext) % 16)
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def aes_decrypt(key, ciphertext):
    # Decrypt the ciphertext using AES in CBC mode with PKCS7 padding.
    
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    return plaintext.rstrip(b"\0")

if __name__ == "__main__":
    key = generate_aes_key()
    print(f"Generated AES key: {key.hex()}")

    message = b"Hello, AES encryption!"
    print(f"Original message: {message}")

    encrypted = aes_encrypt(key, message)
    print(f"Encrypted message: {encrypted.hex()}")

    decrypted = aes_decrypt(key, encrypted)
    print(f"Decrypted message: {decrypted}")

    assert message == decrypted, "Decryption failed"
    print("Encryption and decryption successful!")