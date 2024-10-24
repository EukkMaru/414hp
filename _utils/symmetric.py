# -*- coding: utf-8 -*-

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

def generate_aes_key():
    return get_random_bytes(32)  # 32 bytes = 256 bits

def aes_encrypt(key, plaintext):
    """
    Encrypt the plaintext using AES in ECB mode with PKCS7 padding.
    
    :param key: 256-bit key for AES encryption
    :param plaintext: The message to encrypt (string or bytes)
    :return: Base64 encoded string of ciphertext
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
    
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    
    return base64.b64encode(ciphertext).decode('utf-8')

def aes_decrypt(key, ciphertext):
    """
    Decrypt the ciphertext using AES in ECB mode with PKCS7 padding.
    
    :param key: 256-bit key for AES decryption
    :param ciphertext: Base64 encoded string of encrypted message
    :return: Decrypted message as a string
    """
    ciphertext = base64.b64decode(ciphertext)
    cipher = AES.new(key, AES.MODE_ECB)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    
    return plaintext.decode('ascii') if isinstance(plaintext, str) else plaintext

def generate_aes_key_from_dh(dh_shared_secret):
    return dh_shared_secret[:32]

# Test the functions if this script is run directly
if __name__ == "__main__":
    # Generate a random AES key
    key = generate_aes_key()
    print(f"Generated AES key: {key.hex()}")

    # Test message
    message = "Hello, AES encryption using PyCryptodome!"
    print(f"Original message: {message}")

    # Encrypt the message
    encrypted = aes_encrypt(key, message)
    print(f"Encrypted message: {encrypted}")

    # Decrypt the message
    decrypted = aes_decrypt(key, encrypted)
    print(f"Decrypted message: {decrypted}")

    # Verify the decryption
    assert message == decrypted, "Decryption failed"
    print("Encryption and decryption successful!")

    # Test DH key derivation
    dh_secret = get_random_bytes(256)  # Simulate a DH shared secret
    aes_key = generate_aes_key_from_dh(dh_secret)
    print(f"AES key derived from DH secret: {aes_key.hex()}")