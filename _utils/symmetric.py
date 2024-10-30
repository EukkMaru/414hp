# -*- coding: ascii -*-

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from typing import Union, List
from functools import reduce
import base64

def generate_aes_key(as_list:bool = False) -> Union[bytes, List[bytes]]:
    return get_random_bytes(32) if not as_list else [bytes([b]) for b in get_random_bytes(32)] # 32 bytes = 256 bits
    # return [b'|', b'y', b'S', b'\x00', b'\x00', b'\x85', b'\x0f', b'\x13', b'\x98', b'\xe1', b'\\', b'\x86', b'i', b'~', b'?', b'(', b'%', b'o', b'\xfe', b'\xc8', b'\x0c', b'\x13', b'\x94', b'\xab', b'c', b'q', b'\x0e', b'\xa3', b'\xaa', b'>', b'\x91', b'\x00']
    # return [b'|', b'y', b'S', b'\x03', b'\x00', b'\x85', b'\x0f', b'\x13', b'\x98', b'\xe1', b'\\', b'\x86', b'i', b'~', b'?', b'(', b'%', b'o', b'\xfe', b'\xc8', b'\x0c', b'\x13', b'\x94', b'\xab', b'c', b'q', b'\x0e', b'\xa3', b'\xaa', b'>', b'\x91', b'\x00']


def aes_encrypt(key: Union[bytes, List[bytes]], plaintext: Union[str, bytes]) -> bytes:
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
        
    if isinstance(key, list):
        if not all(isinstance(k, bytes) for k in key):
            raise TypeError("Key must be a list of bytes")
        key = reduce(lambda x, y: x + y, key)
    
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    
    return ciphertext

def aes_decrypt(key: Union[bytes, List[bytes]], ciphertext:Union[str, bytes]) -> str:
    if isinstance(ciphertext, str):
        ciphertext = ciphertext.encode()
        
    if isinstance(key, list):
        if not all(isinstance(k, bytes) for k in key):
            raise TypeError("Key must be a list of bytes")
        key = reduce(lambda x, y: x + y, key)

    cipher = AES.new(key, AES.MODE_ECB)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    
    return plaintext.decode('ascii')

def generate_aes_key_from_dh(dh_shared_secret: bytes) -> bytes:
    # shared secret size is 2 bytes (express shared secret in bytes)
    # repeat that 2 bytes 16 times to get 32 bytes (256 bits)
    return reduce(lambda x, y: x + y, [dh_shared_secret] * 16)

# Test the functions if this script is run directly
if __name__ == "__main__":
    # Generate a random AES key
    key = generate_aes_key(True)
    print(f"Generated AES key (list): {key}")
    print(type(key[0]))

    # Test message
    message = "Hello, world!"
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
    dh_secret = get_random_bytes(2)  # Simulate a DH shared secret
    print(f"Generated DH shared secret: {dh_secret}")
    aes_key = generate_aes_key_from_dh(dh_secret)
    print(f"AES key derived from DH secret: {aes_key}\nSize: {len(aes_key)}")