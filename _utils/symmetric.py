# -*- coding: ascii -*-

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from typing import Union, List
from functools import reduce
import base64

def generate_aes_key(as_list:bool = False) -> Union[bytes, List[bytes]]:
    key = get_random_bytes(32) #32 bytes = 256 bits
    return list(key) if as_list else key

def aes_encrypt(key: Union[bytes, List[bytes]], plaintext: Union[str, bytes]) -> bytes:
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
    if isinstance(key, list):
        key = bytes(key)  #List of bytes -> single byte string

    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return ciphertext

def aes_decrypt(key: Union[bytes, List[bytes]], ciphertext:Union[str, bytes]) -> str:
    if isinstance(ciphertext, str):
        ciphertext = ciphertext.encode()
    if isinstance(key, list):
        key = bytes(key)
    
    cipher = AES.new(key, AES.MODE_ECB)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)

    return plaintext.decode('ascii')

def generate_aes_key_from_dh(dh_shared_secret: bytes) -> bytes:
    return (dh_shared_secret * (32 // len(dh_shared_secret) + 1))[:32]

if __name__ == "__main__":
    #AES 키 생성
    key = generate_aes_key(as_list=True)
    print(f"Generated AES key (list): {key}")

    #테스트 메시지
    message = "Hello, world!"
    print(f"Original message: {message}")

    #메시지 암호화
    encrypted = aes_encrypt(key, message)
    print(f"Encrypted message: {encrypted}")

    #메시지 복호화
    decrypted = aes_decrypt(key, encrypted)
    print(f"Decrypted message: {decrypted}")

    #복호화 결과 검증
    assert message == decrypted, "Decryption failed"
    print("Encryption and decryption successful!")

    #Diffie-Hellman 공유 비밀로부터 AES 키 파생시키기
    dh_secret = get_random_bytes(2)  #예제 DH 공유 비밀 (2바이트)
    print(f"Generated DH shared secret: {dh_secret}")
    derived_key = derive_aes_key_from_dh(dh_secret)
    print(f"Derived AES key from DH shared secret: {derived_key}\nKey length: {len(derived_key)}")
