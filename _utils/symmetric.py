# -*- coding: ascii -*-

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from typing import Union, List
from functools import reduce
import base64

def generate_aes_key(as_list:bool = False) -> Union[bytes, List[bytes]]:
    pass

def aes_encrypt(key: Union[bytes, List[bytes]], plaintext: Union[str, bytes]) -> bytes:
    pass

def aes_decrypt(key: Union[bytes, List[bytes]], ciphertext:Union[str, bytes]) -> str:
    pass

def generate_aes_key_from_dh(dh_shared_secret: bytes) -> bytes:
    pass

if __name__ == "__main__":
    pass