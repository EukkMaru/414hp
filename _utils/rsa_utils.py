# -*- coding: utf-8 -*-

import random
import logging
from .math_utils import mod_inverse, generate_prime, is_prime, is_generator, gcd

def generate_rsa_keypair(bits: int=4) -> tuple[int, int, int, int]:
    pass

def verify_rsa_keypair(public_key: int, private_key: int, p: int, q: int) -> bool:
    pass

def rsa_encrypt(message: bytes, public_key: int, n: int) -> int:
    pass

def rsa_decrypt(ciphertext: int, private_key: int, n: int, return_bytes: bool=False) -> str:
    pass

if __name__ == "__main__":
    pass