# -*- coding: utf-8 -*-

import random
from math_utils import mod_inverse, mod_exp, generate_prime

def generate_rsa_keypair(bits=1024):
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = 65537
    d = mod_inverse(e, phi)
    
    public_key = {'n': n, 'e': e}
    private_key = {'n': n, 'd': d}
    
    return public_key, private_key

def rsa_encrypt(message, public_key):
    n = public_key['n']
    e = public_key['e']
    m = int.from_bytes(message.encode(), 'big')
    if m >= n:
        raise ValueError("Message is too long")
    c = mod_exp(m, e, n)
    return c

def rsa_decrypt(ciphertext, private_key):
    n = private_key['n']
    d = private_key['d']
    m = mod_exp(ciphertext, d, n)
    return m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()

def verify_rsa_keypair(public_key, private_key, p, q):
    n = public_key['n']
    e = public_key['e']
    d = private_key['d']
    
    if n != p * q:
        return False
    
    phi = (p - 1) * (q - 1)
    
    if (e * d) % phi != 1:
        return False
    
    message = random.getrandbits(64)
    encrypted = rsa_encrypt(str(message), public_key)
    decrypted = int(rsa_decrypt(encrypted, private_key))
    
    return message == decrypted

if __name__ == "__main__":
    public_key, private_key = generate_rsa_keypair(1024)
    print("Public key:", public_key)
    print("Private key:", private_key)

    message = "Hello"
    encrypted = rsa_encrypt(message, public_key)
    decrypted = rsa_decrypt(encrypted, private_key)
    print("Original message:", message)
    print("Encrypted message:", encrypted)
    print("Decrypted message:", decrypted)

    p = generate_prime(512)
    q = generate_prime(512)
    is_valid = verify_rsa_keypair(public_key, private_key, p, q)
    print("Keypair is valid:", is_valid)