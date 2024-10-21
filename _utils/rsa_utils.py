# -*- coding: utf-8 -*-

import random
import logging
from .math_utils import mod_inverse, mod_exp, generate_prime

def generate_rsa_keypair(bits=1024):
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = 65537  # Commonly used value for e
    d = mod_inverse(e, phi)
    
    public_key = {'n': n, 'e': e}
    private_key = {'n': n, 'd': d}
    
    return public_key, private_key, p, q

def verify_rsa_keypair(public_key, private_key, p, q):
    n = public_key['n']
    e = public_key['e']
    d = private_key['d']
    
    logging.debug(f"Verifying RSA keypair: n={n}, e={e}, d={d}, p={p}, q={q}")

    # Check if n = p * q
    calculated_n = p * q
    if n != calculated_n:
        logging.error(f"n ({n}) does not equal p*q ({calculated_n})")
        return False
    
    # Check if (p-1)(q-1) = phi
    phi = (p - 1) * (q - 1)
    logging.debug(f"Calculated phi: {phi}")
    
    # Check if e * d ≡ 1 (mod phi)
    ed_mod_phi = (e * d) % phi
    if ed_mod_phi != 1:
        logging.error(f"e*d mod phi ({ed_mod_phi}) is not 1")
        return False
    
    # Additional check: encrypt and decrypt a random message
    message = random.getrandbits(64)
    logging.debug(f"Test message: {message}")
    try:
        encrypted = rsa_encrypt(str(message), public_key)
        logging.debug(f"Encrypted message: {encrypted}")
        decrypted = int(rsa_decrypt(encrypted, private_key))
        logging.debug(f"Decrypted message: {decrypted}")
    except Exception as exc:
        logging.error(f"Error during encryption/decryption test: {exc}")
        return False
    
    if message != decrypted:
        logging.error(f"Decrypted message ({decrypted}) does not match original message ({message})")
        return False

    logging.debug("RSA keypair verified successfully")
    return True

def rsa_encrypt(message, public_key):
    n = public_key['n']
    e = public_key['e']
    m = int.from_bytes(message.encode(), 'big')
    if m >= n:
        raise ValueError("Message is too long")
    return pow(m, e, n)

def rsa_decrypt(ciphertext, private_key):
    n = private_key['n']
    d = private_key['d']
    m = pow(ciphertext, d, n)
    return m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()


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