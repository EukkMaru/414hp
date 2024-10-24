# -*- coding: utf-8 -*-

import random
import logging
from .math_utils import mod_inverse, mod_exp, generate_prime, is_prime

def generate_rsa_keypair(bits=2048):
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

    calculated_n = p * q
    if n != calculated_n:
        logging.error(f"n ({n}) does not equal p*q ({calculated_n})")
        return False
    
    phi = (p - 1) * (q - 1)
    logging.debug(f"Calculated phi: {phi}")
    
    ed_mod_phi = (e * d) % phi
    if ed_mod_phi != 1:
        logging.error(f"e*d mod phi ({ed_mod_phi}) is not 1")
        return False
    
    if not is_prime(p) or not is_prime(q):
        logging.error(f"p ({p}) or q ({q}) is not prime")
        return False
    
    # Test encryption/decryption
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

def rsa_encrypt(message: bytes, public_key):
    try:
        n = public_key['n']
        e = public_key['e']
        m: int = int.from_bytes(message, 'big') if type(message) is bytes else int.from_bytes(str(message).encode('ascii'), 'big')
        # m: int = int.from_bytes(message, 'big')
        if m >= n:
            raise ValueError("Message is too long")
        if type(m) is not int:
            raise ValueError("M is not int")
    except Exception as e:
        logging.error(f"Error during RSA encryption: {e}")
    finally:
        return pow(m, e, n) if type(m) is int else None
    

def rsa_decrypt(ciphertext, private_key, return_bytes=False):
    try:
        n = private_key['n']
        d = private_key['d']
        # m: int = pow(ciphertext, d, n) if type(ciphertext) is int else pow(int.from_bytes(ciphertext, 'big'), d, n)
        if isinstance(ciphertext, str):
            ciphertext = int.from_bytes(ciphertext, 'big')
        elif isinstance(ciphertext, bytes):
            ciphertext = int(ciphertext)
        m: int = pow(ciphertext, d, n)
        logging.debug(f"TEST: int(ciphertext): {int(ciphertext)}")
    except Exception as e:
        logging.error(f"Error during RSA decryption: {e}")
    finally:
        try:
            return m.to_bytes((m.bit_length() + 7) // 8, 'big').decode('ascii') if not return_bytes else m.to_bytes((m.bit_length() + 7) // 8, 'big')
        except Exception as e:
            logging.error(f"Error during m.to_bytes: {e}\nValue of m: {m}")


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