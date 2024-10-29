from math_utils import generate_prime, generate_relative_prime, mod_inverse, is_prime
import random
import logging
def generate_rsa_keypair():
    p = generate_prime(2, True)
    q = generate_prime(2, True)
    while p == q:
        q = generate_prime(2, True)
    
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # public key
    e = generate_relative_prime(phi)
    # private key
    d = mod_inverse(e, phi)
    logging.info("RSA keypair generated: e={}, d={}, n={}".format(e, d, n))
    return e, d, p, q

def rsa_encrypt(message, public_key):
    pass

def rsa_decrypt(ciphertext, private_key):
    pass

def verify_rsa_keypair(public_key, private_key, p, q):
    e = public_key
    d = private_key
    phi = (p - 1) * (q - 1)

    if not is_prime(e) or not is_prime(d):
        logging.error("Either e or d is not prime: e={}, d={}".format(e, d))
        return False

    if e * d % phi != 1:
        logging.error("{} * {} % {} != 1".format(e, d, phi))
        return False
    
    return True
    



if __name__ == "__main__":
    # Testing code goes here
    pass

print(generate_rsa_keypair())