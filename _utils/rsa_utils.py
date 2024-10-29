from .math_utils import generate_prime
import random

def generate_rsa_keypair():
    primes = [p for p in generate_prime(2) if 400< p <500]
    p = random.choice(primes)
    q = random.choice(primes)
    
    n = p * q
    phi = (p - 1) * (q - 1)

def rsa_encrypt(message, public_key):
    pass

def rsa_decrypt(ciphertext, private_key):
    pass

def verify_rsa_keypair(public_key, private_key, p, q):
    pass

if __name__ == "__main__":
    # Testing code goes here
    pass