from .math_utils import generate_prime, generate_relative_prime, mod_inverse, is_prime
import random
import logging



def generate_rsa_keypair() -> tuple[int, int, int, int]:
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

def rsa_encrypt(message: bytes, public_key: int, n: int) -> int:
    e = public_key
    message_encoded = int.from_bytes(message.encode('ascii'), 'big') if isinstance(message, str) else int.from_bytes(message, 'big')
    ciphertext = pow(message_encoded, e, n)
    return ciphertext


def rsa_decrypt(ciphertext: int, private_key: int, n: int, return_bytes: bool=False) -> bytes:
    d = private_key
    message_encoded = pow(ciphertext, d, n)
    message_length = (message_encoded.bit_length() + 7) // 8
    message_decoded = message_encoded.to_bytes(message_length, 'big').decode('ascii') if not return_bytes else message_encoded.to_bytes(message_length, 'big')
    return message_decoded

def verify_rsa_keypair(public_key: int, private_key: int, p: int, q: int) -> bool:
    e = public_key
    d = private_key
    n = p * q
    phi = (p - 1) * (q - 1)

    if not (is_prime(p) and is_prime(q)):
        logging.error("p or q is not prime: p={}, q={}".format(p, q))
        return False

    if e * d % phi != 1:
        logging.error("{} * {} % {} != 1".format(e, d, phi))
        return False
    
    test_M = random.randbytes(2)
    enc_M = rsa_encrypt(test_M, public_key, n)
    dec_M = rsa_decrypt(enc_M, private_key, n)
    if dec_M != test_M:
        logging.error("Decrypted message is not the same as the original message: {} != {}".format(dec_M, test_M))
        return False
    
    logging.info("RSA keypair is valid")
    return True
    

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    public_key, private_key, p, q = generate_rsa_keypair()
    verify_rsa_keypair(public_key, private_key, p, q)

    pass

