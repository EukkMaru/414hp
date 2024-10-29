import random
from .math_utils import generate_prime

__all__ = [
    "generate_dh_params",
    "generate_dh_keypair",
    "compute_dh_shared_secret",
    "verify_dh_generator",
]


def generate_dh_params(bits: int=4) -> tuple[int, int]:
    p = generate_prime(bits, set_range=True)

    for g in [2, 3, 5]:
        if verify_dh_generator(g, p):
            return p, g

    for g in range(2, p - 1):
        if verify_dh_generator(g, p):
            return p, g

    raise ValueError("Could not find a suitable generator")


def generate_dh_keypair(p: int, g: int) -> tuple[int, int]:
    private_key = random.randint(2, p - 2)
    public_key = pow(g, private_key, p)
    return private_key, public_key


def compute_dh_shared_secret(private_key: int, other_public_key: int, p: int) -> int:
    return pow(other_public_key, private_key, p)

def verify_dh_generator(g, p):
    if g <= 1 or g >= p:
        return False

    factors = factorize(p - 1)
    for q in factors:
        if pow(g, (p - 1) // q, p) == 1:
            return False
    return True

def factorize(n):
    factors = []
    d = 2
    while n > 1:
        while n % d == 0:
            if d not in factors:
                factors.append(d)
            n //= d
        d += 1
        if d * d > n:
            if n > 1:
                factors.append(n)
            break
    return factors


if __name__ == "__main__":
    p, g = generate_dh_params(256)
    print(f"Generated DH parameters: p = {p}, g = {g}")

    is_valid_generator = verify_dh_generator(g, p)
    print(f"Is g a valid generator? {is_valid_generator}")

    alice_private, alice_public = generate_dh_keypair(p, g)
    bob_private, bob_public = generate_dh_keypair(p, g)

    print(f"Alice's public key: {alice_public}")
    print(f"Bob's public key: {bob_public}")

    alice_shared_secret = compute_dh_shared_secret(alice_private, bob_public, p)
    bob_shared_secret = compute_dh_shared_secret(bob_private, alice_public, p)

    print(f"Alice's computed shared secret: {alice_shared_secret}")
    print(f"Bob's computed shared secret: {bob_shared_secret}")

    print(f"Shared secrets match: {alice_shared_secret == bob_shared_secret}")