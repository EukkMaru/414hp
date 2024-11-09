import random
from .math_utils import is_generator, generate_prime

__all__ = [
    "generate_dh_params",
    "generate_dh_keypair",
    "compute_dh_shared_secret",
    "verify_dh_generator",
]

def find_generators(n: int) -> list[int]:
    generators = []
    for i in range(2, n):
        if is_generator(i, n):
            generators.append(i)
    return generators

def generate_dh_params(bits: int=4) -> tuple[int, int]:
     p = generate_prime(bits, True)
     generators = find_generators(p)
     g = random.choice(generators)
     return p, g

def generate_dh_keypair(p: int, g: int) -> tuple[int, int]:
    x = random.randint(2, p - 2)
    y = pow(g, x, p)
    return x, y

def compute_dh_shared_secret(private_key:int, other_public_key:int, p:int) -> int:
    s = pow(other_public_key, private_key, p)
    return s

def verify_dh_generator(g: int, p: int) -> bool:
    generators = find_generators(p)
    if g in generators:
        return True
    else:
        return False

if __name__ == "__main__":
    p, g = generate_dh_params()
    print(p, g)
    x, y = generate_dh_keypair(p, g)
    print(x, y)
    s = compute_dh_shared_secret(p, g, x, y)
    print(s)
    print(verify_dh_generator(p, g))
