import random
from .math_utils import generate_prime

__all__ = [
    "generate_dh_params",
    "generate_dh_keypair",
    "compute_dh_shared_secret",
    "verify_dh_generator",
]

def generate_dh_params(bits: int=4) -> tuple[int, int]:
    pass

def generate_dh_keypair(p: int, g: int) -> tuple[int, int]:
    pass

def compute_dh_shared_secret(private_key: int, other_public_key: int, p: int) -> int:
    pass

def verify_dh_generator(g: int, p: int) -> bool:
    pass

if __name__ == "__main__":
    pass