import random

__all__ = [
    "generate_dh_params",
    "generate_dh_keypair",
    "compute_dh_shared_secret",
    "verify_dh_generator",
]

#수빈이꺼
def gauss_func(n: float) -> int:
    return int(n)

def is_prime_1(n: int) -> bool:
    if n <= 1:
        return False
    if n == 2 or n == 3:
        return True
    test_mod = gauss_func(n**0.5)
    for i in range(2, test_mod + 1):
        if n % i == 0:
            return False
    return True

def generate_prime(bytes: int = 2) -> int:
    ret = []
    for i in range(2, 2**(8 * bytes)):
        if is_prime_1(i):
            ret.append(i)
        else:
            continue
    p = random.choice(ret)
    print(ret)
    return p

def is_generater(i:int, n: int) -> bool:
    if n <= 1:
        return False
    a = set()
    for j in range(1,n):
        mod = pow(i, j, n)
        a.add(mod)

    return len(a) == n - 1

def find_generators(n: int) -> list[int]:
    generators = []
    for i in range(2, n):
        if is_generater(i, n):
            generators.append(i)
    return generators
#여기까지

def generate_dh_params(bits: int=4) -> tuple[int, int]:
     bytes = bits // 8 if bits % 8 == 0 else (bits // 8) + 1
     p = generate_prime(bytes)
     generators = find_generators(p)
     g = random.choice(generators)
     return p, g

def generate_dh_keypair(p: int, g: int) -> tuple[int, int]:
    x = random.randint(1, p - 1)
    y = pow(g, x, p)
    return x, y

def compute_dh_shared_secret(p: int, g: int, x: int, y: int) -> int:
    s = pow(y, x, p)
    return s

def verify_dh_generator(p: int, g: int) -> bool:
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
