# -*- coding: utf-8 -*-

import random
import secrets # Provides secure rng
from typing import Tuple

__all__ = ['is_prime', 'generate_prime', 'mod_exp', 'mod_inverse', 'gcd', 'discrete_log']

def _is_prime_brute_force(n: int) -> bool:
    #* 병신돌대가리방법
    if n < 2:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True

def _is_prime_trial_division(n: int) -> bool:
    #* 2와 3의 배수인지 확인 후 각 홀수에 대해 확인
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

def _miller_rabin_test(n: int, k: int=5) -> bool:
    #* 밀러-라빈 소수 판별법
    """
    어떤 홀수인 소수 n에 대해서 (n-1)은 짝수이므로
    (n-1) = 2^s * ...
          = 2^s * d 의 꼴로 나타낼 수 있음 (d는 약수로 2를 가지지 않으므로 홀수임)
    1 < a < n-1 을 만족하는 무작위 밑 a에 대해:
    x = a^d mod n
    x가 1 또는 n-1일 시 패스
    그렇지 않다면 1부터 s-1까지:
    y = x^2 mod n
    y가 n-1일 시 패스
    y가 1일 시 n은 합성수임

    모든 과정을 패스하였다면 n은 소수임
    
    이 과정을 여러 가지 a값에 대해 반복함.
    더 많은 a값을 테스트할 수록 결과의 신뢰도가 올라가나 시간이 오래 걸림
    따라서 아주 낮은 확률로 (>4^-k) 소수가 아닐 수 있다.
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def _fermat_primality_test(n: int, k: int=5) -> bool:
    #* 페르마의 작은정리
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    for _ in range(k):
        a = random.randint(2, n - 2)
        if pow(a, n - 1, n) != 1:
            return False
    return True

def _generate_prime_naive(bits: int) -> int:
    #* 병신돌대가리방법2
    while True:
        # Generate a random odd number with the specified number of bits
        n = secrets.randbits(bits) | (1 << bits - 1) | 1
        if is_prime(n):
            return n

def _generate_prime_smallFactors(bits: int) -> int:
    #* 병신돌대가리방법3
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]
    
    while True:
        n = secrets.randbits(bits) | (1 << bits - 1) | 1
        if all(n % p != 0 for p in small_primes):
            if is_prime(n):
                return n
            
def _generate_prime_miller_rabin(bits: int, k: int=64) -> int:
    def miller_rabin_generation(n, k):
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False

        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        for _ in range(k):
            a = random.randrange(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    while True:
        n = secrets.randbits(bits) | (1 << bits - 1) | 1
        if miller_rabin_generation(n, k):
            return n

def is_prime(n: int) -> bool:
    return _miller_rabin_test(n)

def is_prime_strict(n: int) -> bool:
    return _is_prime_trial_division(n)

def generate_prime(bits: int) -> int:
    return _generate_prime_miller_rabin(bits)

def mod_exp(base: int, exponent: int, modulus: int) -> int:
    #* base^exponent mod modulus의 값을 계산하는 알고리즘
    # result = 1
    # base = base % modulus
    # while exponent > 0:
    #     if exponent % 2 == 1:
    #         result = (result * base) % modulus
    #     exponent = exponent >> 1
    #     base = (base * base) % modulus
    # return result
    
    #* The code wasn't working as intended, replaced with pow()
    return pow(base, exponent, modulus)

def _extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    #* Extended Euclidean Algorithm
    if a == 0:
        return b, 0, 1
    else:
        gcd, x, y = _extended_gcd(b % a, a)
        return gcd, y - (b // a) * x, x

def mod_inverse(a: int, m: int) -> int:
    #* a mod m의 multiplicative inverse를 계산하는 알고리즘
    gcd, x, _ = _extended_gcd(a, m)
    if gcd != 1:
        raise ValueError("Multiplicative inverse does not exist")
    else:
        return x % m

def gcd(a: int, b: int) -> int:
    return a if b == 0 else gcd(b, a % b)

def discrete_log(g: int, h: int, p: int, max_iterations: int=1000000) -> int:
    if h == 1:
        return 0
    
    m = int((p - 1)**0.5) + 1

    baby_steps = {pow(g, i, p): i for i in range(m)}

    factor = pow(g, m * (p - 2), p)

    for j in range(m):
        y = (h * pow(factor, j, p)) % p
        if y in baby_steps:
            return j * m + baby_steps[y]

    raise ValueError("Discrete logarithm not found")

if __name__ == "__main__":
    import time

    def run_test(func, *args):
        start_time = time.time()
        result = func(*args)
        end_time = time.time()
        print(f"{func.__name__}{args} = {result}")
        print(f"Time taken: {end_time - start_time:.6f} seconds\n")
        return result

    print("Testing is_prime:")
    run_test(is_prime, 997)
    run_test(is_prime, 999)

    print("Testing generate_prime:")
    prime = run_test(generate_prime, 32)  # Generate a 32-bit prime
    print(f"Verifying generated prime: {run_test(is_prime, prime)}\n")

    print("Testing mod_exp:")
    run_test(mod_exp, 3, 200, 17)

    print("Testing mod_inverse:")
    run_test(mod_inverse, 3, 11)  # 3^(-1) mod 11

    print("Testing gcd:")
    run_test(gcd, 48, 18)

    print("Testing discrete_log:")
    try:
        run_test(discrete_log, 2, 3, 5)  # 2^x ≡ 3 (mod 5), x should be 3
    except ValueError as e:
        print(f"Error in discrete_log: {e}")

    print("Test complete.")