# import 
import random
from typing import *

__all__ = ["is_prime", "is_generator", "generate_prime", "mod_exp", "mod_inverse", "gcd", "discrete_log"]

# def _new_func():

# def is_prime(n, size): 

def gauss_func(n: float) -> int:
    return int(n) 


def is_generator(g: int, p: int) -> bool:
    if g <= 1 or g >= p:
        return False

    factors = factorize(p - 1)
    for q in factors:
        if pow(g, (p - 1) // q, p) == 1:
            return False
    return True

def factorize(n: int) -> list:
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

def is_prime_1(n: int) -> bool: # Trial Devision
    if n <= 1:
        return False
    if n == 2 or n == 3:
        return True
    test_mod = gauss_func(n**0.5)
    for i in range(2, test_mod + 1):
        if n % i == 0:
            return False
    return True

def is_prime_2(n: int) -> bool: # fermat's primarily test
    if n <= 1:
        return False
    if n == 2 or n == 3:
        return True
    
    for i in range(2, n+1):
        if is_generator(i, n) == True:
            return i
        break

    if (i**(n-1)) % n == 1:
        return True
    else:
        return False
    
def is_prime_3(n: int) -> bool: #Miller-Rabin primarily test
    if n <= 1 or n % 2 == 0:
        return False
    if n == 2 or n == 3:
        return True
    
    k = n - 1
    s = 0
    while k % 2 == 0:
        k //= 2
        s += 1

    for _ in range(5):
        a = random.randint(2, n - 2)
        x = pow(a, k, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def EEA(a: int, b: int):
    x_0, x_1 = 1, 0
    y_0, y_1 = 0, 1

    while b != 0:
        q = a // b
        a, b = b, a % b
        x_0, x_1 = x_1, x_0 - q * x_1
        y_0, y_1 = y_1, y_0 - q * y_1
    
    return a, x_0, y_0

def is_relative_prime(a:int, b:int) -> bool:
    if EEA(a, b)[0] == 1:
        return True
    else:
        return False

def generate_prime(bytes: int=2, set_range: bool = False) -> int:
    r = range(2, 2**(8*bytes)) if not set_range else range(400, 501)
    ret = []
    for i in r:
        if is_prime_1(i) == True: # You can choose primarily test
            ret.append(i)
        elif is_prime_1(i) == False: # You can choose primarily test
            continue
    
    p = random.choice(ret)
    return p

def mod_inverse(a, m):
    if is_relative_prime(a, m) == True:
        k = EEA(a, m)[1]
        if k < 0:
            return m + k
        else:
            return k
    else:
        print("a and m is not relative prime, so inverse doesn't exist")

def gcd(a, b):
    return EEA(a, b)[0]

def is_prime(p: int, strict: bool = True):
    return is_prime_1(p) if strict else is_prime_3(p)

def generate_relative_prime(n: int) -> int:
    ret = []
    for i in range(2, n+1):
        if is_relative_prime(i, n) == 1:
            ret.append(i)
        else:
            continue
    
    p = random.choice(ret)
    return p


def discrete_log(g, h, p):
    pass

if __name__ == "__main__":
    # Testing code goes here
    # print(is_prime(32), is_prime(31))...
    pass
