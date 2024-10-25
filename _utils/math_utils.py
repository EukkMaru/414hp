# import 
from typing import *

__all__ = ["is_prime", "generate_prime", "mod_exp", "mod_inverse", "gcd", "discrete_log"]

# def _new_func():

# def is_prime(n, size): 

def gauss_func(n: float) -> int:
    return int(n) 

def is_generater(n: int) -> bool:
    ret = True

    return ret

def is_prime_1(n: int) -> bool: # Trial Devision
    test_mod = gauss_func(n**0.5)
    ret = True
    for i in range(2, test_mod + 1):
        if n % i == 0:
            return False
        break
    return ret

def is_prime_2(n: int) -> bool: # fermat's primarily test
    for i in range(2, n+1):
        if is_generater(i) == True:
            return i
        break

    if (i**(n-1)) % n == 1:
        return True
    else:
        return False





def generate_prime(bits: int=2) -> int:
    pass

def mod_inverse(a, m):
    pass

def gcd(a, b):
    pass

def discrete_log(g, h, p):
    pass

if __name__ == "__main__":
    # Testing code goes here
    # print(is_prime(32), is_prime(31))...
    pass