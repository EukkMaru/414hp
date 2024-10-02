import random

def is_prime_brute_force(n):
    #* 병신돌대가리방법
    if n < 2:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True

def is_prime_trial_division(n):
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

def miller_rabin_test(n, k=5):
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

def fermat_primality_test(n, k=5):
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


def is_prime(n):
    return miller_rabin_test(n)

def is_prime_strict(n):
    return is_prime_trial_division(n)

def generate_prime(bits):
    pass

def mod_exp(base, exponent, modulus):
    pass

def mod_inverse(a, m):
    pass

def gcd(a, b):
    pass

def discrete_log(g, h, p):
    pass

if __name__ == "__main__":
    # Testing code goes here
    pass