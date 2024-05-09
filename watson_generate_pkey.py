 #
 # This code is inspired from https://www.geeksforgeeks.org/how-to-generate-large-prime-numbers-for-rsa-algorithm/
 #

import random
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateNumbers, RSAPublicNumbers
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Pre generated primes
first_primes_list = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                     31, 37, 41, 43, 47, 53, 59, 61, 67,
                     71, 73, 79, 83, 89, 97, 101, 103,
                     107, 109, 113, 127, 131, 137, 139,
                     149, 151, 157, 163, 167, 173, 179,
                     181, 191, 193, 197, 199, 211, 223,
                     227, 229, 233, 239, 241, 251, 257,
                     263, 269, 271, 277, 281, 283, 293,
                     307, 311, 313, 317, 331, 337, 347, 349]
 
 
def nBitRandom(n):
    return random.randrange(2**(n-1)+1, 2**n - 1)
 
 
def getLowLevelPrime(n):
    '''Generate a prime candidate divisible 
    by first primes'''
    while True:
        # Obtain a random number
        pc = nBitRandom(n)
 
        # Test divisibility by pre-generated
        # primes
        for divisor in first_primes_list:
            if pc % divisor == 0 and divisor**2 <= pc:
                break
        else:
            return pc
 
 
def isMillerRabinPassed(mrc):
    '''Run 20 iterations of Rabin Miller Primality test'''
    maxDivisionsByTwo = 0
    ec = mrc-1

    while ec % 2 == 0:
        ec >>= 1
        maxDivisionsByTwo += 1
    assert(2**maxDivisionsByTwo * ec == mrc-1)
 
    def trialComposite(round_tester):
        if pow(round_tester, ec, mrc) == 1:
            return False
        for i in range(maxDivisionsByTwo):
            if pow(round_tester, 2**i * ec, mrc) == mrc-1:
                return False
        return True
 

    # Set number of trials here
    numberOfRabinTrials = 20
    for i in range(numberOfRabinTrials):
        print(".", end="", flush=True)
        round_tester = random.randrange(2, mrc)
        if trialComposite(round_tester):
            print(".", end="", flush=True)
            return False
    print("+")
    return True
 
 
def generate_prime(size):
    while True:
        n = size
        p = getLowLevelPrime(n)
        if not isMillerRabinPassed(p):
            continue
        else:
            return p

if __name__ == "__main__":
    key_size = 2048
    while True:
        p = generate_prime(key_size - 20)
        q = generate_prime(20)
        n = p * q

        if n.bit_length() == key_size:
            break

    et = (p - 1) * (q - 1)

    e = 65537
    d = pow(e, -1, et)

    print("p=", p)
    print("q=", q)
    print("n=", n)
    print("e=", e)
    print("d=", d)

    public_numbers = RSAPublicNumbers(e, n)
    private_numbers = RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=pow(d, 1, p - 1),
        dmq1=pow(d, 1, q - 1),
        iqmp=pow(q, -1, p),
        public_numbers=public_numbers
    )

    private_key = private_numbers.private_key(default_backend())
    public_key = public_numbers.public_key(default_backend())
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    timestamp = time.strftime("%Y%m%d-%H%M%S")

    with open("build/watson_private-{}.pem".format(timestamp), "wb") as f:
        f.write(pem)
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("build/watson_public-{}.pem".format(timestamp), "wb") as f:
        f.write(pem)
    print("Keys generated and saved to private_key.pem and public_key.pem")
