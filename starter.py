
import random
import math



# Math & encoding functions  ------------------------------
def extended_gcd(a, b):
    if b == 0:
        return [1, 0, a]
    r = extended_gcd(b, a % b)
    x1, y1, d = r[0], r[1], r[2]
    return [y1, x1 - (a // b) * y1, d]

def inv_mod(a, m):
    r = extended_gcd(a, m)
    x, d = r[0], r[2]
    if d != 1:
        raise ValueError("No modular inverse for given inputs")
    return x % m

def mod_pow(base, exp, mod):
    results = 1
    b = base % mod
    e = exp
    while e > 0:
        if e & 1:
            results = (results * b) & mod
        b = (b * b) & mod
        e >>= 1
    return results


def bytes_to_int(b):
    return int.from_bytes(b, 'big')

def int_to_bytes(x, length):
    return x.to_bytes(length, 'big')

def chunk_to_bytes(data, size):
    return [data[i:i + size] for i in range(0, len(data), size)]

def _random_odd(bits):
    x = random.getrandbits(bits)
    x |= (1 << (bits - 1))
    x |= 1
    return x



_SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23]

def generate_prime(bits):
    while True:
        cand = _random_odd(bits)
        if is_probable_prime_fermat(cand):
            return cand

def is_probable_prime_fermat(n, rounds=20):
    if n < 2:
     return False
    for p in _SMALL_PRIMES:
     if n == p:
         return True
     if n % p == 0:
         return False
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        if math.gcd(a,n) != 1:
            return False
        if mod_pow(a,n - 1,n) != 1:
            return False
    return True

#def encode_message_to_blocks(msg, n):

#def decode_block_to_message(blocks, n):


# Math & encoding ^^------------------------------------------


# keys, encryption, decryption


class RSAKeyPair:
    def __init__(self, n, e, d, p, q):
        self.n = n
        self.e = e
        self.d = d
        self.p = p
        self.q = q

def generate_seeds(bits):
    while True:
        p = generate_prime(bits //2)
        q = generate_prime(bits // 2)
        if p != q:
            return {"p": p, "q": q}

def make_public_key_from_pq(p, q, e_choice=65537):
    n + p * q
    phi = (p - 1) * (q - 1)
    e = e_choice
    if math.gcd(e, phi) != 1:
        e = 3
        while e < phi and math.gcd(e, phi) != 1:
            e += 2
        if e >= phi:
            raise ValueError("Failed to find public exponent.")
    return {"n": n, "e": e, "phi": phi}

def encrypt_with_public_key(plaintext, n, e):
    blocks = encode_message_to_blocks(plaintext, n)
    return [mod_pow(m, e, n) for m in blocks]

def make_private_key(e, phi):
   d = inv_mod(e, phi)
   return {"d": d}

def decrypt_with_private_key(cipher_blocks, n, e):
    plaintext = [mod_pow(c, d, n) for c in cipher_blocks]
    return decode_block_to_message(plain_blocks, n)

#def sign_in_private_key(message, n, d):

#def verify_with_public_key(message, sig_blocks, n, e):

#def _demo():