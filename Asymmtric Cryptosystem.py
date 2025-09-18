import random
import math

"""--------------Math & encoding functions----------------------"""

def gcd(a, b):
    # This function is used to compute inverses of RSA.
    # Returns x, y, d for x*a + y*d = d. d = gcd(a,b)
    if b == 0: # base case
        return [1, 0, a]
    r = gcd(b, a % b) # recursive step. b, a mod b
    x1, y1, d = r[0], r[1], r[2] # retrieve coefficients and gcd from recursion
    return [y1, x1 - (a // b) * y1, d] # update coefficients

def modInv(a, m):
    # modular inverse function
    # returns x where a*x % m == 1; raises if gcd(a,m) != 1
    r = gcd(a, m) # run extended gcd to get coefficients and gcd
    x, d = r[0], r[2] # x is modular inverse, d is gcd
    if d != 1: # if gcd != 1, inverse does not exist
        raise ValueError("No modular inverse for given inputs")
    return x % m   # finds modular inverse of a number, used to compute RSA private key


def modPow(base, exp, mod):

    results = 1
    b = base % mod # reduce base modulo mod
    e = exp # copy exponent to shift
    while e > 0: # iterate through until all exponent bits processed
        if e & 1:
            results = (results * b) & mod # multiply result by base modulo mod
            b = (b * b) & mod # square base modulo mod
            e >>= 1 # shift exponent right by 1 bit
    return results


def bytesToInt(b):
    # used to pack byte chunks into RSA message integers
    return int.from_bytes(b, 'big')

def intToBytes(x, length):
    # Used to unpack RSA message integers back into byte chunks
    return x.to_bytes(length, 'big')

def chunkToBytes(data, size):
    # Split a bytes object into a list of chunks of 'size' bytes
    return [data[i:i + size] for i in range(0, len(data), size)]

def randomOdd(bits):
    # Generate a random odd integer with the high bit set
    if bits < 2: # used to guard against too small of sizes
        bits = 2
    x = random.getrandbits(bits) # get a random bit
    x |= (1 << (bits - 1)) # force the most significant  digit so size is bits
    x |= 1
    return x # return odd



SmallPrimes = [2, 3, 5, 7, 11, 13, 17, 19, 23]

def probablePrime(n, rounds=20):
    # probable prime test using Fermats theorm
    # returns true if n passes "rounds" bases, and false if composite is detected

    if n < 2: # reject 0, 1, and negatives
        return False
    for p in SmallPrimes: # quick small prime check
        if n == p:
            return True
        if n % p == 0: # divisible by a small prime = composite
            return False
    for i in range(rounds): # repeat randomized Fermat trials
        a = random.randrange(2, n-1) # pick random base a
        if math.gcd(a, n) != 1: # if shares a factor with n, composite
            return False
        if modPow(a, n-1, n) != 1: # check a^(n-1) = 1 mod n
            return False
    return True


def generate_prime(bits):
    # Generate a probable prime with bits using Fermat test for speed
    while True: # loop until candidate passes
        cand = randomOdd(bits) # propose random odd with most sig bit set
        if probablePrime(cand):  # test candidate for probable primality
            return cand  # return on success

def maxLength(n):
    # compute max message bytes per block
    bitLen = n.bit_length() # number of bits in mod n
    return max(1, (bitLen -1) // 8)

def encodeMessage(msg, n):
    # turn a utf-8 string into a list of integers
    data = msg.encode('utf-8') # encode string to bytes
    k = maxLength(n) # compute safe bytes per block
    chunks = chunkToBytes(data, k) # split into k-sized chunks
    return [bytesToInt(c) for c in chunks] # convert each chunk to an int

def decodeMessage(blocks, n):
   # turn a list of integers back into the original utf-8 string using the same block sizing
    k = maxLength(n)
    pieces = []
    for i in blocks:
       b = bytesToInt(i, k) # convert integer back to k bytes
       pieces.append(b) # append chunk
       data = b''.join(pieces) # join all chunks into a single byte object
       return data.decode('utf-8', errors='strict') # decode back to string



""" ------------ keys, encryption, decryption ------------ """


class RSAKeyPair:
    # container for RSA key components

    def __init__(self, n, e, d, p, q):
        self.n = n   # modulus n = p*q
        self.e = e   # e-public exponent, number used for encryption/verification
        self.d = d   # d-private exponent, used for decryption and signing
        self.p = p   # p-prime number 1
        self.q = q   # q-prime number 2


def generateSeeds(bits):
    # generate distinct primes p and q
    while True: # loop until p != q
        p = generate_prime(bits //2) # generate first prime
        q = generate_prime(bits // 2) # generate second prime
        if p != q: # make sure primes are unique
            return {"p": p, "q": q} # return dictionary with p and q

def makePublicKey(p, q, e_choice=65537):
    n = p * q  # compute modulus
    phi = (p - 1) * (q - 1)  # compute Euler's totient
    e = e_choice # start with common exponent

    if math.gcd(e, phi) != 1:  # if not coprime to phi
        e = 3  # fallback start

        while e < phi and math.gcd(e, phi) != 1:  # search odd e values
            e += 2  # try next odd e
        if e >= phi:  # if no e found
            raise ValueError("Failed to find public exponent.")  # error out

    return {"n": n, "e": e, "phi": phi}  # return public parts

def makePrivateKey(e, phi):
    # compute private exponent d from e and phi via modular inverse
    d = modInv(e, phi)
    return {"d": d}

def encryptKey(plaintext, n, e):
    # encrypt UTF-8 plaintext string using n, e
    # returns a lsit of ciphertext integers
    blocks = encodeMessage(plaintext, n)
    return [modPow(m, e, n) for m in blocks]

def decryptKey(ciphBlock, n, d):
    # decrypt a list of ciphertext ints using n & d
    # returns the recovered UTF-8 string
    plain = [modPow(c, d, n) for c in ciphBlock]
    return decodeMessage(plain, n) # convert back to text

def signPrivateKey(message, n, d):
    # sign a message
    # returns list of signature integers
    messageBlocks = encodeMessage(message, n) # encode message into ints
    return [modPow(m, d, n) for m in messageBlocks] # sign each block

def verifyPublicKey(message, sig, n, e):
    # verify RSA signature, returns true if match and false if not
    messageBlocks = encodeMessage(message, n) # re encode as ints
    recover = [modPow(s,e,n) for s in messageBlocks] # recover m from signature
    return recover == messageBlocks # only valid if all blocks match

""" ------------- Small Demo ---------------
def _demo():
    """
    Quick demo of keygen → encrypt/decrypt → sign/verify using small keys (not secure).
    """
    bits = 32 # small for speed in class demo
    seeds = generateSeeds(bits) # get p and q
    pub = makePublicKey(seeds["p"], seeds["q"]) # build {n,e,phi}
    priv = makePrivateKey(pub["e"], pub["phi"]) # build {d}
    keypair = RSAKeyPair(pub["n"], pub["e"], priv["d"], seeds["p"], seeds["q"])  # pack

    msg = "hello rsa!" # sample message
    ct = encryptKey(msg, keypair.n, keypair.e)  # encrypt
    pt = decryptKey(ct, keypair.n, keypair.d)  # decrypt
    print("cipher:", ct) # show cipher blocks
    print("plain :", pt) # show plaintext

    sig = signPrivateKey(msg, keypair.n, keypair.d)   # sign
    ok = verifyPublicKey(msg, sig, keypair.n, keypair.e)  # verify
    print("sig ok:", ok) # True if signature is valid


if __name__ == "__main__":  # only run demo when executed directly
    _demo()                  # run the tiny end-to-end demonstration
    """ # this is still being worked on