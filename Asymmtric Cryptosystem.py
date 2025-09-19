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
            results = (results * b) % mod # multiply result by base modulo mod
        b = (b * b) % mod # square base modulo mod
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


def generatePrime(bits):
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
       b = intToBytes(i, k) # convert integer back to k bytes
       pieces.append(b) # append chunk
    data = b"".join(pieces) # join all chunks into a single byte object
    return data.decode("utf-8", errors="strict") # decode back to string



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
        p = generatePrime(bits //2) # generate first prime
        q = generatePrime(bits // 2) # generate second prime
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
    recover = [modPow(s,e,n) for s in sig] # recover m from signature
    return recover == messageBlocks # only valid if all blocks match

""" ------------- Small Demo --------------- """


def demo():
    # ----- helpers -----
    def genKeyPair(bits=32):
        seeds = generateSeeds(bits) # generate two random primes
        pub = makePublicKey(seeds["p"], seeds["q"]) # build public parts from p and q
        priv = makePrivateKey(pub["e"], pub["phi"]) # compute private exponent
        # return a container will all key components
        return RSAKeyPair(pub["n"], pub["e"], priv["d"], seeds["p"], seeds["q"])

    def mainMenu():
        # role selection prompt to show throughout loop
        print("What is your user type?")
        print("1. A public user")
        print("2. The owner of the keys")
        print("3. Exit")
        return input("Enter your choice: ")

    def publicMenu():
        # display menu actions for public user
        print("\nAs a public user, what would you like to do?")
        print("1. Send an encrypted message")
        print("2. Verify a digital signature")
        print("3. Exit")
        return input("Enter your choice: ")

    def ownersMenu():
        # display menu actions for the owner
        print("\nAs the owner of the keys, what would you like to do?")
        print("1. Decrypt a message")
        print("2. Digitally sign a message")
        print("3. Show the keys")
        print("4. Generate a new set of keys")
        print("5. Exit")
        return input("Enter your choice: ")

    # ----- state -----
    encrypted_messages = [] # holds ciphertexts the public sends
    signatures = [] # holds tuples for verify menu
    keyPair = genKeyPair(bits=32) # creates a small demo keypair to be fast
    print("RSA keys have been generated.")


    """----- main loop ----- """

    while True: # repeat until user exits
        choice = mainMenu() # ask which role to do
        if choice == "1":
            # PUBLIC USER LOOP
            while True: # stay in public menu until exit
                c = publicMenu() # ask which action to do
                if c == "1":
                    # encrypt the text to the owners public key and store it
                    message = input("Enter your message: ")
                    ct = encryptKey(message, keyPair.n, keyPair.e) # RSA encrypt
                    encrypted_messages.append(ct) # send
                    print("Message encrypted and sent.")
                elif c == "2":
                    # verify a signature the owner has posted
                    if not signatures:
                        print("There are no signatures to authenticate.")
                    else:
                        print("The following messages are available:")
                        # list messages with signatures
                        for i, (m, _) in enumerate(signatures, 1):
                            print(f"{i}. {m}")
                        index = input("Enter your choice: ")
                        try:
                            # pick the message by index
                            m, s = signatures[int(index) - 1]
                            # verify
                            ok = verifyPublicKey(m, s, keyPair.n, keyPair.e)
                            print("Signature verified." if ok else "Signature is NOT valid.")
                        except Exception:
                            # handles non integer input or out of range index
                            print("Invalid selection.")
                elif c == "3":
                    # leave public menu and go back to main menu
                    break
                else:
                    print("Invalid selection.")

        elif choice == "2":
            # OWNER LOOP
            while True: # stay in owner memu until exit
                c = ownersMenu() # ask which action to do
                if c == "1":
                    # decrypt a ciphertext previously sent
                    if not encrypted_messages:
                        print("No messages available.")
                    else:
                        print("The following messages are available:")

                        for i, ct in enumerate(encrypted_messages, 1):
                            print(f"{i}. (length = {len(ct)})")
                        idx = input("Enter your choice: ")
                        try:
                            # pop the ciphertext out of the queue
                            ct = encrypted_messages.pop(int(idx) - 1)
                            # decrypt
                            pt = decryptKey(ct, keyPair.n, keyPair.d)
                            print("Decrypted message:", pt)
                        except Exception:
                            print("Invalid selection.")
                elif c == "2":
                    # create a digital signature over a message and publish it
                    msg = input("Enter a message: ")
                    sig = signPrivateKey(msg, keyPair.n, keyPair.d)
                    signatures.append((msg, sig))
                    print("Message signed and sent.")
                elif c == "3":
                    # display current key matieral (for demo)
                    print(f"n = {keyPair.n}\ne = {keyPair.e}\nd = {keyPair.d}\np = {getattr(keyPair,'p','?')}\nq = {getattr(keyPair,'q','?')}")
                elif c == "4":
                    # regenerate keys and clear old messages
                    keyPair = genKeyPair(bits=32)
                    encrypted_messages.clear()
                    signatures.clear()
                    print("New keys have been generated.")
                elif c == "5":
                    # leave owner menu and return to main menu
                    break
                else:
                    print("Invalid selection.")

        elif choice == "3":
            print("Bye!")
            break
        else:
            print("Invalid selection.")

"""------------- Unit Testing ------------- """

def unitTests():
    print("Running unit tests...")

    # --- Known small RSA example (toy, not secure) ---
    # p = 61, q = 53  => n = 3233, phi = 3120

    pTest, qTest = 61, 53 # two small primes
    nTest = pTest * qTest # 3233
    phiTest = (pTest - 1) * (qTest - 1) # 3120
    eTest = 17 # exponent
    dTest = modInv(eTest, phiTest) # compute private exponent
    assert dTest == 2753, "modInv produced wrong private exponent for toy RSA"

    # modPow function should match pythons built in pow
    for a in [2, 5, 12345]:
        for e in [0, 1, 2, 3, 10, 57]:
            for n in [7, 97, 1009]:
                assert modPow(a, e, n) == pow(a, e, n), "modPow mismatch vs pow()"

    # modInv checks
    for (a, m) in [(3, 11), (7, 40), (17, 3120)]:
        inv = modInv(a, m)
        assert (a * inv) % m == 1, f"modInv failed for a={a}, m={m}"

    # encode and decode tests
    for msg in ["Hello", "RSA test ✅", "🙂 unicode"]:
        k = maxLength(nTest)
        blocks = encodeMessage(msg, nTest)
        back = decodeMessage(blocks, nTest)
        assert back == msg, "encode/decode round-trip failed"

    # --- encrypt/decrypt tests
    msg = "attack at dawn"
    ct = [modPow(m, eTest, nTest) for m in encodeMessage(msg, nTest)]
    pt = decodeMessage([modPow(c, dTest, nTest) for c in ct], nTest)
    assert pt == msg, "encrypt/decrypt round-trip failed"

    # --- sign/verify tests ---
    mblocks = encodeMessage(msg, nTest)
    sig = [modPow(m, dTest, nTest) for m in mblocks] # sign with d
    recovered = [modPow(s, eTest, nTest) for s in sig] # verify with e
    assert recovered == mblocks, "sign/verify round-trip failed"

    print("All unit tests passed.\n")


if __name__ == "__main__":
    unitTests() # unit tests small known primes
    demo()