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

