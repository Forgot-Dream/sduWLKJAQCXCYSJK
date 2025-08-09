# -*- coding: utf-8 -*-
# Reference implementation of DDH-based Private Intersection-Sum with Cardinality (semi-honest)
# Implements Figure 2 (Section 3.1) with:
# - DDH group: prime-order subgroup of Z_p* (safe prime p = 2q+1)
# - AHE: Paillier (Enc/Dec/ASum/ARefresh)

import os, random, hashlib
from math import gcd
from typing import List, Tuple, Dict, Iterable

# --------------------------
# Utilities
# --------------------------
def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'big')

def H_int(data: bytes, mod: int) -> int:
    # Hash-to-[0,mod-1]
    h = hashlib.sha256(data).digest()
    x = bytes_to_int(h) % mod
    if x == 0:
        x = 1
    return x

def rand_between(a: int, b: int) -> int:
    return random.randrange(a, b+1)

# --------------------------
# DDH group (Z_p* safe prime)
# --------------------------
class DDHGroup:
    def __init__(self, p: int, q: int, g: int):
        # p = 2q+1 (safe prime), g of order q
        self.p = p
        self.q = q
        self.g = g

    @staticmethod
    def generate(bits: int = 2048):
        # Very simple safe-prime search; for demo only (not constant-time)
        # In practice use vetted parameters / ECC (e.g., P-256).
        from sympy import nextprime, isprime  # only for quick demo; remove in prod or replace
        # pick a random q then set p=2q+1 until both prime
        while True:
            q = nextprime(random.getrandbits(bits-1))
            p = 2*q + 1
            if isprime(p):
                break
        # find generator of order q: pick h in Z_p*, set g = h^2 mod p, ensure g^q == 1 and g != 1
        while True:
            h = rand_between(2, p-2)
            g = pow(h, 2, p)
            if pow(g, q, p) == 1 and g != 1:
                return DDHGroup(p, q, g)

    def hash_to_group(self, identifier: bytes) -> int:
        # H: U -> G ; map to exponent in [1,q-1], return g^exp mod p
        e = H_int(identifier, self.q)
        return pow(self.g, e, self.p)

    def rand_exp(self) -> int:
        return rand_between(1, self.q-1)

    def exp(self, elt: int, k: int) -> int:
        return pow(elt, k, self.p)

# --------------------------
# Paillier AHE (toy)
# --------------------------
def lcm(a, b): return a // gcd(a,b) * b

class PaillierPK:
    def __init__(self, n, g):
        self.n = n
        self.g = g
        self.n2 = n*n

class PaillierSK:
    def __init__(self, lam, mu, n):
        self.lam = lam
        self.mu = mu
        self.n = n
        self.n2 = n*n

class Paillier:
    @staticmethod
    def keygen(bits=2048):
        # demo keygen (not constant-time). For production use a vetted library.
        from sympy import randprime
        p = randprime(2**(bits//2-1), 2**(bits//2)-1)
        q = randprime(2**(bits//2-1), 2**(bits//2)-1)
        n = p*q
        lam = lcm(p-1, q-1)
        g = n + 1  # typical choice
        # mu = (L(g^λ mod n^2))^{-1} mod n
        n2 = n*n
        def L(u): return (u-1)//n
        x = pow(g, lam, n2)
        mu = pow(L(x), -1, n)
        return PaillierPK(n,g), PaillierSK(lam,mu,n)

    @staticmethod
    def enc(pk: PaillierPK, m: int) -> int:
        # ciphertext in Z_{n^2}*
        r = rand_between(1, pk.n-1)
        while gcd(r, pk.n) != 1:
            r = rand_between(1, pk.n-1)
        return (pow(pk.g, m, pk.n2) * pow(r, pk.n, pk.n2)) % pk.n2

    @staticmethod
    def dec(sk: PaillierSK, c: int) -> int:
        def L(u, n): return (u - 1) // n
        x = pow(c, sk.lam, sk.n2)
        return (L(x, sk.n) * sk.mu) % sk.n

    @staticmethod
    def add(pk: PaillierPK, c1: int, c2: int) -> int:
        return (c1 * c2) % pk.n2

    @staticmethod
    def add_many(pk: PaillierPK, cts: Iterable[int]) -> int:
        prod = 1
        for c in cts:
            prod = (prod * c) % pk.n2
        return prod

    @staticmethod
    def refresh(pk: PaillierPK, c: int) -> int:
        # re-randomize: c * Enc(0)
        return Paillier.add(pk, c, Paillier.enc(pk, 0))

# --------------------------
# Figure 2 protocol roles
# --------------------------
class Party1:
    def __init__(self, group: DDHGroup, V: List[bytes], pk: PaillierPK):
        self.G = group
        self.V = V
        self.k1 = group.rand_exp()
        self.pk2 = pk  # P2's Paillier pk
        self.cache_Z = None  # set of H(v)^{k1k2}
    # Round 1
    def round1_send(self) -> List[int]:
        items = [ self.G.exp(self.G.hash_to_group(v), self.k1) for v in self.V ]
        random.shuffle(items)
        return items
    # Round 3
    def round3_compute_and_send_sum(self, pairs_from_p2: List[Tuple[int,int]], Z_from_p2: List[int]) -> int:
        # pairs_from_p2: list of (H(w)^k2, Enc(t))
        # step1: exponentiate first component by k1 -> get H(w)^{k1k2}
        transformed = [ (self.G.exp(hk2, self.k1), cenc) for (hk2, cenc) in pairs_from_p2 ]
        # Intersection: pick indices j s.t. H(w_j)^{k1k2} in Z
        Zset = set(Z_from_p2)
        inx = [ j for j,(h12,_) in enumerate(transformed) if h12 in Zset ]
        # Homomorphic sum of Enc(t_j) over intersection
        sum_ct = Paillier.add_many(self.pk2, (transformed[j][1] for j in inx)) if inx else Paillier.enc(self.pk2, 0)
        sum_ct = Paillier.refresh(self.pk2, sum_ct)
        return sum_ct

class Party2:
    def __init__(self, group: DDHGroup, W: List[Tuple[bytes,int]]):
        self.G = group
        self.W = W
        self.k2 = group.rand_exp()
        self.pk, self.sk = Paillier.keygen(bits=2048)

    def get_public_key(self) -> PaillierPK:
        return self.pk

    # Round 2 (respond to P1 Round1)
    def round2_process_and_send(self, Hvi_k1_list: List[int]) -> Tuple[List[int], List[Tuple[int,int]]]:
        # step 1 & 2: compute H(vi)^{k1k2} and send back in shuffled order
        Z = [ self.G.exp(h, self.k2) for h in Hvi_k1_list ]
        random.shuffle(Z)
        # step 3 & 4: for each (w,t) compute (H(w)^k2, Enc(t)) and send in shuffled order
        pairs = []
        for (w,t) in self.W:
            hw = self.G.hash_to_group(w)
            hw_k2 = self.G.exp(hw, self.k2)
            c = Paillier.enc(self.pk, t % self.pk.n)  # keep within plaintext ring
            pairs.append((hw_k2, c))
        random.shuffle(pairs)
        return Z, pairs

    # Output: decrypt sum
    def output_decrypt_sum(self, ct_sum: int) -> int:
        return Paillier.dec(self.sk, ct_sum)

# --------------------------
# Demo / Test
# --------------------------
if __name__ == "__main__":
    random.seed(42)

    # 1) build a DDH group (demo). In production, use fixed parameters.
    #    For speed in demo, use smaller bits like 512/768; for security pick >=2048 for this subgroup approach,
    #    or switch to P-256 EC as in the paper.
    group = DDHGroup.generate(bits=512)

    # 2) inputs
    # P1 has identifiers V; P2 has (w, t)
    # Use bytes identifiers (e.g., emails after normalization+salt)
    V = [b"userA", b"userB", b"userC", b"userX"]
    W = [(b"userB", 10), (b"userC", 20), (b"userZ", 7)]

    P2 = Party2(group, W)
    P1 = Party1(group, V, P2.get_public_key())

    # Round 1 (P1 -> P2)
    msg1 = P1.round1_send()

    # Round 2 (P2 -> P1)
    Z, pairs = P2.round2_process_and_send(msg1)

    # Round 3 (P1 -> P2)
    ct_sum = P1.round3_compute_and_send_sum(pairs, Z)

    # Output (P2)
    total = P2.output_decrypt_sum(ct_sum)

    inter = set([w for (w,_) in W]) & set(V)
    expected = sum(t for (w,t) in W if w in set(V))

    print("Intersection identifiers:", inter)
    print("Expected sum:", expected)
    print("Decrypted sum:", total)
