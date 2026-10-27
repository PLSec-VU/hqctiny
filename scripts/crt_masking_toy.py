#!/usr/bin/env python3
"""Exhaustive check of the CRT masking claim at toy ring sizes.

Ring F_2[X]/(X^n - 1). For every unreduced value Z0 of degree <= 2n-2 the script
enumerates every quotient mask mu and truncate mask tau and collects the vector of
residues of Z0 + tau + mu (X^n - 1) modulo each f_i. The claim: this multiset depends
only on the first n1n2 bits of Z0 mod X^n - 1, and it is uniform on its support.
"""

import itertools
import sys
from collections import Counter, defaultdict


def degree(p):
    return p.bit_length() - 1


def polymod(a, m):
    dm = degree(m)
    while a.bit_length() > dm:
        a ^= m << (a.bit_length() - 1 - dm)
    return a


def polymul(a, b):
    out = 0
    while b:
        low = b & -b
        out ^= a << (low.bit_length() - 1)
        b ^= low
    return out


def reduce_ring(z, n):
    mask = (1 << n) - 1
    out = 0
    while z:
        out ^= z & mask
        z >>= n
    return out


def residues(u, moduli):
    return tuple(polymod(u, f) for f in moduli)


def distribution(z0, moduli, n, n1n2, mu_bits, tau_bits):
    xn1 = (1 << n) | 1
    counter = Counter()
    for tau in range(1 << tau_bits):
        for mu in range(1 << mu_bits):
            u = z0 ^ (tau << n1n2) ^ polymul(mu, xn1)
            counter[residues(u, moduli)] += 1
    return counter


def check(name, moduli, n, n1n2, mu_bits=None, tau_bits=None, expect_pass=True):
    mu_bits = n - 1 if mu_bits is None else mu_bits
    tau_bits = n - n1n2 if tau_bits is None else tau_bits
    by_view = defaultdict(list)
    for z0 in range(1 << (2 * n - 1)):
        view = reduce_ring(z0, n) & ((1 << n1n2) - 1)
        by_view[view].append(z0)
    functional = True
    uniform = True
    supports = set()
    for view, members in by_view.items():
        reference = None
        for z0 in members:
            dist = distribution(z0, moduli, n, n1n2, mu_bits, tau_bits)
            if reference is None:
                reference = dist
            elif dist != reference:
                functional = False
            if len(set(dist.values())) != 1:
                uniform = False
        supports.add(len(reference))
    degrees = [degree(f) for f in moduli]
    verdict = "as expected" if (functional and uniform) == expect_pass else "UNEXPECTED"
    print(
        f"{name}: n={n} n1n2={n1n2} degrees={degrees} sum={sum(degrees)} 2n-1={2 * n - 1} "
        f"mu_bits={mu_bits} tau_bits={tau_bits} | z0 values={1 << (2 * n - 1)} views={len(by_view)} "
        f"| depends only on view: {functional} | uniform on support: {uniform} "
        f"| support sizes={sorted(supports)} | {verdict}"
    )
    return functional and uniform


def subspace_dimension(moduli, n):
    """Dimension of the span of all residue vectors of polynomials of degree <= 2n-2."""
    basis = []
    for i in range(2 * n - 1):
        vec = 0
        for f in moduli:
            vec = (vec << degree(f)) | polymod(1 << i, f)
        for b in basis:
            vec = min(vec, vec ^ b)
        if vec:
            basis.append(vec)
    return len(basis)


def main():
    n, n1n2 = 7, 4
    exact = [0b10011, 0b11001, 0b100101]
    redundant = [0b100101, 0b101001, 0b111101]
    check("exact CRT, full masks", exact, n, n1n2)
    check("redundant CRT, full masks", redundant, n, n1n2)
    check("no quotient mask", exact, n, n1n2, mu_bits=0, expect_pass=False)
    check("no truncate mask", exact, n, n1n2, tau_bits=0, expect_pass=False)
    check("quotient mask with n bits (private, but U no longer fits in 2n-1 bits)", exact, n, n1n2, mu_bits=n)
    check("quotient mask one bit too short", exact, n, n1n2, mu_bits=n - 2, expect_pass=False)
    for name, moduli in (("exact", exact), ("redundant", redundant)):
        total = sum(degree(f) for f in moduli)
        print(f"{name}: residue space dimension {total}, span of residues of deg<=2n-2 polynomials: "
              f"{subspace_dimension(moduli, n)}")


if __name__ == "__main__":
    sys.exit(0 if main() is None else 1)
