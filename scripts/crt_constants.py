#!/usr/bin/env python3
"""Chooses the CRT moduli and writes the Garner constants for each HQC level."""

import struct
import sys
from pathlib import Path

LEVELS = {
    "hqc1": {"n": 17669, "k": 5},
    "hqc3": {"n": 35851, "k": 9},
    "hqc5": {"n": 57637, "k": 14},
}
MIDDLE_TERM_LIMIT = 4096
OUT_DIR = Path(__file__).resolve().parent.parent / "src" / "crt"


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


def polygcd(a, b):
    while b:
        a, b = b, polymod(a, b)
    return a


def polyinv(a, m):
    r0, r1 = m, polymod(a, m)
    t0, t1 = 0, 1
    while r1:
        shift = degree(r0) - degree(r1)
        if shift < 0:
            r0, r1, t0, t1 = r1, r0, t1, t0
            shift = -shift
        r0 ^= r1 << shift
        t0 ^= t1 << shift
    assert r0 == 1
    return polymod(t0, m)


def trinomial(d, a):
    return (1 << d) | (1 << a) | 1


def split_degrees(total, k):
    base, extra = divmod(total, k)
    return [base + 1] * extra + [base] * (k - extra)


def choose_moduli(n, k):
    degrees = split_degrees(2 * n - 1, k)
    moduli = []
    for d in degrees:
        for a in range(1, MIDDLE_TERM_LIMIT):
            f = trinomial(d, a)
            if all(polygcd(f, g) == 1 for g in moduli):
                moduli.append(f)
                break
        else:
            raise SystemExit(f"no coprime trinomial of degree {d}")
    return moduli


def garner_constants(moduli):
    constants = []
    product = 1
    for i, f in enumerate(moduli):
        if i > 0:
            constants.append(polyinv(polymod(product, f), f))
        product = polymul(product, f)
    return constants


def to_words(p, words):
    return b"".join(struct.pack("<Q", (p >> (64 * w)) & (2**64 - 1)) for w in range(words))


def main():
    for name, params in LEVELS.items():
        moduli = choose_moduli(params["n"], params["k"])
        assert sum(degree(f) for f in moduli) == 2 * params["n"] - 1
        constants = garner_constants(moduli)
        blob = b"".join(to_words(c, (degree(f) + 63) // 64) for c, f in zip(constants, moduli[1:]))
        (OUT_DIR / f"garner_{name}.bin").write_bytes(blob)
        pairs = [(degree(f), degree(f ^ (1 << degree(f)) ^ 1)) for f in moduli]
        print(name, pairs, len(blob), "bytes")


if __name__ == "__main__":
    sys.setrecursionlimit(10000)
    OUT_DIR.mkdir(exist_ok=True)
    main()
