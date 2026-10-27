import itertools
import re
import sys
from pathlib import Path

RING_DEGREE = {"hqc1": 17669, "hqc3": 35851, "hqc5": 57637}
MODULUS_PATTERN = re.compile(r"Modulus::new\((\d+),\s*(\d+)\)")


def trinomial(degree, middle):
    return (1 << degree) | (1 << middle) | 1


def gf2_gcd(a, b):
    while b:
        while a and a.bit_length() >= b.bit_length():
            a ^= b << (a.bit_length() - b.bit_length())
        a, b = b, a
    return a


def moduli_by_level(params_text):
    blocks = re.split(r"(?=pub const HQC\d_MODULI|const HQC\d)", params_text)
    levels = {}
    for level, block in zip(RING_DEGREE, [b for b in blocks if MODULUS_PATTERN.search(b)]):
        levels[level] = [tuple(map(int, m)) for m in MODULUS_PATTERN.findall(block)]
    return levels


def check_level(level, moduli):
    polys = [trinomial(d, a) for d, a in moduli]
    nonconstant = all(d > 0 for d, _ in moduli)
    coprime = all(gf2_gcd(p, q) == 1 for p, q in itertools.combinations(polys, 2))
    total_degree = sum(d for d, _ in moduli)
    cover = total_degree >= 2 * RING_DEGREE[level] - 1
    print(f"{level}: k={len(moduli)} sum_deg={total_degree} need>={2 * RING_DEGREE[level] - 1} "
          f"nonconstant={nonconstant} pairwise_coprime={coprime} cover={cover}")
    return nonconstant and coprime and cover


def main(params_path):
    levels = moduli_by_level(Path(params_path).read_text())
    return 0 if all(check_level(level, moduli) for level, moduli in levels.items()) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "src/crt/params.rs"))
