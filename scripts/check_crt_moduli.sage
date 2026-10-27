import itertools
import re
import sys

RING_DEGREE = {"hqc1": 17669, "hqc3": 35851, "hqc5": 57637}
MODULUS_PATTERN = re.compile(r"Modulus::new\((\d+),\s*(\d+)\)")
LEVEL_PATTERN = re.compile(r"pub const (HQC\d)_MODULI[^=]*=\s*\[(.*?)\];", re.S)
RECONSTRUCTION_TRIALS = 3

R.<x> = GF(2)[]


def moduli_by_level(params_text):
    return {name.lower(): [x^int(d) + x^int(a) + 1 for d, a in MODULUS_PATTERN.findall(body)]
            for name, body in LEVEL_PATTERN.findall(params_text)}


def reconstructs_random_products(moduli, n):
    for _ in range(RECONSTRUCTION_TRIALS):
        w = R.random_element(degree=2 * n - 2)
        if CRT_list([w % f for f in moduli], moduli) != w:
            return False
    return True


def check_level(level, moduli):
    n = RING_DEGREE[level]
    nonconstant = all(f.degree() > 0 for f in moduli)
    coprime = all(gcd(f, g) == 1 for f, g in itertools.combinations(moduli, 2))
    total_degree = sum(f.degree() for f in moduli)
    cover = total_degree >= 2 * n - 1
    reconstructs = reconstructs_random_products(moduli, n)
    print(f"{level}: k={len(moduli)} sum_deg={total_degree} need>={2 * n - 1} "
          f"nonconstant={nonconstant} pairwise_coprime={coprime} cover={cover} "
          f"crt_reconstructs={reconstructs}")
    return nonconstant and coprime and cover and reconstructs


params_path = sys.argv[1] if len(sys.argv) > 1 else "src/crt/params.rs"
levels = moduli_by_level(open(params_path).read())
if sorted(levels) != sorted(RING_DEGREE):
    sys.exit(f"expected levels {sorted(RING_DEGREE)}, found {sorted(levels)}")
all_levels_pass = all([check_level(level, levels[level]) for level in RING_DEGREE])
sys.exit(int(not all_levels_pass))
