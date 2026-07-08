"""
Generate Newton divided-difference weight matrices for interpolation over GF(2^9009).

For each HQC parameter n, the evaluation points are x_k = a^k for k = 1..M
where a is the generator of GF(2^9009) and M = 2*ceil(n/W) - 1, W = ceil(9009/2).

The precomputed weights are:
  weight[s][i] = 1 / (x[i] - x[i-s])   for s = 1..M-1, i = s..M-1

stored flat in order (s=1,i=1..M-1), (s=2,i=2..M-1), ..., (s=M-1,i=M-1).

Binary format: 4 bytes (M as little-endian u32), then M*(M-1)/2 blocks of
141*8 = 1128 bytes each (little-endian u64 limbs of the GF element).
"""
import struct
import math

F2x.<x> = PolynomialRing(GF(2), 'x')
K.<a> = GF((2, 9009), name='a', modulus=x^9009 + x^29 + 1)
W = math.ceil(K.degree() / 2)  # = 4505

def save_newton_weights_bin(n, filename):
    M = 2 * math.ceil(n / W) - 1
    # Evaluation points: x[k] = a^(k+1) for k = 0..M-1
    points = [a ^ (k + 1) for k in range(M)]

    # Collect weights in flat order: for s=1..M-1, for i=s..M-1
    weights = []
    for s in range(1, M):
        for i in range(s, M):
            xi = points[i]
            xis = points[i - s]
            w = K(1) / (xi - xis)
            weights.append(w)

    num_weights = M * (M - 1) // 2
    assert len(weights) == num_weights

    print(f"n={n}: M={M}, weights={num_weights}")

    with open(filename, 'wb') as f:
        f.write(struct.pack('<I', M))
        for w in weights:
            val_int = int(w.to_integer())
            val_bytes = val_int.to_bytes(141 * 8, byteorder='little')
            f.write(val_bytes)

    expected = 4 + num_weights * 141 * 8
    print(f"  Saved {filename} ({expected} bytes)")

for n in [17669, 35851, 57637]:
    save_newton_weights_bin(n, f'src/math/newton_weights_{n}.bin')
