F2x.<x> = PolynomialRing(GF(2), 'x')
K.<a> = GF((2, 8984), name='a', modulus=x^8984 + x^9 + x^8 + x^6 + 1)
W = K.degree() // 2

def save_interpolate_matrix(n, filename):
    num_points = 2 * ceil(n / W) - 1
    points = [a ^ k for k in range(1, num_points + 1)]
    M = matrix.vandermonde(points).inverse()
    m = len(points)
    
    print(f"n={n}: m={m}, matrix {m}x{m}")
    
    # Export as hex strings (one per matrix entry)
    with open(filename, 'w') as f:
        f.write(f"{m}\n")
        for i in range(m):
            for j in range(m):
                val = M[i,j]
                # Convert K element to integer, then to hex (big-endian, 8984 bits)
                val_int = val.to_integer()
                hex_str = format(val_int, 'x').zfill(2246)  # 8984 bits = 2246 hex chars
                f.write(hex_str + '\n')
    
    print(f"  Saved {m*m} entries to {filename}")
    print(f"  Example M[0,0] = ...{hex_str[:40]}...{hex_str[-20:]}")

for n in [17669, 35851, 57637]:
    save_interpolate_matrix(n, f'interpolate_matrix_{n}.txt')
