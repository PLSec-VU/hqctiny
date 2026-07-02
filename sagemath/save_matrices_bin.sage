import struct

F2x.<x> = PolynomialRing(GF(2), 'x')
K.<a> = GF((2, 9009), name='a', modulus=x^9009 + x^29 + 1)
W = K.degree() // 2

def save_interpolate_matrix_bin(n, filename):
    num_points = 2 * ceil(n / W) - 1
    points = [a ^ k for k in range(1, num_points + 1)]
    M = matrix.vandermonde(points).inverse()
    m = len(points)
    
    print(f"n={n}: m={m}, matrix {m}x{m}")
    
    with open(filename, 'wb') as f:
        # Write m as little-endian u32
        f.write(struct.pack('<I', m))
        
        # Write each matrix element as 141 * 8 = 1128 bytes in little-endian
        for i in range(m):
            for j in range(m):
                val = M[i,j]
                val_int = int(val.to_integer())
                val_bytes = val_int.to_bytes(141 * 8, byteorder='little')
                f.write(val_bytes)
                
    print(f"  Saved {filename}")

for n in [17669, 35851, 57637]:
    save_interpolate_matrix_bin(n, f'src/math/interpolate_matrix_{n}.bin')
