from math import ceil

F2x.<x> = PolynomialRing(GF(2), 'x')

# Parameters: d = 9009, modulus = x^9009 + x^29 + 1
K.<a> = GF((2, 9009), name='a', modulus=x^9009 + x^29 + 1)
# Bump W to 4505.
# This satisfies:
# 1. 2*W - 1 = 9009 <= 9009 = d (W2_lt_d constraint)
# 2. d = 9009 <= 9010 = 2*W (d_le_W2 constraint)
W = 4505
Kx.<z> = PolynomialRing(K, 'z')

def split(poly) -> 'list[K]':
    coeffs = poly.list()
    blocks = ceil(len(coeffs) / W)
    result = []
    for k in range(blocks):
        val = 0
        for j in range(W):
            idx = k * W + j
            if idx < len(coeffs) and coeffs[idx]:
                val |= (1 << j)
        result.append(K.from_integer(val))
    return result

def combine(blocks: 'list[K]') -> 'F2x':
    result = F2x(0)
    x = F2x.gen()
    for k, elem in enumerate(blocks):
        if elem == 0:
            continue
        result += elem.polynomial().change_variable_name('x') * (x ^ (k * W))
    return result

def evaluate(k_poly: 'list[K]', val: 'K') -> 'K':
    result = K(0)
    for k, coeff in enumerate(k_poly):
        result += coeff * (val ^ k)
    return result

def ker_chain(deltas: 'list[F2x]') -> 'list[K]':
    # ker_chain(ds) = sum of shifted ker_elem terms
    # Each delta in deltas has degree <= W - 2 (size < W - 1).
    # ker_elem(d) has constant term K(d * x^W) and linear term K(d).
    coeffs = [K(0)] * (len(deltas) + 1)
    for idx, d in enumerate(deltas):
        coeffs[idx] += K(d * (x ^ W))
        coeffs[idx + 1] += K(d)
    return coeffs

def create_quotient_mask(n):
    """Return (m, s) where s = x^n + 1 and m is random of degree n-2.
    They must be kept separate so that split(m) and split(s) each stay
    within ceil(n/W) blocks, and their product in K[z] stays at degree
    2*ceil(n/W)-2 — exactly fitting the client interpolation points."""
    return F2x.random_element(degree=n - 2)

def server_respond(p_y, point_x, q, r, m, s_y):
    q_y = evaluate(split(q), point_x)
    r_y = evaluate(split(r), point_x)
    m_y = evaluate(split(m), point_x)
    return p_y * q_y + r_y + m_y * s_y

def test_communicate(n):
    R = F2x.quotient(x^n - 1, 'xbar')
    nblocks = ceil(n / W)

    # Pre-computation phase
    points = [a ^ k for k in range(1, 2 * nblocks)]
    interpolate_M = matrix.vandermonde(points).inverse()

    s_split = split(R.modulus())
    s_ys = [evaluate(s_split, point) for point in points]

    print(f"Testing basic split/combine communication for n={n} with {len(points)} points")

    # Generate random polynomials p, q, r of degree n
    p = R.random_element()
    q = R.random_element()
    r = R.random_element()
    mask_m, mask_s = create_quotient_mask(n), R.modulus()

    # Client side: split p into blocks
    p_split = split(p.lift())
    print(f"Split into {len(p_split)} blocks")
    pqr_ys = []
    for point_x, s_y in zip(points, s_ys):
        p_y = evaluate(p_split, point_x)
        pqr_y = server_respond(p_y, point_x, q.lift(), r.lift(), mask_m, s_y)
        pqr_ys.append(pqr_y)

    # Client side: interpolate to find pqr
    pqr = list(interpolate_M * vector(K, pqr_ys))
    assert len(pqr) == len(points)
    pqr = R(combine(pqr))
    assert pqr == p * q + r
    print("Basic communication assertion passed.")

def test_kernel_blinding(n):
    R = F2x.quotient(x^n - 1, 'xbar')
    nblocks = ceil(n / W)

    print(f"\nTesting kernel blinding for n={n} (nblocks={nblocks}, W={W})")

    # 1. Generate keys and parameters
    h_poly = R.random_element().lift()
    x_poly = R.random_element().lift() # secret key
    
    # Message to encrypt
    msg_poly = F2x.random_element(degree=n-1)
    
    # Encryption randomness
    r1 = F2x.random_element(degree=n-1)
    r2 = F2x.random_element(degree=n-1)
    e = F2x.random_element(degree=n-1)
    
    # 2. Client-side encryption with blinding
    r1_split = split(r1)
    r2_split = split(r2)
    h_split = split(h_poly)
    msg_split = split(msg_poly)
    e_split = split(e)
    gen_split = split(x^n - 1)
    
    # Blinding polynomials k_u, k_v
    k_u = F2x.random_element(degree=n-1)
    k_v = F2x.random_element(degree=n-1)
    k_u_split = split(k_u)
    k_v_split = split(k_v)
    
    # Blinding kernel chains
    # Since W = 4505, to ensure degree(d * x^W) < 9009 (to avoid reduction),
    # we restrict degree(d) <= W - 2 = 4503.
    deltas_u = [F2x.random_element(degree=W - 2) for _ in range(2 * nblocks)]
    deltas_v = [F2x.random_element(degree=W - 2) for _ in range(2 * nblocks)]
    ku_ker = ker_chain(deltas_u)
    kv_ker = ker_chain(deltas_v)
    
    # Degree of U_poly and V_poly in K[z] is 2 * nblocks
    # So we need 2 * nblocks + 1 points to interpolate
    points = [a ^ k for k in range(1, 2 * nblocks + 2)]
    interpolate_M = matrix.vandermonde(points).inverse()
    
    # Evaluate at points
    u_ys = []
    v_ys = []
    for pt in points:
        # Encryption of u = r1 + h * r2 + k_u * gen + ku_ker
        r1_y = evaluate(r1_split, pt)
        h_y = evaluate(h_split, pt)
        r2_y = evaluate(r2_split, pt)
        ku_y = evaluate(k_u_split, pt)
        gen_y = evaluate(gen_split, pt)
        ker_u_y = evaluate(ku_ker, pt)
        u_y = r1_y + h_y * r2_y + ku_y * gen_y + ker_u_y
        u_ys.append(u_y)
        
        # Encryption of v = msg + h_poly * r2 + e + k_v * gen + kv_ker
        msg_y = evaluate(msg_split, pt)
        e_y = evaluate(e_split, pt)
        kv_y = evaluate(k_v_split, pt)
        ker_v_y = evaluate(kv_ker, pt)
        v_y = msg_y + h_y * r2_y + e_y + kv_y * gen_y + ker_v_y
        v_ys.append(v_y)
        
    # 3. Decryptor interpolates points to get K[z] polynomials
    u_interp = list(interpolate_M * vector(K, u_ys))
    v_interp = list(interpolate_M * vector(K, v_ys))
    
    # 4. Decryptor combines them back to F2[x]
    u_combined = combine(u_interp)
    v_combined = combine(v_interp)
    
    # 5. Decryptor performs standard HQC decryption modulo x^n - 1
    u_mod = R(u_combined)
    v_mod = R(v_combined)
    
    decrypted = v_mod - u_mod * R(x_poly)
    
    # Expected plaintext (without blinding/noise):
    expected_dec = R(msg_poly) + R(h_poly) * R(r2) + R(e) - (R(r1) + R(h_poly) * R(r2)) * R(x_poly)
    
    assert decrypted == expected_dec
    print("Kernel blinding correctness assertion passed successfully!")

if __name__ == "__main__":
    print("Using K with degree", K.degree())
    print("Window size W =", W)
    for n in [17669, 35851, 57637]:
        test_communicate(n)
        test_kernel_blinding(n)
