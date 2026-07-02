F2x.<x> = PolynomialRing(GF(2), 'x')

# We are assuming a 1280 MTU, so the maximum degree is ~ 1200 * 8 = 9600
# But 8984 is smaller and still has the same RTT as 9600, and it has a
# irreducible polynomial: x^8984 + x^9 + x^8 + x^6 + 1
K.<a> = GF((2, 8984), name='a', modulus=x^8984 + x^9 + x^8 + x^6 + 1)
W = K.degree() // 2
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

def create_quotient_mask(n):
    """Return (m, s) where s = x^n + 1 and m is random of degree n-2.
    They must be kept separate so that split(m) and split(s) each stay
    within ceil(n/W) blocks, and their product in K[z] stays at degree
    2*ceil(n/W)-2 — exactly fitting the client interpolation points."""
    return F2x.random_element(degree=n - 2)

def server_respond(p_y, point_x, q, r, m, s_y):
    q_y = evaluate(split(q), point_x)
    r_y = evaluate(split(r), point_x)
    # Evaluate mask components separately, multiply in K to avoid
    # degree blow-up in K[z] that would exceed interpolation capacity.
    m_y = evaluate(split(m), point_x)
    return p_y * q_y + r_y + m_y * s_y

def test_communicate(n):
    R = F2x.quotient(x^n - 1, 'xbar')

    # Pre-computation phase
    points = [a ^ k for k in range(1, 2 * ceil(n / W))]
    interpolate_M = matrix.vandermonde(points).inverse()

    s_split = split(R.modulus())
    s_ys = [evaluate(s_split, point) for point in points]
    print(s_ys)

    print(f"Testing n={n} with {len(points)} points")

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
        print(f"P: {ceil(F2x(p_y).degree() / 8)}, PQR: {ceil(F2x(pqr_y).degree() / 8)}")
        pqr_ys.append(pqr_y)

    # Client side: interpolate to find pqr
    pqr = list(interpolate_M * vector(K, pqr_ys))
    assert len(pqr) == len(points)
    pqr = R(combine(pqr))
    assert pqr == p * q + r

if __name__ == "__main__":
    print("Using K with degree", K.degree())
    for n in [17669, 35851, 57637]:
        test_communicate(n)
