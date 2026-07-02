load("sagemath/hqctiny.sage")
import json
import binascii

def to_hex(elem):
    # K elements can be converted to integers using to_integer()
    # We want a fixed length hex string (9009 bits = 1127 bytes = 2254 hex chars)
    if hasattr(elem, 'parent') and elem.parent() == K:
        val = int(elem.to_integer())
        h = hex(val)[2:]
        if h.endswith('L'): h = h[:-1]
        return h.zfill(2254)

    # For F2x elements or others
    try:
        val = sum(int(c) << i for i, c in enumerate(elem.list()))
    except AttributeError:
        val = int(elem)

    h = hex(val)[2:]
    if h.endswith('L'): h = h[:-1]
    return h

def generate_vectors():
    # 1. Field info
    info = {
        "degree": int(K.degree()),
        "modulus": str(K.modulus())
    }

    # 2. Basic Arithmetic
    arithmetic = []
    for _ in range(10):
        a = K.random_element()
        b = K.random_element()
        arithmetic.append({
            "a": to_hex(a),
            "b": to_hex(b),
            "sum": to_hex(a + b),
            "prod": to_hex(a * b)
        })

    # 3. Evaluate Test
    evaluate_tests = []
    for n in [17669]: # Just one n for now
        p = F2x.random_element(degree=n)
        p_split = split(p)
        point = K.random_element()
        res = evaluate(p_split, point)

        evaluate_tests.append({
            "poly": [to_hex(c) for c in p_split],
            "point": to_hex(point),
            "result": to_hex(res)
        })

    # 4. Split/Combine Test
    split_combine = []
    for n in [17669]:
        p = F2x.random_element(degree=n)
        p_split = split(p)
        p_back = combine(p_split)
        assert p == p_back

        split_combine.append({
            "poly_f2x": to_hex(p),
            "split": [to_hex(c) for c in p_split]
        })

    vectors = {
        "info": info,
        "arithmetic": arithmetic,
        "evaluate": evaluate_tests,
        "split_combine": split_combine
    }

    with open("src/math/test_vectors.json", "w") as f:
        json.dump(vectors, f, indent=2)
    print("Generated src/math/test_vectors.json")

if __name__ == "__main__":
    set_random_seed(0)
    generate_vectors()
