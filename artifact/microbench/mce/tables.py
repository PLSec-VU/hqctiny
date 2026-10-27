import re, sys, pathlib
RAW = pathlib.Path(__file__).resolve().parent.parent / "raw"
UNIT_MS = {"ns": 1e-6, "µs": 1e-3, "us": 1e-3, "ms": 1.0, "s": 1e3}
CLOCK_MHZ = 1200

def criterion_medians(path):
    result, name = {}, None
    for line in path.read_text().splitlines():
        match = re.match(r"^(hqc\d_\w+)", line)
        if match:
            name = match.group(1)
        match = re.search(r"time:\s+\[\S+ \S+ (\S+) (\S+) \S+ \S+\]", line)
        if match and name:
            result[name] = float(match.group(1)) * UNIT_MS[match.group(2)]
    return result

def mc(ms):
    return ms * CLOCK_MHZ / 1000

def fmt(ms):
    return f"{ms:.3f} ({mc(ms):.2f})" if ms < 10 else f"{ms:.1f} ({mc(ms):.1f})"

def main():
    base, vec, head = (criterion_medians(RAW / f"phases_{label}.out") for label in ("base", "vec", "head"))
    print("| Bench | clean (before) | vec | vec + NEON ChaCha | speed-up vec | speed-up vec+ChaCha |")
    print("|---|---|---|---|---|---|")
    for level in (1, 3, 5):
        for bench in ("server_handshake", "server_mceliece_decap", "client_mceliece_encap", "full_transaction"):
            key = f"hqc{level}_{bench}"
            b, v, h = base.get(key), vec.get(key), head.get(key)
            if None in (b, v, h):
                continue
            print(f"| {key} | {fmt(b)} | {fmt(v)} | {fmt(h)} | {b/v:.1f}x | {b/h:.1f}x |")
    print()
    print("| Set | Backend | keygen ms (Mcycles) | encaps ms (Mcycles) | decaps ms (Mcycles) |")
    print("|---|---|---|---|---|")
    for line in (RAW / "mceliece_bench.out").read_text().splitlines():
        parts = line.split()
        values = [float(p.split("=")[1]) for p in parts[2:]]
        print(f"| {parts[0]} | {parts[1]} | " + " | ".join(fmt(v) for v in values) + " |")

main()
