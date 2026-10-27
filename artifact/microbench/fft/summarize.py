import re, sys, glob, os
d = sys.argv[1]
labels = ["ref", "vm", "fft", "toom"]
names = {"ref": "normal HQC C", "vm": "our NEON vect_mul (eb6c864)", "fft": "addFFT KS+CRT", "toom": "Toom-Karatsuba port"}
UNIT = {"ns": 1e-3, "µs": 1.0, "us": 1.0, "ms": 1e3, "s": 1e6}
pat = re.compile(r"^(hqc\d_\w+)\s+time:\s+\[\S+ \S+ (\S+) (\S+) \S+ \S+\]")
data = {}
for f in glob.glob(os.path.join(d, "*.out")):
    base = os.path.basename(f)
    m = re.match(r"(bench|kem)_(\w+?)_hqc\d\.out", base)
    if not m: continue
    label = m.group(2)
    text = re.sub(r"\n\s+time:", " time:", open(f).read())
    for line in text.splitlines():
        r = re.match(r"^(hqc\d_\w+)\s+time:\s+\[([\d.]+) (\S+) ([\d.]+) (\S+) ([\d.]+) (\S+)\]", line)
        if r:
            data.setdefault(r.group(1), {})[label] = float(r.group(4)) * UNIT[r.group(5)]
order = ["vect_mul", "keygen", "enc", "dec", "server_uchunk_request", "server_vpoint_request", "client_keygen", "client_initialize", "client_decap", "full_transaction"]
print("| benchmark | " + " | ".join(f"{names[l]} ms (Mcyc)" for l in labels) + " | speed-up fft | speed-up toom |")
print("|---|" + "---|" * (len(labels) + 2))
for lvl in (1, 3, 5):
    for op in order:
        key = f"hqc{lvl}_{op}"
        if key not in data: continue
        row = data[key]
        cells = []
        for l in labels:
            if l in row:
                us = row[l]
                cells.append(f"{us/1000:.3f} ({us*1.2/1000:.2f})" if us < 1e5 else f"{us/1000:.1f} ({us*1.2/1000:.1f})")
            else:
                cells.append("-")
        sp = lambda l: f"{row['ref']/row[l]:.1f}x" if l in row and "ref" in row else "-"
        print(f"| {key} | " + " | ".join(cells) + f" | {sp('fft')} | {sp('toom')} |")
