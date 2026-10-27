import json, sys, glob
root = sys.argv[1]
labels = sys.argv[2:]
CLOCK_MHZ = 1200
rows = {}
for label in labels:
    for est in glob.glob(f"{root}/{label}/*/new/estimates.json"):
        name = est.split("/")[-3]
        mean = json.load(open(est))["mean"]
        rows.setdefault(name, {})[label] = (mean["point_estimate"] / 1000.0, mean["confidence_interval"]["lower_bound"] / 1000.0, mean["confidence_interval"]["upper_bound"] / 1000.0)
def key(n):
    return (n.split("_")[0], n)
print("| benchmark | " + " | ".join(f"{l} us | {l} Mcyc" for l in labels) + " | speedup last vs first |")
print("|---|" + "---|" * (2 * len(labels) + 1))
for n in sorted(rows, key=key):
    cells = []
    for l in labels:
        if l in rows[n]:
            us = rows[n][l][0]
            cells.append(f"{us:,.1f}")
            cells.append(f"{us * CLOCK_MHZ / 1e6:,.2f}")
        else:
            cells += ["-", "-"]
    first, last = rows[n].get(labels[0]), rows[n].get(labels[-1])
    sp = f"{first[0] / last[0]:.2f}x" if first and last else "-"
    print(f"| {n} | " + " | ".join(cells) + f" | {sp} |")
