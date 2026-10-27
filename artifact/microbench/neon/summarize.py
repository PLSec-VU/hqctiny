import json, sys, glob, os
root = sys.argv[1]
labels = sys.argv[2:]
names = []
data = {}
for label in labels:
    for est in glob.glob(f"{root}/{label}/*/new/estimates.json"):
        name = est.split("/")[-3]
        data.setdefault(name, {})[label] = json.load(open(est))["mean"]["point_estimate"] / 1000.0
order = sorted(data, key=lambda n: (n[:4], n))
print("benchmark".ljust(34) + "".join(l.rjust(14) for l in labels))
for n in order:
    print(n.ljust(34) + "".join((f"{data[n][l]:14.1f}" if l in data[n] else " " * 13 + "-") for l in labels))
