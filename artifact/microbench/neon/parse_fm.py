import re, sys
from collections import defaultdict
res = {}
name = None
for l in open(sys.argv[1]):
    if re.match(r'^(poly_mul|tuning|kernel|comb4)/', l):
        name = l.split()[0]
    t = re.search(r'time:\s+\[\S+ \S+ (\S+) (\S+) ', l)
    if t and name:
        res[name] = float(t.group(1)) * {'ns': 1e-3, 'µs': 1, 'ms': 1e3}[t.group(2)]
tab = defaultdict(dict)
for k, v in res.items():
    g, var, n = k.split('/')[:3]
    tab[(g, var)][int(n)] = v
for (g, var), d in tab.items():
    print(g.ljust(8), var.ljust(26), ' '.join(f"{n}:{d[n]:.2f}" for n in sorted(d)))
