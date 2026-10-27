import glob, re, sys
rows = []
for fn in sorted(glob.glob(sys.argv[1] + "/*.env.txt")):
    lines = open(fn).read().strip().split("\n")
    if len(lines) < 5:
        continue
    def snap(a, b):
        m = dict(kv.split("=", 1) for kv in lines[a].split())
        t = lines[b].split("=", 1)[1].split()
        ts = {int(t[i]): int(t[i + 1]) for i in range(0, len(t), 2)}
        return m, ts
    m0, t0 = snap(0, 1)
    m1, t1 = snap(2, 3)
    off = sum(t1[f] - t0[f] for f in t0 if f != 1200000)
    on = t1[1200000] - t0[1200000]
    rows.append((fn.split("/")[-1][:-8], m0["temp_mC"], m1["temp_mC"], m1["cur_khz"], m1["undervolt_alarm"], on * 10 / 1000.0, off * 10 / 1000.0, lines[-1]))
print("| run | start temp mC | end temp mC | end freq kHz | undervolt | s at 1.2 GHz | s at other freq | exit |")
print("|---|---|---|---|---|---|---|---|")
for r in rows:
    print("| " + " | ".join(str(x) for x in r) + " |")
