#!/usr/bin/env python3
"""Builds the tables of RESULTS.md from the result directories under $RESULTS_DIR/part1."""
import glob, json, math, os, random, statistics as st, sys

import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from results_dir import study_dir
ROOT = study_dir("part1")
A, R2, R3 = "20261009T125317Z", "20261009T132419Z", "20261009T140254Z"
RUNS = [A, R2, R3]
WAN = {"wan_profiles": "20261009T135113Z", "wan_loss_low": "20261009T143035Z",
       "wan_ge": "20261009T150000Z", "wan_loss_high": "20261009T155350Z"}
LEVELS = ["hqc1", "hqc3", "hqc5"]
out = []
def p(s=""): out.append(s)
def jl(path): return json.load(open(os.path.join(ROOT, path)))
def table(head, rows):
    p("| " + " | ".join(head) + " |"); p("|" + "---|" * len(head))
    for r in rows: p("| " + " | ".join(str(c) for c in r) + " |")
    p()
def f(x, n=2): return f"{x:.{n}f}"
def sd(v): return st.stdev(v) if len(v) > 1 else 0.0

MHZ = jl(f"{A}/raw/run_state_cpu_benchmarks.json")["start"]["frequency_under_load"]
def clock_mhz(run):
    s = jl(f"{run}/raw/run_state_cpu_benchmarks.json")
    return {ph: {c: st.median(v["samples_mhz"]) for c, v in s[ph]["frequency_under_load"].items()} for ph in ("start", "end")}

# ---- provenance
p("### Provenance (frequency of pinned cores under load, MHz; target 3169)")
rows = []
for name, d in [("A", A), ("R2", R2), ("R3", R3)] + [(k, v) for k, v in WAN.items()]:
    for drv in sorted(glob.glob(f"{ROOT}/{d}/raw/run_state_*.json")):
        s = json.load(open(drv)); b = os.path.basename(drv)[10:-5]
        def fr(ph): return "/".join(f"{st.median(v['samples_mhz']):.0f}" for v in s[ph]["frequency_under_load"].values())
        rows.append([name, d, b, s["git"]["commit"][:7], s["git"]["dirty"], fr("start"), fr("end"),
                     len(s["start"]["violations"]) + len(s["end"]["violations"])])
table(["part", "dir", "driver", "commit", "dirty", "cpu0/2/4 start", "cpu0/2/4 end", "violations"], rows)

# ---- sizes and stack
stk = jl(f"{A}/raw/stack.json")
p("### Binary size (bytes) and minimum server stack")
table(["binary", "text", "data", "bss", "total"],
      [[os.path.basename(x["binary"]), x["text"], x["data"], x["bss"], x["total"]] for x in stk["sizes"]])
sysname = {}
st_rows = {}
for x in stk["stack"]: st_rows[(x["system"], x["variant"])] = x["min_stack_kib"]
others = [k for k in stk if k not in ("sizes", "stack")]
mct = [x for x in stk["stack"] if x["system"] not in ("stateless", "stateful")]
table(["system", "HQC-1", "HQC-3", "HQC-5"],
      [[s] + [st_rows.get((s, v), "-") for v in LEVELS] for s in ("stateless", "stateful")] +
      [[x["system"], x.get("min_stack_kib"), "", ""] for x in mct])
p("(KiB; smallest `ulimit -s` in 4 KiB steps at which one full session succeeds, confirmed by 5 sessions; ASLR off.)\n")

# ---- allocation audit
p("### Allocation audit (strace, 50 sessions per level)")
rows = []
log = open(f"{ROOT}/{A}/raw/memory_footprint.log").read().split("--- Dynamic allocation audit: ")[1:]
for blk in log:
    lv = blk.split(",")[0]
    g = lambda k: [l.split(":")[1].strip() for l in blk.splitlines() if l.startswith(k)][0]
    rows.append([lv, g("completed_sessions"), g("startup_brk_mmap_calls"), g("post_warmup_brk_mmap_calls")])
table(["level", "completed", "startup brk/mmap calls", "brk/mmap calls after warm-up"], rows)

# ---- bandwidth
p("### Bandwidth per session (bytes, UDP payload)")
bs = jl(f"{A}/raw/bandwidth.json"); bf = jl(f"{A}/raw/bandwidth_stateful.json")
rows = []
for b in bs:
    rows.append(["stateless", b["variant"], b["total_sent_bytes"], b["total_received_bytes"], b["total_bytes"],
                 sum(x["count"] for x in b["packets"]) * 2, b["round_trips"], b["raw_baseline_bytes"], f(b["overhead_ratio"]), b["max_packet_bytes"]])
for b in bf:
    rows.append(["stateful", b["variant"], b["total_sent_bytes"], b["total_received_bytes"], b["total_bytes"],
                 b["packets_total"], "-", b["raw_baseline_bytes"], f(b["total_bytes"] / b["raw_baseline_bytes"]), b.get("max_packet_bytes", "-")])
table(["system", "level", "sent (client->server)", "received", "total", "packets", "round trips", "raw pk+ct", "total / raw", "max pkt"], rows)
p("Per request kind (request B / response B / amplification = response / request; count = number of requests):\n")
rows = []
for b in bs:
    for x in b["packets"]:
        rows.append(["stateless", b["variant"], x["kind"], x["count"], x["request_bytes"], x["response_bytes"],
                     f(x["amplification_ratio"]), f(x["amplification_ratio_total"])])
for b in bf:
    for x in b["packets"]:
        rows.append(["stateful", b["variant"], x["kind"], x["count"], x["request_bytes"], x["response_bytes"],
                     f(x["amplification_ratio"]), f(x.get("amplification_ratio_total", float("nan")))])
table(["system", "level", "kind", "count", "request B", "response B (first/each)", "amplification", "amplification (all of that kind)"], rows)

# ---- Criterion
def crit(run):
    return {os.path.basename(x)[:-5]: json.load(open(x)) for x in glob.glob(f"{ROOT}/{run}/raw/criterion/*.json")}
C = [crit(r) for r in RUNS]
names = sorted(C[0])
p("### Criterion medians (us), per run, and spread across the 3 independent runs")
rows = []
for n in names:
    m = [c[n]["median"]["point_estimate"] / 1000 for c in C]
    lo = [c[n]["median"]["confidence_interval"]["lower_bound"] / 1000 for c in C]
    hi = [c[n]["median"]["confidence_interval"]["upper_bound"] / 1000 for c in C]
    mean = st.mean(m)
    rows.append([n, f(m[0], 3), f(m[1], 3), f(m[2], 3), f(st.median(m), 3), f(sd(m), 3), f(100 * (max(m) - min(m)) / mean, 2) + "%",
                 f"[{min(lo):.3f}, {max(hi):.3f}]"])
table(["bench", "run A", "run R2", "run R3", "median of runs", "sd", "(max-min)/mean", "union of within-run 95% CIs"], rows)

# ---- session CPU
p("### Server CPU per session (schedstat, ms per session)")
SC = [jl(f"{r}/raw/session_cpu.json") for r in RUNS]
def cell(sc, s, v):
    for r in sc["results"]:
        if r["system"] == s and r["variant"] == v: return r
rows = []; cyc = []
ci_t = {4: 2.776, 5: 2.571}
for s, v in [(s, v) for s in ("stateless", "stateful") for v in LEVELS] + [("mctiny", None)]:
    per_run = []; wins = []; fails = 0; idle = []
    for sc in SC:
        c = cell(sc, s, v)
        vals = [x["cpu_ms_per_session_schedstat"] for x in c["per_rep"]]
        per_run.append(st.mean(vals)); wins.append((st.mean(vals), sd(vals), len(vals)))
        fails += sum(x["sessions_attempted"] - x["sessions_completed"] for x in c["per_rep"])
        idle.append(max(x.get("idle_cpu_ms_same_wall_schedstat", 0) for x in c["per_rep"]))
    m, s_ = st.mean(per_run), sd(per_run)
    within = ", ".join(f"{a:.3f}±{b:.3f}(n={n})" for a, b, n in wins)
    ci = [ci_t.get(n - 1, 2.776) * b / math.sqrt(n) for a, b, n in wins]
    rows.append([s, v or "-", f(per_run[0], 3), f(per_run[1], 3), f(per_run[2], 3), f(m, 3), f(s_, 3),
                 f"{m * MHZ_CY / 1e6:.3f}" if False else "", within, "±" + "/".join(f"{x:.3f}" for x in ci), fails])
    cyc.append((s, v, m, s_))
MHZc = st.median(clock_mhz(A)["start"].values())
for r, (s, v, m, s_) in zip(rows, cyc):
    r[7] = f"{m * MHZc / 1e3:.3f} ± {s_ * MHZc / 1e3:.3f}"
table(["system", "level", "run A mean", "run R2 mean", "run R3 mean", "mean of runs", "sd across runs", "Mcycles (mean ± sd)",
       "within-run mean±sd over rounds", "within-run 95% CI half-width (t, n rounds)", "failed sessions"], rows)
p(f"Cycles use {MHZc:.1f} MHz (median measured clock of cpu0/2/4). Within-run: 5 rounds of 1000 sessions (McTiny: 100).\nServer CPU is divided by the sessions that completed; the two failed McTiny sessions (see anomalies) are in rep 3 of runs A and R3.\n")

# ---- cycles per byte
dm = jl(f"{A}/raw/derived_metrics.json")
p("### Cycles per byte of attacker traffic (median of the 3 Criterion runs; request bytes from the bandwidth report)")
def bench_key(row):
    s, v, r = row["system"], row["variant"], row["request"]
    return row["bench"]
rows = []; worst = None
for row in dm["rows"]:
    b = row["bench"]
    ms = [c[b]["median"]["point_estimate"] for c in C if b in c]
    med_ns = st.median(ms)
    cyc_ = med_ns * 1e-9 * MHZc * 1e6
    cpb = cyc_ / row["request_payload_bytes"]; cpw = cyc_ / row["request_wire_bytes"]
    if worst is None or cpb > worst[0]: worst = (cpb, row["system"], row["variant"], row["request"])
    rows.append([row["system"], row["variant"], row["request"], f(med_ns / 1000, 1), f"{cyc_:.3g}", row["request_payload_bytes"],
                 f"{cpb:.0f}", f"{cpw:.0f}", f"{cpb / 400:.1f}x", f"{9920 / cpb:.1f}x"])
table(["system", "level", "request", "median us", "cycles", "request B", "cycles/B (payload)", "cycles/B (with headers)", "vs McTiny ~400", "margin to 9,920"], rows)
p(f"Worst row: {worst[1]} {worst[2]} {worst[3]}, {worst[0]:.0f} cycles per payload byte. The stateless `auth` row is the McEliece decapsulation bench alone (a lower bound of the invalid request).\n")
p("Benches used by the table (`bench` column of derived_metrics.json): " + ", ".join(sorted({r["bench"] for r in dm["rows"]})) + "\n")

# ---- WAN
def pct(vs, q):
    vs = sorted(vs); k = (len(vs) - 1) * q; f_ = int(k); c = min(f_ + 1, len(vs) - 1)
    return vs[f_] + (vs[c] - vs[f_]) * (k - f_)
def boot(vs, n=10000, seed=42):
    rng = random.Random(seed); m = sorted(st.median([vs[rng.randrange(len(vs))] for _ in vs]) for _ in range(n))
    return m[int(.025 * n)], m[int(.975 * n) - 1]
W = {}; meta = {}
for k, d in WAN.items():
    j = jl(f"{d}/raw/{k}.json"); W.update(j["results"]); meta[k] = j["meta"]
cells = {}
for k in WAN:
    for c in meta[k]["cells"]: cells[f'{c["name"]}/{c["direction"]}'] = c
def wan_rows(keys):
    rows = []
    for key in keys:
        for s in ("stateless", "stateful", "mctiny"):
            r = W.get(f"{s}/{key}")
            if not r: continue
            ok = [x["session_s"] for x in r if x.get("ok")]; nf = len(r) - len(ok)
            if ok:
                lo, hi = boot(ok)
                body = [f(st.median(ok), 3), f(pct(ok, .95), 3), f(max(ok), 3), f"[{lo:.3f}, {hi:.3f}]"]
            else: body = ["-"] * 4
            rt = sum(1 for x in r if x.get("retries", 0) > 0) if s != "mctiny" else "n/a"
            pk = f(st.median([x["packets_sent"] for x in r if "packets_sent" in x]), 0) if s == "mctiny" and any("packets_sent" in x for x in r) else ""
            rows.append([key, s, len(r)] + body + [nf, rt, pk])
    return rows
H = ["cell", "system", "n", "median s", "p95 s", "max s", "95% CI of median", "failures", "reps with retransmit (HqcLethe)", "McTiny median packets sent"]
prof = [f'{n}/{d}' for n in ("local", "same_continent", "transatlantic", "transpacific", "satellite") for d in ("uplink", "both")]
p("### WAN: RTT profiles (HQC-5; n=30 per cell)")
p("Cell parameters: " + "; ".join(f'{n}: rtt {cells[n]["rtt_ms"]} ms, jitter {cells[n]["jitter_ms"]} ms, loss {cells[n]["loss_pct"]}%' for n in prof if n.endswith("/both")) + "\n")
table(H, wan_rows(prof))
p("### WAN: loss sweep (20 ms RTT, 3 ms jitter, uniform loss per direction, both directions)")
loss = [f"loss{x}/both" for x in ("0", "1", "2", "2.5", "3", "4", "5")]
table(H, wan_rows(loss))
p("Plot table (median / p95 / max, seconds):\n")
rows = []
for x in ("0", "1", "2", "2.5", "3", "4", "5"):
    r = [x]
    for s in ("stateless", "stateful", "mctiny"):
        ok = [y["session_s"] for y in W[f"{s}/loss{x}/both"] if y.get("ok")]
        nf = 30 - len(ok)
        r.append(f"{st.median(ok):.3f} / {pct(ok, .95):.3f} / {max(ok):.3f}" + (f" ({nf} fail)" if nf else ""))
    rows.append(r)
table(["loss % per direction", "stateless", "stateful", "mctiny"], rows)
p("### WAN: Gilbert-Elliott burst loss (20 ms RTT, about 5% per direction, both directions)")
ge = [k.split("/", 1)[1] for k in W if k.startswith("stateless/ge")]
table(H, wan_rows(sorted(ge)))
print("\n".join(out))
