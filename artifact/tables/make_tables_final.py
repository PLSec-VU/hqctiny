#!/usr/bin/env python3
"""Builds the part-1 style tables (stage A and stage C) of the final x86 campaign.

Run in this directory:  python3 make_tables_final.py > tables_final.md
Input: stages_used.json (stage name -> results directory), the raw directories next
to this file, and the old part 1 and part 3 directories (../part1, ../part3) for the
old-next-to-new columns.
"""
import glob
import json
import math
import os
import random
import statistics as st

import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from results_dir import study_dir
ROOT = study_dir("final-x86")
USED = json.load(open(os.path.join(ROOT, "stages_used.json")))
A_RUNS = [USED["A1"], USED["A2"], USED["A3"]]
OLD_RUNS = ["../part1/20261009T125317Z", "../part1/20261009T132419Z", "../part1/20261009T140254Z"]
OLD_A = OLD_RUNS[0]
OLD_WAN_PART1 = {"wan_profiles": "../part1/20261009T135113Z", "wan_loss_low": "../part1/20261009T143035Z",
                 "wan_ge": "../part1/20261009T150000Z", "wan_loss_high": "../part1/20261009T155350Z"}
PART3_WAN = {"wan_profiles": "../part3/20261012T155637Z", "wan_loss_low": "../part3/20261012T160820Z",
             "wan_ge": "../part3/20261012T165326Z", "wan_loss_high": "../part3/20261012T174816Z"}
LEVELS = ["hqc1", "hqc3", "hqc5"]
LEVEL_NAMES = {"hqc1": "HQC-1", "hqc3": "HQC-3", "hqc5": "HQC-5"}
HQC5_LOSSES = ["0", "1", "2", "2.5", "3", "4", "5"]
SMALL_LOSSES = ["0", "2.5", "5"]
PROFILES = ["local", "same_continent", "transatlantic", "transpacific", "satellite"]
DIRECTIONS = ["uplink", "both"]
SYSTEMS = ["stateless", "stateful"]
NIC_FLAG_BYTES = 50e6
BOOTSTRAP_ROUNDS = 10000
BOOTSTRAP_SEED = 42
WAN_REPS = 30
MCTINY_TARGET = 400
FLOOD_THRESHOLD_CYCLES_PER_BYTE = 9920

out = []


def p(s=""):
    out.append(s)


def jl(path):
    return json.load(open(os.path.join(ROOT, path)))


def table(head, rows):
    p("| " + " | ".join(head) + " |")
    p("|" + "---|" * len(head))
    for r in rows:
        p("| " + " | ".join(str(c) for c in r) + " |")
    p()


def f(x, n=2):
    return f"{x:.{n}f}"


def sd(v):
    return st.stdev(v) if len(v) > 1 else 0.0


def change(old, new, digits=1):
    if old in (None, 0) or new is None:
        return ""
    return f"{(new - old) / old * 100:+.{digits}f}%"


def old_new(old, new, digits=2):
    if old is None:
        return f(new, digits)
    if round(old, digits) == round(new, digits):
        return f(new, digits)
    return f"{f(old, digits)} -> {f(new, digits)}"


def clock_of(run, driver="cpu_benchmarks"):
    s = jl(f"{run}/raw/run_state_{driver}.json")
    return st.median(st.median(v["samples_mhz"]) for ph in ("start", "end") for v in s[ph]["frequency_under_load"].values())


# ------------------------------------------------------------------ provenance
def clock_text(state, phase):
    return "/".join(f"{st.median(v['samples_mhz']):.1f}" for v in state[phase]["frequency_under_load"].values())


def nic_irq_text(deltas):
    for label, row in deltas.get("interrupt_deltas", {}).items():
        if label.isdigit() and row["description"].endswith(nic_name_hint(deltas)):
            return ", ".join(f"cpu{c}: {n}" for c, n in row["delta_per_cpu"].items() if n)
    return "none"


def nic_name_hint(deltas):
    return deltas.get("nic", {}).get("interface") or ""


def provenance():
    p("### Provenance: clock of the pinned cores under load (MHz, target 3169), commit, NIC and interrupts per driver\n")
    rows = []
    irq_rows = []
    for name, d in USED.items():
        for path in sorted(glob.glob(f"{ROOT}/{d}/raw/run_state_*.json")):
            s = json.load(open(path))
            driver = os.path.basename(path)[10:-5]
            deltas = s.get("counter_deltas", {})
            nic = deltas.get("nic", {})
            total = nic.get("rx_bytes", 0) + nic.get("tx_bytes", 0)
            dev = deltas.get("device_interrupts_on_pinned_cores", {})
            violations = len(s["start"]["violations"]) + len(s["end"]["violations"])
            extreme = [x for ph in ("start", "end") for v in s[ph]["frequency_under_load"].values() for x in v["samples_mhz"]]
            dev_pct = max(abs(x - 3169.0) for x in extreme) / 3169.0 * 100
            rows.append([name, d, driver, s["git"]["commit"][:7], s["git"]["dirty"], clock_text(s, "start"), clock_text(s, "end"),
                         f"{dev_pct:.3f}", violations, f"{round(deltas.get('seconds', 0))}",
                         f"{nic.get('rx_bytes', 0) / 1e6:.2f}", f"{nic.get('tx_bytes', 0) / 1e6:.2f}", "FLAG" if total > NIC_FLAG_BYTES else "ok",
                         nic_irq_text(deltas)])
            for label, counts in dev.items():
                desc = deltas["interrupt_deltas"][label]["description"]
                irq_rows.append([name, driver, label, desc.split()[-1], ", ".join(f"cpu{c}: {n}" for c, n in counts.items())])
    table(["stage", "dir", "driver", "commit", "dirty", "cpu0/2/4 MHz start", "cpu0/2/4 MHz end", "max sample dev (%)", "violations",
           "driver seconds", "NIC rx MB", "NIC tx MB", ">50 MB", "NIC interrupts (enp2s0) by cpu"], rows)
    p("Device interrupts that landed on a measured core (cpu0, 2, 4, 10) during a driver run. Only the NVMe queues the kernel does not allow to move remain; the NIC and all other movable interrupts went to cpus 12-15.\n")
    table(["stage", "driver", "irq", "device", "interrupts during the run"], irq_rows)


def nic_stage_table():
    path = os.path.join(ROOT, "campaign_final.provenance.jsonl")
    if not os.path.exists(path):
        return
    p("### NIC traffic per stage attempt (enp2s0, counters read between lock acquisition+measurement_on and measurement_off)\n")
    rows = []
    for line in open(path):
        r = json.loads(line)
        total = r["rx_bytes"] + r["tx_bytes"]
        rows.append([r["stage"], r["attempt"], r["dirs"], r["rc"], r["measure_start"], r["measure_end"], f"{r['rx_bytes'] / 1e6:.2f}",
                     f"{r['tx_bytes'] / 1e6:.2f}", r["rx_packets"], r["tx_packets"], f"{r['peak_5s_bytes'] / 1e6:.2f}",
                     "FLAG" if total > NIC_FLAG_BYTES else "ok"])
    table(["stage", "attempt", "dirs", "rc", "measure start", "measure end", "rx MB", "tx MB", "rx packets", "tx packets", "peak 5 s window MB", ">50 MB"], rows)


# ------------------------------------------------------------------ sizes, stack, audit
def sizes_and_stack():
    new, old = jl(f"{USED['A1']}/raw/stack.json"), jl(f"{OLD_RUNS[0]}/raw/stack.json")
    old_sizes = {os.path.basename(x["binary"]): x for x in old["sizes"]}
    p("### Binary size (bytes), new (old in brackets when it differs)\n")
    rows = []
    for x in new["sizes"]:
        name = os.path.basename(x["binary"])
        o = old_sizes.get(name, {})
        rows.append([name] + [old_new(o.get(k), x[k], 0) for k in ("text", "data", "bss", "total")])
    table(["binary", "text", "data", "bss", "total"], rows)
    new_rows = {(x["system"], x["variant"]): x["min_stack_kib"] for x in new["stack"]}
    old_rows = {(x["system"], x["variant"]): x["min_stack_kib"] for x in old["stack"]}
    p("### Minimum server stack (KiB; smallest `ulimit -s` in 4 KiB steps at which one full session succeeds, confirmed by 5 sessions; ASLR off)\n")
    table(["system", "HQC-1", "HQC-3", "HQC-5"],
          [[s] + [old_new(old_rows.get((s, v)), new_rows[(s, v)], 0) if (s, v) in new_rows else "-" for v in LEVELS] for s in SYSTEMS]
          + [[x["system"], old_new(old_rows.get((x["system"], x["variant"])), x["min_stack_kib"], 0), "", ""]
             for x in new["stack"] if x["system"] not in SYSTEMS])


def audit():
    p("### Allocation audit (strace, 50 sessions per level)\n")
    log = open(f"{ROOT}/{USED['A1']}/raw/memory_footprint.log").read().split("--- Dynamic allocation audit: ")[1:]
    rows = []
    for blk in log:
        lv = blk.split(",")[0]
        g = lambda k: [l.split(":")[1].strip() for l in blk.splitlines() if l.startswith(k)][0]
        rows.append([lv, g("completed_sessions"), g("startup_brk_mmap_calls"), g("post_warmup_brk_mmap_calls")])
    table(["level", "completed", "startup brk/mmap calls", "brk/mmap calls after warm-up"], rows)


# ------------------------------------------------------------------ bandwidth
def bandwidth():
    ns, nf = jl(f"{USED['A1']}/raw/bandwidth.json"), jl(f"{USED['A1']}/raw/bandwidth_stateful.json")
    os_, of = jl(f"{OLD_A}/raw/bandwidth.json"), jl(f"{OLD_A}/raw/bandwidth_stateful.json")
    p("### Bandwidth per session (bytes, UDP payload); old value -> new value where it changed\n")
    rows = []
    for new, old, system in ((ns, os_, "stateless"), (nf, of, "stateful")):
        oldmap = {b["variant"]: b for b in old}
        for b in new:
            o = oldmap.get(b["variant"], {})
            packets = sum(x["count"] for x in b["packets"]) * 2 if system == "stateless" else b["packets_total"]
            old_packets = (sum(x["count"] for x in o["packets"]) * 2 if system == "stateless" else o["packets_total"]) if o else None
            rows.append([system, b["variant"], old_new(o.get("total_sent_bytes"), b["total_sent_bytes"], 0),
                         old_new(o.get("total_received_bytes"), b["total_received_bytes"], 0),
                         old_new(o.get("total_bytes"), b["total_bytes"], 0), old_new(old_packets, packets, 0),
                         b.get("round_trips", "-"), b["raw_baseline_bytes"],
                         old_new(o.get("total_bytes", 0) / o["raw_baseline_bytes"] if o else None, b["total_bytes"] / b["raw_baseline_bytes"]),
                         b["max_packet_bytes"]])
    table(["system", "level", "sent (client->server)", "received", "total", "packets", "round trips", "raw pk+ct", "total / raw", "max pkt"], rows)
    p("Per request kind (request B / response B; amplification = response / request; count = requests per session):\n")
    rows = []
    for new, old, system in ((ns, os_, "stateless"), (nf, of, "stateful")):
        oldmap = {(b["variant"], x["kind"]): x for b in old for x in b["packets"]}
        for b in new:
            for x in b["packets"]:
                o = oldmap.get((b["variant"], x["kind"]), {})
                rows.append([system, b["variant"], x["kind"], x["count"], old_new(o.get("request_bytes"), x["request_bytes"], 0),
                             old_new(o.get("response_bytes"), x["response_bytes"], 0),
                             old_new(o.get("amplification_ratio"), x["amplification_ratio"]),
                             old_new(o.get("amplification_ratio_total"), x.get("amplification_ratio_total", float("nan")))])
    table(["system", "level", "kind", "count", "request B", "response B (first/each)", "amplification", "amplification (all of that kind)"], rows)


# ------------------------------------------------------------------ Criterion
def crit(run):
    return {os.path.basename(x)[:-5]: json.load(open(x)) for x in glob.glob(f"{ROOT}/{run}/raw/criterion/*.json")}


def criterion():
    runs = [crit(r) for r in A_RUNS]
    old = [crit(r) for r in OLD_RUNS]
    p("### Criterion medians (us): the three final runs, their median, and the part 1 median of runs\n")
    rows = []
    for n in sorted(runs[0]):
        m = [c[n]["median"]["point_estimate"] / 1000 for c in runs]
        lo = [c[n]["median"]["confidence_interval"]["lower_bound"] / 1000 for c in runs]
        hi = [c[n]["median"]["confidence_interval"]["upper_bound"] / 1000 for c in runs]
        mean = st.mean(m)
        om = [c[n]["median"]["point_estimate"] / 1000 for c in old if n in c]
        old_med = st.median(om) if om else None
        rows.append([n, f(m[0], 3), f(m[1], 3), f(m[2], 3), f(st.median(m), 3), f(sd(m), 3),
                     f(100 * (max(m) - min(m)) / mean, 2) + "%", f"[{min(lo):.3f}, {max(hi):.3f}]",
                     f(old_med, 3) if old_med else "-", change(old_med, st.median(m))])
    table(["bench", "run A1", "run A2", "run A3", "median of runs", "sd", "(max-min)/mean", "union of within-run 95% CIs", "part 1 median of runs", "change"], rows)
    return runs


# ------------------------------------------------------------------ session CPU
def session_cell(run, system, variant):
    for r in jl(f"{run}/raw/session_cpu.json")["results"]:
        if r["system"] == system and r["variant"] == variant:
            return r


def session_cpu():
    mhz = st.median(clock_of(r, "session_cpu") for r in A_RUNS)
    p("### Server CPU per session (schedstat, ms per session); old = part 1 mean of 3 runs\n")
    cells = [(s, v) for s in SYSTEMS for v in LEVELS] + [("mctiny", None)]
    rows = []
    means = {}
    old_means = {}
    for s, v in cells:
        per_run, wins, fails = [], [], 0
        for run in A_RUNS:
            c = session_cell(run, s, v)
            vals = [x["cpu_ms_per_session_schedstat"] for x in c["per_rep"]]
            per_run.append(st.mean(vals))
            wins.append((st.mean(vals), sd(vals), len(vals)))
            fails += sum(x["sessions_attempted"] - x["sessions_completed"] for x in c["per_rep"])
        old_per_run = [st.mean([x["cpu_ms_per_session_schedstat"] for x in session_cell(r, s, v)["per_rep"]]) for r in OLD_RUNS]
        m, s_ = st.mean(per_run), sd(per_run)
        means[(s, v)], old_means[(s, v)] = m, st.mean(old_per_run)
        ci = [2.776 * b / math.sqrt(n) for a, b, n in wins]
        rows.append([s, v or "-", f(per_run[0], 3), f(per_run[1], 3), f(per_run[2], 3), f(m, 3), f(s_, 3), f"{m * mhz / 1e3:.3f} ± {s_ * mhz / 1e3:.3f}",
                     ", ".join(f"{a:.3f}±{b:.3f}(n={n})" for a, b, n in wins), "±" + "/".join(f"{x:.3f}" for x in ci), fails,
                     f(old_means[(s, v)], 3), change(old_means[(s, v)], m)])
    table(["system", "level", "run A1 mean", "run A2 mean", "run A3 mean", "mean of runs", "sd across runs", "Mcycles (mean ± sd)",
           "within-run mean±sd over rounds", "within-run 95% CI half-width", "failed sessions", "part 1 mean", "change"], rows)
    p(f"Cycles use {mhz:.1f} MHz (median measured clock). Within-run: 5 rounds of 1000 sessions (McTiny: 100). Server CPU is divided by the sessions that completed.\n")
    p("McTiny / HqcLethe session CPU ratio (new; part 1 in brackets):\n")
    table(["level", "stateless ms", "McTiny / stateless", "stateful ms", "McTiny / stateful"],
          [[LEVEL_NAMES[v], f(means[("stateless", v)], 3),
            f"{means[('mctiny', None)] / means[('stateless', v)]:.1f}x ({old_means[('mctiny', None)] / old_means[('stateless', v)]:.1f}x)",
            f(means[("stateful", v)], 3),
            f"{means[('mctiny', None)] / means[('stateful', v)]:.1f}x ({old_means[('mctiny', None)] / old_means[('stateful', v)]:.1f}x)"] for v in LEVELS])
    return means, mhz


def rss_table():
    p("### Server RSS (kB) during the session-CPU runs: idle = after start-up and 1 s, before warm-up; after = after the timed sessions; peak = VmHWM after the timed sessions\n")
    p("Median over the 5 rounds of each run, then the three runs (A1/A2/A3). The HqcLethe servers run in the container and the stateful server keeps a table; McTiny runs on the host.\n")
    rows = []
    for s, v in [(s, v) for s in SYSTEMS for v in LEVELS] + [("mctiny", None)]:
        cols = {}
        for key in ("rss_idle_kb", "rss_after_kb", "rss_peak_kb"):
            per_run = [st.median([x[key] for x in session_cell(r, s, v)["per_rep"]]) for r in A_RUNS]
            cols[key] = "/".join(f"{x:.0f}" for x in per_run)
        rows.append([s, v or "-", cols["rss_idle_kb"], cols["rss_after_kb"], cols["rss_peak_kb"]])
    table(["system", "level", "idle (A1/A2/A3)", "after sessions", "peak (VmHWM)"], rows)


# ------------------------------------------------------------------ cycles per byte
def cycles_per_byte(runs, mhz):
    dm, odm = jl(f"{USED['A1']}/raw/derived_metrics.json"), jl(f"{OLD_A}/raw/derived_metrics.json")
    old_runs = [crit(r) for r in OLD_RUNS]
    old_rows = {(r["system"], r["variant"], r["request"]): r for r in odm["rows"]}
    p("### Cycles per byte of attacker traffic (median of the 3 Criterion runs; request bytes from the new bandwidth report); old -> new\n")
    rows = []
    worst = None
    for row in dm["rows"]:
        b = row["bench"]
        med_ns = st.median(c[b]["median"]["point_estimate"] for c in runs if b in c)
        cyc = med_ns * 1e-9 * mhz * 1e6
        cpb, cpw = cyc / row["request_payload_bytes"], cyc / row["request_wire_bytes"]
        o = old_rows.get((row["system"], row["variant"], row["request"]))
        ocpb = ocpw = ocyc = None
        if o:
            ob = o["bench"]
            ons = st.median(c[ob]["median"]["point_estimate"] for c in old_runs if ob in c)
            ocyc = ons * 1e-9 * mhz * 1e6
            ocpb, ocpw = ocyc / o["request_payload_bytes"], ocyc / o["request_wire_bytes"]
        if worst is None or cpb > worst[0]:
            worst = (cpb, row["system"], row["variant"], row["request"])
        rows.append([row["system"], row["variant"], row["request"], f(med_ns / 1000, 1), f"{cyc:.3g}",
                     old_new(o["request_payload_bytes"] if o else None, row["request_payload_bytes"], 0),
                     old_new(ocpb, cpb, 0), old_new(ocpw, cpw, 0), f"{cpb / MCTINY_TARGET:.1f}x", f"{FLOOD_THRESHOLD_CYCLES_PER_BYTE / cpb:.1f}x"])
    table(["system", "level", "request", "median us", "cycles", "request B", "cycles/B (payload)", "cycles/B (with headers)", "vs McTiny ~400", "margin to 9,920"], rows)
    p(f"Worst row: {worst[1]} {worst[2]} {worst[3]}, {worst[0]:.0f} cycles per payload byte. The stateless `auth` row is the McEliece decapsulation bench alone (a lower bound of the invalid request).\n")


# ------------------------------------------------------------------ WAN
def pct(vs, q):
    vs = sorted(vs)
    k = (len(vs) - 1) * q
    lo = int(k)
    hi = min(lo + 1, len(vs) - 1)
    return vs[lo] + (vs[hi] - vs[lo]) * (k - lo)


def boot(vs):
    rng = random.Random(BOOTSTRAP_SEED)
    m = sorted(st.median([vs[rng.randrange(len(vs))] for _ in vs]) for _ in range(BOOTSTRAP_ROUNDS))
    return m[int(.025 * BOOTSTRAP_ROUNDS)], m[int(.975 * BOOTSTRAP_ROUNDS) - 1]


def wan_results(path):
    j = jl(path)
    return j["results"], {f'{c["name"]}/{c["direction"]}': c for c in j["meta"]["cells"]}


def oks(rows, key="session_s"):
    return [x[key] for x in rows if x.get("ok") and x.get(key) is not None]


def wan_old_part1():
    merged = {}
    for k, d in OLD_WAN_PART1.items():
        merged.update(jl(f"{d}/raw/{k}.json")["results"])
    return merged


def wan_part3_mctiny():
    merged = {}
    for k, d in PART3_WAN.items():
        merged.update(jl(f"{d}/raw/{k}.json")["results"])
    return merged


def wan_rows(results, old, keys):
    rows = []
    for key in keys:
        for s in SYSTEMS:
            r = results.get(f"{s}/{key}")
            if not r:
                continue
            ok = oks(r)
            failures = len(r) - len(ok)
            lo, hi = boot(ok) if ok else (None, None)
            retrans = sum(1 for x in r if x.get("retries", 0) > 0)
            old_ok = oks(old.get(f"{s}/{key}", [])) if old else []
            old_med = st.median(old_ok) if old_ok else None
            proc = oks(r, "process_s")
            rows.append([key, s, len(r), f(st.median(ok), 3) if ok else "-", f(pct(ok, .95), 3) if ok else "-", f(max(ok), 3) if ok else "-",
                         f"[{lo:.3f}, {hi:.3f}]" if ok else "-", failures, retrans, f(st.median(proc), 3) if proc else "-",
                         f(old_med, 3) if old_med is not None else "-"])
    return rows


WAN_HEAD = ["cell", "system", "n", "median s", "p95 s", "max s", "95% CI of median", "failures", "reps with retransmit", "process_s median",
            "part 1 median (HQC-5 only)"]


def wan_tables():
    old = wan_old_part1()
    p("## WAN\n")
    p(f"HqcLethe stateless and stateful only; n={WAN_REPS} sessions per cell and system, session timeout 300 s. McTiny was not rerun. `process_s` is the wall time of the whole client process; `session_s` (the median columns) starts at the first request.\n")
    for variant in LEVELS:
        name = f"wan_{variant}"
        key = f"C_{name}"
        if key not in USED:
            continue
        results, cells = wan_results(f"{USED[key]}/raw/{name}.json")
        has_old = variant == "hqc5"
        ref = old if has_old else None
        p(f"### {LEVEL_NAMES[variant]}: RTT profiles ({USED[key]})\n")
        p("Cell parameters: " + "; ".join(f'{n}: rtt {cells[n + "/both"]["rtt_ms"]} ms, jitter {cells[n + "/both"]["jitter_ms"]} ms, loss {cells[n + "/both"]["loss_pct"]}%' for n in PROFILES if n + "/both" in cells) + "\n")
        table(WAN_HEAD, wan_rows(results, ref, [f"{n}/{d}" for n in PROFILES for d in DIRECTIONS]))
        losses = HQC5_LOSSES if variant == "hqc5" else SMALL_LOSSES
        p(f"### {LEVEL_NAMES[variant]}: loss sweep (20 ms RTT, 3 ms jitter, uniform loss per direction, both directions)\n")
        table(WAN_HEAD, wan_rows(results, ref, [f"loss{x}/both" for x in losses]))
        p("Plot table (median / p95 / max, seconds):\n")
        rows = []
        for x in losses:
            r = [x]
            for s in SYSTEMS:
                ok = oks(results[f"{s}/loss{x}/both"])
                nf = WAN_REPS - len(ok)
                r.append(f"{st.median(ok):.3f} / {pct(ok, .95):.3f} / {max(ok):.3f}" + (f" ({nf} fail)" if nf else ""))
            rows.append(r)
        table(["loss % per direction", "stateless", "stateful"], rows)
        if variant == "hqc5":
            ge = sorted({k.split("/", 1)[1] for k in results if k.startswith("stateless/ge")})
            p(f"### {LEVEL_NAMES[variant]}: Gilbert-Elliott burst loss (20 ms RTT, about 5% per direction, both directions)\n")
            table(WAN_HEAD, wan_rows(results, ref, ge))


def mctiny_ratio():
    results, _ = wan_results(f"{USED['C_wan_hqc5']}/raw/wan_hqc5.json")
    mct = wan_part3_mctiny()
    p("### Ratio McTiny network-only time / HqcLethe session time (HQC-5)\n")
    p("McTiny `network_s` (first packet sent to last reply received) comes from part 3 (McTiny code and host setup unchanged; not rerun). HqcLethe medians are the new ones. Ratio = McTiny network_s median / HqcLethe session_s median. Cells from 2.5 % loss are heavy-tailed on the McTiny side (two samples in parts 1 and 3 differ by a large factor); use them as a range only.\n")
    rows = []
    keys = [f"{n}/{d}" for n in PROFILES for d in DIRECTIONS] + [f"loss{x}/both" for x in HQC5_LOSSES] + ["ge/both"]
    for key in keys:
        m = oks(mct.get(f"mctiny/{key}", []), "network_s")
        if not m or f"stateless/{key}" not in results:
            continue
        sl, sf = st.median(oks(results[f"stateless/{key}"])), st.median(oks(results[f"stateful/{key}"]))
        mm = st.median(m)
        rows.append([key, f(mm, 3), f(sl, 3), f"{mm / sl:.1f}", f(sf, 3), f"{mm / sf:.1f}"])
    table(["cell", "McTiny network_s median (part 3)", "stateless median s", "ratio", "stateful median s", "ratio"], rows)


def main():
    p("# Final x86 campaign tables (generated by make_tables_final.py)\n")
    provenance()
    nic_stage_table()
    sizes_and_stack()
    audit()
    bandwidth()
    runs = criterion()
    means, mhz = session_cpu()
    rss_table()
    cycles_per_byte(runs, mhz)
    wan_tables()
    mctiny_ratio()
    print("\n".join(out))


if __name__ == "__main__":
    main()
