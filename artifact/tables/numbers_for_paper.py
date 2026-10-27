#!/usr/bin/env python3
"""Prints the headline numbers of the final x86 campaign as Markdown.

Usage: RESULTS_DIR=<results-sp27> python3 numbers_for_paper.py > numbers_for_paper.md
Reads stages_used.json and the stage directories in $RESULTS_DIR/final-x86.
"""
import importlib.util
import json
import os
import statistics as st
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
from results_dir import study_dir
ROOT = study_dir("final-x86")
LEVELS = ["hqc1", "hqc3", "hqc5"]
LEVEL_NAMES = {"hqc1": "HQC-1", "hqc3": "HQC-3", "hqc5": "HQC-5"}
STATELESS_KINDS = ["handshake", "auth", "uchunk", "vpoint"]
PAIRS = [("handshake", "hello"), ("auth", "auth"), ("uchunk", "partial"), ("vpoint", "fullkey")]
WAN_CELLS = ["local/both", "same_continent/both", "transatlantic/both", "transpacific/both", "satellite/both",
             "loss0/both", "loss1/both", "loss2/both", "loss2.5/both", "loss3/both", "loss4/both", "loss5/both", "ge/both"]
WAN_SMALL_CELLS = ["local/both", "same_continent/both", "transatlantic/both", "transpacific/both", "satellite/both",
                   "loss0/both", "loss2.5/both", "loss5/both"]
SYSTEMS = ["stateless", "stateful"]


def cap_for(system, kind):
    return 1024 if system == "stateful" and kind in ("partial", "churn2") else None


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(SCRIPT_DIR, filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


final = load_module("final_tables", "make_tables_final.py")
dos = load_module("dos_tables", "make_tables_dos.py")
out = []


def p(s=""):
    out.append(s)


def table(head, rows):
    p("| " + " | ".join(head) + " |")
    p("|" + "---|" * len(head))
    for r in rows:
        p("| " + " | ".join(str(c) for c in r) + " |")
    p()


def session_cpu_section():
    mhz = st.median(final.clock_of(r, "session_cpu") for r in final.A_RUNS)
    means = {}
    sds = {}
    for s, v in [(s, v) for s in SYSTEMS for v in LEVELS] + [("mctiny", None)]:
        per_run = [st.mean([x["cpu_ms_per_session_schedstat"] for x in final.session_cell(r, s, v)["per_rep"]]) for r in final.A_RUNS]
        means[(s, v)], sds[(s, v)] = st.mean(per_run), final.sd(per_run)
    p("## Session CPU (schedstat; mean of 3 runs of 5 rounds x 1000 sessions, McTiny 100)\n")
    rows = []
    for v in LEVELS:
        m = means[("mctiny", None)]
        rows.append([LEVEL_NAMES[v], f"{means[('stateless', v)]:.3f}", f"{means[('stateless', v)] * mhz / 1e3:.2f}", f"{m / means[('stateless', v)]:.1f}x",
                     f"{means[('stateful', v)]:.3f}", f"{means[('stateful', v)] * mhz / 1e3:.2f}", f"{m / means[('stateful', v)]:.1f}x"])
    table(["level", "stateless ms", "Mcycles", "McTiny/stateless", "stateful ms", "Mcycles", "McTiny/stateful"], rows)
    p(f"McTiny: {means[('mctiny', None)]:.2f} ms ({means[('mctiny', None)] * mhz / 1e3:.1f} Mcycles) per session. Clock {mhz:.1f} MHz.\n")


def cost_section():
    stages = dos.load_stages()
    index = {}
    for s in stages:
        for e in dos.entries(s):
            c = e["cell"]
            if e["rtt_ms"] == 0:
                index[(c["variant"], c["system"], c["shape"], c["kind"], c["cap"] if c["kind"] in dos.TABLE_KINDS and c["system"] == "stateful" else None)] = e
    mhz = dos.mhz(stages[0])
    p("## Per-request cost (single shape, flood window): Criterion request cost and measured cost per answered request incl. system calls\n")
    rows = []
    for system, kinds in (("stateless", STATELESS_KINDS), ("stateful", ["hello", "auth"])):
        for kind in kinds:
            for v in LEVELS:
                e = index.get((v, system, "single", kind, cap_for(system, kind)))
                crit = dos.CRITERION_US[(system, kind)][v]
                cost = dos.answered_cost_us(e)
                req_bytes = dos_request_bytes(system, kind, v)
                rows.append([system, kind, LEVEL_NAMES[v], f"{crit:.1f}", f"{cost:.1f}", f"{cost - crit:+.1f}", f"{cost / crit:.2f}",
                             f"{cost * mhz:.0f}", f"{cost * mhz / req_bytes:.0f}" if req_bytes else "-"])
    table(["system", "kind", "level", "Criterion us", "measured us per answered request", "gap us (syscalls, kernel path)", "measured/Criterion",
           "cycles per answered request", "cycles per request byte"], rows)
    p(f"Cycles at {mhz:.1f} MHz. Request bytes from the bandwidth report (final A1).\n")


def dos_request_bytes(system, kind, variant):
    reports = final.jl(f"{final.USED['A1']}/raw/bandwidth.json" if system == "stateless" else f"{final.USED['A1']}/raw/bandwidth_stateful.json")
    names = {"auth": "handshake" if system == "stateless" else "hello"}
    wanted = names.get(kind, kind)
    for report in reports:
        if report["variant"] == variant:
            for x in report["packets"]:
                if x["kind"] == wanted:
                    return x["request_bytes"]
    return None


def bandwidth_section():
    p("## Bandwidth per session (UDP payload bytes)\n")
    ns, nf = final.jl(f"{final.USED['A1']}/raw/bandwidth.json"), final.jl(f"{final.USED['A1']}/raw/bandwidth_stateful.json")
    rows = []
    for b in ns:
        o = {x["variant"]: x for x in final.jl(f"{final.OLD_RUNS[0]}/raw/bandwidth.json")}[b["variant"]]
        rows.append(["stateless", LEVEL_NAMES[b["variant"]], b["total_bytes"], o["total_bytes"], b["raw_baseline_bytes"], f"{b['overhead_ratio']:.2f}",
                     sum(x["count"] for x in b["packets"]) * 2, b["max_packet_bytes"]])
    for b in nf:
        o = {x["variant"]: x for x in final.jl(f"{final.OLD_RUNS[0]}/raw/bandwidth_stateful.json")}[b["variant"]]
        rows.append(["stateful", LEVEL_NAMES[b["variant"]], b["total_bytes"], o["total_bytes"], b["raw_baseline_bytes"],
                     f"{b['total_bytes'] / b['raw_baseline_bytes']:.2f}", b["packets_total"], b["max_packet_bytes"]])
    table(["system", "level", "total bytes (new)", "total bytes (part 1)", "raw pk+ct", "total / raw", "packets", "max pkt"], rows)


def stack_section():
    stk = final.jl(f"{final.USED['A1']}/raw/stack.json")
    p("## Minimum stack (KiB) and binary size\n")
    rows = [[x["system"], LEVEL_NAMES.get(x["variant"], x["variant"] or "-"), x["min_stack_kib"]] for x in stk["stack"]]
    table(["system", "level", "min stack KiB"], rows)
    table(["binary", "text+data+bss bytes"], [[os.path.basename(x["binary"]), x["total"]] for x in stk["sizes"]])


def flood_section():
    stages = dos.load_stages()
    index = {}
    for s in stages:
        for e in dos.entries(s):
            c = e["cell"]
            index[(e["rtt_ms"], c["variant"], c["system"], c["shape"], c["kind"], c["cap"] if c["kind"] in dos.TABLE_KINDS and c["system"] == "stateful" else None)] = e

    def cell(e):
        if e is None:
            return "-"
        rs = e["reps"]
        return f"{st.mean(dos.steady_rate(rs, 1.0)) * 100:.0f} / {st.mean(dos.col(rs, 'legit_frac_completed_during_flood_attack')) * 100:.0f}"

    p("## Flood: steady success <= 1 s % / done in flood % (attack phase, mean of 10 reps, rtt 0)\n")
    rows = []
    for shape in ("single", "botnet"):
        for sl, sf in PAIRS:
            r = [shape, f"{sl} / {sf}"]
            for v in LEVELS:
                a = index.get((0, v, "stateless", shape, sl, None))
                b = index.get((0, v, "stateful", shape, sf, cap_for("stateful", sf)))
                r += [cell(a), cell(b)]
            rows.append(r)
    table(["shape", "stateless kind / stateful kind"] + [f"{LEVEL_NAMES[v]} {s}" for v in LEVELS for s in ("stateless", "stateful")], rows)
    p("Server capacity under a saturating flood (answered requests per second, single shape, from CPU per answered request):\n")
    rows = []
    for kind in STATELESS_KINDS:
        r = [kind]
        for v in LEVELS:
            e = index.get((0, v, "stateless", "single", kind, None))
            r.append(f"{1e6 / dos.answered_cost_us(e):.0f}")
        rows.append(r)
    table(["stateless kind"] + [LEVEL_NAMES[v] for v in LEVELS], rows)
    p("RTT cells (HQC-5): steady success <= 1 s % / <= 5 s % / idle p50 s\n")
    rows = []
    for system, kinds in (("stateless", ["none", "handshake", "uchunk", "vpoint"]), ("stateful", ["none", "hello", "partial", "fullkey", "churn2"])):
        for kind in kinds:
            for shape in ("single", "botnet"):
                r = [system, kind, shape]
                found = False
                for rtt in (0, 75, 300):
                    e = index.get((rtt, "hqc5", system, shape, kind, cap_for(system, kind)))
                    if e is None:
                        r.append("-")
                        continue
                    found = True
                    rs = e["reps"]
                    if kind == "none":
                        r.append(f"100 / 100 / {st.mean(dos.col(rs, 'legit_idle_p50_s')):.3f}")
                    else:
                        r.append(f"{st.mean(dos.steady_rate(rs, 1.0)) * 100:.0f} / {st.mean(dos.steady_rate(rs, 5.0)) * 100:.0f} / {st.mean(dos.col(rs, 'legit_idle_p50_s')):.3f}")
                if found:
                    rows.append(r)
    table(["system", "kind", "shape", "rtt 0", "rtt 75", "rtt 300"], rows)


def wan_section():
    if "C_wan_hqc5" not in final.USED:
        return
    mct = final.wan_part3_mctiny()
    p("## WAN medians (s; session_s, n = 30) and McTiny network-only ratio (part 3 McTiny network_s)\n")
    rows = []
    for key in WAN_CELLS:
        r = [key]
        results, _ = final.wan_results(f"{final.USED['C_wan_hqc5']}/raw/wan_hqc5.json")
        sl, sf = st.median(final.oks(results[f"stateless/{key}"])), st.median(final.oks(results[f"stateful/{key}"]))
        mm = st.median(final.oks(mct[f"mctiny/{key}"], "network_s"))
        r += [f"{sl:.3f}", f"{sf:.3f}", f"{mm:.3f}", f"{mm / sl:.1f}", f"{mm / sf:.1f}"]
        rows.append(r)
    table(["cell (HQC-5)", "stateless", "stateful", "McTiny network_s", "ratio stateless", "ratio stateful"], rows)
    for v in ("hqc1", "hqc3"):
        key_name = f"C_wan_{v}"
        if key_name not in final.USED:
            continue
        results, _ = final.wan_results(f"{final.USED[key_name]}/raw/wan_{v}.json")
        rows = []
        for key in WAN_SMALL_CELLS:
            rows.append([key] + [f"{st.median(final.oks(results[f'{s}/{key}'])):.3f}" for s in SYSTEMS])
        p(f"{LEVEL_NAMES[v]} medians (s):\n")
        table(["cell", "stateless", "stateful"], rows)


def main():
    p("# Numbers for the paper (generated by numbers_for_paper.py)\n")
    session_cpu_section()
    cost_section()
    bandwidth_section()
    stack_section()
    flood_section()
    wan_section()
    print("\n".join(out))


if __name__ == "__main__":
    main()
