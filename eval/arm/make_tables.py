#!/usr/bin/env python3
"""Builds the tables of RESULTS.md from raw/ (Pi data) and the x86 data of part1 and part2.

  make_tables.py > tables.md
"""

from __future__ import annotations

import json
import os
import shutil
import statistics
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
HERE = Path(os.environ.get("ARM_DIR", REPO / "eval" / "results" / "arm"))
RAW = HERE / "raw"
PI = RAW / "pi"
X86_PART1 = Path(os.environ.get("X86_PART1_DIR", HERE / "x86_part1"))
TOOLS = REPO / "eval" / "scripts"
VARIANTS = ("hqc1", "hqc3", "hqc5")
PI_MHZ = 1200.0


def load(path: Path):
    return json.loads(path.read_text()) if path.exists() else None


def med(values):
    return statistics.median(values) if values else float("nan")


def flatten_criterion() -> None:
    target = RAW / "criterion"
    shutil.rmtree(target, ignore_errors=True)
    target.mkdir(parents=True)
    source = PI / "criterion"
    for estimates in source.glob("**/new/estimates.json"):
        name = "__".join(estimates.parent.parent.relative_to(source).parts)
        shutil.copy(estimates, target / f"{name}.json")
    for name in ("bandwidth.json", "bandwidth_stateful.json"):
        shutil.copy(X86_PART1 / name, RAW / name)


def derived() -> list[dict]:
    script = TOOLS / "derived_metrics.py"
    subprocess.run([sys.executable, str(script), "--results-dir", str(HERE), "--mhz", str(PI_MHZ)],
                   check=True, capture_output=True)
    return load(RAW / "derived_metrics.json")["rows"]


def x86_cpb() -> dict:
    rows = load(X86_PART1 / "derived_metrics.json")["rows"]
    return {(r["system"], r["variant"], r["request"]): r for r in rows}


def table(header: list[str], rows: list[list]) -> str:
    out = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    out += ["| " + " | ".join(str(c) for c in row) + " |" for row in rows]
    return "\n".join(out)


def section_criterion() -> str:
    rows = derived()
    x86 = x86_cpb()
    body = []
    for r in rows:
        ref = x86.get((r["system"], r["variant"], r["request"]))
        ratio = f"{r['median_us'] / ref['median_us']:.0f}" if ref else "-"
        cpb_ratio = f"{r['cycles_per_payload_byte'] / ref['cycles_per_payload_byte']:.0f}" if ref else "-"
        body.append([r["system"], r["variant"], r["request"], f"{r['median_us']:.0f}", f"{r['cycles'] / 1e6:.3f}",
                     r["request_payload_bytes"], f"{r['cycles_per_payload_byte']:.0f}",
                     f"{ref['cycles_per_payload_byte']:.0f}" if ref else "-", ratio, cpb_ratio])
    return table(["system", "level", "request", "Pi median us", "Pi Mcycles", "request B", "Pi cycles/B",
                  "x86 cycles/B", "time ratio Pi/x86", "cycles/B ratio Pi/x86"], body)


def x86_session() -> dict:
    data = load(X86_PART1 / "session_cpu.json")
    return {(r["system"], r["variant"]): r["measured_cpu_ms_per_session"] for r in data["results"]}


def section_session() -> str:
    x86 = x86_session()
    body = []
    for name in ("session_cpu_hqclethe.json", "session_cpu_mctiny.json"):
        data = load(PI / name)
        if not data:
            continue
        for r in data["results"]:
            values = [row.get("cpu_ms_per_session_schedstat", row["cpu_ms_per_session"]) for row in r["per_rep"]]
            idle = [row.get("idle_cpu_ms_same_wall_schedstat", float("nan")) for row in r["per_rep"]]
            m = med(values)
            ref = x86.get((r["system"], r["variant"]))
            body.append([r["system"], r["variant"] or "-", len(values), f"{m:.2f}", f"{min(values):.2f}-{max(values):.2f}",
                         f"{m * PI_MHZ / 1000:.1f}", f"{med(idle):.1f}", f"{ref:.3f}" if ref else "-",
                         f"{m / ref:.0f}" if ref else "-"])
    return table(["system", "level", "reps", "Pi server CPU ms/session (median)", "range", "Mcycles/session",
                  "idle ms same wall", "x86 ms/session", "ratio Pi/x86"], body)


def section_client() -> str:
    crit = lambda n: load(RAW / "criterion" / f"{n}.json")  # noqa: E731
    body = []
    for v in VARIANTS:
        row = [v]
        for name in ("client_keygen", "client_initialize", "client_decap", "client_mlkem_encap"):
            d = crit(f"{v}_{name}")
            x = load(X86_PART1 / "criterion" / f"{v}_{name}.json")
            row.append(f"{d['median']['point_estimate'] / 1e6:.1f} ({d['median']['point_estimate'] / x['median']['point_estimate']:.0f}x)" if d and x else "-")
        body.append(row)
    out = table(["level", "keygen ms (ratio to x86)", "initialise ms", "decap ms", "ML-KEM encap ms"], body)
    sessions = []
    for name in ("client_cpu_hqclethe.json", "client_cpu_mctiny.json"):
        data = load(PI / name)
        if not data:
            continue
        for r in data["results"]:
            values = [row["client_cpu_ms_per_session"] for row in r["per_rep"]]
            wall = [row["wall_ms_per_session"] for row in r["per_rep"]]
            sessions.append([r["system"], r["variant"] or "-", len(values), f"{med(values):.0f}",
                             f"{min(values):.0f}-{max(values):.0f}", f"{med(wall):.0f}"])
    return out + "\n\n" + table(["system", "level", "reps", "client CPU ms/session (median)", "range", "wall ms/session"], sessions)


def section_memory() -> str:
    body = []
    for name in ("memory_hqclethe.json", "memory_mctiny.json"):
        data = load(PI / name)
        if not data:
            continue
        stacks = {(s["system"], s["variant"]): s["min_stack_kib"] for s in data["stack"]}
        for r in data["rss"]:
            key = (r["system"], r["variant"])
            body.append([r["system"], r["variant"] or "-", stacks.get(key), r["idle"]["VmRSS_kb"],
                         r["after_sessions"]["VmRSS_kb"], r["after_sessions"]["VmHWM_kb"],
                         r["after_sessions"].get("Pss_kb"), r["after_sessions"].get("Private_Dirty_kb")])
    sizes = {}
    for name in ("memory_hqclethe.json", "memory_mctiny.json"):
        data = load(PI / name)
        for s in (data or {}).get("sizes", []):
            sizes[s["binary"]] = [s["binary"], s["text"], s["data"], s["bss"], s["total"]]
    sizes = list(sizes.values())
    return (table(["system", "level", "min stack KiB", "idle RSS kB", "RSS after 20 sessions kB", "VmHWM kB", "Pss kB",
                   "Private_Dirty kB"], body) + "\n\n" + table(["binary", "text", "data", "bss", "total"], sizes))


def dos_cells() -> dict:
    cells: dict = {}
    for path in sorted(PI.glob("dos_lan_*.json")):
        profile = path.stem.removeprefix("dos_lan_").split("_fix")[0]
        for key, cell in load(path)["cells"].items():
            good = [r for r in cell["reps"] if "flood_error" not in r["flood_client_json"]]
            cells.setdefault(f"{profile}/{key}", []).extend(good)
    return cells


def section_dos() -> str:
    cells = dos_cells()
    if not cells:
        return "(no data)"
    body = []
    for key, reps in sorted(cells.items()):
        def m(f, fmt="{:.0f}"):
            values = []
            for r in reps:
                try:
                    value = f(r)
                except (KeyError, TypeError):
                    value = None
                if value is not None:
                    values.append(value)
            return fmt.format(med(values)) if values else "-"

        either = lambda a, b: (lambda r: r[a] if r.get(a) is not None else r.get(b))  # noqa: E731
        answers = lambda r: r["pi_udp"]["OutDatagrams"] / r["pi_window_s"]  # noqa: E731
        core = lambda c, k: (lambda r: r["pi_core_pct"][c][k])  # noqa: E731
        body.append([key, len(reps), m(answers), m(lambda r: r.get("attacker_packets_per_s_attack_phase"), "{:.0f}"),
                     m(lambda r: r["pi_nic_rx_pps"]), m(lambda r: r["pi_nic_rx_mbit"], "{:.1f}"),
                     m(lambda r: r["pi_udp_rcvbuf_errors"] / r["pi_window_s"]),
                     m(either("cpu_util_pct_attack_phase", "cpu_util_pct"), "{:.1f}"),
                     m(core("cpu0", "softirq"), "{:.1f}"), m(core("cpu2", "softirq"), "{:.1f}"),
                     m(either("legit_success_within_1s_attack", "legit_success_within_1s"), "{:.2f}"),
                     m(either("legit_success_within_5s_attack", "legit_success_within_5s"), "{:.2f}"),
                     m(either("legit_frac_completed_during_flood_attack", "legit_frac_completed_during_flood"), "{:.2f}"),
                     m(lambda r: r["legit_n_attack"] if r.get("legit_n_attack") is not None else r["legit_n"], "{:.0f}"),
                     m(lambda r: r["peak_rss_growth_kb"]), m(lambda r: r["pi_temp_c_end"], "{:.1f}")])
    return table(["profile/level:system:kind:shape", "reps", "answers/s (Pi UDP out)", "attacker pkt/s sent",
                  "Pi NIC rx pkt/s", "Pi NIC rx Mbit/s", "RcvbufErrors/s", "server CPU % (attack)", "core 0 softirq %",
                  "core 2 softirq %", "legit <=1 s", "legit <=5 s", "done in flood", "probes per rep", "peak RSS growth kB",
                  "SoC C end"], body)


def section_latency() -> str:
    results = [r for name in ("lan_latency.json", "lan_latency_mctiny.json") for r in (load(PI / name) or {"results": []})["results"]]
    if not results:
        return "(no data)"
    body = []
    for r in results:
        s = r["session_s"]
        if not s:
            continue
        ok = [x for x in r["rows"] if x["ok"]]
        retried = [x for x in ok if x.get("retries")]
        clean = [x["session_s"] for x in ok if not x.get("retries")]
        body.append([r["system"], r["variant"] or "-", f"{s['n']}/{len(r['rows'])}", f"{s['median'] * 1000:.0f}",
                     f"{s['q1'] * 1000:.0f}-{s['q3'] * 1000:.0f}", f"{s['min'] * 1000:.0f}-{s['max'] * 1000:.0f}",
                     len(retried), f"{med(clean) * 1000:.0f}" if clean else "-"])
    return table(["system", "level", "ok sessions", "median ms", "IQR ms", "min-max ms", "sessions with a retransmit",
                  "median ms without retransmit"], body)


def section_state() -> str:
    body = []
    for series in sorted((PI / "state").glob("*.state_series.jsonl")):
        samples = [json.loads(line) for line in series.read_text().splitlines() if line.strip()]
        if not samples:
            continue
        clocks = [s["arm_clock_hz"] for s in samples]
        flags = sorted({f for s in samples for f in s["throttled"]["active"]})
        body.append([series.name.removesuffix(".state_series.jsonl"), len(samples),
                     f"{min(clocks) / 1e6:.3f}-{max(clocks) / 1e6:.3f}",
                     f"{min(s['temp_c'] for s in samples):.1f}-{max(s['temp_c'] for s in samples):.1f}",
                     ",".join(flags) or "none", samples[-1]["throttled"]["raw"]])
    return table(["run", "samples (2 s)", "ARM clock MHz (vcgencmd)", "SoC temp C", "active throttle flags", "final get_throttled"], body)


def sections() -> dict:
    flatten_criterion()
    return {"server": section_criterion(), "session": section_session(), "client": section_client(),
            "memory": section_memory(), "state": section_state(), "dos": section_dos(), "latency": section_latency()}


def main() -> None:
    flatten_criterion()
    for title, builder in (("Server per-request CPU (Criterion)", section_criterion),
                           ("Server CPU per session", section_session), ("Client cost", section_client),
                           ("Memory", section_memory), ("Clock and temperature evidence", section_state), ("Real-network flood", section_dos),
                           ("LAN session latency", section_latency)):
        print(f"### {title}\n")
        print(builder())
        print()


if __name__ == "__main__":
    main()
