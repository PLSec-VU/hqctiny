#!/usr/bin/env python3
"""Compares two attempts of the same flood stage cell by cell.

Usage: compare_attempts.py DIR_A DIR_B   (directories next to this file, each with raw/dos_flood.json)
Prints a Markdown table: steady success <=1 s, attack-phase server CPU %, attacker kpkt/s,
server responses per second, for attempt A and attempt B.
"""
import json
import os
import statistics as st
import sys

import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from results_dir import study_dir
ROOT = study_dir("final-x86")
STEADY_MARGIN_S = 5.0
LIMIT_S = 1.0


def load(directory):
    return json.load(open(f"{ROOT}/{directory}/raw/dos_flood.json"))["cells"]


def setup_s(rep):
    return (rep.get("flood_client_json") or {}).get("attack_started_secs") or 0.0


def steady_success(entry):
    rates = []
    for rep in entry["reps"]:
        probes = [q for q in rep["probes"] if q["phase"] == "flood" and setup_s(rep) <= q["start_offset_s"] <= rep["flood_window_s"] - STEADY_MARGIN_S]
        if probes:
            rates.append(sum(1 for q in probes if q["ok"] and q["latency_s"] <= LIMIT_S) / len(probes))
    return st.mean(rates) * 100 if rates else float("nan")


def mean_of(entry, key):
    return st.mean(r[key] for r in entry["reps"])


def main():
    a, b = load(sys.argv[1]), load(sys.argv[2])
    print("| cell | steady <=1 s % A / B | attack CPU % A / B | attacker kpkt/s A / B | server responses/s A / B (diff) |")
    print("|---|---|---|---|---|")
    for key in a:
        ea, eb = a[key], b[key]
        if ea["cell"]["kind"] == "none":
            continue
        ra, rb = mean_of(ea, "server_responses_per_s"), mean_of(eb, "server_responses_per_s")
        print(f"| {key} | {steady_success(ea):.1f} / {steady_success(eb):.1f} | {mean_of(ea, 'cpu_util_pct_attack_phase'):.1f} / {mean_of(eb, 'cpu_util_pct_attack_phase'):.1f} "
              f"| {mean_of(ea, 'attacker_packets_per_s_attack_phase') / 1e3:.1f} / {mean_of(eb, 'attacker_packets_per_s_attack_phase') / 1e3:.1f} "
              f"| {ra:.0f} / {rb:.0f} ({(rb - ra) / ra * 100:+.1f}%) |")


if __name__ == "__main__":
    main()
