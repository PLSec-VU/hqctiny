#!/usr/bin/env python3
"""Compares two attempts of a Criterion + session-CPU stage (directories next to this file).

Usage: compare_attempts_A.py DIR_A DIR_B
Prints the largest Criterion median differences and the session-CPU means of both attempts.
"""
import glob
import json
import os
import statistics as st
import sys

import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from results_dir import study_dir
ROOT = study_dir("final-x86")
TOP = 6


def criterion(directory):
    return {os.path.basename(x)[:-5]: json.load(open(x))["median"]["point_estimate"] / 1000
            for x in glob.glob(f"{ROOT}/{directory}/raw/criterion/*.json")}


def session(directory):
    data = json.load(open(f"{ROOT}/{directory}/raw/session_cpu.json"))
    return {(r["system"], r["variant"]): st.mean(x["cpu_ms_per_session_schedstat"] for x in r["per_rep"]) for r in data["results"]}


def main():
    a, b = sys.argv[1], sys.argv[2]
    ca, cb = criterion(a), criterion(b)
    diffs = sorted(((abs(cb[k] - ca[k]) / ca[k] * 100, k, ca[k], cb[k]) for k in ca), reverse=True)
    print(f"Criterion: {len(diffs)} benches; median absolute difference {st.median(d[0] for d in diffs):.2f}%; largest:\n")
    print("| bench | A us | B us | difference |")
    print("|---|---|---|---|")
    for d, k, x, y in diffs[:TOP]:
        print(f"| {k} | {x:.3f} | {y:.3f} | {d:.2f}% |")
    print("\nSession CPU (ms per session, mean of 5 rounds):\n")
    print("| system | level | A | B | difference |")
    print("|---|---|---|---|---|")
    sa, sb = session(a), session(b)
    for key in sa:
        print(f"| {key[0]} | {key[1] or '-'} | {sa[key]:.4f} | {sb[key]:.4f} | {(sb[key] - sa[key]) / sa[key] * 100:+.2f}% |")


if __name__ == "__main__":
    main()
