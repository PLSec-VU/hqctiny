#!/usr/bin/env python3
"""Prints the tables of two ARM campaigns side by side (old value / new value), and the rate limits derived from the per-request
and per-session costs.

  compare_tables.py --old DIR --new DIR [--x86-part1 DIR]

DIR holds raw/pi (and raw/link) of one campaign. Both are read through make_tables.py in a scratch copy, so DIR is not changed.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SECTION_KEYS = {
    "Server per-request CPU (Criterion)": 3,
    "Server CPU per session": 2,
    "Client cost": 1,
    "Memory": 2,
    "Clock and temperature evidence": 1,
    "Real-network flood": 1,
    "LAN session latency": 2,
}
STATELESS_QUERIES_PER_SESSION = {"hqc1": 10, "hqc3": 20, "hqc5": 33}
SECOND_TABLE_KEYS = {"Client cost": 2, "Memory": 1}


def run_tables(campaign: Path, x86_part1: Path | None, scratch: Path) -> str:
    target = scratch / campaign.name
    shutil.copytree(campaign / "raw", target / "raw")
    env = {**os.environ, "ARM_DIR": str(target)}
    if x86_part1:
        env["X86_PART1_DIR"] = str(x86_part1)
    result = subprocess.run([sys.executable, str(HERE / "make_tables.py")], env=env, capture_output=True, text=True)
    if result.returncode:
        sys.stderr.write(result.stderr)
    return result.stdout


def split_sections(text: str) -> dict[str, list[list[list[str]]]]:
    sections: dict[str, list[list[list[str]]]] = {}
    current = None
    for block in text.split("### ")[1:]:
        title, _, body = block.partition("\n")
        tables, rows = [], []
        for line in body.splitlines():
            if line.startswith("|"):
                cells = [c.strip() for c in line.strip().strip("|").split("|")]
                if not all(set(c) <= {"-"} for c in cells):
                    rows.append(cells)
            elif rows:
                tables.append(rows)
                rows = []
        if rows:
            tables.append(rows)
        sections[title.strip()] = tables
        current = title
    return sections


def merge(old: list[list[str]], new: list[list[str]], key_count: int) -> list[list[str]]:
    header = new[0] if new else old[0]
    old_rows = {tuple(r[:key_count]): r for r in old[1:]}
    new_rows = {tuple(r[:key_count]): r for r in new[1:]}
    out = [header[:key_count] + [f"{h} (old / new)" for h in header[key_count:]]]
    for key in dict.fromkeys([*new_rows, *old_rows]):
        o, n = old_rows.get(key), new_rows.get(key)
        cells = []
        for i in range(key_count, len(header)):
            ov = o[i] if o and i < len(o) else "-"
            nv = n[i] if n and i < len(n) else "-"
            cells.append(f"{ov} / {nv}")
        out.append(list(key) + cells)
    return out


def markdown(rows: list[list[str]]) -> str:
    lines = ["| " + " | ".join(rows[0]) + " |", "|" + "---|" * len(rows[0])]
    lines += ["| " + " | ".join(r) + " |" for r in rows[1:]]
    return "\n".join(lines)


def median(values):
    return statistics.median(values) if values else float("nan")


def derived_rates(campaign: Path) -> list[list[str]]:
    pi = campaign / "raw" / "pi"
    rows = [["system", "level", "unit", "CPU cost ms", "max per second on one core (1 / cost)"]]
    derived = json.loads((campaign / "raw" / "derived_metrics.json").read_text())["rows"] if (campaign / "raw" / "derived_metrics.json").exists() else []
    for r in derived:
        if r["request"] in ("handshake", "uchunk", "vresidue", "hello", "full key upload (all fragments, HQC encaps)"):
            ms = r["median_us"] / 1000
            rows.append([r["system"], r["variant"], f"request: {r['request']}", f"{ms:.3f}", f"{1000 / ms:.1f}"])
    session = pi / "session_cpu_hqclethe.json"
    if session.exists():
        for r in json.loads(session.read_text())["results"]:
            ms = median([x.get("cpu_ms_per_session_schedstat", x["cpu_ms_per_session"]) for x in r["per_rep"]])
            rows.append([r["system"], r["variant"], "session", f"{ms:.2f}", f"{1000 / ms:.2f}"])
            if r["system"] == "stateless":
                queries = STATELESS_QUERIES_PER_SESSION[r["variant"]]
                rows.append([r["system"], r["variant"], f"query (session cost / {queries} queries)", f"{ms / queries:.3f}", f"{queries * 1000 / ms:.0f}"])
    mctiny = pi / "mctiny_cost.json"
    if mctiny.exists():
        data = json.loads(mctiny.read_text())
        queries = data["queries_per_session"]
        full = [x for x in data["rows"] if x["sessions_completed"] == x["sessions_attempted"]] or data["rows"]
        ms = median([x["schedstat_ms_per_session"] for x in full])
        rows.append(["mctiny", "-", f"session ({queries} queries)", f"{ms:.2f}", f"{1000 / ms:.2f}"])
        rows.append(["mctiny", "-", "query (session cost / queries)", f"{ms / queries:.3f}", f"{queries * 1000 / ms:.0f}"])
        phase1 = median([x["phase1_cycles_per_query"] for x in full]) / 1.2e6
        rows.append(["mctiny", "-", "phase-1 syndrome step only (server cycle counter)", f"{phase1:.3f}", f"{1000 / phase1:.0f}"])
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--old", type=Path, required=True)
    parser.add_argument("--new", type=Path, required=True)
    parser.add_argument("--x86-part1", type=Path)
    args = parser.parse_args()
    args.old, args.new = args.old.resolve(), args.new.resolve()
    args.x86_part1 = args.x86_part1.resolve() if args.x86_part1 else None
    with tempfile.TemporaryDirectory() as scratch:
        scratch_dir = Path(scratch)
        old_text = run_tables(args.old, args.x86_part1, scratch_dir)
        new_text = run_tables(args.new, args.x86_part1, scratch_dir)
        old, new = split_sections(old_text), split_sections(new_text)
        for title, key_count in SECTION_KEYS.items():
            print(f"### {title}\n")
            old_tables, new_tables = old.get(title, []), new.get(title, [])
            for index in range(max(len(old_tables), len(new_tables))):
                keys = key_count if index == 0 else SECOND_TABLE_KEYS.get(title, key_count)
                o = old_tables[index] if index < len(old_tables) else [new_tables[index][0]]
                n = new_tables[index] if index < len(new_tables) else [o[0]]
                print(markdown(merge(o, n, keys)))
                print()
        for label, campaign in (("old", args.old), ("new", args.new)):
            scratch_campaign = Path(scratch) / campaign.name
            print(f"### Derived rate limits ({label})\n")
            print(markdown(derived_rates_from(scratch_campaign, campaign)))
            print()


def derived_rates_from(scratch_campaign: Path, campaign: Path) -> list[list[str]]:
    mirror = Path(tempfile.mkdtemp(dir=scratch_campaign))
    (mirror / "raw").mkdir()
    for name in ("derived_metrics.json",):
        source = scratch_campaign / "raw" / name
        if source.exists():
            shutil.copy(source, mirror / "raw" / name)
    (mirror / "raw" / "pi").symlink_to(campaign / "raw" / "pi")
    return derived_rates(mirror)


if __name__ == "__main__":
    main()
