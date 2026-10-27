#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

KIB = 1024
WORKLOAD_ORDER = ("seq50", "k1", "k16", "k64")
SYSTEM_ORDER = ("stateless", "stateful", "stateful-stats", "mctiny")


def kib(value: int | None) -> str:
    return "-" if value is None else f"{value / KIB:.0f}"


def label_key(label: str) -> tuple:
    system, _, variant = label.partition("-hqc")
    return (SYSTEM_ORDER.index(system) if system in SYSTEM_ORDER else 9, variant)


def split_label(label: str) -> tuple[str, str]:
    system, _, variant = label.partition("-hqc")
    return system, f"HQC-{variant}" if variant else "-"


def minimum_rows(results: dict) -> list[str]:
    lines = ["| server | level | workload | min memory.max (KiB) | memory.peak there (KiB) | quiet min memory.max (KiB) "
             "| memory.peak there (KiB) |", "|---|---|---|---:|---:|---:|---:|"]
    keys = [k for k in results if "/" in k]
    keys.sort(key=lambda k: (label_key(k.split("/")[0]), WORKLOAD_ORDER.index(k.split("/")[1])))
    for key in keys:
        label, workload = key.split("/")
        system, level = split_label(label)
        row = results[key]
        if "min_cap_bytes" not in row:
            lines.append(f"| {system} | {level} | {workload} | {row.get('error', 'missing')} | | | |")
            continue
        quiet_cap = row.get("quiet_min_cap_bytes")
        quiet_peak = row["quiet_trial"]["final"]["memory_peak"] if quiet_cap else None
        lines.append(f"| {system} | {level} | {workload} | {kib(row['min_cap_bytes'])} "
                     f"| {kib(row['min_cap_trial']['final']['memory_peak'])} | {kib(quiet_cap)} | {kib(quiet_peak)} |")
    return lines


def composition_rows(results: dict) -> list[str]:
    lines = ["| server | level | workload | memory.peak (KiB) | anon | file | slab | pagetables | kernel stack | sock "
             "| VmRSS | VmHWM | Threads |", "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    keys = [k for k in results if "/" in k and "generous" in results[k] and "final" in results[k]["generous"]]
    keys.sort(key=lambda k: (label_key(k.split("/")[0]), WORKLOAD_ORDER.index(k.split("/")[1])))
    for key in keys:
        label, workload = key.split("/")
        system, level = split_label(label)
        final = results[key]["generous"]["final"]
        stat, proc = final["stat"], final["proc"]
        lines.append(f"| {system} | {level} | {workload} | {kib(final['memory_peak'])} | {kib(stat['anon'])} "
                     f"| {kib(stat['file'])} | {kib(stat['slab'])} | {kib(stat['pagetables'])} "
                     f"| {kib(stat['kernel_stack'])} | {kib(stat['sock'])} | {proc.get('VmRSS_kb', '-')} "
                     f"| {proc.get('VmHWM_kb', '-')} | {proc.get('Threads', '-')} |")
    return lines


def sanity_rows(trials: list[dict]) -> list[str]:
    lines = ["| server | level | datagram loss | K | clients ok | server peak entries | accounted key bytes "
             "| bytes per entry | memory.peak (KiB) | anon (KiB) | VmRSS (KiB) |", "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    rows = [t for t in trials if t["purpose"].startswith("sanity") and t["clients"]]
    rows.sort(key=lambda t: (label_key(t["cell"]), t["purpose"], t["clients"]["k"]))
    for t in rows:
        system, level = split_label(t["cell"])
        stats = t["clients"].get("server_stats") or {}
        entries, accounted = stats.get("peak_entries"), stats.get("peak_bytes")
        per_entry = f"{accounted / entries:.0f}" if entries else "-"
        final = t["final"]
        loss = t["purpose"].removeprefix("sanity-loss")
        lines.append(f"| {system} | {level} | {loss} | {t['clients']['k']} | {t['clients']['completed']}/{t['clients']['attempted']} "
                     f"| {entries if entries is not None else '-'} | {accounted if accounted is not None else '-'} | {per_entry} "
                     f"| {kib(final['memory_peak'])} | {kib(final['stat']['anon'])} | {final['proc'].get('VmRSS_kb', '-')} |")
    return lines


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("raw", type=Path)
    args = parser.parse_args()
    results = json.loads((args.raw / "min_caps.json").read_text())
    trials = [json.loads(line) for line in (args.raw / "trials.jsonl").read_text().splitlines()]
    print("## Minimum memory.max\n")
    print("\n".join(minimum_rows(results)))
    print("\n## Composition at a generous cap\n")
    print("\n".join(composition_rows(results)))
    print("\n## Scaling with concurrent clients\n")
    print("\n".join(sanity_rows(trials)))


if __name__ == "__main__":
    main()
