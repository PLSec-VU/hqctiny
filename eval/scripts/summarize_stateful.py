#!/usr/bin/env python3
"""Turns raw/dos_flood.json (written by dos_flood.py) into a Markdown
table. One row per cell. Attack-phase columns use the part of the
flood after the flood client's set-up. Each value is mean +- sd across repetitions
(the between-run spread), with the repetition count.

Usage: eval/scripts/summarize_stateful.py eval/results/<ts>/raw/dos_flood.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

COLUMNS = [
    ("attack_started_s", "set-up s", "{:.1f}"),
    ("cpu_util_pct_attack_phase", "cpu % (attack)", "{:.1f}"),
    ("attacker_packets_per_s_attack_phase", "attacker pkt/s (attack)", "{:.0f}"),
    ("server_responses_per_s", "server resp/s", "{:.0f}"),
    ("kernel_udp_drops", "udp drops", "{:.0f}"),
    ("entries_created_per_s", "entries/s", "{:.0f}"),
    ("d_evictions", "evictions", "{:.0f}"),
    ("d_dropped_table_full", "table full", "{:.0f}"),
    ("peak_table_bytes", "peak table B", "{:.0f}"),
    ("legit_n_attack", "probes (attack)", "{:.0f}"),
    ("legit_success_within_1s_attack", "ok<=1s (attack)", "{:.2f}"),
    ("legit_success_within_5s_attack", "ok<=5s (attack)", "{:.2f}"),
    ("legit_p50_s_attack", "p50 s (attack)", "{:.3f}"),
    ("legit_p99_s_attack", "p99 s (attack)", "{:.3f}"),
    ("legit_success_within_1s", "ok<=1s (window)", "{:.2f}"),
    ("recovery_ok", "recov ok", "{:.1f}"),
]


def cell(stats: dict, key: str, fmt: str) -> str:
    entry = stats.get(key)
    if entry is None:
        return "-"
    spread = f" +- {fmt.format(entry['sd'])}" if entry["sd"] is not None else ""
    return fmt.format(entry["mean"]) + spread


def table(grid: dict) -> str:
    header = ["cell", "rtt", "reps", *(title for _, title, _ in COLUMNS)]
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    for key, entry in grid["cells"].items():
        stats = entry["between_rep_stats"]
        cells = [cell(stats, name, fmt) for name, _, fmt in COLUMNS]
        label = key.split("/", 1)[1]
        lines.append("| " + " | ".join([label, str(entry["rtt_ms"]), str(len(entry["reps"])), *cells]) + " |")
    return "\n".join(lines)


def main() -> None:
    print(table(json.loads(Path(sys.argv[1]).read_text())))


if __name__ == "__main__":
    main()
