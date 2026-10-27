#!/usr/bin/env python3
"""Cycles per byte of attacker traffic, for every server request kind of
both HqcLethe systems. Same measure as McTiny (Bernstein and Lange,
USENIX Security 2020) section 10.6.

Method. For one request kind:

  cycles = Criterion median time of the server handler * clock of the server core
  cycles per byte = cycles / bytes the attacker sends for that request

The clock is the median clock of the server core under load, from
raw/run_state_*.json (written by measured_run). `--mhz` overrides it. The
bytes are UDP payload bytes of the request, from the bandwidth reports
(raw/bandwidth.json and raw/bandwidth_stateful.json). A second column adds
the IPv6 and UDP headers (48 bytes per datagram).

An attacker overloads a server when the server has to spend more cycles
per second than it owns. McTiny section 10.6 takes a quad-core 3.1 GHz CPU
and a 10 Mbit/s link: 4 * 3.1e9 / 1.25e6 bytes per second = 9,920 cycles per
byte. At or above about 10,000 cycles per byte the link, not the CPU, is
the limit. McTiny reports a worst case near 400 cycles per byte. That
figure is quoted from the paper, not measured here.

Inputs are read from a results directory made by eval/run.py (category 2
and category 3 first). Usage:

  eval/scripts/derived_metrics.py [--results-dir eval/results/<ts>] [--mhz 3169]
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

EVAL_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent / "container"))
from placement import SERVER_CORE  # noqa: E402

IPV6_UDP_HEADER_BYTES = 48
CORES = 4
CORE_GHZ = 3.1
LINK_BITS_PER_S = 10e6
OVERLOAD_CYCLES_PER_BYTE = CORES * CORE_GHZ * 1e9 / (LINK_BITS_PER_S / 8)
MCTINY_WORST_CYCLES_PER_BYTE = 400
NS_PER_S = 1e9
VARIANTS = ("hqc1", "hqc3", "hqc5")


@dataclass(frozen=True)
class RequestKind:
    system: str
    label: str
    bench: str
    packet_kind: str
    request_count: str


STATELESS_KINDS = (
    RequestKind("stateless", "handshake", "{v}_server_handshake", "handshake", "one"),
    RequestKind("stateless", "auth (invalid ML-KEM ciphertext)", "{v}_server_mlkem_decap", "handshake", "one"),
    RequestKind("stateless", "uchunk", "{v}_server_uchunk_request", "uchunk", "one"),
    RequestKind("stateless", "vresidue", "{v}_server_vresidue_request", "vresidue", "one"),
)
STATEFUL_KINDS = (
    RequestKind("stateful", "hello", "stateful_{v}__hello_to_cookie", "hello", "one"),
    RequestKind("stateful", "auth (invalid ML-KEM ciphertext)", "stateful_{v}__mlkem_decaps", "hello", "one"),
    RequestKind("stateful", "first key fragment (allocates entry)", "stateful_{v}__first_fragment_allocates_entry", "key_fragment", "one"),
    RequestKind("stateful", "duplicate key fragment", "stateful_{v}__duplicate_fragment", "key_fragment", "one"),
    RequestKind("stateful", "key fragment with bad cookie", "stateful_{v}__bad_cookie_fragment", "key_fragment", "one"),
    RequestKind("stateful", "full key upload (all fragments, HQC encaps)", "stateful_{v}__full_key_upload_with_encaps", "key_fragment", "all"),
)


def median_ns(criterion_dir: Path, bench: str) -> float | None:
    path = criterion_dir / f"{bench}.json"
    if not path.exists():
        return None
    return json.loads(path.read_text())["median"]["point_estimate"]


def server_core_mhz(raw_dir: Path) -> tuple[float, str] | None:
    """Mean over the start and end snapshots of the median clock of the
    server core. Prefers the Criterion driver's own run state."""
    candidates = [raw_dir / "run_state_cpu_benchmarks.json", *sorted(raw_dir.glob("run_state_*.json"))]
    for path in candidates:
        if not path.exists():
            continue
        state = json.loads(path.read_text())
        clocks = [
            state[phase]["frequency_under_load"].get(str(SERVER_CORE), {}).get("median_mhz")
            for phase in ("start", "end") if phase in state
        ]
        clocks = [c for c in clocks if c]
        if clocks:
            return sum(clocks) / len(clocks), path.name
    return None


def request_bytes(report: dict, packet_kind: str, which: str) -> int | None:
    for packet in report["packets"]:
        if packet["kind"] == packet_kind:
            return packet["request_bytes_total"] if which == "all" else packet["request_bytes"]
    return None


def load_reports(raw_dir: Path) -> dict[str, dict[str, dict]]:
    files = {"stateless": "bandwidth.json", "stateful": "bandwidth_stateful.json"}
    reports = {}
    for system, name in files.items():
        path = raw_dir / name
        if path.exists():
            reports[system] = {v["variant"]: v for v in json.loads(path.read_text())}
    return reports


def datagrams(report: dict, packet_kind: str, which: str) -> int:
    count = next(p["count"] for p in report["packets"] if p["kind"] == packet_kind)
    return count if which == "all" else 1


def rows_for(raw_dir: Path, mhz: float) -> list[dict]:
    criterion_dir = raw_dir / "criterion"
    reports = load_reports(raw_dir)
    rows = []
    for kinds in (STATELESS_KINDS, STATEFUL_KINDS):
        for variant in VARIANTS:
            for kind in kinds:
                report = reports.get(kind.system, {}).get(variant)
                ns = median_ns(criterion_dir, kind.bench.format(v=variant))
                if report is None or ns is None:
                    continue
                payload = request_bytes(report, kind.packet_kind, kind.request_count)
                if not payload:
                    continue
                cycles = ns / NS_PER_S * mhz * 1e6
                wire = payload + IPV6_UDP_HEADER_BYTES * datagrams(report, kind.packet_kind, kind.request_count)
                rows.append({
                    "system": kind.system, "variant": variant, "request": kind.label,
                    "bench": kind.bench.format(v=variant), "median_us": ns / 1e3,
                    "cycles": cycles, "request_payload_bytes": payload, "request_wire_bytes": wire,
                    "cycles_per_payload_byte": cycles / payload, "cycles_per_wire_byte": cycles / wire,
                    "link_mbit_per_s_to_use_all_cores": CORES * CORE_GHZ * 1e9 / (cycles / wire) * 8 / 1e6,
                })
    return rows


def markdown(rows: list[dict], mhz: float, mhz_source: str) -> str:
    lines = [
        f"Clock {mhz:.0f} MHz (from {mhz_source}). Overload threshold "
        f"{OVERLOAD_CYCLES_PER_BYTE:.0f} cycles/byte (quad-core {CORE_GHZ} GHz, "
        f"{LINK_BITS_PER_S / 1e6:.0f} Mbit/s). McTiny worst case, quoted from the paper: "
        f"about {MCTINY_WORST_CYCLES_PER_BYTE} cycles/byte.",
        "",
        "| system | level | request | median us | cycles | request B | cycles/B (payload) | cycles/B (with headers) | Mbit/s that keeps 4x3.1 GHz busy |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(
            f"| {r['system']} | {r['variant']} | {r['request']} | {r['median_us']:.1f} | {r['cycles']:.3g} | "
            f"{r['request_payload_bytes']} | {r['cycles_per_payload_byte']:.0f} | "
            f"{r['cycles_per_wire_byte']:.0f} | {r['link_mbit_per_s_to_use_all_cores']:.1f} |"
        )
    worst = max(rows, key=lambda r: r["cycles_per_payload_byte"]) if rows else None
    if worst:
        lines += ["", f"Worst case: {worst['system']} {worst['variant']} {worst['request']}, "
                      f"{worst['cycles_per_payload_byte']:.0f} cycles/byte of payload."]
    return "\n".join(lines)


def latest_results_dir() -> Path:
    candidates = sorted((EVAL_DIR / "results").glob("*/raw/criterion"))
    if not candidates:
        sys.exit("no results directory with Criterion data; run category 3 first")
    return candidates[-1].parent.parent


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--results-dir", type=Path)
    parser.add_argument("--mhz", type=float)
    args = parser.parse_args()
    results_dir = args.results_dir or latest_results_dir()
    raw_dir = results_dir / "raw"
    if args.mhz:
        mhz, source = args.mhz, "--mhz"
    else:
        found = server_core_mhz(raw_dir)
        if found is None:
            sys.exit("no measured clock in raw/run_state_*.json; pass --mhz")
        mhz, source = found
    rows = rows_for(raw_dir, mhz)
    if not rows:
        sys.exit(f"no rows: need raw/criterion/*.json and raw/bandwidth*.json in {raw_dir}")
    table = markdown(rows, mhz, source)
    print(table)
    (raw_dir / "derived_metrics.json").write_text(json.dumps(
        {"mhz": mhz, "mhz_source": source, "overload_cycles_per_byte": OVERLOAD_CYCLES_PER_BYTE,
         "mctiny_worst_cycles_per_byte_paper": MCTINY_WORST_CYCLES_PER_BYTE, "rows": rows}, indent=1) + "\n")
    (raw_dir / "derived_metrics.md").write_text(table + "\n")


if __name__ == "__main__":
    main()
