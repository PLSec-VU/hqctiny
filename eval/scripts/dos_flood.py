#!/usr/bin/env python3
"""Category 4: denial-of-service comparison of the stateless HQCLethe server
and the cookie-gated stateful baseline. Both authenticate with the same
static ML-KEM key.

The grid has these cells: variant x system x shape x flood kind (x table cap
for the stateful table-filling kinds). Shapes:

  single  SINGLE_HOST_SOCKETS flood sockets, one source address
  botnet  BOTNET_SOCKETS flood sockets spread over BOTNET_IPS source
          addresses. This is one host with BOTNET_IPS bound 127.1.x.y
          loopback addresses, not many machines. The output metadata says so.

Both systems run both shapes. Each system runs its own flood kinds (see
container/systems.py; the stateless kinds can be switched with the
STATELESS_FLOOD_KINDS environment variable). A `none` cell (no flood, same
probes) is run once per system and variant.

The grid runs DOS_REPS repetitions. Inside each repetition every cell runs
once, in a shuffled order (seed printed and stored), each with a fresh
server process. Output is raw/dos_flood.json: per cell the per-repetition rows
(with every legitimate-client probe) and the between-repetition statistics.

  eval/scripts/dos_flood.py [--reps N] [--duration S] [--variants hqc1 hqc5]
      [--systems stateless,stateful] [--shapes single,botnet]
      [--kinds a,b] [--caps 16,64,256,1024] [--rtts-ms 0,75,300] [--seed N]
      [--dry-run]

Env knobs: see lib/knobs.py.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
sys.path.insert(0, str(Path(__file__).resolve().parent / "container"))
from common import (  # noqa: E402
    RAW_DIR, TS, VARIANTS, cargo_build, dexec_py, dexec_server, ensure_up, hqc_features, knobs,
    log_section, measured_run, setup_keys, start_log,
)
from reps import describe_rows, new_seed, shuffled_for_rep  # noqa: E402
from systems import LEGIT_SOURCE_IP, SYSTEMS, TABLE_FILLING_KINDS  # noqa: E402

NO_FLOOD = "none"
SHAPES = ("single", "botnet")
DEFAULT_CAP = 1024
EXCLUDED_KINDS = frozenset({"churn"})
BOTNET_NOTE = (
    "botnet = BOTNET_IPS bound 127.1.x.y loopback addresses on one host, "
    "sockets spread round robin over them; not distinct machines"
)
SUMMARY_HIDDEN = frozenset({"probes", "flood_client_json"})


@dataclass(frozen=True)
class Cell:
    variant: str
    system: str
    shape: str
    kind: str
    sockets: int
    source_ips: int
    cap: int | None

    @property
    def id(self) -> str:
        cap = f"/cap{self.cap}" if self.cap else ""
        return f"{self.variant}/{self.system}/{self.shape}/{self.kind}{cap}"


def shape_dimensions(shape: str) -> tuple[int, int]:
    if shape == "botnet":
        return knobs.get_int("BOTNET_SOCKETS"), knobs.get_int("BOTNET_IPS")
    return knobs.get_int("SINGLE_HOST_SOCKETS"), 1


def kinds_for(system: str, requested: list[str] | None) -> list[str]:
    available = [k for k in SYSTEMS[system].flood_kinds if k not in EXCLUDED_KINDS]
    return available if not requested else [k for k in requested if k in SYSTEMS[system].flood_kinds]


def build_cells(
    variants: list[str], systems: list[str], shapes: list[str], requested_kinds: list[str] | None,
    caps: list[int],
) -> list[Cell]:
    cells = []
    for variant in variants:
        for system in systems:
            stateful = system == "stateful"
            for shape in shapes:
                sockets, source_ips = shape_dimensions(shape)
                kinds = kinds_for(system, requested_kinds)
                if shape == shapes[0] and (requested_kinds is None or NO_FLOOD in requested_kinds):
                    kinds = [NO_FLOOD, *kinds]
                for kind in kinds:
                    sweeps_cap = stateful and shape == "botnet" and kind in TABLE_FILLING_KINDS
                    cell_caps = caps if sweeps_cap else [DEFAULT_CAP if stateful else None]
                    for cap in cell_caps:
                        cells.append(Cell(variant, system, shape, kind, sockets, source_ips, cap))
    return cells


def build_binaries() -> None:
    server_features = hqc_features("quiet", "flood-stats")
    client_features = hqc_features("quiet")
    cargo_build("--profile", "tiny-release", "-p", "hqclethe-server", features=server_features)
    cargo_build("--profile", "tiny-release", "-p", "hqclethe-stateful",
                "--bin", "hqclethe-server-stateful", features=server_features)
    cargo_build("--release", "-p", "hqclethe-client", features=client_features)
    cargo_build("--release", "-p", "hqclethe-stateful",
                "--bin", "hqclethe-client-stateful", features=client_features)


def keys_exist() -> bool:
    return all(
        dexec_server("test", "-f", f"/work/target-linux/eval-keys/server-{v}.sk", check=False).returncode == 0
        for v in VARIANTS
    )


def tc_clear() -> None:
    dexec_server("sh", "-c", "tc qdisc del dev lo root 2>/dev/null || true")


def tc_apply(rtt_ms: int) -> None:
    """Delays only the legitimate client's traffic (127.2.0.1) on loopback.
    A packet crosses lo once each way, so one-way delay = RTT/2."""
    tc_clear()
    if rtt_ms == 0:
        return
    commands = [
        ["tc", "qdisc", "add", "dev", "lo", "root", "handle", "1:", "prio", "bands", "3"],
        ["tc", "qdisc", "add", "dev", "lo", "parent", "1:3", "handle", "30:", "netem",
         "delay", f"{rtt_ms / 2:g}ms"],
        *(["tc", "filter", "add", "dev", "lo", "parent", "1:0", "protocol", "ip", "u32",
           "match", "ip", direction, f"{LEGIT_SOURCE_IP}/32", "flowid", "1:3"]
          for direction in ("dst", "src")),
    ]
    for command in commands:
        dexec_server(*command)


def run_cell_once(cell: Cell, rep: int, duration: int, last_rep: bool) -> dict | None:
    extra_env = {"REP_BASE": str(rep - 1)}
    if cell.cap:
        extra_env["STATEFUL_SERVER_ARGS"] = f"--max-entries {cell.cap} --watch-source {LEGIT_SOURCE_IP}"
    if not last_rep:
        extra_env["STRACE_BURST"] = "0"
    result = dexec_py(
        "server", "dos_flood_variant.py", cell.system, cell.variant, str(duration), str(cell.sockets),
        "1", cell.kind, str(cell.source_ips), capture_output=True, check=False, extra_env=extra_env,
    )
    print(result.stdout, end="")
    print(result.stderr, end="", file=sys.stderr)
    for line in result.stdout.splitlines():
        if line.startswith("RESULT "):
            return json.loads(line[len("RESULT "):])["rows"][0]
    return None


def summarize_cell(rows: list[dict]) -> dict:
    stripped = [{k: v for k, v in row.items() if k not in SUMMARY_HIDDEN} for row in rows]
    return describe_rows(stripped)


def write_grid(path: Path, meta: dict, results: dict[str, dict]) -> None:
    for entry in results.values():
        entry["between_rep_stats"] = summarize_cell(entry["reps"])
    path.write_text(json.dumps({"meta": meta, "cells": results}, indent=1) + "\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--reps", type=int, default=knobs.get_int("DOS_REPS"))
    parser.add_argument("--duration", type=int, default=knobs.get_int("FLOOD_DURATION"))
    parser.add_argument("--variants", default=" ".join(VARIANTS))
    parser.add_argument("--systems", default=",".join(SYSTEMS))
    parser.add_argument("--shapes", default=",".join(SHAPES))
    parser.add_argument("--kinds", help="comma list; default: every kind of each system plus none")
    parser.add_argument("--caps", default=knobs.get("DOS_CAPS"))
    parser.add_argument("--rtts-ms", default="0", help="legit-client RTT conditions, outer loop")
    parser.add_argument("--seed", type=int, default=new_seed())
    parser.add_argument("--name", default="dos_flood")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    variants = args.variants.replace(",", " ").split()
    caps = [int(c) for c in args.caps.replace(",", " ").split()]
    rtts = [int(r) for r in args.rtts_ms.split(",")]
    requested = args.kinds.split(",") if args.kinds else None
    cells = build_cells(variants, args.systems.split(","), args.shapes.split(","), requested, caps)

    print(f"{len(cells)} cells x {args.reps} reps x {len(rtts)} RTT conditions, seed={args.seed}")
    for cell in cells:
        print(f"  {cell.id} sockets={cell.sockets} source_ips={cell.source_ips}")
    if args.dry_run:
        return

    ensure_up()
    with start_log(f"{args.name}.log"), measured_run(args.name):
        log_section("4. Denial-of-Service: stateless HQCLethe vs cookie-gated stateful baseline")
        if not keys_exist():
            setup_keys()
        print("Building servers and clients...")
        build_binaries()

        meta = {
            "timestamp": TS, "seed": args.seed, "reps": args.reps, "duration_s": args.duration,
            "variants": variants, "caps": caps, "rtts_ms": rtts, "botnet": BOTNET_NOTE,
            "probe_interval_ms": knobs.get("LEGIT_INTERVAL_MS"),
            "probe_timeout_s": knobs.get("LEGIT_TIMEOUT_S"),
            "recovery_probes": knobs.get("LEGIT_RECOVERY_PROBES"),
            "stateless_kinds": list(SYSTEMS["stateless"].flood_kinds),
            "knobs": knobs.resolved(), "rep_orders": {},
        }
        results: dict[str, dict] = {}
        grid_path = RAW_DIR / f"{args.name}.json"
        for rtt in rtts:
            log_section(f"legit-client RTT {rtt} ms")
            tc_apply(rtt)
            try:
                for rep in range(1, args.reps + 1):
                    order = shuffled_for_rep(cells, args.seed + rtt, rep)
                    meta["rep_orders"][f"rtt{rtt}/rep{rep}"] = [c.id for c in order]
                    for cell in order:
                        print(f"\n--- rtt={rtt}ms rep={rep}/{args.reps} {cell.id} "
                              f"sockets={cell.sockets} source_ips={cell.source_ips} ---", flush=True)
                        row = run_cell_once(cell, rep, args.duration, rep == args.reps)
                        key = f"rtt{rtt}/{cell.id}"
                        entry = results.setdefault(
                            key, {"cell": asdict(cell), "rtt_ms": rtt, "reps": [], "failed_reps": []})
                        entry["reps" if row else "failed_reps"].append(row or rep)
                        write_grid(grid_path, meta, results)
            finally:
                tc_clear()
        print(f"\nwrote {grid_path}")


if __name__ == "__main__":
    main()
