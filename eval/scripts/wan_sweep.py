#!/usr/bin/env python3
"""WAN comparison of stateless HqcLethe, the stateful baseline and McTiny.

A cell is one network condition: RTT, jitter, loss model and the direction
that carries the loss. The cell sets are:

  profiles  the five RTT profiles, each with its own small loss, for each
            direction in --directions (default uplink and both)
  ge        one Gilbert-Elliott burst-loss profile (about 5% per direction,
            20 ms RTT, 3 ms jitter), loss in both directions
  loss      20 ms RTT, 3 ms jitter, uniform independent loss in both
            directions at each rate of --losses (default 0, 1, 2, 2.5, 3, 4, 5 %)
  stress    satellite RTT and jitter (300 ms, 20 ms) with 5 % uniform loss, and
            with the Gilbert-Elliott model, loss in both directions (not in
            the default sets)

--sets picks the sets (default all three). --profiles, --directions and
--losses narrow them. --only keeps the cells whose id contains one of the
given texts, so a long run can be split over several invocations; give each
a --name so the outputs do not overwrite each other. --list prints the
cells and exits. STATEFUL_SERVER_ARGS (host environment) passes extra
options to the stateful server, for example --cookie-lifetime-ms 3000.
--stateful-stats builds the stateful server with its statistics probe and
records the server counters of every stateful session (wan_client_run.py). Cell ids look like `same_continent/uplink`, `ge/both`,
`loss2.5/both`.

HqcLethe's two servers run in two Docker Compose services, each with its own
eth0. netem on each eth0 shapes that side's egress, which gives independent
uplink and downlink control. McTiny is a host program. It gets the same
shape from two `ip netns` namespaces joined by one veth pair
(mctiny_netns.py). Delay is half the RTT on each side.

For each cell the three systems run as blocks of --reps sessions, block
order shuffled with a seed derived from the cell id. A session that does
not finish within SESSION_TIMEOUT_S counts as a failure. The HqcLethe client
script and the McTiny launcher both enforce the timeout from Python, with no
`timeout` program in the chain.

Timing differs by system. HqcLethe `session_s` runs from the first request
sent to the session key derived (client-side timestamps). McTiny `session_s`
runs from the creation of the client process to its exit, so it also
contains the client's start-up and key set-up. Both exclude `sudo`.
Every HqcLethe row also has `process_s`, the wall time of the whole client
process (start-up and key generation included), which is the McTiny
`session_s` way of timing. Every McTiny row also has `network_s`, from the
first packet sent to the last reply received, parsed from the McTiny client
stderr. That stderr is kept in raw/<name>_mctiny_stderr/<system>_<cell>/
repNNN.stderr.gz. `--only-mctiny` runs just the McTiny blocks.

Output: raw/<name>.json (meta, and per `system/cell` the per-session rows)
and raw/<name>.log. wan_bootstrap_ci.py turns one or more of these files into
a table.

  eval/scripts/wan_sweep.py [--sets profiles,ge,loss] [--reps 30] [--name wan_sweep]
      [--only loss4,loss5] [--systems stateless,stateful,mctiny] [--only-mctiny] [--list]
"""

from __future__ import annotations

import argparse
import base64
import gzip
import json
import os
import random
import statistics
import subprocess
import sys
import time
import zlib
from dataclasses import asdict, dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from common import (  # noqa: E402
    RAW_DIR, TS, cargo_build, compose, dexec, dexec_client, dexec_py, dexec_server, hqc_features,
    knobs, log_section, measured_run, setup_keys, start_log,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent / "container"))
import mctiny_netns as mn  # noqa: E402
from placement import CLIENT_CORE, SERVER_CORE  # noqa: E402

DEFAULT_VARIANT = "hqc5"
SESSION_TIMEOUT_S = 300
PROFILES = {
    "local": (2, 0.5, 0),
    "same_continent": (20, 3, 0.05),
    "transatlantic": (75, 8, 0.1),
    "transpacific": (140, 15, 0.2),
    "satellite": (300, 20, 0.5),
}
DIRECTIONS = ("uplink", "both")
SWEEP_RTT_MS, SWEEP_JITTER_MS = 20, 3
SWEEP_LOSSES_PCT = (0, 1, 2, 2.5, 3, 4, 5)
SWEEP_DIRECTION = "both"
# Gilbert-Elliott: p, r, 1-h, 1-k as percentages for `tc netem loss gemodel`.
# The bad state has 50% loss, the good state 1%. The mean is
# frac_bad * 0.50 + (1 - frac_bad) * 0.01 with frac_bad = p / (p + r) = 0.0816,
# which is 4.97% per direction.
GE_PARAMS = (2.667, 30.0, 50.0, 1.0)
GE_RTT_MS, GE_JITTER_MS = SWEEP_RTT_MS, SWEEP_JITTER_MS
SETS = ("profiles", "ge", "loss")
STRESS_RTT_MS, STRESS_JITTER_MS = PROFILES["satellite"][:2]
STRESS_UNIFORM_LOSS_PCT = 5.0
SYSTEMS = ("stateless", "stateful", "mctiny")
WAN_PORTS = {"stateless": "24200", "stateful": "24201"}
MCTINY_PORT = 24420
MCTINY_DIR = os.environ.get("MCTINY_DIR", str(Path.home() / "mctiny_build" / "mctiny-20200804"))
MCTINY_STATE = os.environ.get("MCTINY_STATE", str(Path.home() / "mctiny_state"))
MCTINY_SERVER_STARTUP_S = 1.0
LAUNCHER = Path(__file__).resolve().parent / "mctiny_session_launcher.py"
LAUNCHER_SLACK_S = 30
SERVER_STOP_WAIT_S = 5
MCTINY_SERVER_NAME = "mctiny-server"


@dataclass(frozen=True)
class Cell:
    name: str
    direction: str
    rtt_ms: float
    jitter_ms: float
    loss_pct: float
    gemodel: tuple | None = None

    @property
    def id(self) -> str:
        return f"{self.name}/{self.direction}"


def loss_label(loss_pct: float) -> str:
    return f"loss{loss_pct:g}"


def build_cells(sets: list[str], profiles: list[str], directions: list[str], losses: list[float]) -> list[Cell]:
    cells = []
    if "profiles" in sets:
        for name in profiles:
            rtt, jitter, loss = PROFILES[name]
            cells += [Cell(name, d, rtt, jitter, loss) for d in directions]
    if "ge" in sets:
        cells.append(Cell("ge", "both", GE_RTT_MS, GE_JITTER_MS, 0.0, GE_PARAMS))
    if "loss" in sets:
        cells += [
            Cell(loss_label(loss), SWEEP_DIRECTION, SWEEP_RTT_MS, SWEEP_JITTER_MS, loss) for loss in losses
        ]
    if "stress" in sets:
        cells += [
            Cell(f"sat_{loss_label(STRESS_UNIFORM_LOSS_PCT)}", SWEEP_DIRECTION, STRESS_RTT_MS, STRESS_JITTER_MS,
                 STRESS_UNIFORM_LOSS_PCT),
            Cell("sat_ge", SWEEP_DIRECTION, STRESS_RTT_MS, STRESS_JITTER_MS, 0.0, GE_PARAMS),
        ]
    return cells


def set_netem_container(service: str, half_rtt_ms: float, half_jitter_ms: float, loss_pct: float,
                        gemodel: tuple | None) -> None:
    run = dexec_client if service == "client" else dexec_server
    run("tc", "qdisc", "del", "dev", "eth0", "root", check=False, capture_output=True)
    cmd = ["tc", "qdisc", "add", "dev", "eth0", "root", "netem", "delay", f"{half_rtt_ms:.2f}ms"]
    if half_jitter_ms > 0:
        cmd += [f"{half_jitter_ms:.2f}ms", "distribution", "normal"]
    if gemodel:
        cmd += ["loss", "gemodel", *[str(x) for x in gemodel]]
    elif loss_pct > 0:
        cmd += ["loss", f"{loss_pct}%"]
    run(*cmd)


def apply_netem_all(cell: Cell) -> None:
    half_rtt, half_jitter = cell.rtt_ms / 2, cell.jitter_ms / 2
    uplink_lossy = cell.direction in ("uplink", "both")
    downlink_lossy = cell.direction in ("downlink", "both")
    set_netem_container(
        "client", half_rtt, half_jitter, cell.loss_pct if uplink_lossy else 0.0,
        cell.gemodel if uplink_lossy else None)
    set_netem_container(
        "server", half_rtt, half_jitter, cell.loss_pct if downlink_lossy else 0.0,
        cell.gemodel if downlink_lossy else None)
    mn.apply_netem(cell.rtt_ms, cell.jitter_ms, cell.loss_pct, cell.direction, gemodel=cell.gemodel)


def clear_netem_all() -> None:
    dexec_client("tc", "qdisc", "del", "dev", "eth0", "root", check=False, capture_output=True)
    dexec_server("tc", "qdisc", "del", "dev", "eth0", "root", check=False, capture_output=True)
    mn.clear_netem()


def find_mctiny_pk() -> str:
    keys = list(Path(MCTINY_STATE, "public").iterdir())
    assert len(keys) == 1, keys
    return str(keys[0])


def save_mctiny_stderr(stderr_path: Path, result: dict) -> None:
    encoded = result.pop("stderr_gz_b64", None)
    if encoded is None:
        return
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.write_bytes(base64.b64decode(encoded))
    result["stderr_file"] = str(stderr_path.relative_to(RAW_DIR))


def mctiny_stderr_path(name: str, block_key: str, rep: int) -> Path:
    return RAW_DIR / f"{name}_mctiny_stderr" / block_key.replace("/", "_") / f"rep{rep:03d}.stderr.gz"


def run_mctiny_session(pk_file: str) -> dict:
    command = [
        "sudo", "ip", "netns", "exec", mn.NETNS_CLI, sys.executable, str(LAUNCHER),
        str(CLIENT_CORE), str(SESSION_TIMEOUT_S), f"{MCTINY_DIR}/mctiny-client", pk_file, mn.IP_SRV,
        str(MCTINY_PORT),
    ]
    try:
        done = subprocess.run(command, capture_output=True, text=True, timeout=SESSION_TIMEOUT_S + LAUNCHER_SLACK_S)
    except subprocess.TimeoutExpired:
        return {"ok": False, "session_s": None, "reason": "launcher_hung"}
    lines = done.stdout.strip().splitlines()
    if done.returncode != 0 or not lines:
        return {"ok": False, "session_s": None, "reason": "launcher_failed", "stderr_tail": done.stderr[-400:]}
    return json.loads(lines[-1])


def run_mctiny_block(n: int, name: str, block_key: str) -> list[dict]:
    pk_file = find_mctiny_pk()
    server = subprocess.Popen(
        ["sudo", "ip", "netns", "exec", mn.NETNS_SRV, "taskset", "-c", str(SERVER_CORE),
         f"{MCTINY_DIR}/{MCTINY_SERVER_NAME}", MCTINY_STATE, mn.IP_SRV, str(MCTINY_PORT)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(MCTINY_SERVER_STARTUP_S)
        results = []
        for rep in range(1, n + 1):
            res = run_mctiny_session(pk_file)
            save_mctiny_stderr(mctiny_stderr_path(name, block_key, rep), res)
            results.append(res)
            tag = "OK" if res["ok"] else f"FAIL({res.get('reason', res.get('returncode'))})"
            seconds = res["session_s"]
            network = res.get("network_s")
            print(f"mctiny rep {rep}/{n}: {tag} session_s={'-' if seconds is None else f'{seconds:.4f}'} "
                  f"network_s={'-' if network is None else f'{network:.4f}'} "
                  f"packets_sent={res.get('packets_sent')} packets_received={res.get('packets_received')}",
                  flush=True)
        return results
    finally:
        stop_mctiny_server(server)


def stop_mctiny_server(server: subprocess.Popen) -> None:
    server.terminate()
    try:
        server.wait(timeout=SERVER_STOP_WAIT_S)
    except subprocess.TimeoutExpired:
        subprocess.run(["sudo", "pkill", "-KILL", "-x", MCTINY_SERVER_NAME], check=False)
        server.kill()
        server.wait(timeout=SERVER_STOP_WAIT_S)


def run_hqclethe_block(system: str, variant: str, n: int, client_env: dict[str, str]) -> list[dict]:
    port = WAN_PORTS[system]
    dexec_py("server", "server_ctl.py", "start", port, variant, system)
    try:
        done = dexec("client", "python3", "/work/eval/scripts/container/wan_client_run.py",
                     f"server:{port}", variant, str(n), system, capture_output=True, check=False,
                     extra_env=client_env)
    finally:
        dexec_py("server", "server_ctl.py", "stop", port)
    print(done.stdout)
    if done.stderr:
        print(done.stderr, file=sys.stderr)
    for line in done.stdout.splitlines():
        if line.startswith("RESULT "):
            return json.loads(line[len("RESULT "):])["rows"]
    return [{"rep": rep, "ok": False, "session_s": None, "reason": "no_result"} for rep in range(1, n + 1)]


def summarize(values: list[float]) -> dict:
    if not values:
        return {}
    p95 = statistics.quantiles(values, n=20, method="inclusive")[18] if len(values) >= 2 else values[0]
    return {"median": statistics.median(values), "p95": p95, "max": max(values), "n": len(values)}


def block_order(cell: Cell, systems: list[str]) -> tuple[int, list[str]]:
    seed = zlib.crc32(cell.id.encode())
    order = list(systems)
    random.Random(seed).shuffle(order)
    return seed, order


def select_cells(cells: list[Cell], only: str | None) -> list[Cell]:
    if not only:
        return cells
    wanted = only.split(",")
    return [c for c in cells if any(w in c.id for w in wanted)]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--sets", default=",".join(SETS))
    parser.add_argument("--profiles", default=",".join(PROFILES))
    parser.add_argument("--directions", default=",".join(DIRECTIONS))
    parser.add_argument("--losses", default=",".join(f"{x:g}" for x in SWEEP_LOSSES_PCT),
                        help="uniform loss rates in percent for the loss set")
    parser.add_argument("--only", help="keep cells whose id contains one of these comma-separated texts")
    parser.add_argument("--systems", default=",".join(SYSTEMS))
    parser.add_argument("--only-mctiny", action="store_true",
                        help="run only the McTiny blocks (same as --systems mctiny)")
    parser.add_argument("--variant", default=DEFAULT_VARIANT)
    parser.add_argument("--reps", type=int, default=knobs.get_int("WAN_REPS"))
    parser.add_argument("--name", default="wan_sweep")
    parser.add_argument("--stateful-stats", action="store_true",
                        help="build the stateful server with its statistics probe and record its "
                             "counters around every stateful session")
    parser.add_argument("--list", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    cells = select_cells(
        build_cells(args.sets.split(","), args.profiles.split(","), args.directions.split(","),
                    [float(x) for x in args.losses.split(",")]),
        args.only)
    systems = ["mctiny"] if args.only_mctiny else args.systems.split(",")
    print(f"{len(cells)} cells x {len(systems)} systems x {args.reps} sessions")
    for cell in cells:
        print(f"  {cell.id}: rtt={cell.rtt_ms}ms jitter={cell.jitter_ms}ms loss={cell.loss_pct}% gemodel={cell.gemodel}")
    if args.list:
        return

    with start_log(f"{args.name}.log"), measured_run(args.name):
        log_section("5. WAN: HqcLethe (stateless, stateful) and McTiny")
        compose("up", "-d", "server", "client")
        setup_keys([args.variant])
        features = hqc_features("quiet")
        cargo_build("--profile", "tiny-release", "-p", "hqclethe-server", features=features)
        stateful_server_features = hqc_features("quiet", "flood-stats") if args.stateful_stats else features
        cargo_build("--profile", "tiny-release", "-p", "hqclethe-stateful",
                    "--bin", "hqclethe-server-stateful", features=stateful_server_features)
        client_env = {"WAN_STATEFUL_STATS": "1"} if args.stateful_stats else {}
        cargo_build("--release", "-p", "hqclethe-client", features=features)
        cargo_build("--release", "-p", "hqclethe-stateful", "--bin", "hqclethe-client-stateful",
                    features=features)

        meta = {
            "timestamp": TS, "variant": args.variant, "reps": args.reps, "systems": systems,
            "session_timeout_s": SESSION_TIMEOUT_S, "cells": [asdict(c) for c in cells],
            "stateful_server_args": os.environ.get("STATEFUL_SERVER_ARGS", ""),
            "stateful_stats": args.stateful_stats,
            "timing_note": "hqclethe session_s: first request sent to key derived (client timestamps); "
                           "hqclethe process_s: whole client process incl. start-up and key generation; "
                           "mctiny session_s: client process creation to exit (= process_s); "
                           "mctiny network_s: first packet sent to last reply received, parsed from the "
                           "stored client stderr (<name>_mctiny_stderr/)",
        }
        results: dict[str, list] = {}
        out_path = RAW_DIR / f"{args.name}.json"
        mn.up()
        try:
            for cell in cells:
                print(f"\n=== cell {cell.id}: rtt={cell.rtt_ms}ms jitter={cell.jitter_ms}ms "
                      f"loss={cell.loss_pct}% gemodel={cell.gemodel} ===", flush=True)
                apply_netem_all(cell)
                seed, order = block_order(cell, systems)
                print(f"block order (seed={seed}): {order}")
                for system in order:
                    print(f"--- block {cell.id} system={system} n={args.reps} ---", flush=True)
                    rows = (run_mctiny_block(args.reps, args.name, f"{system}/{cell.id}") if system == "mctiny"
                            else run_hqclethe_block(system, args.variant, args.reps, client_env))
                    results[f"{system}/{cell.id}"] = rows
                    oks = [r["session_s"] for r in rows if r["ok"]]
                    print(f"SUMMARY {system}/{cell.id}: n_ok={len(oks)} n_fail={len(rows) - len(oks)} "
                          f"{json.dumps(summarize(oks))}")
                    out_path.write_text(json.dumps({"meta": meta, "results": results}, indent=1) + "\n")
                clear_netem_all()
        finally:
            clear_netem_all()
            mn.down()
            for port in WAN_PORTS.values():
                dexec_py("server", "server_ctl.py", "stop", port)
        print(f"\nwrote {out_path}")


if __name__ == "__main__":
    main()
