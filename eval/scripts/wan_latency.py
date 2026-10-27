#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from common import (  # noqa: E402
    VARIANTS, cargo_build, compose, dexec_client, dexec_py, dexec_server, hqc_features, knobs, log_section, measured_run,
    start_log,
)

PROFILES = {
    # name: (rtt_ms, jitter_ms, loss_pct)
    # rtt_ms is the full round-trip time; half is applied to each direction.
    "local": (2, 0.5, 0),
    "same_continent": (20, 3, 0.05),
    "transatlantic": (75, 8, 0.1),
    "transpacific": (140, 15, 0.2),
    "satellite": (300, 20, 0.5),
}

# Loss directions. In all cases both sides get half the RTT delay, matching a
# symmetric WAN. "uplink" and "downlink" add loss to one direction only;
# "both" adds it symmetrically. The default is "uplink" so the reviewer
# concern about McTiny's large client-to-server upload is directly addressed.
DIRECTIONS = ("uplink", "downlink", "both")

WAN_REPS = knobs.get_int("WAN_REPS")
SYSTEM_NAMES = ("stateless", "stateful")
WAN_PORTS = {"stateless": "24200", "stateful": "24201"}


def _set_netem(service: str, half_rtt_ms: float, half_jitter_ms: float, loss_pct: float) -> None:
    dexec = dexec_client if service == "client" else dexec_server
    dexec("tc", "qdisc", "del", "dev", "eth0", "root", check=False, capture_output=True)
    cmd = [
        "tc", "qdisc", "add", "dev", "eth0", "root", "netem",
        "delay", f"{half_rtt_ms:.2f}ms", f"{half_jitter_ms:.2f}ms", "distribution", "normal",
    ]
    if loss_pct > 0:
        cmd += ["loss", f"{loss_pct}%"]
    dexec(*cmd)


def _apply_netem(rtt_ms: float, jitter_ms: float, loss_pct: float, direction: str) -> None:
    half_rtt = rtt_ms / 2
    half_jitter = jitter_ms / 2
    client_loss = loss_pct if direction in ("uplink", "both") else 0.0
    server_loss = loss_pct if direction in ("downlink", "both") else 0.0
    _set_netem("client", half_rtt, half_jitter, client_loss)
    _set_netem("server", half_rtt, half_jitter, server_loss)


def _clear_netem() -> None:
    dexec_client("tc", "qdisc", "del", "dev", "eth0", "root", check=False, capture_output=True)
    dexec_server("tc", "qdisc", "del", "dev", "eth0", "root", check=False, capture_output=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", default="local")
    parser.add_argument(
        "--direction", default="uplink", choices=DIRECTIONS,
        help="which direction(s) carry the loss percentage (default: uplink). "
             "RTT delay is always split equally between both sides.",
    )
    parser.add_argument("--remote", help="host:port of a running stateless server")
    parser.add_argument("--remote-stateful", help="host:port of a running stateful server")
    args = parser.parse_args()

    with start_log("wan_latency.log"), measured_run("wan_latency"):
        log_section("5. Network Latency & Congestion Control")

        compose("up", "-d", "server", "client")

        print("Building both servers and both clients...")
        features = hqc_features()
        cargo_build("--profile", "tiny-release", "-p", "hqclethe-server", features=features)
        cargo_build("--profile", "tiny-release", "-p", "hqclethe-stateful", features=features)
        cargo_build("--release", "-p", "hqclethe-client", features=features)
        cargo_build("--release", "-p", "hqclethe-stateful", "--bin", "hqclethe-client-stateful",
                    features=features)

        remotes = {"stateless": args.remote, "stateful": args.remote_stateful}
        if args.remote or args.remote_stateful:
            print()
            print("--- Remote host mode (netem skipped; the servers must already run there) ---")
            for variant in VARIANTS:
                for system, remote in remotes.items():
                    if not remote:
                        continue
                    print()
                    print(f"--- {system} {variant} at {remote} ({WAN_REPS} reps) ---")
                    dexec_py("client", "wan_client_run.py", remote, variant, str(WAN_REPS), system)
            return

        profiles_to_run = list(PROFILES.keys()) if args.profile == "all" else [args.profile]
        for profile_name in profiles_to_run:
            if profile_name not in PROFILES:
                print(
                    f"unknown profile '{profile_name}'; available: {', '.join(PROFILES)}, all",
                    file=sys.stderr,
                )
                sys.exit(1)

        for profile_name in profiles_to_run:
            rtt_ms, jitter_ms, loss_pct = PROFILES[profile_name]

            print()
            print(
                f"--- WAN profile: {profile_name} "
                f"(RTT {rtt_ms}ms ±{jitter_ms}ms split equally, loss {loss_pct}% on {args.direction}) ---"
            )
            print(f"Applying {rtt_ms/2:.2f}ms one-way delay to both sides; loss on {args.direction}...")
            _apply_netem(rtt_ms, jitter_ms, loss_pct, args.direction)

            for variant in VARIANTS:
                for system in SYSTEM_NAMES:
                    port = WAN_PORTS[system]
                    print()
                    print(f"--- {system} {variant} profile={profile_name} direction={args.direction} ({WAN_REPS} reps) ---")
                    dexec_py("server", "server_ctl.py", "start", port, variant, system)
                    dexec_py("client", "wan_client_run.py", f"server:{port}", variant, str(WAN_REPS), system)
                    dexec_py("server", "server_ctl.py", "stop", port)

            print()
            print(f"Clearing netem after profile {profile_name}...")
            _clear_netem()

        print()
        print("Cleaning up servers...")
        for port in WAN_PORTS.values():
            dexec_py("server", "server_ctl.py", "stop", port)


if __name__ == "__main__":
    main()
