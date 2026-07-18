#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from common import VARIANTS, compose, dexec_client, dexec_py, dexec_server, log_section, start_log  # noqa: E402

PROFILES = {
    # name: (rtt_ms, jitter_ms, loss_pct)
    "local": (2, 0.5, 0),
    "same_continent": (20, 3, 0.05),
    "transatlantic": (75, 8, 0.1),
    "transpacific": (140, 15, 0.2),
    "satellite": (300, 20, 0.5),
}

# eval/run.py's --wan-reps overrides this via $WAN_REPS; standalone
# invocations (not through run.py) fall back to this default. See
# eval/scripts/container/wan_client_run.py.
WAN_REPS = int(os.environ.get("WAN_REPS", "30"))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", default="local")
    parser.add_argument("--remote")
    args = parser.parse_args()

    with start_log("wan_latency.log"):
        log_section("5. Network Latency & Congestion Control")

        compose("up", "-d", "server", "client")

        print("Building hqclethe-server and hqclethe-client...")
        dexec_server("cargo", "build", "--profile", "tiny-release", "-p", "hqclethe-server", "-q")
        dexec_server("cargo", "build", "--release", "-p", "hqclethe-client", "-q")

        if args.remote:
            print()
            print(
                f"--- Remote host mode: {args.remote} (netem skipped; "
                f"you must have a server already running there) ---"
            )
            for variant in VARIANTS:
                print()
                print(f"--- Variant: {variant} ({WAN_REPS} reps) ---")
                dexec_py("client", "wan_client_run.py", args.remote, variant, str(WAN_REPS))
            return

        if args.profile not in PROFILES:
            print(
                f"unknown profile '{args.profile}'; available: {', '.join(PROFILES)}",
                file=sys.stderr,
            )
            sys.exit(1)
        rtt_ms, jitter_ms, loss_pct = PROFILES[args.profile]

        print()
        print(
            f"--- WAN profile: {args.profile} (target RTT {rtt_ms}ms, "
            f"jitter {jitter_ms}ms, loss {loss_pct}%) ---"
        )
        print("Applying netem to the client container's egress...")
        dexec_client("tc", "qdisc", "del", "dev", "eth0", "root", check=False, capture_output=True)
        dexec_client(
            "tc", "qdisc", "add", "dev", "eth0", "root", "netem",
            "delay", f"{rtt_ms}ms", f"{jitter_ms}ms",
            "distribution", "normal", "loss", f"{loss_pct}%",
        )

        for variant in VARIANTS:
            print()
            print(f"--- Variant: {variant} ({WAN_REPS} reps) ---")
            dexec_py("server", "server_ctl.py", "start", "24200", variant)
            dexec_py("client", "wan_client_run.py", "server:24200", variant, str(WAN_REPS))

        print()
        print("Cleaning up netem qdisc and server...")
        dexec_client("tc", "qdisc", "del", "dev", "eth0", "root", check=False, capture_output=True)
        dexec_py("server", "server_ctl.py", "stop", "24200")


if __name__ == "__main__":
    main()
