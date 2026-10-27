#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from common import RAW_DIR, cargo_build, dexec_server, ensure_up, log_section, start_log  # noqa: E402

CLIENTS = {
    "stateless": ("hqclethe-client", "hqclethe-client", "bandwidth.json"),
    "stateful": ("hqclethe-stateful", "hqclethe-client-stateful", "bandwidth_stateful.json"),
}


def datagram_count(report: dict) -> int:
    """Request datagrams of one session. The stateless report counts one per
    round trip; the stateful report lists its request packets."""
    return report.get("round_trips") or report["packets_sent"]


def worst_amplification(report: dict) -> float:
    return max(kind["amplification_ratio"] for kind in report["packets"])


def summarize(system: str, data: list[dict]) -> None:
    for v in data:
        status = "OK" if v["mtu_ok"] else "MTU VIOLATION"
        print(
            f"{system:9} {v['variant']:5} | {datagram_count(v):2} requests | "
            f"sent {v['total_sent_bytes']:6}B + received {v['total_received_bytes']:6}B "
            f"= {v['total_bytes']:6}B total | raw pk+ct baseline {v['raw_baseline_bytes']:6}B "
            f"| overhead {v['overhead_ratio']:.2f}x | worst single-request amplification "
            f"{worst_amplification(v):.2f} | max packet {v['max_packet_bytes']:4}B "
            f"/ {v['mtu_limit_bytes']}B MTU: {status}"
        )
        for kind in v["packets"]:
            print(
                f"{'':9} {'':5}   {kind['kind']:13} x{kind['count']:<3} request {kind['request_bytes']:5}B "
                f"response {kind['response_bytes']:5}B amplification {kind['amplification_ratio']:.2f}"
            )


def main() -> None:
    ensure_up()
    with start_log("bandwidth.log"):
        log_section("2. Network Bandwidth and Packet Overhead (both systems, with ML-KEM auth)")

        print("Building the clients (release)...")
        cargo_build("--release", "-p", "hqclethe-client")
        cargo_build("--release", "-p", "hqclethe-stateful", "--bin", "hqclethe-client-stateful")

        for system, (_package, binary, out_name) in CLIENTS.items():
            print()
            print(f"--- {system} ---")
            result = dexec_server(
                f"/work/target-linux/release/{binary}", "bandwidth-report", capture_output=True
            )
            print(result.stdout, end="")
            (RAW_DIR / out_name).write_text(result.stdout)
            print()
            print("--- Summary ---")
            summarize(system, json.loads(result.stdout))


if __name__ == "__main__":
    main()
