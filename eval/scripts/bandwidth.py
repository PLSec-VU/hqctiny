#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from common import RAW_DIR, dexec_server, ensure_up, log_section, start_log  # noqa: E402


def main() -> None:
    ensure_up()
    with start_log("bandwidth.log"):
        log_section("2. Network Bandwidth and Packet Overhead")

        print("Building hqctiny-client (release)...")
        dexec_server("cargo", "build", "--release", "-p", "hqctiny-client", "-q")

        print()
        result = dexec_server(
            "/work/target-linux/release/hqctiny-client", "bandwidth-report", capture_output=True
        )
        report_json = result.stdout
        print(report_json, end="")
        (RAW_DIR / "bandwidth.json").write_text(report_json)

        print()
        print("--- Summary ---")
        data = json.loads(report_json)
        for v in data:
            status = "OK" if v["mtu_ok"] else "MTU VIOLATION"
            print(
                f"{v['variant']:5} | {v['round_trips']:2} round trips | "
                f"sent {v['total_sent_bytes']:6}B + received {v['total_received_bytes']:6}B "
                f"= {v['total_bytes']:6}B total | raw pk+ct baseline {v['raw_baseline_bytes']:6}B "
                f"| overhead {v['overhead_ratio']:.2f}x | max packet {v['max_packet_bytes']:4}B "
                f"/ {v['mtu_limit_bytes']}B MTU: {status}"
            )


if __name__ == "__main__":
    main()
