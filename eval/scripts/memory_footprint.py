#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from common import (  # noqa: E402
    VARIANTS, cargo_build, dexec_py, dexec_server, ensure_up, hqc_features, knobs, log_section, setup_keys,
    start_log,
)


def main() -> None:
    ensure_up()
    with start_log("memory_footprint.log"):
        log_section("1. Memory and Storage Footprint")

        print("Building the servers (tiny-release profile) and hqclethe-client...")
        # --features quiet: the strace audit below drives 50 real client
        # sessions per variant, each of which would otherwise print a
        # session key -- 150 lines of noise in the log, and (as with
        # category 4's flood build) an extra write syscall/formatting pass
        # per session that has no business being in a memory/allocation
        # measurement.
        setup_keys()
        quiet = hqc_features("quiet")
        cargo_build("--profile", "tiny-release", "-p", "hqclethe-server", features=quiet)
        cargo_build("--profile", "tiny-release", "-p", "hqclethe-stateful",
                    "--bin", "hqclethe-server-stateful", features=quiet)
        cargo_build("--release", "-p", "hqclethe-client", features=quiet)

        print()
        print("--- Static binary size (text/data/bss) ---")
        dexec_server(
            "size", "/work/target-linux/tiny-release/hqclethe-server",
            "/work/target-linux/tiny-release/hqclethe-server-stateful",
        )

        print()
        print("(minimum stack: category 7, scripts/stack.py)")

        for variant in VARIANTS:
            print()
            print(f"--- Dynamic allocation audit: {variant}, strace across {knobs.get('AUDIT_SESSIONS')} client sessions ---")
            dexec_py("server", "memory_syscall_audit.py", variant, knobs.get("AUDIT_SESSIONS"), "24001")


if __name__ == "__main__":
    main()
