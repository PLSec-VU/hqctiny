#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from common import VARIANTS, dexec_py, dexec_server, ensure_up, log_section, start_log  # noqa: E402


def main() -> None:
    ensure_up()
    with start_log("memory_footprint.log"):
        log_section("1. Memory and Storage Footprint")

        print("Building hqclethe-server (tiny-release profile), stack-test, and hqclethe-client...")
        # --features quiet: the strace audit below drives 50 real client
        # sessions per variant, each of which would otherwise print a
        # session key -- 150 lines of noise in the log, and (as with
        # category 4's flood build) an extra write syscall/formatting pass
        # per session that has no business being in a memory/allocation
        # measurement.
        dexec_server(
            "cargo", "build", "--profile", "tiny-release", "-p", "hqclethe-server",
            "--features", "quiet,avx2", "-q",
        )
        dexec_server("cargo", "build", "--profile", "tiny-release", "--bin", "stack-test", "--features", "avx2", "-q")
        dexec_server("cargo", "build", "--release", "-p", "hqclethe-client", "--features", "avx2", "-q")

        print()
        print("--- Static binary size (text/data/bss) ---")
        dexec_server("size", "/work/target-linux/tiny-release/hqclethe-server")

        print()
        print("--- Minimum stack size (ulimit -s binary search, HQC-5 round trip) ---")
        dexec_py("server", "stack_search.py")

        for variant in VARIANTS:
            print()
            print(f"--- Dynamic allocation audit: {variant}, strace across 50 client sessions ---")
            dexec_py("server", "memory_syscall_audit.py", variant, "50", "24001")


if __name__ == "__main__":
    main()
