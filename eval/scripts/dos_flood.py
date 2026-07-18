#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from common import VARIANTS, dexec_py, dexec_server, ensure_up, log_section, start_log  # noqa: E402

FLOOD_DURATION = 8
SOCKETS = 128
REPS = int(os.environ.get("DOS_REPS", "10"))
KINDS = ["handshake", "point"]


def main() -> None:
    ensure_up()
    with start_log("dos_flood.log"):
        log_section("4. Denial-of-Service (DoS) Resilience")

        print("Building hqclethe-server and hqclethe-client...")
        dexec_server(
            "cargo", "build", "--profile", "tiny-release", "-p", "hqclethe-server",
            "--features", "quiet,flood-stats", "-q",
        )
        dexec_server("cargo", "build", "--release", "-p", "hqclethe-client", "-q")

        for variant in VARIANTS:
            for kind in KINDS:
                print()
                print(
                    f"--- Variant: {variant}, kind: {kind} (flood: {FLOOD_DURATION}s x {REPS} reps, "
                    f"{SOCKETS} sockets) ---"
                )
                dexec_py(
                    "server", "dos_flood_variant.py", variant, str(FLOOD_DURATION), str(SOCKETS),
                    str(REPS), kind,
                )


if __name__ == "__main__":
    main()
