#!/usr/bin/env python3
"""Category 10: resident memory of the stateless and stateful servers, idle
and after 20 sessions, three repetitions per variant (container/memfoot.py).

Output: raw/memfoot.json and one server log per run next to it.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from common import RAW_DIR, cargo_build, dexec_py, ensure_up, hqc_features, log_section, start_log  # noqa: E402

CONTAINER_RAW_DIR = "/work/eval/results"


def build() -> None:
    quiet = hqc_features("quiet")
    cargo_build("--profile", "tiny-release", "-p", "hqclethe-server", features=quiet)
    cargo_build("--profile", "tiny-release", "-p", "hqclethe-stateful",
                "--bin", "hqclethe-server-stateful", features=quiet)
    cargo_build("--release", "-p", "hqclethe-client", features=quiet)
    cargo_build("--release", "-p", "hqclethe-stateful",
                "--bin", "hqclethe-client-stateful", features=quiet)


def main() -> None:
    ensure_up()
    with start_log("rss.log"):
        log_section("10. Resident memory, idle and after 20 sessions")
        build()
        out = f"{CONTAINER_RAW_DIR}/{RAW_DIR.parent.name}/raw/memfoot.json"
        dexec_py("server", "memfoot.py", out)


if __name__ == "__main__":
    main()
