#!/usr/bin/env python3
"""Runs inside the eval container. Binary-searches ulimit -s for the
smallest stack size stack-test (one full HQC-5 round trip, client+server,
the deepest call stack the implementation produces) survives.
"""

from __future__ import annotations

import resource
import subprocess

BIN = "/work/target-linux/tiny-release/stack-test"


def survives(stack_kb: int) -> bool:
    def set_limit() -> None:
        limit_bytes = stack_kb * 1024
        resource.setrlimit(resource.RLIMIT_STACK, (limit_bytes, limit_bytes))

    result = subprocess.run(
        [BIN], preexec_fn=set_limit, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    return result.returncode == 0


def main() -> None:
    low, high = 64, 8192
    if not survives(high):
        print(f"note: fails even at {high}KB, raising search ceiling")
        high = 65536

    while high - low > 8:
        mid = (low + high) // 2
        if survives(mid):
            high = mid
        else:
            low = mid

    print(f"minimum_stack_kb (upper bound, 8KB search resolution): {high}")


if __name__ == "__main__":
    main()
