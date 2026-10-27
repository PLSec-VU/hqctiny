"""Repetition counts and durations for every category, in one place.

Each knob is an environment variable. `EVAL_SMOKE=1` (set by
`eval/run_all.sh --smoke`) switches the defaults to the small values. A
variable you set yourself always wins over both.
"""

from __future__ import annotations

import os

FULL = {
    "VARIANTS": "hqc1 hqc3 hqc5",
    "CPU_SESSIONS": "1000",
    "CPU_REPS": "5",
    "MCTINY_SESSIONS": "100",
    "DOS_REPS": "10",
    "FLOOD_DURATION": "10",
    "LEGIT_INTERVAL_MS": "200",
    "LEGIT_RECOVERY_PROBES": "3",
    "LEGIT_TIMEOUT_S": "10",
    "SINGLE_HOST_SOCKETS": "128",
    "BOTNET_IPS": "1024",
    "BOTNET_SOCKETS": "4096",
    "DOS_CAPS": "16 64 256 1024",
    "WAN_REPS": "30",
    "AUDIT_SESSIONS": "50",
    "CRITERION_ARGS": "",
    "SKIP_CALLGRIND": "0",
    "STRACE_BURST": "1",
}

SMOKE = {
    "VARIANTS": "hqc1",
    "CPU_SESSIONS": "40",
    "CPU_REPS": "1",
    "MCTINY_SESSIONS": "10",
    "DOS_REPS": "1",
    "FLOOD_DURATION": "3",
    "LEGIT_INTERVAL_MS": "500",
    "LEGIT_RECOVERY_PROBES": "2",
    "LEGIT_TIMEOUT_S": "10",
    "SINGLE_HOST_SOCKETS": "32",
    "BOTNET_IPS": "64",
    "BOTNET_SOCKETS": "256",
    "DOS_CAPS": "16 1024",
    "WAN_REPS": "3",
    "AUDIT_SESSIONS": "5",
    "CRITERION_ARGS": "--quick",
    "SKIP_CALLGRIND": "1",
    "STRACE_BURST": "0",
}


def is_smoke() -> bool:
    return os.environ.get("EVAL_SMOKE") == "1"


def defaults() -> dict[str, str]:
    return dict(SMOKE if is_smoke() else FULL)


def get(name: str) -> str:
    return os.environ.get(name, defaults()[name])


def get_int(name: str) -> int:
    return int(get(name))


def resolved() -> dict[str, str]:
    """Every knob with the value this run uses."""
    return {name: get(name) for name in FULL}
