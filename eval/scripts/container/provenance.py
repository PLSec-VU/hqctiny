#!/usr/bin/env python3
"""Runs inside the eval container. Prints the container-side half of the
provenance record (host-side git/platform info is gathered separately, by
capture_provenance() in lib/common.py, since it doesn't need a container).
"""

from __future__ import annotations

import os
import platform
import re
import subprocess
from pathlib import Path


def sh(*argv: str) -> str:
    try:
        return subprocess.run(argv, capture_output=True, text=True, check=True).stdout.strip()
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        return f"(unavailable: {e})"


def cpu_model() -> str:
    try:
        text = Path("/proc/cpuinfo").read_text()
    except OSError:
        return "(unavailable)"
    m = re.search(r"^model name\s*:\s*(.+)$", text, re.MULTILINE)
    return m.group(1) if m else "(not present in /proc/cpuinfo -- e.g. under QEMU/Rosetta emulation)"


def cpu_flags() -> str:
    try:
        text = Path("/proc/cpuinfo").read_text()
    except OSError:
        return "(unavailable)"
    m = re.search(r"^flags\s*:\s*(.+)$", text, re.MULTILINE)
    if not m:
        return "(not present in /proc/cpuinfo)"
    wanted = ("avx2", "bmi1", "bmi2", "pclmulqdq", "avx512f")
    present = set(m.group(1).split())
    return " ".join(f"{flag}={'yes' if flag in present else 'no'}" for flag in wanted)


def mem_total() -> str:
    try:
        text = Path("/proc/meminfo").read_text()
    except OSError:
        return "(unavailable)"
    m = re.search(r"^MemTotal:\s*(.+)$", text, re.MULTILINE)
    return m.group(1) if m else "(unavailable)"


def main() -> None:
    print(f"container_uname: {sh('uname', '-a')}")
    print(f"container_arch: {platform.machine()}")
    print(f"nproc: {sh('nproc')}")
    print(f"cpu_model: {cpu_model()}")
    print(f"cpu_flags: {cpu_flags()}")
    print(f"clock_ticks_per_second: {os.sysconf('SC_CLK_TCK')}")
    print(f"mem_total: {mem_total()}")
    print(f"rustc: {sh('rustc', '-V')}")
    print(f"cargo: {sh('cargo', '-V')}")
    print(f"iai_callgrind_runner: {sh('iai-callgrind-runner', '--version')}")
    print(f"valgrind: {sh('valgrind', '--version')}")


if __name__ == "__main__":
    main()
