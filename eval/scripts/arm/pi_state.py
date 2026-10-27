#!/usr/bin/env python3
"""Clock, temperature and throttle state of a Raspberry Pi.

  pi_state.py snapshot             one JSON line
  pi_state.py sample FILE SECS     append one JSON line every SECS until killed
  pi_state.py wait-cool MAX_C      block until the SoC is below MAX_C degrees

Run as root: cpuinfo_cur_freq and vcgencmd need it.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

CPU_DIR = Path("/sys/devices/system/cpu")
THERMAL = Path("/sys/class/thermal/thermal_zone0/temp")
THROTTLE_BITS = {
    0: "under_voltage", 1: "freq_capped", 2: "throttled", 3: "soft_temp_limit",
    16: "under_voltage_occurred", 17: "freq_capped_occurred", 18: "throttled_occurred",
    19: "soft_temp_limit_occurred",
}


def read_text(path: Path) -> str:
    return path.read_text().strip()


def cpus() -> list[Path]:
    return sorted(CPU_DIR.glob("cpu[0-9]*"), key=lambda p: int(p.name[3:]))


def throttled_flags() -> dict:
    out = subprocess.run(["vcgencmd", "get_throttled"], capture_output=True, text=True).stdout
    value = int(out.strip().split("=")[1], 16)
    return {"raw": hex(value), "active": [n for b, n in THROTTLE_BITS.items() if b < 16 and value >> b & 1],
            "occurred": [n for b, n in THROTTLE_BITS.items() if b >= 16 and value >> b & 1]}


def arm_clock_hz() -> int:
    out = subprocess.run(["vcgencmd", "measure_clock", "arm"], capture_output=True, text=True).stdout
    return int(out.strip().split("=")[1])


def temperature_c() -> float:
    return int(read_text(THERMAL)) / 1000


def snapshot() -> dict:
    return {
        "time": time.time(),
        "temp_c": temperature_c(),
        "arm_clock_hz": arm_clock_hz(),
        "freq_khz": {c.name: int(read_text(c / "cpufreq/cpuinfo_cur_freq")) for c in cpus()},
        "governor": {c.name: read_text(c / "cpufreq/scaling_governor") for c in cpus()},
        "throttled": throttled_flags(),
    }


def wait_cool(max_c: float) -> None:
    while temperature_c() >= max_c:
        time.sleep(2)


def main() -> None:
    mode = sys.argv[1]
    if mode == "snapshot":
        print(json.dumps(snapshot()))
    elif mode == "sample":
        interval = float(sys.argv[3])
        with open(sys.argv[2], "a", buffering=1) as out:
            while True:
                out.write(json.dumps(snapshot()) + "\n")
                time.sleep(interval)
    elif mode == "wait-cool":
        wait_cool(float(sys.argv[2]))


if __name__ == "__main__":
    main()
