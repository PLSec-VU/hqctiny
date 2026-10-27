"""Records and checks the state of the measurement host: governor, boost,
SMT and online state of every CPU, and the clock the pinned cores really
reach under load. Standard library only. Import, or run:

  python3 host_state.py [--cores 0,2,4] [--target-mhz 3169] [--seconds 2]

The command exits 0 when the host is in measurement state, 3 when not,
and prints the snapshot as JSON.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "container"))
import placement  # noqa: E402

CPU_ROOT = Path("/sys/devices/system/cpu")
BUSY_LOOP = "while True: pass"
RAMP_SECONDS = 0.6
SAMPLE_INTERVAL_SECONDS = 0.1
KHZ_PER_MHZ = 1000
INTERRUPTS_FILE = Path("/proc/interrupts")
IRQ_ROOT = Path("/proc/irq")
NET_ROOT = Path("/sys/class/net")
ROUTE_FILE = Path("/proc/net/route")
DEFAULT_ROUTE_DESTINATION = "00000000"
NIC_COUNTERS = ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "rx_dropped", "tx_dropped", "rx_errors", "tx_errors")


def read_text(path: Path) -> str | None:
    try:
        return path.read_text().strip()
    except OSError:
        return None


def cpu_numbers() -> list[int]:
    return sorted(int(p.name[3:]) for p in CPU_ROOT.glob("cpu[0-9]*"))


def cpu_record(number: int) -> dict:
    base = CPU_ROOT / f"cpu{number}"
    online = read_text(base / "online")
    return {
        "online": online != "0",
        "governor": read_text(base / "cpufreq" / "scaling_governor"),
        "epp": read_text(base / "cpufreq" / "energy_performance_preference"),
        "min_khz": read_text(base / "cpufreq" / "scaling_min_freq"),
        "max_khz": read_text(base / "cpufreq" / "scaling_max_freq"),
        "idle_cur_khz": read_text(base / "cpufreq" / "scaling_cur_freq"),
        "siblings": read_text(base / "topology" / "thread_siblings_list"),
    }


def nic_name() -> str | None:
    forced = os.environ.get("MEASURE_NIC")
    if forced:
        return forced
    text = read_text(ROUTE_FILE)
    for line in (text or "").splitlines()[1:]:
        fields = line.split()
        if len(fields) > 1 and fields[1] == DEFAULT_ROUTE_DESTINATION:
            return fields[0]
    return None


def nic_counters() -> dict:
    name = nic_name()
    if name is None:
        return {}
    values = {c: read_text(NET_ROOT / name / "statistics" / c) for c in NIC_COUNTERS}
    return {"interface": name, **{c: int(v) for c, v in values.items() if v and v.isdigit()}}


def interrupt_counts() -> dict[str, dict]:
    lines = (read_text(INTERRUPTS_FILE) or "").splitlines()
    if not lines:
        return {}
    cpus = [int(token[3:]) for token in lines[0].split()]
    rows = {}
    for line in lines[1:]:
        label, _, rest = line.partition(":")
        tokens = rest.split()
        counts = []
        for token in tokens[: len(cpus)]:
            if not token.isdigit():
                break
            counts.append(int(token))
        description = " ".join(tokens[len(counts):])
        rows[label.strip()] = {"description": description, "per_cpu": dict(zip(cpus, counts))}
    return rows


def irq_affinities() -> dict[str, dict]:
    result = {}
    for directory in sorted(IRQ_ROOT.glob("[0-9]*"), key=lambda p: int(p.name)):
        result[directory.name] = {
            "smp_affinity_list": read_text(directory / "smp_affinity_list"),
            "effective_affinity_list": read_text(directory / "effective_affinity_list"),
        }
    return result


def counters() -> dict:
    return {
        "time_monotonic": time.monotonic(),
        "nic": nic_counters(),
        "interrupts": interrupt_counts(),
        "irq_affinity": irq_affinities(),
    }


def counter_deltas(start: dict, end: dict, cores: list[int]) -> dict:
    nic = {
        key: end["nic"][key] - start["nic"][key]
        for key in NIC_COUNTERS
        if key in end.get("nic", {}) and key in start.get("nic", {})
    }
    nic["interface"] = end.get("nic", {}).get("interface")
    interrupts = {}
    for label, row in end["interrupts"].items():
        before = start["interrupts"].get(label, {"per_cpu": {}})["per_cpu"]
        delta = {cpu: n - before.get(cpu, 0) for cpu, n in row["per_cpu"].items()}
        if any(delta.values()):
            interrupts[label] = {"description": row["description"], "delta_per_cpu": delta}
    on_pinned = {
        label: {cpu: n for cpu, n in row["delta_per_cpu"].items() if cpu in cores and n}
        for label, row in interrupts.items()
    }
    return {
        "seconds": end["time_monotonic"] - start["time_monotonic"],
        "nic": nic,
        "interrupt_deltas": interrupts,
        "device_interrupts_on_pinned_cores": {
            label: counts for label, counts in on_pinned.items() if counts and label.isdigit()
        },
        "irq_affinity_end": end["irq_affinity"],
    }


def measure_under_load(cores: list[int], seconds: float) -> dict[int, dict]:
    """Runs one busy loop per core, pinned with taskset, and samples
    scaling_cur_freq of each core while it runs."""
    busy = [
        subprocess.Popen(["taskset", "-c", str(core), sys.executable, "-c", BUSY_LOOP])
        for core in cores
    ]
    samples: dict[int, list[float]] = {core: [] for core in cores}
    try:
        time.sleep(RAMP_SECONDS)
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            for core in cores:
                khz = read_text(CPU_ROOT / f"cpu{core}" / "cpufreq" / "scaling_cur_freq")
                if khz and khz.isdigit():
                    samples[core].append(int(khz) / KHZ_PER_MHZ)
            time.sleep(SAMPLE_INTERVAL_SECONDS)
    finally:
        for proc in busy:
            proc.kill()
            proc.wait()
    return {
        core: {
            "samples_mhz": values,
            "median_mhz": statistics.median(values) if values else None,
            "min_mhz": min(values) if values else None,
            "max_mhz": max(values) if values else None,
        }
        for core, values in samples.items()
    }


def violations_for(snapshot: dict, cores: list[int], target_mhz: float, tolerance: float) -> list[str]:
    found = []
    cpus = snapshot["cpus"]
    for core in cores:
        record = cpus.get(str(core))
        if record is None or not record["online"]:
            found.append(f"cpu{core} is offline")
            continue
        if record["governor"] != placement.REQUIRED_GOVERNOR:
            found.append(f"cpu{core} governor is {record['governor']}")
        measured = snapshot["frequency_under_load"].get(str(core), {}).get("median_mhz")
        if measured is None:
            found.append(f"cpu{core} frequency not measured")
        elif abs(measured - target_mhz) / target_mhz > tolerance:
            found.append(f"cpu{core} measured {measured:.0f} MHz, target {target_mhz} MHz")
    if snapshot["boost"] not in ("0", None):
        found.append(f"boost is {snapshot['boost']}")
    server = cpus.get(str(placement.SERVER_CORE), {})
    if server.get("siblings") not in (None, str(placement.SERVER_CORE)):
        found.append(f"server core sibling still online: siblings={server.get('siblings')}")
    return found


def snapshot(
    cores: list[int] | None = None,
    target_mhz: float = placement.TARGET_MHZ,
    tolerance: float = placement.FREQUENCY_TOLERANCE,
    seconds: float = 2.0,
) -> dict:
    cores = list(placement.PINNED_CORES) if cores is None else cores
    has_cpufreq = (CPU_ROOT / "cpu0" / "cpufreq").exists()
    result = {
        "time_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "kernel": platform.release(),
        "machine": platform.machine(),
        "cpufreq_available": has_cpufreq,
        "pinned_cores": cores,
        "placement": placement.description(),
        "target_mhz": target_mhz,
        "tolerance": tolerance,
        "boost": read_text(CPU_ROOT / "cpufreq" / "boost"),
        "smt_control": read_text(CPU_ROOT / "smt" / "control"),
        "pstate_driver": read_text(CPU_ROOT / "cpu0" / "cpufreq" / "scaling_driver"),
        "pstate_status": read_text(CPU_ROOT / "amd_pstate" / "status"),
        "cpus": {str(n): cpu_record(n) for n in cpu_numbers()},
        "measurement_method": "scaling_cur_freq median under taskset busy loop",
    }
    result["frequency_under_load"] = (
        {str(c): v for c, v in measure_under_load(cores, seconds).items()} if has_cpufreq else {}
    )
    result["violations"] = (
        violations_for(result, cores, target_mhz, tolerance)
        if has_cpufreq
        else ["cpufreq is not available on this host"]
    )
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cores", default=",".join(map(str, placement.PINNED_CORES)))
    parser.add_argument("--target-mhz", type=float, default=placement.TARGET_MHZ)
    parser.add_argument("--seconds", type=float, default=2.0)
    args = parser.parse_args()
    state = snapshot([int(c) for c in args.cores.split(",")], args.target_mhz, seconds=args.seconds)
    print(json.dumps(state, indent=2))
    if state["violations"]:
        print("NOT IN MEASUREMENT STATE: " + "; ".join(state["violations"]), file=sys.stderr)
        sys.exit(3)


if __name__ == "__main__":
    main()
