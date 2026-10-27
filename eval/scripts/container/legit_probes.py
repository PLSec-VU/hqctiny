"""Legitimate-client probes for the flood experiments. Import, do not run.

Probes start open loop: one new client process every `interval_s` across
the whole flood window, each in its own thread, whether or not earlier
probes have finished. Every probe record holds the start offset relative
to the flood start, the latency, the outcome and whether the probe
finished while the flood was still running.
"""

from __future__ import annotations

import math
import subprocess
import threading
import time
from dataclasses import dataclass

DEADLINES_S = (1.0, 5.0)
PHASE_IDLE, PHASE_FLOOD, PHASE_RECOVERY = "idle", "flood", "recovery"
RECOVERY_DELAY_S = 1.0


@dataclass(frozen=True)
class ProbeConfig:
    command: list[str]
    interval_s: float
    timeout_s: float
    recovery_probes: int


class ProbeRunner:
    def __init__(self, config: ProbeConfig, origin: float):
        self.config = config
        self.origin = origin
        self.records: list[dict] = []
        self.threads: list[threading.Thread] = []
        self.lock = threading.Lock()

    def offset(self) -> float:
        return time.monotonic() - self.origin

    def run_probe(self, phase: str, index: int, scheduled_s: float) -> None:
        start = self.offset()
        try:
            proc = subprocess.run(
                self.config.command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=self.config.timeout_s,
            )
            ok, timed_out = proc.returncode == 0, False
        except subprocess.TimeoutExpired:
            ok, timed_out = False, True
        end = self.offset()
        record = {
            "phase": phase, "index": index, "scheduled_offset_s": scheduled_s,
            "start_offset_s": start, "end_offset_s": end, "latency_s": end - start,
            "ok": ok, "timed_out": timed_out,
        }
        with self.lock:
            self.records.append(record)

    def start_open_loop(self, phase: str, stop: threading.Event) -> threading.Thread:
        """Starts one probe every `interval_s` until `stop` is set."""
        def schedule() -> None:
            index = 0
            while not stop.is_set():
                scheduled = index * self.config.interval_s
                if stop.wait(max(0.0, scheduled - self.offset())):
                    break
                worker = threading.Thread(target=self.run_probe, args=(phase, index, scheduled))
                worker.start()
                self.threads.append(worker)
                index += 1

        scheduler = threading.Thread(target=schedule)
        scheduler.start()
        return scheduler

    def run_sequential(self, phase: str, count: int, first_offset_s: float) -> None:
        for index in range(count):
            scheduled = first_offset_s + index * self.config.interval_s
            time.sleep(max(0.0, scheduled - self.offset()))
            self.run_probe(phase, index, scheduled)

    def join(self) -> None:
        for worker in list(self.threads):
            worker.join()


def nearest_rank(sorted_values: list[float], quantile: float) -> float | None:
    if not sorted_values:
        return None
    rank = max(1, math.ceil(quantile * len(sorted_values)))
    return sorted_values[rank - 1]


def mark_during_flood(records: list[dict], flood_end_offset_s: float) -> None:
    for record in records:
        record["during_flood"] = record["ok"] and record["end_offset_s"] <= flood_end_offset_s


def summarize_flood_probes(records: list[dict], started_after_s: float | None = None) -> dict:
    """Outcome statistics of the flood-phase probes. With `started_after_s`
    only probes that started at or after that offset count, and every key
    gets the suffix `_attack`."""
    probes = [r for r in records if r["phase"] == PHASE_FLOOD]
    suffix = ""
    if started_after_s is not None:
        probes = [r for r in probes if r["start_offset_s"] >= started_after_s]
        suffix = "_attack"
    ok_latencies = sorted(r["latency_s"] for r in probes if r["ok"])
    total = len(probes)
    within = lambda limit: sum(1 for r in probes if r["ok"] and r["latency_s"] <= limit)  # noqa: E731
    fraction = lambda count: count / total if total else None  # noqa: E731
    columns = {
        "legit_n": total,
        "legit_ok": len(ok_latencies),
        "legit_success_within_1s": fraction(within(DEADLINES_S[0])),
        "legit_success_within_5s": fraction(within(DEADLINES_S[1])),
        "legit_frac_completed_during_flood": fraction(sum(1 for r in probes if r["during_flood"])),
        "legit_p50_s": nearest_rank(ok_latencies, 0.50),
        "legit_p90_s": nearest_rank(ok_latencies, 0.90),
        "legit_p99_s": nearest_rank(ok_latencies, 0.99),
        "legit_max_s": ok_latencies[-1] if ok_latencies else None,
    }
    return {f"{name}{suffix}": value for name, value in columns.items()}


def summarize_other_phase(records: list[dict], phase: str) -> dict:
    probes = [r for r in records if r["phase"] == phase]
    ok_latencies = sorted(r["latency_s"] for r in probes if r["ok"])
    return {
        f"{phase}_n": len(probes),
        f"{phase}_ok": len(ok_latencies),
        f"{phase}_p50_s": nearest_rank(ok_latencies, 0.50),
    }
