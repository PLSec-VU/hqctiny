#!/usr/bin/env python3
"""Runs inside the eval container (invoked by ../dos_flood.py). Floods one
system (stateless HQCLethe or the stateful baseline, both with ML-KEM
server authentication) with one flood kind, for `reps` repetitions. Each
repetition starts a fresh server process and records:

  * server CPU over the flood interval, exactly: schedstat of all server
    threads when the flood process starts and when it exits, divided by the
    time between the two (`cpu_util_pct`). The tick-based figure from
    /proc/<pid>/stat is a cross-check (`cpu_util_pct_ticks`).
  * attacker packets sent and per second, server responses sent and per
    second, kernel receive-buffer drops of the server socket,
  * for the stateful server: its table counters (entries created, evictions,
    dropped_table_full, peak bytes, watched-source counters),
  * server RSS (idle, mean and peak during the flood, after settling),
  * legitimate-client probes, started open loop every LEGIT_INTERVAL_MS
    across the flood window from another source address, plus recovery
    probes after the flood. See legit_probes.py.

The "none" kind runs the same measurement with no flood process.

Args: <mode> <variant> <duration_secs> <sockets> <reps> <kind> [source_ips]
  mode:  stateless | stateful (see systems.py)
  kind:  none, or one of the system's flood kinds
Env:   STATEFUL_SERVER_ARGS  extra arguments for hqclethe-server-stateful
       LEGIT_INTERVAL_MS     probe interval (default 200)
       LEGIT_RECOVERY_PROBES probes after the flood (default 3)
       LEGIT_TIMEOUT_S       kill a probe after this long (default 10)
       REP_BASE              repetitions are numbered from REP_BASE+1
       SETTLE_SECS           wait before the final RSS read (default 0)
       STRACE_BURST          1 runs the post-flood strace check for the
                             stateless server after the last repetition
Prints "RUN {json}" per repetition and one "RESULT {json}" at the end.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import signal
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import legit_probes as lp  # noqa: E402
from placement import FLOOD_CORE, LEGIT_CORE, ORCHESTRATOR_CORE, SERVER_CORE  # noqa: E402
from systems import LEGIT_SOURCE_IP, SYSTEMS, System  # noqa: E402
from util import (  # noqa: E402
    median_iqr, pin_to_core, popen_logged, query_responses_sent, query_stateful_stats_full,
    read_cpu_ns, read_cpu_ticks, read_rss_kb, read_udp_socket_drops, run_logged,
)

PORT = 24100
ADDR = f"127.0.0.1:{PORT}"
IDLE_PROBES = 3
IDLE_RSS_SECS = 2.0
RSS_SAMPLE_INTERVAL_S = 0.1
SERVER_STARTUP_SECS = 1.0
FLOOD_EXIT_GRACE_S = 30
STATS_DELTAS = (
    "hellos_answered", "fragments_accepted", "fragments_duplicate", "rejected_cookie",
    "dropped_source_limit", "dropped_table_full", "encaps_completed", "auth_proofs", "rejected_auth",
    "rejected_ae", "evictions", "timeouts", "entries_created", "watched_created", "watched_evictions", "watched_timeouts",
)
BRK_MMAP_RE = re.compile(r"\b(?:brk|mmap)\(")
NO_FLOOD = "none"


def take_snapshot(ctx: dict, *, cpu_first: bool) -> dict:
    """Server counters at one instant. CPU is read last before the flood
    starts and first after it exits, so the queries stay outside the
    measured interval."""
    def counters() -> dict:
        return {
            "drops": read_udp_socket_drops(PORT),
            "responses": query_responses_sent(PORT),
            "stats": query_stateful_stats_full(PORT) if ctx["system"].stats_probe else None,
        }

    def cpu() -> dict:
        return {"ns": read_cpu_ns(ctx["pid"]), "ticks": read_cpu_ticks(ctx["pid"])}

    if cpu_first:
        cpu_part = cpu()
        return {**cpu_part, **counters()}
    counter_part = counters()
    return {**counter_part, **cpu()}


def delta(after: int | None, before: int | None) -> int:
    return after - before if None not in (after, before) else 0


def run_flood_window(ctx: dict, runner: lp.ProbeRunner) -> dict:
    """Runs the flood process (or an idle wait for kind `none`) and
    returns the snapshots and timing around it."""
    before = take_snapshot(ctx, cpu_first=False)
    flood = None
    runner.origin = time.monotonic()
    if ctx["kind"] != NO_FLOOD:
        flood_cmd = [
            *ctx["flood_prefix"],
            *ctx["system"].flood_command(
                ctx["variant"], ADDR, ctx["duration"], ctx["sockets"], ctx["source_ips"], ctx["kind"]
            ),
        ]
        flood = popen_logged("flood", flood_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    probes_stop = threading.Event()
    probe_scheduler = runner.start_open_loop(lp.PHASE_FLOOD, probes_stop)
    rss_samples = []
    cpu_series = [(0.0, before["ns"])]
    flood_stdout = flood_stderr = b""
    if flood:
        while True:
            try:
                flood.wait(timeout=RSS_SAMPLE_INTERVAL_S)
                break
            except subprocess.TimeoutExpired:
                cpu_series.append((runner.offset(), read_cpu_ns(ctx["pid"])))
                rss_samples.append(read_rss_kb(ctx["pid"]))
        end_offset = runner.offset()
        probes_stop.set()
        flood_stdout, flood_stderr = flood.communicate(timeout=FLOOD_EXIT_GRACE_S)
    else:
        while runner.offset() < ctx["duration"]:
            cpu_series.append((runner.offset(), read_cpu_ns(ctx["pid"])))
            rss_samples.append(read_rss_kb(ctx["pid"]))
            time.sleep(RSS_SAMPLE_INTERVAL_S)
        end_offset = runner.offset()
        probes_stop.set()
    after = take_snapshot(ctx, cpu_first=True)
    cpu_series.append((end_offset, after["ns"]))
    probe_scheduler.join()
    return {
        "before": before, "after": after, "window_s": end_offset, "rss_samples": rss_samples,
        "cpu_series": cpu_series,
        "flood_stdout": flood_stdout, "flood_stderr": flood_stderr,
        "exit_code": flood.returncode if flood else 0,
    }


def parse_flood_json(window: dict, flooding: bool) -> dict:
    if not flooding:
        return {}
    lines = window["flood_stdout"].decode(errors="replace").strip().splitlines()
    if window["exit_code"] != 0 or not lines:
        return {"flood_error": window["flood_stderr"].decode(errors="replace")[-400:] or "no output"}
    return json.loads(lines[-1])


def cpu_columns(window: dict, tick_hz: int) -> dict:
    before, after, seconds = window["before"], window["after"], window["window_s"]
    ticks_s = (after["ticks"] - before["ticks"]) / tick_hz
    columns = {"cpu_util_pct_ticks": 100 * ticks_s / seconds, "cpu_seconds_ticks": ticks_s}
    if None in (before["ns"], after["ns"]):
        return {**columns, "cpu_source": "ticks", "cpu_util_pct": columns["cpu_util_pct_ticks"]}
    cpu_s = (after["ns"] - before["ns"]) / 1e9
    return {**columns, "cpu_source": "schedstat", "cpu_seconds": cpu_s, "cpu_util_pct": 100 * cpu_s / seconds}


def cpu_ns_at(series: list[tuple[float, int | None]], offset_s: float) -> float | None:
    """Server CPU ns at `offset_s`, linearly interpolated between samples."""
    points = [(t, ns) for t, ns in series if ns is not None]
    for (t0, ns0), (t1, ns1) in zip(points, points[1:]):
        if t0 <= offset_s <= t1:
            return ns0 + (ns1 - ns0) * (offset_s - t0) / (t1 - t0) if t1 > t0 else ns1
    return None


def attack_phase_columns(window: dict, flood_json: dict) -> dict:
    """Metrics for the part of the flood window after the flood client has
    finished its setup (it reports `attack_started_secs`; the stateful
    client spends up to a few seconds collecting cookies first)."""
    started = flood_json.get("attack_started_secs")
    if started is None:
        return {}
    window_s = window["window_s"]
    attack_s = max(0.0, window_s - started)
    columns = {"attack_started_s": started, "attack_phase_s": attack_s}
    if attack_s <= 0:
        return columns
    columns["attacker_packets_per_s_attack_phase"] = flood_json.get("packets_sent", 0) / attack_s
    ns_start, ns_end = cpu_ns_at(window["cpu_series"], started), window["after"]["ns"]
    if ns_start is not None and ns_end is not None:
        columns["cpu_util_pct_attack_phase"] = 100 * (ns_end - ns_start) / 1e9 / attack_s
    return columns


def attack_probe_columns(probes: list[dict], flood_json: dict) -> dict:
    """Probe outcomes for the probes that started after the attack started."""
    started = flood_json.get("attack_started_secs")
    return {} if started is None else lp.summarize_flood_probes(probes, started_after_s=started)


def load_columns(window: dict, flood_json: dict) -> dict:
    before, after, seconds = window["before"], window["after"], window["window_s"]
    sent = flood_json.get("packets_sent", 0)
    responses = delta(after["responses"], before["responses"])
    columns = {
        "flood_window_s": seconds,
        "attacker_packets_sent": sent,
        "attacker_packets_per_s": sent / seconds,
        "server_responses_sent": responses,
        "server_responses_per_s": responses / seconds,
        "kernel_udp_drops": delta(after["drops"], before["drops"]),
    }
    if "flood_error" in flood_json:
        columns["flood_error"] = flood_json["flood_error"]
    if before["stats"] and after["stats"]:
        for key in STATS_DELTAS:
            columns[f"d_{key}"] = after["stats"][key] - before["stats"][key]
        columns["entries_created_per_s"] = columns["d_entries_created"] / seconds
        columns["evictions_per_s"] = columns["d_evictions"] / seconds
        columns["table_entries_end"] = after["stats"]["table_entries"]
        columns["table_bytes_end"] = after["stats"]["table_bytes"]
        columns["peak_table_entries"] = after["stats"]["peak_entries"]
        columns["peak_table_bytes"] = after["stats"]["peak_bytes"]
    return columns


def run_one(ctx: dict) -> dict:
    system, pid = ctx["system"], ctx["pid"]
    probe_config = lp.ProbeConfig(
        command=[*ctx["legit_prefix"], *system.client_command(ctx["variant"], ADDR, LEGIT_SOURCE_IP)],
        interval_s=ctx["probe_interval_s"], timeout_s=ctx["probe_timeout_s"],
        recovery_probes=ctx["recovery_probes"],
    )
    idle = lp.ProbeRunner(probe_config, time.monotonic())
    run_logged("legit", probe_config.command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    idle.run_sequential(lp.PHASE_IDLE, IDLE_PROBES, 0.0)
    idle_samples = []
    end = time.monotonic() + IDLE_RSS_SECS
    while time.monotonic() < end:
        idle_samples.append(read_rss_kb(pid))
        time.sleep(RSS_SAMPLE_INTERVAL_S)
    idle_rss = statistics.mean(idle_samples)

    runner = lp.ProbeRunner(probe_config, time.monotonic())
    window = run_flood_window(ctx, runner)
    flood_json = parse_flood_json(window, ctx["kind"] != NO_FLOOD)
    runner.run_sequential(lp.PHASE_RECOVERY, probe_config.recovery_probes,
                          window["window_s"] + lp.RECOVERY_DELAY_S)
    runner.join()
    time.sleep(ctx["settle_secs"])
    settled_rss = read_rss_kb(pid)

    probes = sorted(runner.records, key=lambda r: r["scheduled_offset_s"])
    lp.mark_during_flood(probes, window["window_s"])
    samples = window["rss_samples"] or [idle_rss]
    row = {
        "rep": ctx["rep"],
        "idle_rss_kb": idle_rss,
        "rss_growth_kb": statistics.mean(samples) - idle_rss,
        "peak_rss_growth_kb": max(samples) - idle_rss,
        "peak_rss_abs_kb": max(samples),
        "rss_after_settle_growth_kb": settled_rss - idle_rss,
        **cpu_columns(window, ctx["tick_hz"]),
        **load_columns(window, flood_json),
        **attack_phase_columns(window, flood_json),
        **lp.summarize_flood_probes(probes),
        **attack_probe_columns(probes, flood_json),
        **lp.summarize_other_phase(probes, lp.PHASE_RECOVERY),
        "legit_idle_p50_s": lp.summarize_other_phase(idle.records, lp.PHASE_IDLE)["idle_p50_s"],
        "flood_client_json": flood_json,
        "probes": probes,
    }
    if row.get("attack_phase_s", 1) <= 0:
        print(f"WARNING: rep {ctx['rep']}: the flood client was still setting up when the flood "
              "window ended (attack_started_s >= flood_window_s). Raise FLOOD_DURATION.", flush=True)
    print("RUN " + json.dumps(row), flush=True)
    return row


def strace_burst(system: System, variant: str, server_pid: int, flood_prefix: list[str], kind: str) -> None:
    """Counts brk/mmap calls of a running stateless server during a short
    flood after the main measurement, so it cannot perturb those numbers."""
    trace_path = Path("/tmp/flood.strace")
    trace_path.unlink(missing_ok=True)
    tracer = popen_logged(
        "strace", ["strace", "-f", "-o", str(trace_path), "-e", "trace=memory", "-p", str(server_pid)]
    )
    time.sleep(0.3)
    run_logged(
        "flood-burst",
        [*flood_prefix, *system.flood_command(variant, ADDR, 1, 16, 1, kind)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(0.2)
    tracer.terminate()
    tracer.wait(timeout=5)
    text = trace_path.read_text() if trace_path.exists() else ""
    print(f"brk_mmap_calls_during_1s_burst_after_main_flood: {len(BRK_MMAP_RE.findall(text))}")


def server_extra_args(system: System) -> list[str]:
    extra = shlex.split(os.environ.get(system.server_extra_args_env or "", ""))
    if system.stats_probe and "--watch-source" not in extra:
        extra += ["--watch-source", LEGIT_SOURCE_IP]
    return extra


def numeric_summary(rows: list[dict]) -> dict:
    summary = {}
    for key in rows[0]:
        values = [r[key] for r in rows if isinstance(r.get(key), (int, float)) and r[key] == r[key]]
        if values and key != "rep":
            med, q1, q3 = median_iqr(values)
            summary[key] = {"median": med, "q1": q1, "q3": q3, "n": len(values)}
            print(f"{key}: median={med:.4g} iqr=[{q1:.4g}, {q3:.4g}] (n={len(values)})")
    return summary


def main() -> None:
    mode, variant, duration, sockets, reps, kind = sys.argv[1:7]
    source_ips = int(sys.argv[7]) if len(sys.argv) > 7 else 1
    duration, sockets, reps = int(duration), int(sockets), int(reps)
    system = SYSTEMS[mode]
    if kind != NO_FLOOD and kind not in system.flood_kinds:
        sys.exit(f"{mode} has no flood kind {kind}; choose from {system.flood_kinds}")
    nproc = os.cpu_count() or 1
    if nproc > ORCHESTRATOR_CORE:
        os.sched_setaffinity(0, {ORCHESTRATOR_CORE})
    print(f"mode={mode} variant={variant} kind={kind} sockets={sockets} source_ips={source_ips} "
          f"duration={duration}s reps={reps} nproc={nproc}")

    extra = server_extra_args(system)
    rep_base = int(os.environ.get("REP_BASE", "0"))
    base_ctx = {
        "system": system, "variant": variant, "duration": duration, "sockets": sockets,
        "kind": kind, "source_ips": source_ips, "tick_hz": os.sysconf("SC_CLK_TCK"),
        "flood_prefix": pin_to_core(FLOOD_CORE, nproc, 2),
        "legit_prefix": pin_to_core(LEGIT_CORE, nproc, 3),
        "probe_interval_s": int(os.environ.get("LEGIT_INTERVAL_MS", "200")) / 1000,
        "probe_timeout_s": float(os.environ.get("LEGIT_TIMEOUT_S", "10")),
        "recovery_probes": int(os.environ.get("LEGIT_RECOVERY_PROBES", "3")),
        "settle_secs": float(os.environ.get("SETTLE_SECS", "0")),
    }
    rows = []
    for index in range(1, reps + 1):
        rep = rep_base + index
        print(f"--- Rep {rep} (fresh server process) ---")
        server = popen_logged(
            "server", [*pin_to_core(SERVER_CORE, nproc, 2), *system.server_command(variant, PORT, extra)]
        )
        try:
            time.sleep(SERVER_STARTUP_SECS)
            rows.append(run_one({**base_ctx, "pid": server.pid, "rep": rep}))
            strace_wanted = (
                index == reps and mode == "stateless" and kind != NO_FLOOD
                and os.environ.get("STRACE_BURST", "0") == "1"
            )
            if strace_wanted:
                strace_burst(system, variant, server.pid, base_ctx["flood_prefix"], kind)
        finally:
            server.send_signal(signal.SIGTERM)
            server.wait(timeout=5)

    summary = {"mode": mode, "variant": variant, "kind": kind, "sockets": sockets,
               "source_ips": source_ips, "reps": reps, "duration_s": duration,
               "server_args": extra, "rows": rows}
    print(f"--- Aggregate across {reps} reps ---")
    summary["summary"] = numeric_summary(rows)
    print("RESULT " + json.dumps(summary))


if __name__ == "__main__":
    main()
