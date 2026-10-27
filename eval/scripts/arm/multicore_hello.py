#!/usr/bin/env python3
"""Answers per second of one server with N workers on N Pi cores, under a real LAN request flood.

Runs on the control host, which reaches both the Pi (ssh) and the flood host (ssh). Per run it starts one
server with --workers N on Pi cores 0..N-1 (one port, BASE_PORT), starts N flood clients on the flood host (one
core each, all to that port), and reads the Pi's UDP send counter at two instants inside the flood. The server is
the only UDP sender on the Pi. The NIC transmit counter is kept beside it but not used: under a flood of large
requests the Pi 3 B+ USB Ethernet stops transmitting for seconds while the server keeps answering.
--system picks the stateful baseline (hello floods) or the stateless HQCLethe server (handshake, auth, u-chunk
or v-residue floods), run with its replay filter on. The flood client cycles through every valid u-chunk/
v-residue index and refreshes its cookie every --cookie-refresh-secs, so it sends genuinely distinct valid
requests rather than tripping the filter's per-fingerprint cap. The answers per second are the counter
difference over the window, so the start-up of the flood and the drain of the socket queues after the flood
do not count.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class System:
    server: str
    server_args: str
    client: str
    stats_query: bytes
    answered_offset: int


SYSTEMS = {
    "stateful": System("hqclethe-server-stateful", "--max-entries 1024", "hqclethe-client-stateful",
                       b"HQCLETHE_STATEFUL_STATS_QUERY_V1", 8),
    "stateless": System("hqclethe-server", "", "hqclethe-client", b"HQCLETHE_FLOOD_STATS_QUERY_V1", 0),
}
BASE_PORT = 24100
PI_SERVER_DIR = os.environ.get("MULTICORE_SERVER_DIR", "/mnt/arm/bin/floodstats")
PI_KEY_DIR = "/mnt/arm/keys"
FLOOD_CORES = (12, 13, 14, 15)
SERVER_STARTUP_S = 1.5
FLOOD_DURATION_S = 16
WINDOW_START_S = 4.0
WINDOW_END_S = 12.0
DRAIN_S = 6.0
SAMPLER_MARGIN_S = 2.0
QUERY_ATTEMPTS = 20
QUERY_TIMEOUT_S = 1.0
FLOOD_SOCKETS = 128
MAX_START_TEMP_C = 60
PI_SAMPLER = r"""
import json, sys, time
NIC = "/sys/class/net/eth0/statistics/"
def read(path):
    with open(path) as f:
        return f.read()
def udp_out_datagrams():
    names, values = [line.split() for line in read("/proc/net/snmp").splitlines() if line.startswith("Udp:")]
    return int(values[names.index("OutDatagrams")])
end = time.time() + float(sys.argv[1])
while time.time() < end:
    cores = [line.split() for line in read("/proc/stat").splitlines() if line.startswith("cpu")]
    print(json.dumps({"t": time.time(), "rx_packets": int(read(NIC + "rx_packets")),
                      "tx_packets": int(read(NIC + "tx_packets")), "udp_out": udp_out_datagrams(),
                      "temp_c": int(read("/sys/class/thermal/thermal_zone0/temp")) / 1000,
                      "freq_khz": int(read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq")),
                      "jiffies": {c[0]: [int(x) for x in c[1:]] for c in cores}}), flush=True)
    time.sleep(SAMPLE_INTERVAL_S)
""".replace("SAMPLE_INTERVAL_S", "0.5")
FLOOD_ACTIVE_RX_PPS = 10_000
WARMUP_S = 3.0
SETTLE_S = 1.0


def ssh(host: str, command: str, check: bool = True) -> str:
    result = subprocess.run(["ssh", "-n", "-o", "BatchMode=yes", host, command], capture_output=True, text=True)
    if check and result.returncode:
        raise RuntimeError(f"{host}: {command}: {result.stderr}")
    return result.stdout


def answered(system: System, host: str, port: int) -> int:
    for _ in range(QUERY_ATTEMPTS):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(QUERY_TIMEOUT_S)
            try:
                sock.sendto(system.stats_query, (host, port))
                data = sock.recvfrom(4096)[0]
                return int.from_bytes(data[system.answered_offset:system.answered_offset + 8], "little")
            except OSError:
                continue
    raise RuntimeError(f"no answer to the stats query on port {port}")


def steady_window(samples: list[dict]) -> tuple[dict, dict]:
    """First and last sample of the part of the flood after WARMUP_S and before the last SETTLE_S."""
    rates = [(b["rx_packets"] - a["rx_packets"]) / (b["t"] - a["t"]) for a, b in zip(samples, samples[1:])]
    active = [i for i, rate in enumerate(rates) if rate > FLOOD_ACTIVE_RX_PPS]
    flood_start, flood_end = samples[active[0]]["t"], samples[active[-1] + 1]["t"]
    inside = [s for s in samples if flood_start + WARMUP_S <= s["t"] <= flood_end - SETTLE_S]
    return inside[0], inside[-1]


def pi_temperature_c(pi: str) -> float:
    return int(ssh(pi, "cat /sys/class/thermal/thermal_zone0/temp")) / 1000


def wait_until_cool(pi: str) -> None:
    while pi_temperature_c(pi) > MAX_START_TEMP_C:
        time.sleep(5)


def replay_rate_args(system: System, variant: str) -> str:
    """The Pi's replay-filter rate for the stateless server, from STATELESS_REPLAY_RATES (hqc1=R,...)."""
    rates = dict(item.split("=") for item in os.environ.get("STATELESS_REPLAY_RATES", "").split(",") if item)
    return f"--replay-rate {rates[variant]}" if system is SYSTEMS["stateless"] and variant in rates else ""


def start_servers(pi: str, system: System, variant: str, cores: list[int], extra_server_args: str) -> None:
    core_list = ",".join(map(str, cores))
    ssh(pi, f"sudo sh -c 'taskset -c {core_list} {PI_SERVER_DIR}/{system.server} --port {BASE_PORT} "
            f"--workers {len(cores)} --variant {variant} --key {PI_KEY_DIR}/server-{variant}.sk "
            f"{system.server_args} {replay_rate_args(system, variant)} {extra_server_args} >/dev/null 2>&1 &'")
    time.sleep(SERVER_STARTUP_S)


def stop_servers(pi: str) -> None:
    ssh(pi, "sudo pkill -f hqclethe-server; sleep 0.5", check=False)


def start_floods(flood_host: str, pi_host: str, system: System, kind: str, variant: str, cores: list[int],
                 client_dir: str, key_dir: str, cookie_refresh_secs: int):
    refresh_flag = f" --cookie-refresh-secs {cookie_refresh_secs}" if system is SYSTEMS["stateless"] else ""
    procs = []
    for index in range(len(cores)):
        command = (
            f"ulimit -n 65536; taskset -c {FLOOD_CORES[index]} {client_dir}/{system.client} flood-client "
            f"--addr {pi_host}:{BASE_PORT} --variant {variant} --server-key {key_dir}/server-{variant}.pk "
            f"--duration {FLOOD_DURATION_S} --sockets {FLOOD_SOCKETS} --source-ips 1 --kind {kind}"
            f"{refresh_flag}")
        procs.append(subprocess.Popen(["ssh", "-n", flood_host, command], stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, text=True))
    return procs


def busy_pct(before: list[int], after: list[int]) -> float:
    delta = [b - a for a, b in zip(before, after)]
    idle = delta[3] + delta[4]
    return round(100 * (1 - idle / sum(delta)), 1)


def sleep_until(deadline: float) -> None:
    time.sleep(max(0.0, deadline - time.monotonic()))


def run_once(args, variant: str, core_count: int, rep: int) -> dict:
    cores = [args.single_core] if core_count == 1 else list(range(core_count))
    system = SYSTEMS[args.system]
    wait_until_cool(args.pi)
    start_servers(args.pi, system, variant, cores, args.extra_server_args)
    sampler = subprocess.Popen(["ssh", "-n", args.pi, "python3", "-c", shlex.quote(PI_SAMPLER),
                                str(FLOOD_DURATION_S + 2 * SAMPLER_MARGIN_S)], stdout=subprocess.PIPE, text=True)
    time.sleep(SAMPLER_MARGIN_S)
    floods = start_floods(args.flood_host, args.pi_host, system, args.kind, variant, cores, args.client_dir,
                          args.key_dir, args.cookie_refresh_secs)
    try:
        outputs = [p.communicate(timeout=FLOOD_DURATION_S + 60) for p in floods]
        time.sleep(DRAIN_S)
        answered_after_drain = answered(system, args.pi_host, BASE_PORT)
        samples = [json.loads(line) for line in sampler.communicate(timeout=60)[0].splitlines()]
    finally:
        stop_servers(args.pi)
    start, end = steady_window(samples)
    seconds = end["t"] - start["t"]
    answers = (end["udp_out"] - start["udp_out"]) / seconds
    row = {
        "system": args.system, "kind": args.kind, "variant": variant, "servers": core_count, "cores": cores, "rep": rep, "window_s": seconds,
        "answers_per_s_total": answers, "answers_per_s_per_server": answers / core_count,
        "nic_rx_pps": (end["rx_packets"] - start["rx_packets"]) / seconds,
        "nic_tx_pps": (end["tx_packets"] - start["tx_packets"]) / seconds,
        "temp_c_start": start["temp_c"], "temp_c_end": end["temp_c"], "freq_khz_end": end["freq_khz"],
        "core_busy_pct": {core: busy_pct(start["jiffies"][core], end["jiffies"][core])
                          for core in start["jiffies"]},
        "answered_after_drain": answered_after_drain,
        "flood_json": [out[0].strip().splitlines()[-1:] for out in outputs],
        "flood_exit": [p.returncode for p in floods],
        "flood_stderr": [out[1].strip()[-500:] for out in outputs],
        "samples": [{key: sample[key] for key in ("t", "rx_packets", "tx_packets", "udp_out")} for sample in samples],
    }
    print(f"{args.system} {args.kind} {variant} servers={core_count} rep={rep} total={row['answers_per_s_total']:.1f}/s "
          f"per_server={row['answers_per_s_per_server']:.1f}/s nic_tx_pps={row['nic_tx_pps']:.0f} rx_pps={row['nic_rx_pps']:.0f} "
          f"temp={end['temp_c']:.1f}C busy={row['core_busy_pct']}", flush=True)
    return row


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--pi", default="user@rpi")
    parser.add_argument("--pi-host", default="192.168.50.241")
    parser.add_argument("--flood-host", default="playground")
    parser.add_argument("--client-dir", required=True)
    parser.add_argument("--key-dir", required=True)
    parser.add_argument("--system", choices=SYSTEMS, default="stateful")
    parser.add_argument("--kind", default="hello", help="flood-client --kind: hello (stateful); handshake, "
                        "auth, uchunk or vresidue (stateless)")
    parser.add_argument("--variants", default="hqc1,hqc3,hqc5")
    parser.add_argument("--server-counts", default="1,4")
    parser.add_argument("--single-core", type=int, default=2)
    parser.add_argument("--reps", type=int, default=3)
    parser.add_argument("--cookie-refresh-secs", type=int, default=5,
                        help="flood-client --cookie-refresh-secs for uchunk/vresidue (default matches the client's own default)")
    parser.add_argument("--extra-server-args", default="",
                        help="extra args appended to the stateless server command line, "
                             "e.g. '--replay-rate 50000 --puzzle-difficulty 16'")
    args = parser.parse_args()
    rows = []
    for rep in range(1, args.reps + 1):
        for variant in args.variants.split(","):
            for count in map(int, args.server_counts.split(",")):
                rows.append(run_once(args, variant, count, rep))
                args.out.write_text(json.dumps(rows, indent=1) + "\n")


if __name__ == "__main__":
    main()
