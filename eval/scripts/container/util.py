"""Shared helpers for eval/scripts/container/*.py. Import, don't run
directly. These run *inside* the eval container.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable


def find_pids(matches: Callable[[list[str]], bool]) -> list[int]:
    """Returns PIDs of processes whose argv (read from /proc/PID/cmdline)
    satisfies `matches`. Used instead of `pkill -f <pattern>`, which
    matches against every process's *full command line* including our own
    invoking shell -- if the pattern text is ever also present in our own
    argv (easy to do by accident), pkill kills itself out from under us.
    Reading /proc directly and matching against a specific target's argv
    list sidesteps that whole class of bug.
    """
    pids = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            raw = (entry / "cmdline").read_bytes()
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        argv = raw.decode(errors="replace").split("\x00")
        if argv and argv[-1] == "":
            argv.pop()
        if matches(argv):
            pids.append(int(entry.name))
    return pids


def find_tiny_server_pids(port: str) -> list[int]:
    def matches(argv: list[str]) -> bool:
        return any(a.endswith(("hqclethe-server", "hqclethe-server-stateful")) for a in argv) and "--port" in argv and port in argv

    return find_pids(matches)


def read_proc_field(pid: int, filename: str) -> str:
    return Path(f"/proc/{pid}/{filename}").read_text()


def read_status_kb(pid: int, field: str) -> int:
    for line in read_proc_field(pid, "status").splitlines():
        if line.startswith(f"{field}:"):
            return int(line.split()[1])
    return 0


def read_rss_kb(pid: int) -> int:
    return read_status_kb(pid, "VmRSS")


def read_peak_rss_kb(pid: int) -> int:
    return read_status_kb(pid, "VmHWM")


def read_cpu_ticks(pid: int) -> int:
    # /proc/pid/stat: pid (comm) state ppid ... utime(14) stime(15) ...
    # (1-indexed in the proc(5) man page; comm can itself contain spaces/
    # parens, so split after the last ')' rather than by fixed position.)
    fields = read_proc_field(pid, "stat").rsplit(")", 1)[1].split()
    utime, stime = fields[11], fields[12]  # index 13,14 minus the 2 consumed by pid/comm
    return int(utime) + int(stime)


def read_udp_socket_drops(port: int) -> int | None:
    """Reads the per-socket `drops` counter (last column) for the UDP
    socket bound to `port`, from /proc/net/udp -- the number of datagrams
    the kernel discarded for *that exact socket* because its receive
    buffer was full when they arrived (i.e. dropped before the server's
    recv_from loop ever got to them). Deliberately per-socket rather than
    the netns-wide Udp: counters in /proc/net/snmp: this container also
    runs the flood client's ~128 connected-but-never-read sockets, whose
    own receive buffers fill up with unread server replies and swamp any
    aggregate counter with an artifact that has nothing to do with the
    server's resilience. `local_address` is `HEXIP:HEXPORT`; the port is
    plain hex, no byte-swapping (only the IP octets are reordered).
    """
    port_hex = f"{port:04X}"
    for line in Path("/proc/net/udp").read_text().splitlines()[1:]:
        fields = line.split()
        if len(fields) < 2:
            continue
        local_addr = fields[1]
        if local_addr.split(":")[1] == port_hex:
            return int(fields[-1])
    return None


def log_command(label: str, argv: list[str]) -> None:
    """Prints the exact command line, so the raw log records it."""
    import shlex

    print(f"CMD[{label}]: {shlex.join(argv)}", flush=True)


def popen_logged(label: str, argv: list[str], **kwargs):
    import subprocess

    log_command(label, argv)
    return subprocess.Popen(argv, **kwargs)


def run_logged(label: str, argv: list[str], **kwargs):
    import subprocess

    log_command(label, argv)
    return subprocess.run(argv, **kwargs)


def pin_to_core(core: int, nproc: int, needed: int) -> list[str]:
    """`taskset` prefix that pins a process to `core`. Empty below `needed`
    cores, where isolation is not possible."""
    return ["taskset", "-c", str(core)] if nproc >= needed else []


STATEFUL_STATS_QUERY = b"HQCLETHE_STATEFUL_STATS_QUERY_V1"
STATEFUL_STATS_FIELDS = [
    "responses_sent", "hellos_answered", "fragments_accepted", "fragments_duplicate",
    "rejected_malformed", "rejected_cookie", "dropped_source_limit", "dropped_table_full",
    "encaps_completed", "encaps_failed", "auth_proofs", "rejected_auth", "table_entries",
    "table_bytes", "evictions", "timeouts", "peak_entries", "peak_bytes",
    "entries_created", "watched_created", "watched_evictions", "watched_timeouts",
    "oldest_entry_age_ms", "rejected_ae",
]


def query_stateful_stats_full(port: int, timeout: float = 1.0) -> dict | None:
    """Full stats snapshot from a stateful server built with
    `--features flood-stats`. Mirrors dos_flood_variant.py's
    query_stateful_stats but importable from other container scripts.
    `STATEFUL_STATS_FIELDS` may be longer than what an older binary's
    datagram carries; `zip` just stops at the shorter one, so a stale
    binary still parses, missing only its newest fields."""
    import socket as pysocket

    with pysocket.socket(pysocket.AF_INET, pysocket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        try:
            s.sendto(STATEFUL_STATS_QUERY, ("127.0.0.1", port))
            data, _ = s.recvfrom(4096)
        except OSError:
            return None
    values = [int.from_bytes(data[i : i + 8], "little") for i in range(0, len(data), 8)]
    return dict(zip(STATEFUL_STATS_FIELDS, values))


def query_responses_sent(port: int) -> int | None:
    """Asks a server built with `--features flood-stats` for its response
    counter. Both servers answer the same magic probe. Returns None when
    there is no answer. Safe inside a timed window: no ptrace."""
    import socket as pysocket

    with pysocket.socket(pysocket.AF_INET, pysocket.SOCK_DGRAM) as s:
        s.settimeout(1.0)
        try:
            s.sendto(b"HQCLETHE_FLOOD_STATS_QUERY_V1", ("127.0.0.1", port))
            data, _ = s.recvfrom(16)
        except OSError:
            return None
    return int.from_bytes(data[:8], "little") if len(data) >= 8 else None


def sample_rss_for(pid: int, seconds: float, interval: float = 0.1) -> list[int]:
    import time

    samples = []
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        samples.append(read_rss_kb(pid))
        time.sleep(interval)
    return samples


def median_iqr(values: list[float]) -> tuple[float, float, float]:
    import statistics

    med = statistics.median(values)
    if len(values) >= 4:
        q1, q3 = statistics.quantiles(values, n=4, method="inclusive")[0::2]
    else:
        q1, q3 = min(values), max(values)
    return med, q1, q3


def read_cpu_ns(pid: int) -> int | None:
    """On-CPU time of the whole process in nanoseconds from
    /proc/<pid>/schedstat (all threads). None if the kernel has no
    schedstat. Finer than the 10 ms tick of /proc/<pid>/stat."""
    try:
        total = 0
        for task in Path(f"/proc/{pid}/task").iterdir():
            total += int((task / "schedstat").read_text().split()[0])
        return total
    except (OSError, ValueError, IndexError):
        return None


def read_cpu_split_ticks(pid: int) -> tuple[int, int]:
    """(utime, stime) in clock ticks of the whole process, from
    /proc/<pid>/stat. Same parsing as read_cpu_ticks."""
    fields = read_proc_field(pid, "stat").rsplit(")", 1)[1].split()
    return int(fields[11]), int(fields[12])
