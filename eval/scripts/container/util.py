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
        return any(a.endswith("hqctiny-server") for a in argv) and "--port" in argv and port in argv

    return find_pids(matches)


def read_proc_field(pid: int, filename: str) -> str:
    return Path(f"/proc/{pid}/{filename}").read_text()


def read_rss_kb(pid: int) -> int:
    for line in read_proc_field(pid, "status").splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    return 0


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
