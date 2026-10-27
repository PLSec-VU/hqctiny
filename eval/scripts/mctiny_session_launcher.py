#!/usr/bin/env python3
"""Runs one McTiny client session inside a network namespace and prints one
JSON line with its wall time. wan_sweep.py starts it with
`sudo ip netns exec <ns> python3 mctiny_session_launcher.py ...`.

The timer covers only the client process: it starts just before the client
is created and stops when the client exits. The Python start, `sudo` and
`ip netns exec` are outside it. The launcher enforces the session timeout
itself and kills the client when it passes. No `timeout` program is in the
chain, so no polling tick adds to the measured time.

The launcher also returns the client's whole stderr, gzipped and base64
encoded, in the field `stderr_gz_b64`, and `network_s`: the time from the first
packet sent to the last reply received, parsed from the packet lines of that
stderr ("> <unix time> <length> <tail>" for a send, "<" for a receive).
wan_sweep.py writes the stderr to a file and removes the field from the
result row.

Args: <core> <timeout_s> <client_bin> <server_public_key> <server_ip> <port>
"""

from __future__ import annotations

import base64
import gzip
import json
import os
import re
import subprocess
import sys
import time

STDERR_TAIL_CHARS = 400

PACKET_LINE = re.compile(r"^(?P<direction>[<>]) (?P<time>\d+\.\d+) (?P<length>\d+) ")
DIRECTION_KIND = {">": "sent", "<": "received"}


def packet_events(stderr: str) -> list[tuple[float, str]]:
    """(wall-clock seconds, "sent" | "received") for each packet line of the McTiny client log."""
    events = []
    for line in stderr.splitlines():
        match = PACKET_LINE.match(line)
        if match:
            events.append((float(match.group("time")), DIRECTION_KIND[match.group("direction")]))
    return events


def network_seconds(stderr: str) -> float | None:
    """Time from the first packet sent to the last packet received."""
    events = packet_events(stderr)
    sent = [t for t, kind in events if kind == "sent"]
    received = [t for t, kind in events if kind == "received"]
    if not sent or not received:
        return None
    elapsed = max(received) - min(sent)
    return elapsed if elapsed >= 0 else None


def compress_stderr(stderr: str) -> str:
    return base64.b64encode(gzip.compress(stderr.encode())).decode()


def as_text(partial: bytes | str | None) -> str:
    if partial is None:
        return ""
    return partial.decode(errors="replace") if isinstance(partial, bytes) else partial


def session_numbers(stderr: str) -> dict:
    packets = re.search(r"packets sent (\d+) received (\d+)", stderr)
    volume = re.search(r"bytes sent (\d+) received (\d+)", stderr)
    return {
        "packets_sent": int(packets.group(1)) if packets else None,
        "packets_received": int(packets.group(2)) if packets else None,
        "bytes_sent": int(volume.group(1)) if volume else None,
        "bytes_received": int(volume.group(2)) if volume else None,
    }


def main() -> None:
    core, timeout_s, client, public_key, ip, port = sys.argv[1:7]
    os.sched_setaffinity(0, {int(core)})
    started = time.monotonic()
    try:
        done = subprocess.run(
            [client, public_key, ip, port], capture_output=True, text=True, timeout=float(timeout_s)
        )
    except subprocess.TimeoutExpired as error:
        print(json.dumps({
            "ok": False, "session_s": time.monotonic() - started, "reason": "timeout",
            "stderr_gz_b64": compress_stderr(as_text(error.stderr)),
        }))
        return
    session_s = time.monotonic() - started
    record = {
        "ok": done.returncode == 0, "session_s": session_s, "returncode": done.returncode,
        "network_s": network_seconds(done.stderr), "stderr_gz_b64": compress_stderr(done.stderr),
    }
    if done.returncode == 0:
        record.update(session_numbers(done.stderr))
    else:
        record["stderr_tail"] = done.stderr[-STDERR_TAIL_CHARS:]
    print(json.dumps(record))


if __name__ == "__main__":
    main()
