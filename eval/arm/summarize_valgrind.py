#!/usr/bin/env python3
"""Lists the Memcheck contexts of the Valgrind logs in a state directory: run name, exit, error count, and for every context the
kind of error and the innermost frame, then the first frame that belongs to HQC or the protocol.

  summarize_valgrind.py raw/pi/state
"""

import re
import sys
from pathlib import Path

ERROR = re.compile(r"==\d+== (Conditional jump or move depends on uninitialised value\(s\)|Use of uninitialised value[^\n]*|Invalid [^\n]*)\n((?:==\d+==\s+(?:at|by) 0x[0-9A-F]+: [^\n]*\n)+)")
FRAME = re.compile(r"(?:at|by) 0x[0-9A-F]+: (.*?)(?: \(([^)]*)\))?$")
OWN = re.compile(r"hqc_\d|HQCLethe::(server|client|hqc|encoding|auth)|ct_check::")


def short(frame: str) -> str:
    name, location = (FRAME.match(frame.strip()).groups() + (None,))[:2] if FRAME.match(frame.strip()) else (frame, None)
    name = re.sub(r"<[^<>]*(<[^<>]*>[^<>]*)*>", "<..>", name)
    return f"{name[:60]} ({location})" if location else name[:80]


def contexts(log: str) -> list[tuple[str, str, str]]:
    seen = {}
    for kind, frames in ERROR.findall(log):
        lines = [l.split("== ", 1)[1].strip() for l in frames.strip().splitlines()]
        inner = short(lines[0])
        own = next((short(l) for l in lines if OWN.search(l)), "-")
        seen[(kind[:40], inner, own)] = None
    return list(seen)


def main() -> None:
    for path in sorted(Path(sys.argv[1]).glob("vg_*.log")):
        text = path.read_text(errors="replace")
        summary = re.search(r"ERROR SUMMARY: (\d+) errors from (\d+) contexts", text)
        print(f"{path.stem}: {summary.group(1) if summary else '?'} errors, {summary.group(2) if summary else '?'} contexts")
        for kind, inner, own in contexts(text):
            print(f"    {kind} | {inner} | first own frame: {own}")


if __name__ == "__main__":
    main()
