#!/usr/bin/env python3
"""Builds RESULTS.md from RESULTS_head.md and the generated table files.

Run in this directory after the table scripts:
  python3 make_tables_final.py > tables_final.md
  python3 make_tables_dos.py
  python3 numbers_for_paper.py > numbers_for_paper.md
  python3 build_results.py
"""
import os

import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from results_dir import study_dir
ROOT = study_dir("final-x86")


def text(name, drop_title=False):
    lines = open(os.path.join(ROOT, name)).read().rstrip().splitlines()
    if drop_title and lines and lines[0].startswith("# "):
        lines = lines[1:]
    return "\n".join(lines).strip() + "\n"


def demote(markdown):
    return "\n".join("#" + line if line.startswith("#") else line for line in markdown.splitlines()) + "\n"


def main():
    parts = [
        text("RESULTS_head.md"),
        "## Numbers for the paper\n\n" + demote(text("numbers_for_paper.md", drop_title=True)),
        "## Tables: session, per-request, bandwidth, stack, WAN (tables_final.md)\n\n" + demote(text("tables_final.md", drop_title=True)),
        "## Tables: DoS flood grid (tables_dos.md)\n\n" + demote(text("tables_dos.md", drop_title=True)),
    ]
    open(os.path.join(ROOT, "RESULTS.md"), "w").write("\n".join(parts))


if __name__ == "__main__":
    main()
