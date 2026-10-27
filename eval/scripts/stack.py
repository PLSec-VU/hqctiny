#!/usr/bin/env python3
"""Stack and binary size of the three servers.

For each of stateless HqcLethe, the stateful baseline (each at every
variant) and McTiny, this finds the smallest `ulimit -s` at which the real
server binary still serves one full real client session (see
container/stack_search.py for the exact test; resolution 4 KiB). It also
records `size` (text, data, bss) of the three server binaries. The HqcLethe
servers are the tiny-release builds. McTiny is a host program; it runs on
the host with the same core placement.

  eval/scripts/stack.py [--variants hqc1 hqc3 hqc5] [--no-mctiny]

Output: raw/stack.json and raw/stack.log.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "lib"))
sys.path.insert(0, str(HERE / "container"))
from common import (  # noqa: E402
    RAW_DIR, VARIANTS, cargo_build, dexec_py, dexec_server, ensure_up, hqc_features, log_section,
    setup_keys, start_log,
)
from mctiny_session_cpu import DEFAULT_MCTINY_DIR, DEFAULT_STATE_DIR, McTiny  # noqa: E402
from placement import CLIENT_CORE  # noqa: E402
from stack_search import find_minimum_stack  # noqa: E402

TARGET = "/work/target-linux/tiny-release"
HQCLETHE_SERVERS = {"stateless": f"{TARGET}/hqclethe-server", "stateful": f"{TARGET}/hqclethe-server-stateful"}
MCTINY_PORT = 24501
LOOPBACK = "127.0.0.1"


def parse_size(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 6:
            rows.append({"binary": fields[5], "text": int(fields[0]), "data": int(fields[1]),
                         "bss": int(fields[2]), "total": int(fields[3])})
    return rows


def hqclethe_sizes() -> list[dict]:
    result = dexec_server("size", *HQCLETHE_SERVERS.values(), capture_output=True)
    print(result.stdout, end="")
    return parse_size(result.stdout)


def mctiny_size(mctiny: McTiny) -> list[dict]:
    result = subprocess.run(["size", mctiny.server_bin], capture_output=True, text=True, check=True)
    print(result.stdout, end="")
    return parse_size(result.stdout)


def container_search(system: str, variant: str) -> dict:
    result = dexec_py("server", "stack_search.py", system, variant, capture_output=True)
    print(result.stdout, end="")
    line = next(line for line in result.stdout.splitlines() if line.startswith("RESULT "))
    return json.loads(line[len("RESULT "):])


def mctiny_search(mctiny: McTiny) -> dict:
    server = [mctiny.server_bin, mctiny.state_dir, LOOPBACK, str(MCTINY_PORT)]
    client = ["taskset", "-c", str(CLIENT_CORE), mctiny.client_bin, mctiny.public_key, LOOPBACK, str(MCTINY_PORT)]
    print(f"mctiny: server {' '.join(server)}", flush=True)
    return {"system": "mctiny", "variant": None, **find_minimum_stack(server, client)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--variants", default=" ".join(VARIANTS))
    parser.add_argument("--systems", default="stateless,stateful")
    parser.add_argument("--no-mctiny", action="store_true")
    args = parser.parse_args()
    variants = args.variants.replace(",", " ").split()
    mctiny_dir = Path(os.environ.get("MCTINY_DIR", DEFAULT_MCTINY_DIR))
    state_dir = Path(os.environ.get("MCTINY_STATE", DEFAULT_STATE_DIR))
    mctiny = None if args.no_mctiny or not (mctiny_dir / "mctiny-server").exists() else McTiny(mctiny_dir, state_dir)

    ensure_up()
    with start_log("stack.log"):
        log_section("7. Stack and binary size of the servers")
        setup_keys()
        quiet = hqc_features("quiet")
        cargo_build("--profile", "tiny-release", "-p", "hqclethe-server", features=quiet)
        cargo_build("--profile", "tiny-release", "-p", "hqclethe-stateful",
                    "--bin", "hqclethe-server-stateful", features=quiet)
        cargo_build("--release", "-p", "hqclethe-client", features=quiet)
        cargo_build("--release", "-p", "hqclethe-stateful", "--bin", "hqclethe-client-stateful", features=quiet)

        print("\n--- size (text, data, bss) ---")
        sizes = hqclethe_sizes() + (mctiny_size(mctiny) if mctiny else [])

        searches = []
        for system in args.systems.split(","):
            for variant in variants:
                print(f"\n--- minimum stack: {system} {variant} ---")
                searches.append(container_search(system, variant))
        if mctiny:
            print("\n--- minimum stack: mctiny ---")
            searches.append(mctiny_search(mctiny))

        print("\n--- Summary ---")
        for s in searches:
            print(f"{s['system']:9} {s.get('variant') or '-':5} minimum stack {s['min_stack_kib']} KiB")
        (RAW_DIR / "stack.json").write_text(json.dumps({"sizes": sizes, "stack": searches}, indent=1) + "\n")


if __name__ == "__main__":
    main()
