#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from common import EVAL_DIR, RAW_DIR, dexec_server, ensure_up, log_section, start_log  # noqa: E402

# Bind-mounted at /work in the container (see docker-compose.yml), so the
# criterion output directory is a real path on the host too -- no docker
# exec needed to read it back out.
CRITERION_DIR = EVAL_DIR.parent / "target-linux" / "criterion"


def archive_criterion_estimates() -> None:
    """Copies each benchmark's estimates.json (the summary criterion prints
    from) into raw/criterion/ as supplementary material -- the full
    criterion dir also has HTML reports and raw sample.json iteration
    dumps that are much larger and not worth shipping with the paper.
    """
    dest = RAW_DIR / "criterion"
    if dest.exists():
        shutil.rmtree(dest)
    if not CRITERION_DIR.exists():
        return
    # "**/new/" rather than assuming one directory level: plain
    # c.bench_function ids are flat (criterion/<id>/new/), but that's not
    # guaranteed to stay true if a future benchmark uses BenchmarkGroup/
    # BenchmarkId, which nests an extra level.
    for estimates in CRITERION_DIR.glob("**/new/estimates.json"):
        rel = estimates.relative_to(CRITERION_DIR).parent.parent  # strip trailing "new"
        bench_name = "__".join(rel.parts)
        dest.mkdir(parents=True, exist_ok=True)
        shutil.copy(estimates, dest / f"{bench_name}.json")


def parse_callgrind_cycles(text: str) -> list[tuple[str, int]]:
    """Best-effort parse of iai-callgrind's console table: pairs each
    "Estimated Cycles:" line with the nearest preceding un-indented line,
    which iai-callgrind uses to print the benchmark's identifying header
    (function name + #[bench::id] arguments). Format varies across
    versions, hence the substring-based matching in cycles_per_byte()
    below rather than exact keys.
    """
    results = []
    current = None
    for line in text.splitlines():
        if not line.strip():
            continue
        if line.startswith((" ", "\t")):
            m = re.search(r"Estimated Cycles:\s*([\d,]+)", line)
            if m and current:
                results.append((current, int(m.group(1).replace(",", ""))))
        else:
            current = line.strip()
    return results


def print_cycles_per_byte(results: list[tuple[str, int]], bandwidth_json: Path) -> None:
    if not bandwidth_json.exists():
        print(
            f"(no bandwidth report at {bandwidth_json} -- run category 2 in the same "
            f"results directory first, or use eval/run.py which shares one results "
            f"directory across all categories, to see cycles-per-byte)"
        )
        return
    bw = {v["variant"]: v for v in json.loads(bandwidth_json.read_text())}
    for variant, v in bw.items():
        req_bytes = v["packet_bytes"]["handshake_request"]
        pt_bytes = v["packet_bytes"]["point_request_max"]
        handlers = [
            ("handshake", "handshake", req_bytes),
            ("point_request_u", "point_request(U)", pt_bytes),
            ("point_request_v", "point_request(V)", pt_bytes),
        ]
        for name_substr, label, byte_count in handlers:
            for name, cycles in results:
                if variant in name and name_substr in name:
                    print(
                        f"{variant} {label} handler: {cycles / byte_count:.1f} cycles/byte "
                        f"(of the {byte_count}B request)"
                    )


def main() -> None:
    ensure_up()
    with start_log("cpu_benchmarks.log"):
        log_section("3. CPU Performance & Computational Cost")

        # Criterion compares each run against a saved "base" baseline from
        # target-linux/criterion, printing "change: [...]  Performance has
        # regressed/improved" lines relative to it. That's noise (and
        # actively misleading) for a paper report -- those baselines are
        # whatever a previous local run happened to leave behind, possibly
        # on different hardware or a different commit. Wiping the dir means
        # this run has nothing to compare against, so it reports plain
        # timings only.
        print("Clearing stale criterion baselines...")
        dexec_server("rm", "-rf", "/work/target-linux/criterion")

        print("--- Microbenchmarks + macrobenchmark (criterion, wall-clock median) ---")
        dexec_server("cargo", "bench", "--bench", "kem_primitives", "--bench", "protocol_phases", "--features", "avx2", "-q")

        print()
        print("--- Cumulative CPU time across 200 full transactions (all 3 variants/iter) ---")
        dexec_server("cargo", "build", "--release", "--bin", "flamegraph-workload", "--features", "avx2", "-q")
        dexec_server(
            "/usr/bin/time", "-v", "/work/target-linux/release/flamegraph-workload", "200",
            check=False,
        )

        print()
        print("--- FFI (keypair+dec) vs protocol-layer time share, per variant ---")
        dexec_server("cargo", "build", "--release", "--bin", "timing-breakdown", "--features", "avx2", "-q")
        dexec_server("/work/target-linux/release/timing-breakdown", "300")

        print()
        print("--- Deterministic instruction/cycle counts (iai-callgrind, requires valgrind) ---")
        result = dexec_server("cargo", "bench", "--bench", "callgrind_primitives", "--features", "avx2", "-q", capture_output=True)
        callgrind_text = result.stdout + result.stderr
        print(callgrind_text, end="")
        (RAW_DIR / "callgrind.txt").write_text(callgrind_text)

        print()
        print("--- Cycles-per-byte (handshake and point-request handlers) ---")
        results = parse_callgrind_cycles(callgrind_text)
        if not results:
            print(
                "(could not auto-parse iai-callgrind's console output; "
                "see the raw table above for exact figures)"
            )
        else:
            for name, cycles in results:
                print(f"{name}: {cycles} estimated cycles")
            print()
            print_cycles_per_byte(results, RAW_DIR / "bandwidth.json")

        archive_criterion_estimates()
        print()
        print(f"(criterion estimates.json per benchmark archived to {RAW_DIR / 'criterion'})")


if __name__ == "__main__":
    main()
