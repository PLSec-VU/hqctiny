#!/usr/bin/env python3
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
sys.path.insert(0, str(Path(__file__).resolve().parent / "container"))
from common import (  # noqa: E402
    EVAL_DIR, RAW_DIR, dexec_server, ensure_up, hqc_features, knobs, log_section,
    measured_run, start_log,
)
from placement import SERVER_CORE  # noqa: E402

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


def main() -> None:
    ensure_up()
    with start_log("cpu_benchmarks.log"), measured_run("cpu_benchmarks"):
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
        criterion_args = knobs.get("CRITERION_ARGS").split()
        bench_names = ("kem_primitives", "protocol_phases", "puzzle", "stateful_baseline")
        bench_flags = [flag for name in bench_names for flag in ("--bench", name)]
        features = ["--features", hqc_features()]
        dexec_server("cargo", "bench", *bench_flags, *features, "--no-run", "-q")
        dexec_server(
            "taskset", "-c", str(SERVER_CORE), "cargo", "bench", *bench_flags, *features, "-q",
            "--", *criterion_args,
        )

        print()
        print("--- KEM work of the Rosenpass and PQ-WireGuard responders (criterion) ---")
        comparison_features = ["--features", hqc_features("mceliece-ref")]
        dexec_server("cargo", "bench", "--bench", "kem_comparison", *comparison_features, "--no-run", "-q")
        dexec_server(
            "taskset", "-c", str(SERVER_CORE), "cargo", "bench", "--bench", "kem_comparison",
            *comparison_features, "-q", "--", *criterion_args,
        )

        print()
        print("--- Cumulative CPU time across 200 full transactions (all 3 variants/iter) ---")
        dexec_server("cargo", "build", "--release", "--bin", "flamegraph-workload", "--features", hqc_features(), "-q")
        dexec_server(
            "/usr/bin/time", "-v", "/work/target-linux/release/flamegraph-workload", "200",
            check=False,
        )

        print()
        print("--- FFI (keypair+dec) vs protocol-layer time share, per variant ---")
        dexec_server("cargo", "build", "--release", "--bin", "timing-breakdown", "--features", hqc_features(), "-q")
        dexec_server("/work/target-linux/release/timing-breakdown", "300")

        if knobs.get("SKIP_CALLGRIND") == "1":
            print()
            print("--- iai-callgrind skipped (SKIP_CALLGRIND=1) ---")
        else:
            print()
            print("--- Deterministic instruction/cycle counts (iai-callgrind, requires valgrind) ---")
            result = dexec_server("cargo", "bench", "--bench", "callgrind_primitives", "--features", hqc_features(), "-q", capture_output=True)
            callgrind_text = result.stdout + result.stderr
            print(callgrind_text, end="")
            (RAW_DIR / "callgrind.txt").write_text(callgrind_text)

        archive_criterion_estimates()
        print()
        print(f"(criterion estimates.json per benchmark archived to {RAW_DIR / 'criterion'})")

        print()
        print("--- Cycles per byte of attacker traffic (derived_metrics.py) ---")
        derived = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parent / "derived_metrics.py"),
             "--results-dir", str(RAW_DIR.parent)],
            check=False,
        )
        if derived.returncode != 0:
            print("(derived metrics need raw/bandwidth*.json from category 2 in this results directory)")


if __name__ == "__main__":
    main()
