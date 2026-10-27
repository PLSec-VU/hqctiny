#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "container"))
from systems import replay_rate_args  # noqa: E402

PI = os.environ.get("PI", "user@rpi")
PI_HOST = os.environ.get("PI_HOST", "192.168.50.241")
PI_ROOT = os.environ.get("PI_ROOT", "/mnt/arm")
PI_BIN = os.environ.get("PI_BIN", f"{PI_ROOT}/bin")
PLAY = os.environ.get("PLAY", "playground")
PLAY_TOOLS = os.environ.get("MEMCAP_PLAY_DIR", "memcap-build")
PLAY_CORES = os.environ.get("MEMCAP_PLAY_CORES", "12-15")
BIND_BASE = os.environ.get("MEMCAP_BIND_BASE", "10.99")
PORT = int(os.environ.get("MEMCAP_PORT", "24600"))
GRANULE = int(os.environ.get("MEMCAP_GRANULE_KIB", "64")) * 1024
GENEROUS = int(os.environ.get("MEMCAP_GENEROUS_MIB", "128")) * 1024 * 1024
FLOOR = int(os.environ.get("MEMCAP_FLOOR_KIB", "256")) * 1024
CONFIRMATIONS = int(os.environ.get("MEMCAP_CONFIRMATIONS", "2"))
SESSION_TIMEOUT_S = int(os.environ.get("MEMCAP_SESSION_TIMEOUT_S", "120"))
MCTINY_SESSION_TIMEOUT_S = int(os.environ.get("MEMCAP_MCTINY_SESSION_TIMEOUT_S", "240"))
MCTINY_CONCURRENT_TIMEOUT_S = int(os.environ.get("MEMCAP_MCTINY_CONCURRENT_TIMEOUT_S", "1200"))
ALIVE_POLL_S = float(os.environ.get("MEMCAP_ALIVE_POLL_S", "10"))
QUIET_SCAN_STEP = int(os.environ.get("MEMCAP_QUIET_SCAN_STEP_KIB", "128")) * 1024
QUIET_REFAULT_LIMIT = int(os.environ.get("MEMCAP_QUIET_REFAULTS", "256"))
HEALTHY_FACTOR = float(os.environ.get("MEMCAP_HEALTHY_FACTOR", "5"))
HEALTHY_SLACK_S = float(os.environ.get("MEMCAP_HEALTHY_SLACK_S", "0.1"))


@dataclass(frozen=True)
class Workload:
    name: str
    k: int
    rounds: int
    stagger_ms: int
    stop_on_failure: bool


WORKLOADS = {
    "seq50": Workload("seq50", 1, 50, 0, True),
    "k1": Workload("k1", 1, 1, 0, True),
    "k16": Workload("k16", 16, 2, 1, False),
    "k64": Workload("k64", 64, 2, 1, False),
}
MCTINY_WORKLOADS = {
    "seq50": Workload("seq50", 1, int(os.environ.get("MEMCAP_MCTINY_SEQ", "50")), 0, True),
    "k1": Workload("k1", 1, 1, 0, True),
    "k16": Workload("k16", 16, 1, 1, False),
    "k64": Workload("k64", 64, 1, 1, False),
}


@dataclass(frozen=True)
class Cell:
    system: str
    variant: str | None

    @property
    def label(self) -> str:
        return f"{self.system}-{self.variant}" if self.variant else self.system

    def server_argv(self) -> list[str]:
        if self.system == "mctiny":
            return [f"{PI_BIN}/mctiny/mctiny-server", f"{PI_ROOT}/mctiny_state", PI_HOST, str(PORT)]
        binary = {"stateless": "quiet/hqclethe-server", "stateful": "quiet/hqclethe-server-stateful",
                  "stateful-stats": "floodstats/hqclethe-server-stateful"}[self.system]
        return [f"{PI_BIN}/{binary}", "--port", str(PORT), "--variant", self.variant,
                "--key", f"{PI_ROOT}/keys/server-{self.variant}.sk",
                *(replay_rate_args(self.variant) if self.system == "stateless" else [])]

    def workloads(self) -> dict[str, Workload]:
        return MCTINY_WORKLOADS if self.system == "mctiny" else WORKLOADS

    def client_system(self) -> str:
        return "stateful" if self.system == "stateful-stats" else self.system

    def session_timeout_s(self, workload: Workload) -> int:
        if self.system != "mctiny":
            return SESSION_TIMEOUT_S
        return MCTINY_CONCURRENT_TIMEOUT_S if workload.k > 1 else MCTINY_SESSION_TIMEOUT_S


class Agent:
    def __init__(self):
        self.proc = subprocess.Popen(
            ["ssh", "-o", "BatchMode=yes", "-o", "ServerAliveInterval=30", PI, "sudo", "python3",
             f"{PI_ROOT}/memcap/pi_agent.py"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)

    def call(self, **request) -> dict:
        self.proc.stdin.write(json.dumps(request) + "\n")
        self.proc.stdin.flush()
        return json.loads(self.proc.stdout.readline())

    def close(self) -> None:
        self.call(cmd="quit")
        self.proc.wait(timeout=30)


def run_clients(cell: Cell, workload: Workload, server_alive) -> dict:
    command = ["taskset", "-c", PLAY_CORES, "python3", f"{PLAY_TOOLS}/memcap/clients.py",
               "--system", cell.client_system(), "--addr", f"{PI_HOST}:{PORT}", "--k", str(workload.k),
               "--rounds", str(workload.rounds), "--stagger-ms", str(workload.stagger_ms),
               "--timeout-s", str(cell.session_timeout_s(workload))]
    if cell.variant:
        command += ["--variant", cell.variant, "--bind-base", BIND_BASE]
    if workload.stop_on_failure:
        command.append("--stop-on-failure")
    if cell.system == "stateful-stats":
        command.append("--stats-probe")
    proc = subprocess.Popen(["ssh", PLAY, shlex.join(command)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    while True:
        try:
            stdout, stderr = proc.communicate(timeout=ALIVE_POLL_S)
            break
        except subprocess.TimeoutExpired:
            if server_alive():
                continue
            proc.kill()
            proc.communicate()
            subprocess.run(["ssh", PLAY, "pkill -f '[m]emcap/clients.py'; pkill -f '[m]ctiny-client'; true"])
            return {"completed": 0, "failures": -1, "attempted": 0, "seconds": [], "errors": [{"rc": "server died"}]}
    lines = [line for line in stdout.splitlines() if line.startswith("{")]
    if not lines:
        return {"completed": 0, "failures": -1, "attempted": 0, "seconds": [], "errors": [{"rc": proc.returncode, "stderr_tail": stderr[-300:]}]}
    return json.loads(lines[-1])


class Run:
    def __init__(self, agent: Agent, trials_path: Path):
        self.agent, self.trials_path, self.counter = agent, trials_path, 0

    def trial(self, cell: Cell, workload: Workload, cap: int | None, purpose: str, bound_s: float | None = None) -> dict:
        self.counter += 1
        name = f"{cell.label}-{workload.name}-{int(time.time())}-{self.counter}"
        started = self.agent.call(cmd="start", name=name, argv=cell.server_argv(), cap_bytes=cap, port=PORT,
                                  stderr_path=f"{PI_ROOT}/memcap/server_{name}.log")
        clients = run_clients(cell, workload, lambda: self.agent.call(cmd="stats")["alive"]) if started["ready"] else None
        final = self.agent.call(cmd="stop")
        passed = bool(started["ready"] and clients and clients["failures"] == 0
                      and clients["attempted"] == workload.k * workload.rounds
                      and final["events"].get("oom_kill", 0) == 0 and final["alive"])
        healthy = bool(passed and bound_s is not None and max(clients["seconds"]) <= bound_s)
        quiet = bool(passed and final["stat"]["workingset_refault_file"] <= QUIET_REFAULT_LIMIT)
        row = {"cell": cell.label, "workload": workload.name, "purpose": purpose, "cap_bytes": cap,
               "passed": passed, "healthy": healthy, "quiet": quiet, "bound_s": bound_s, "started": started, "clients": clients,
               "final": final, "time": time.time()}
        with self.trials_path.open("a") as out:
            out.write(json.dumps(row) + "\n")
        print(f"{cell.label} {workload.name} {purpose} cap={cap} pass={passed} healthy={healthy} "
              f"peak={final['memory_peak']} anon={final['stat'].get('anon')} oom={final['events'].get('oom_kill')} "
              f"fail={clients and clients['failures']} max_s={clients and max(clients['seconds'], default=None)}",
              flush=True)
        return row

    def bisect(self, cell: Cell, workload: Workload, low: int, high: int, criterion: str, bound_s: float | None) -> int:
        while high - low > GRANULE:
            middle = (low + high) // 2 // GRANULE * GRANULE
            if middle <= low:
                break
            if self.trial(cell, workload, middle, "search-" + criterion, bound_s)[criterion]:
                high = middle
            else:
                low = middle
        return high

    def confirm(self, cell: Cell, workload: Workload, cap: int, criterion: str, bound_s: float | None) -> dict:
        attempts = 0
        while True:
            attempts += 1
            rows = [self.trial(cell, workload, cap, "confirm-" + criterion, bound_s) for _ in range(CONFIRMATIONS)]
            if all(r[criterion] for r in rows):
                return {"cap": cap, "trial": rows[-1], "attempts": attempts}
            cap += GRANULE

    def search(self, cell: Cell, workload: Workload) -> dict:
        generous = self.trial(cell, workload, GENEROUS, "generous")
        if not generous["passed"]:
            return {"error": "generous cap fails", "generous": generous}
        floor = self.trial(cell, workload, FLOOR, "floor")
        low, high = (0, FLOOR) if floor["passed"] else (FLOOR, GENEROUS)
        high = self.bisect(cell, workload, low, high, "passed", None)
        confirmed = self.confirm(cell, workload, high, "passed", None)
        return {"min_cap_bytes": confirmed["cap"], "min_cap_trial": confirmed["trial"], "generous": generous,
                "confirm_attempts": confirmed["attempts"]}

    def search_quiet(self, cell: Cell, workload: Workload, earlier: dict) -> dict:
        low = earlier["min_cap_bytes"]
        first = self.trial(cell, workload, low, "quiet-first")
        high = low if first["quiet"] else self.bisect(cell, workload, low, GENEROUS, "quiet", None)
        confirmed = self.confirm(cell, workload, high, "quiet", None)
        return {"quiet_min_cap_bytes": confirmed["cap"], "quiet_trial": confirmed["trial"],
                "quiet_refault_limit": QUIET_REFAULT_LIMIT, "quiet_confirm_attempts": confirmed["attempts"]}

    def scan_quiet(self, cell: Cell, workload: Workload, earlier: dict) -> dict:
        cap = earlier["min_cap_bytes"]
        while not self.trial(cell, workload, cap, "quiet-scan")["quiet"]:
            cap += QUIET_SCAN_STEP
        confirmed = self.confirm(cell, workload, cap, "quiet", None)
        return {"quiet_min_cap_bytes": confirmed["cap"], "quiet_trial": confirmed["trial"],
                "quiet_refault_limit": QUIET_REFAULT_LIMIT, "quiet_confirm_attempts": confirmed["attempts"],
                "quiet_method": "upward-scan", "quiet_bisect_cap_bytes": earlier.get("quiet_min_cap_bytes")}

    def search_healthy(self, cell: Cell, workload: Workload, earlier: dict) -> dict:
        bound_s = healthy_bound(earlier["generous"]["clients"]["seconds"])
        low = earlier["min_cap_bytes"]
        first = self.trial(cell, workload, low, "healthy-first", bound_s)
        high = low if first["healthy"] else self.bisect(cell, workload, low, GENEROUS, "healthy", bound_s)
        confirmed = self.confirm(cell, workload, high, "healthy", bound_s)
        return {"healthy_min_cap_bytes": confirmed["cap"], "healthy_trial": confirmed["trial"], "bound_s": bound_s,
                "healthy_confirm_attempts": confirmed["attempts"]}


def verify_sequence(run: Run, cell: Cell, earlier: dict) -> dict:
    workload = Workload("seq50", 1, VERIFY_SESSIONS, 0, True)
    confirmed = run.confirm(cell, workload, earlier["min_cap_bytes"], "passed", None)
    return {"verified_cap_bytes": confirmed["cap"], "verified_trial": confirmed["trial"], "verified_sessions": VERIFY_SESSIONS}


def healthy_bound(reference_seconds: list[float]) -> float:
    return HEALTHY_FACTOR * max(reference_seconds) + HEALTHY_SLACK_S


SANITY_LOSSES = tuple(float(p) for p in os.environ.get("MEMCAP_SANITY_LOSSES", "0,0.2").split(","))
SANITY_KS = (1, 16, 64)
VERIFY_SESSIONS = int(os.environ.get("MEMCAP_VERIFY_SESSIONS", "50"))


def sanity(run: Run, cell: Cell) -> None:
    for loss in SANITY_LOSSES:
        run.agent.call(cmd="loss", port=PORT, probability=loss)
        for k in SANITY_KS:
            run.trial(cell, Workload(f"sanity-k{k}-loss{loss}", k, 2, 1, False), GENEROUS, f"sanity-loss{loss}")
    run.agent.call(cmd="loss", port=PORT, probability=0)


def load(path: Path) -> dict:
    return json.loads(path.read_text()) if path.exists() else {}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cells", default="stateless:hqc1,stateless:hqc3,stateless:hqc5,stateful:hqc1,stateful:hqc3,"
                        "stateful:hqc5,mctiny")
    parser.add_argument("--workloads", default="seq50,k1,k16,k64")
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--healthy", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--quiet-scan", action="store_true")
    parser.add_argument("--sanity", action="store_true")
    parser.add_argument("--verify-sequence", action="store_true")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    results_path = args.out / "min_caps.json"
    results = load(results_path)
    cells = [Cell(*(c.split(":") + [None])[:2]) for c in args.cells.split(",")]
    agent = Agent()
    results["environment"] = agent.call(cmd="env")
    run = Run(agent, args.out / "trials.jsonl")
    try:
        for cell in cells:
            if args.sanity:
                sanity(run, cell)
                continue
            for name in args.workloads.split(","):
                workload = cell.workloads()[name]
                key = f"{cell.label}/{name}"
                if args.smoke:
                    run.trial(cell, workload, GENEROUS, "smoke")
                    continue
                if args.verify_sequence:
                    if name == "seq50" and "verified_cap_bytes" not in results.get(key, {}):
                        results[key].update(verify_sequence(run, cell, results[key]))
                elif args.quiet_scan:
                    if "min_cap_bytes" in results.get(key, {}):
                        results[key].update(run.scan_quiet(cell, workload, results[key]))
                elif args.quiet:
                    if "min_cap_bytes" in results.get(key, {}) and "quiet_min_cap_bytes" not in results[key]:
                        results[key].update(run.search_quiet(cell, workload, results[key]))
                elif args.healthy:
                    if "min_cap_bytes" in results.get(key, {}) and "healthy_min_cap_bytes" not in results[key]:
                        results[key].update(run.search_healthy(cell, workload, results[key]))
                elif key not in results or "min_cap_bytes" not in results[key]:
                    results[key] = run.search(cell, workload)
                else:
                    continue
                results_path.write_text(json.dumps(results, indent=1) + "\n")
    finally:
        agent.close()


if __name__ == "__main__":
    main()
