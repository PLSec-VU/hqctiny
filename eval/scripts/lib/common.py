from __future__ import annotations

import hashlib
import json
import os
import platform
import shlex
import subprocess
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

EVAL_DIR = Path(__file__).resolve().parent.parent.parent
COMPOSE_FILE = EVAL_DIR / "docker-compose.yml"

# TS/HOST_RESULTS_DIR may already be set by run.py (shared across all
# categories in one run); default to a fresh timestamp when a script is
# invoked standalone.
TS = os.environ.get("TS") or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
HOST_RESULTS_DIR = Path(os.environ.get("HOST_RESULTS_DIR") or (EVAL_DIR / "results" / TS))
# Same directory, as seen from inside the containers (bind-mounted at /work).
CRESULTS_DIR = f"/work/eval/results/{TS}"
RAW_DIR = HOST_RESULTS_DIR / "raw"
RAW_DIR.mkdir(parents=True, exist_ok=True)

sys.path.insert(0, str(Path(__file__).resolve().parent))
import knobs  # noqa: E402

VARIANTS = knobs.get("VARIANTS").split()
KEY_DIR = "/work/target-linux/eval-keys"
ML_KEM_768_SECRET_KEY_BYTES = 2400
CLIENT_BIN = "/work/target-linux/release/hqclethe-client"
# One compose project per checkout. Without it every checkout would use the
# project name "eval" and recreate the containers of another checkout.
COMPOSE_PROJECT = os.environ.get("COMPOSE_PROJECT") or (
    "hqclethe-eval-" + hashlib.sha256(str(EVAL_DIR).encode()).hexdigest()[:8]
)
COMMAND_LOG = RAW_DIR / "commands.log"


def _log_host_command(argv: list[str]) -> None:
    without_env = []
    skip_next = False
    for arg in argv:
        if skip_next:
            skip_next = False
        elif arg == "-e":
            skip_next = True
        else:
            without_env.append(arg)
    with COMMAND_LOG.open("a") as log:
        log.write(shlex.join(without_env) + "\n")


PASSTHROUGH_ENV = (
    "STATEFUL_SERVER_ARGS", "STATELESS_SERVER_ARGS", "SETTLE_SECS", "STATELESS_FLOOD_KINDS", "REP_BASE",
)


def _forwarded_env_flags(extra_env: dict[str, str] | None = None) -> list[str]:
    """`docker compose exec` does not pass the host environment on. Forward
    every knob (resolved, so smoke defaults reach the container scripts),
    and the extra options that container scripts read."""
    values = dict(knobs.resolved())
    values.update({name: os.environ[name] for name in PASSTHROUGH_ENV if name in os.environ})
    values["PYTHONDONTWRITEBYTECODE"] = "1"
    values.update(extra_env or {})
    return [flag for name, value in values.items() for flag in ("-e", f"{name}={value}")]


def _compose_argv(*args: str) -> list[str]:
    return ["docker", "compose", "-p", COMPOSE_PROJECT, "-f", str(COMPOSE_FILE), *args]


def compose(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    """Runs `docker compose -f docker-compose.yml <args>`."""
    argv = _compose_argv(*args)
    _log_host_command(argv)
    return subprocess.run(argv, check=check)


def ensure_up(service: str = "server") -> None:
    compose("up", "-d", service, check=True)


def dexec(
    service: str, *argv: str, capture_output: bool = False, check: bool = True,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    """Runs argv directly inside `service` -- see module docstring."""
    cmd = _compose_argv("exec", "-T", *_forwarded_env_flags(extra_env), service, *argv)
    _log_host_command(cmd)
    if capture_output:
        return subprocess.run(cmd, check=check, capture_output=True, text=True)
    return subprocess.run(cmd, check=check)


def dexec_server(*argv: str, capture_output: bool = False, check: bool = True):
    return dexec("server", *argv, capture_output=capture_output, check=check)


def dexec_client(*argv: str, capture_output: bool = False, check: bool = True):
    return dexec("client", *argv, capture_output=capture_output, check=check)


def dexec_py(
    service: str, script: str, *args: str, check: bool = True,
    capture_output: bool = False, extra_env: dict[str, str] | None = None,
):
    """Runs a container/*.py helper script inside `service`."""
    return dexec(
        service, "python3", f"/work/eval/scripts/container/{script}", *args,
        check=check, capture_output=capture_output, extra_env=extra_env,
    )


def hqc_features(*extra: str) -> str:
    """Comma-separated cargo feature list: `extra` plus the HQC backend.
    HQC_BACKEND defaults to "avx2". Set it to the empty string on hosts
    that are not x86_64 with AVX2."""
    backend = os.environ.get("HQC_BACKEND", "avx2")
    return ",".join([*extra, *([backend] if backend else [])])


def cargo_build(*args: str, features: str | None = None) -> None:
    """`cargo build <args>` in the server container. `features` is a
    comma-separated list, or None for the backend feature alone."""
    feature_list = hqc_features() if features is None else features
    feature_args = ["--features", feature_list] if feature_list else []
    dexec_server("cargo", "build", *args, *feature_args, "-q")


GIT_INFO_FILE = EVAL_DIR / "GIT_INFO.json"


def _git(*args: str) -> str:
    try:
        return subprocess.run(
            ["git", "-C", str(EVAL_DIR), *args], capture_output=True, text=True, check=True
        ).stdout.strip()
    except (FileNotFoundError, subprocess.CalledProcessError):
        return "(unavailable)"


def git_info() -> dict:
    """Commit, branch and dirty state. A copy of the tree without a usable
    .git (the measurement host) reads them from eval/GIT_INFO.json, which
    scripts/host/sync_to_host.sh writes before it copies the tree."""
    commit = _git("rev-parse", "HEAD")
    if commit != "(unavailable)":
        dirty_files = [
            line for line in _git("status", "--porcelain").splitlines()
            if line.strip() and "GIT_INFO.json" not in line
        ]
        return {
            "commit": commit, "branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
            "dirty": bool(dirty_files), "dirty_files": dirty_files, "source": "git",
        }
    try:
        return {**json.loads(GIT_INFO_FILE.read_text()), "source": GIT_INFO_FILE.name}
    except (OSError, json.JSONDecodeError):
        return {"commit": "(unavailable)", "branch": "(unavailable)", "dirty": None,
                "dirty_files": [], "source": "none"}


def docker_image_id() -> str:
    image = os.environ.get("EVAL_IMAGE", "hqclethe-eval")
    result = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", image],
        capture_output=True, text=True, check=False,
    )
    return result.stdout.strip() or "(unavailable)"


def _docker_info() -> dict:
    text = subprocess.run(
        ["docker", "info", "--format", "{{json .}}"], capture_output=True, text=True, check=False
    ).stdout
    try:
        info = json.loads(text)
    except json.JSONDecodeError:
        return {}
    return {k: info.get(k) for k in ("ServerVersion", "Architecture", "OperatingSystem", "NCPU", "MemTotal")}


def _container_provenance() -> dict:
    result = dexec("server", "python3", "/work/eval/scripts/container/provenance.py", capture_output=True, check=False)
    pairs = (line.split(": ", 1) for line in result.stdout.splitlines() if ": " in line)
    return {key: value for key, value in pairs}


def capture_provenance(categories: list[str] | None = None) -> dict:
    """Writes raw/provenance.txt and raw/provenance.json: what produced
    these numbers (git commit and dirty state, host, container CPU and
    toolchain, every knob, emulation status). Runs once per run. Every
    figure in a report traces back to one results directory.
    """
    git = git_info()
    commit, dirty_files = git["commit"], git["dirty_files"]
    container = _container_provenance()
    container_arch = container.get("container_arch", "")
    host_arch = platform.machine()
    arch_aliases = {"arm64": "aarch64", "x86_64": "x86_64", "amd64": "x86_64"}
    emulated = arch_aliases.get(host_arch, host_arch) != arch_aliases.get(container_arch, container_arch)
    record = {
        "generated_at_utc": TS,
        "git_commit": commit,
        "git_branch": git["branch"],
        "git_dirty": git["dirty"],
        "git_info_source": git["source"],
        "docker_image_id": docker_image_id(),
        "git_dirty_files": dirty_files,
        "hqc_submodule": _git("submodule", "status", "hqc"),
        "host_platform": platform.platform(),
        "host_machine": host_arch,
        "host_python": platform.python_version(),
        "docker": _docker_info(),
        "docker_default_platform": os.environ.get("DOCKER_DEFAULT_PLATFORM", ""),
        "compose_project": COMPOSE_PROJECT,
        "container": container,
        "emulated": emulated,
        "smoke": knobs.is_smoke(),
        "hqc_backend": os.environ.get("HQC_BACKEND", "avx2"),
        "knobs": knobs.resolved(),
        "categories": categories or [],
        "argv": sys.argv,
    }
    (RAW_DIR / "provenance.json").write_text(json.dumps(record, indent=2) + "\n")
    lines = [f"{key}: {value}" for key, value in record.items() if not isinstance(value, (dict, list))]
    lines += [f"docker: {record['docker']}", f"knobs: {record['knobs']}"]
    lines += [f"container.{key}: {value}" for key, value in container.items()]
    if emulated:
        lines.append(
            "WARNING: the container architecture differs from the host. "
            "Timings are emulated and are smoke-test numbers only."
        )
    if dirty_files:
        lines.append("WARNING: the working tree has uncommitted changes: " + "; ".join(dirty_files))
    (RAW_DIR / "provenance.txt").write_text("\n".join(lines) + "\n")
    return record


def setup_keys(variants: list[str] | None = None) -> None:
    """Generates one ML-KEM key pair per variant in KEY_DIR (inside the
    container, shared by every run of this checkout). Existing ML-KEM-768
    keys are kept; keys of any other size are replaced. `variants` defaults to the VARIANTS knob. Records a SHA-256 of each public key in raw/keys.txt, so the
    keys behind a result can be identified."""
    cargo_build("--release", "-p", "hqclethe-client")
    dexec_server("mkdir", "-p", KEY_DIR)
    for variant in variants or VARIANTS:
        prefix = f"{KEY_DIR}/server-{variant}"
        sk_size = dexec_server("stat", "-c", "%s", f"{prefix}.sk", capture_output=True, check=False)
        has_mlkem_768_key = sk_size.returncode == 0 and sk_size.stdout.strip() == str(ML_KEM_768_SECRET_KEY_BYTES)
        if not has_mlkem_768_key:
            dexec_server("rm", "-f", f"{prefix}.sk", f"{prefix}.pk")
            dexec_server(CLIENT_BIN, "keygen", "--variant", variant, "--out", prefix)
    digests = dexec_server("sh", "-c", f"cd {KEY_DIR} && sha256sum *.pk", capture_output=True)
    (RAW_DIR / "keys.txt").write_text(digests.stdout)


def log_section(title: str) -> None:
    print()
    print("=" * 67)
    print(f"  {title}")
    print("=" * 67)


@contextmanager
def start_log(filename: str):
    """Mirrors everything printed (by us and by any subprocess we spawn,
    since they inherit our file descriptors) to both the terminal and
    results/<ts>/raw/<filename>, matching what `exec > >(tee file) 2>&1`
    did in the bash version -- but reusing the real `tee` binary rather
    than re-implementing line-buffered streaming ourselves.
    """
    log_path = RAW_DIR / filename
    tee = subprocess.Popen(["tee", str(log_path)], stdin=subprocess.PIPE)
    saved_stdout_fd = os.dup(1)
    saved_stderr_fd = os.dup(2)
    os.dup2(tee.stdin.fileno(), 1)
    os.dup2(tee.stdin.fileno(), 2)
    # Python's own print() goes through io.TextIOWrapper's buffer, whose
    # buffering mode was already fixed (usually full/block buffering, since
    # fd 1 typically isn't a tty in this harness) before the dup2 above --
    # redirecting the underlying fd doesn't change that. Without this, our
    # own print() calls sit in Python's buffer until the process exits while
    # subprocesses we spawn write straight through, so the log ends up with
    # all subprocess output before any of our own -- badly out of order.
    sys.stdout.reconfigure(line_buffering=True)
    sys.stderr.reconfigure(line_buffering=True)
    try:
        yield
    finally:
        sys.stdout.flush()
        sys.stderr.flush()
        os.dup2(saved_stdout_fd, 1)
        os.dup2(saved_stderr_fd, 2)
        os.close(saved_stdout_fd)
        os.close(saved_stderr_fd)
        tee.stdin.close()
        tee.wait()


MEASURE_EXIT_CODE = 3


def _freq_check_enforced() -> bool:
    return os.environ.get("FREQ_CHECK", "1") != "0"


def _loud(message: str) -> None:
    bar = "!" * 70
    print(f"\n{bar}\n{message}\n{bar}\n", flush=True)


@contextmanager
def measured_run(name: str):
    """Wraps one driver run. Records the host state before and after it in
    raw/run_state_<name>.json: governor, boost, SMT and online state of every
    CPU, the clock the pinned cores reach under load, core placement, git
    commit and dirty flag, kernel and Docker image id. It also records the
    network interface counters and the interrupt counts between the start and
    the end of the run (`counter_deltas`). If the measured clock
    deviates from the target by more than the tolerance, the run aborts at
    the start and exits non-zero at the end, unless FREQ_CHECK=0 (then it
    only flags it)."""
    import host_state

    def snap(phase: str) -> dict:
        state = host_state.snapshot()
        state["phase"] = phase
        if state["violations"]:
            _loud(f"RUN STATE VIOLATION at {phase} of {name}: " + "; ".join(state["violations"]))
        return state

    record = {
        "name": name, "git": git_info(), "docker_image_id": docker_image_id(),
        "enforced": _freq_check_enforced(), "start": snap("start"),
    }
    path = RAW_DIR / f"run_state_{name}.json"
    path.write_text(json.dumps(record, indent=2) + "\n")
    if record["start"]["violations"] and record["enforced"]:
        sys.exit(MEASURE_EXIT_CODE)
    failed = False
    counters_start = host_state.counters()
    try:
        yield record
    finally:
        counters_end = host_state.counters()
        record["counter_deltas"] = host_state.counter_deltas(
            counters_start, counters_end, list(host_state.placement.PINNED_CORES) + [host_state.placement.ORCHESTRATOR_CORE]
        )
        record["end"] = snap("end")
        path.write_text(json.dumps(record, indent=2) + "\n")
        failed = bool(record["end"]["violations"]) and record["enforced"]
    if failed:
        sys.exit(MEASURE_EXIT_CODE)
