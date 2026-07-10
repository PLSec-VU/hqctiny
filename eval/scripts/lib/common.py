from __future__ import annotations

import os
import platform
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

VARIANTS = os.environ.get("VARIANTS", "hqc1 hqc3 hqc5").split()


def compose(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    """Runs `docker compose -f docker-compose.yml <args>`."""
    return subprocess.run(["docker", "compose", "-f", str(COMPOSE_FILE), *args], check=check)


def ensure_up(service: str = "server") -> None:
    compose("up", "-d", service, check=True)


def dexec(
    service: str, *argv: str, capture_output: bool = False, check: bool = True
) -> subprocess.CompletedProcess:
    """Runs argv directly inside `service` -- see module docstring."""
    cmd = ["docker", "compose", "-f", str(COMPOSE_FILE), "exec", "-T", service, *argv]
    if capture_output:
        return subprocess.run(cmd, check=check, capture_output=True, text=True)
    return subprocess.run(cmd, check=check)


def dexec_server(*argv: str, capture_output: bool = False, check: bool = True):
    return dexec("server", *argv, capture_output=capture_output, check=check)


def dexec_client(*argv: str, capture_output: bool = False, check: bool = True):
    return dexec("client", *argv, capture_output=capture_output, check=check)


def dexec_py(service: str, script: str, *args: str, check: bool = True):
    """Runs a container/*.py helper script inside `service`."""
    return dexec(service, "python3", f"/work/eval/scripts/container/{script}", *args, check=check)


def _host_git_info() -> tuple[str, bool]:
    """(commit, dirty). Not the containers' git -- the bind mount is the
    same working tree, but git plumbing behaves oddly run from inside a
    container as a different user, so this always runs on the host.
    """
    try:
        commit = subprocess.run(
            ["git", "-C", str(EVAL_DIR), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "-C", str(EVAL_DIR), "status", "--porcelain"],
            capture_output=True, text=True, check=True,
        ).stdout
        return commit, bool(status.strip())
    except (FileNotFoundError, subprocess.CalledProcessError):
        return "(unavailable)", False


def capture_provenance() -> None:
    """Writes raw/provenance.txt: what exactly produced these numbers
    (host platform, git commit/dirty state, container toolchain/CPU). Runs
    once per eval/run.py invocation regardless of which --categories were
    selected, so every report.md is traceable back to a specific build.
    """
    commit, dirty = _host_git_info()
    lines = [
        f"generated_at_utc: {TS}",
        f"git_commit: {commit}{' (dirty working tree)' if dirty else ''}",
        f"host_platform: {platform.platform()}",
        f"host_python: {platform.python_version()}",
    ]
    result = dexec("server", "python3", "/work/eval/scripts/container/provenance.py", capture_output=True, check=False)
    lines.append(result.stdout.strip())
    (RAW_DIR / "provenance.txt").write_text("\n".join(lines) + "\n")


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
