import os
import sys
from pathlib import Path

ENV_NAME = "RESULTS_DIR"


def results_dir() -> Path:
    value = os.environ.get(ENV_NAME)
    if not value:
        sys.exit(f"error: set {ENV_NAME} to the directory that holds part1, part2, part3, final-x86 and arm-final")
    return Path(value).resolve()


def study_dir(name: str) -> str:
    return str(results_dir() / name)
