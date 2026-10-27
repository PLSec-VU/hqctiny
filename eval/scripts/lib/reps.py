"""Repetition helpers shared by the drivers. A driver runs N repetitions.
Inside each repetition it runs every cell (a system, variant and attack
combination) once, in an order that is shuffled per repetition. Between-run
variance is then the spread of one cell's values across repetitions.
"""

from __future__ import annotations

import random
import statistics
import time

NON_NUMERIC_KEYS = frozenset({"rep"})


def new_seed() -> int:
    return int(time.time()) % 1_000_000


def shuffled_for_rep(items: list, seed: int, rep: int) -> list:
    order = list(items)
    random.Random(f"{seed}-{rep}").shuffle(order)
    return order


def quartiles(values: list[float]) -> tuple[float, float]:
    if len(values) >= 4:
        q1, _, q3 = statistics.quantiles(values, n=4, method="inclusive")
        return q1, q3
    return min(values), max(values)


def describe(values: list[float]) -> dict:
    q1, q3 = quartiles(values)
    return {
        "n": len(values),
        "mean": statistics.fmean(values),
        "sd": statistics.stdev(values) if len(values) > 1 else None,
        "median": statistics.median(values),
        "q1": q1,
        "q3": q3,
        "min": min(values),
        "max": max(values),
    }


def describe_rows(rows: list[dict]) -> dict:
    """Between-repetition statistics for every numeric column of `rows`
    (one row per repetition)."""
    keys = {k for row in rows for k in row}
    summary = {}
    for key in sorted(keys - NON_NUMERIC_KEYS):
        values = [
            row[key] for row in rows
            if isinstance(row.get(key), (int, float)) and not isinstance(row.get(key), bool)
            and row[key] == row[key]
        ]
        if values:
            summary[key] = describe(values)
    return summary
