#!/usr/bin/env python3
"""Category 9: constant-time check of the ML-KEM-768 decapsulation and of the
server handshake path, in the style of ctgrind.

`profiling/ct_check.rs` puts the secrets in memory that Valgrind Memcheck
reports as uninitialised. A branch or a memory address that depends on a
secret is an error and the exit status is 9. The two control runs must fail,
which shows that the check can see a leak.

The session runs report four known groups, all public by design or known:
the verdict of an XChaCha20-Poly1305 tag check (the tag key is classified),
`residue_is_canonical` on a decrypted v-residue request (the payload is
public), HQC's rejection sampler `vect_generate_random_support1` in the
client's decapsulation, and the client's branch after key confirmation. A
session run passes when every error starts in one of these functions.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
import re  # noqa: E402

from common import RAW_DIR, cargo_build, dexec_server, ensure_up, log_section, start_log  # noqa: E402

ERROR_EXIT_CODE = 9
LEAK_FOUND = ERROR_EXIT_CODE
NO_LEAK = 0
CT_CHECK_BINARY = "/work/target-linux/release/ct-check"

ONLY_KNOWN_GROUPS = "only known groups"
CASES = (
    ("control", LEAK_FOUND),
    ("classify-control", LEAK_FOUND),
    ("mlkem1", NO_LEAK),
    ("mlkem3", NO_LEAK),
    ("mlkem5", NO_LEAK),
    ("session1", ONLY_KNOWN_GROUPS),
    ("session3", ONLY_KNOWN_GROUPS),
    ("session5", ONLY_KNOWN_GROUPS),
)
KNOWN_SESSION_FUNCTIONS = re.compile(
    r"decrypt_in_place_detached|open_request|envelope::open|decrypt_cookie|residue_is_canonical"
    r"|vect_generate_random_support1|Client<.*>>::handle_response|Client<.*>>::finish"
)
FIRST_FRAME = re.compile(r"^==\d+==    at 0x[0-9A-F]+: (.*?)(?: \(in .*\))?$")
ERROR_START = re.compile(r"^==\d+== (Conditional jump|Use of uninitialised|Syscall param)")


def first_frames(log: str) -> list[str]:
    frames, waiting = [], False
    for line in log.splitlines():
        if ERROR_START.match(line):
            waiting = True
        elif waiting and (match := FIRST_FRAME.match(line)):
            frames.append(match.group(1))
            waiting = False
    return frames


def run_case(argument: str, expected: int | str) -> bool:
    result = dexec_server(
        "valgrind", f"--error-exitcode={ERROR_EXIT_CODE}", "--track-origins=yes",
        CT_CHECK_BINARY, argument, capture_output=True, check=False,
    )
    log_path = RAW_DIR / f"ct_check_{argument}.log"
    log_path.write_text(result.stdout + result.stderr)
    summary = next((line for line in result.stderr.splitlines() if "ERROR SUMMARY" in line), "")
    if expected == ONLY_KNOWN_GROUPS:
        unknown = sorted({f for f in first_frames(result.stderr) if not KNOWN_SESSION_FUNCTIONS.search(f)})
        passed = result.returncode in (NO_LEAK, LEAK_FOUND) and not unknown
        detail = "only known groups" if not unknown else f"UNKNOWN first frames: {unknown}"
    else:
        passed = result.returncode == expected
        detail = f"expected exit {expected}"
    print(f"ct-check {argument}: valgrind exit {result.returncode}, {detail}, "
          f"{'as expected' if passed else 'UNEXPECTED'}. {summary}")
    return passed


def main() -> None:
    ensure_up()
    with start_log("ct_check.log"):
        log_section("9. Constant-time check (Valgrind Memcheck, secrets as uninitialised memory)")
        cargo_build("--release", "--bin", "ct-check")
        results = [run_case(argument, expected) for argument, expected in CASES]
        if not all(results):
            sys.exit(1)


if __name__ == "__main__":
    main()
