"""The systems under test. Each entry says how to start the server, run one
client session, and flood the server. All container scripts take their
command lines from here, so a new system (for example the McTiny baseline)
plugs in by adding one `System` entry. Its binaries must:

  * accept `--port P --variant V --key SK` for the server,
  * accept `client --addr A --variant V --server-key PK` and exit 0 only
    after a completed, authenticated session,
  * accept `flood-client --addr A --variant V --server-key PK --duration D
    --sockets N --source-ips M --kind K` (D is the length of the attack
    after the client's own setup), and print one JSON line with
    `packets_sent` and `attack_started_secs` (seconds from process start to
    the first attack packet) at the end,
  * print `[phase] <name> t=<seconds>` lines on stderr (see `phases`).

Run inside the eval container. Import, do not run.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

DEFAULT_STATELESS_FLOOD_KINDS = "handshake auth uchunk vresidue"
STATELESS_FLOOD_KINDS = tuple(
    os.environ.get("STATELESS_FLOOD_KINDS", DEFAULT_STATELESS_FLOOD_KINDS).split()
)
STATEFUL_FLOOD_KINDS = ("hello", "partial", "fullkey", "auth", "churn", "churn2")
TABLE_FILLING_KINDS = ("partial", "churn2")

TARGET_DIR = os.environ.get("TARGET_DIR", "/work/target-linux")
KEY_DIR = os.environ.get("KEY_DIR", f"{TARGET_DIR}/eval-keys")
BIN_DIR = os.environ.get("SERVER_BIN_DIR", f"{TARGET_DIR}/tiny-release")
CLIENT_BIN_DIR = os.environ.get("CLIENT_BIN_DIR", f"{TARGET_DIR}/release")
LEGIT_SOURCE_IP = "127.2.0.1"
REPLAY_RATES_ENV = "STATELESS_REPLAY_RATES"


def replay_rate_args(variant: str) -> list[str]:
    rates = dict(item.split("=") for item in os.environ.get(REPLAY_RATES_ENV, "").split(",") if item)
    return ["--replay-rate", rates[variant]] if variant in rates else []


def secret_key_path(variant: str) -> str:
    return f"{KEY_DIR}/server-{variant}.sk"


def public_key_path(variant: str) -> str:
    return f"{KEY_DIR}/server-{variant}.pk"


@dataclass(frozen=True)
class Phases:
    first_request_sent: str
    first_response_received: str
    second_request_sent: str
    session_done: str


@dataclass(frozen=True)
class System:
    name: str
    server_bin: str
    client_bin: str
    phases: Phases
    flood_kinds: tuple[str, ...]
    legit_bind_flag: str | None = None
    server_extra_args_env: str | None = None
    stats_probe: bool = False
    extra: dict = field(default_factory=dict)

    def server_command(self, variant: str, port: int, extra: list[str] | None = None) -> list[str]:
        return [
            self.server_bin, "--port", str(port), "--variant", variant,
            "--key", secret_key_path(variant), *(extra or []),
            *(replay_rate_args(variant) if self.name == "stateless" else []),
        ]

    def client_command(self, variant: str, addr: str, bind_ip: str | None = None) -> list[str]:
        cmd = [
            self.client_bin, "client", "--addr", addr, "--variant", variant,
            "--server-key", public_key_path(variant),
        ]
        if bind_ip and self.legit_bind_flag:
            cmd += [self.legit_bind_flag, bind_ip]
        return cmd

    def flood_command(
        self, variant: str, addr: str, duration: int, sockets: int, source_ips: int, kind: str
    ) -> list[str]:
        return [
            self.client_bin, "flood-client", "--addr", addr, "--variant", variant,
            "--server-key", public_key_path(variant), "--duration", str(duration),
            "--sockets", str(sockets), "--source-ips", str(source_ips), "--kind", kind,
        ]


SYSTEMS: dict[str, System] = {
    "stateless": System(
        name="stateless",
        server_bin=f"{BIN_DIR}/hqclethe-server",
        client_bin=f"{CLIENT_BIN_DIR}/hqclethe-client",
        phases=Phases(
            "handshake_request_sent", "handshake_response_received",
            "point_requests_sent", "session_key_derived",
        ),
        flood_kinds=STATELESS_FLOOD_KINDS,
        legit_bind_flag="--bind-ip",
        server_extra_args_env="STATELESS_SERVER_ARGS",
        stats_probe=False,
    ),
    "stateful": System(
        name="stateful",
        server_bin=f"{BIN_DIR}/hqclethe-server-stateful",
        client_bin=f"{CLIENT_BIN_DIR}/hqclethe-client-stateful",
        phases=Phases(
            "hello_sent", "hello_response_received",
            "key_fragments_sent", "shared_secret_derived",
        ),
        flood_kinds=STATEFUL_FLOOD_KINDS,
        legit_bind_flag="--bind-ip",
        server_extra_args_env="STATEFUL_SERVER_ARGS",
        stats_probe=True,
    ),
}
