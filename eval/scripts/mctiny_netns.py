#!/usr/bin/env python3
"""T8: network-namespace + veth pair standing in for McTiny's "two hosts".

McTiny is not containerized (it runs as bare host binaries -- see M4/T4/T9).
`wan_latency.py`'s two HQCLethe systems get two genuinely separate network
namespaces for free from two Docker Compose services, each with its own
eth0; netem on each container's own eth0 is enough to shape uplink and
downlink independently, with no ifb needed, because "uplink" and "downlink"
are simply each side's own egress in two different namespaces.

This module gives McTiny the same shape: two `ip netns` namespaces
(mctiny_srv, mctiny_cli) joined by one veth pair, each end living in its own
namespace. Shaping each end's own egress (via `tc qdisc ... netem` on that
end's veth) is uplink (client's egress) or downlink (server's egress) exactly
as in the container case -- no ifb is needed here either, for the same
reason: a namespace's "ingress" is the other namespace's egress, so shaping
both ends' egress already gives independent, symmetric control over both
directions.

Run as root (this host has passwordless sudo). Importable, or:
  mctiny_netns.py up
  mctiny_netns.py down
  mctiny_netns.py netem <uplink_loss_pct> <downlink_loss_pct> <rtt_ms> <jitter_ms> [gemodel_params_csv]
  mctiny_netns.py clear
  mctiny_netns.py verify <rtt_ms> <loss_pct>   # empirical check, see verify()
"""
from __future__ import annotations

import re
import statistics
import subprocess
import sys
import time

NETNS_SRV = "mctiny_srv"
NETNS_CLI = "mctiny_cli"
VETH_SRV = "veth-mt-srv"
VETH_CLI = "veth-mt-cli"
IP_SRV = "10.99.0.1"
IP_CLI = "10.99.0.2"
PREFIX = 24


def run(cmd: list[str], check: bool = True, capture: bool = False):
    if capture:
        return subprocess.run(cmd, check=check, capture_output=True, text=True)
    return subprocess.run(cmd, check=check)


def ns_exec(ns: str, *args: str, check: bool = True, capture: bool = False):
    return run(["sudo", "ip", "netns", "exec", ns, *args], check=check, capture=capture)


def up() -> None:
    down(ignore_errors=True)
    run(["sudo", "ip", "netns", "add", NETNS_SRV])
    run(["sudo", "ip", "netns", "add", NETNS_CLI])
    run(["sudo", "ip", "link", "add", VETH_SRV, "type", "veth", "peer", "name", VETH_CLI])
    run(["sudo", "ip", "link", "set", VETH_SRV, "netns", NETNS_SRV])
    run(["sudo", "ip", "link", "set", VETH_CLI, "netns", NETNS_CLI])
    ns_exec(NETNS_SRV, "ip", "addr", "add", f"{IP_SRV}/{PREFIX}", "dev", VETH_SRV)
    ns_exec(NETNS_CLI, "ip", "addr", "add", f"{IP_CLI}/{PREFIX}", "dev", VETH_CLI)
    ns_exec(NETNS_SRV, "ip", "link", "set", VETH_SRV, "up")
    ns_exec(NETNS_CLI, "ip", "link", "set", VETH_CLI, "up")
    ns_exec(NETNS_SRV, "ip", "link", "set", "lo", "up")
    ns_exec(NETNS_CLI, "ip", "link", "set", "lo", "up")
    # sanity: plain ping with no shaping should succeed
    r = ns_exec(NETNS_CLI, "ping", "-c", "2", "-W", "1", IP_SRV, capture=True, check=False)
    if r.returncode != 0:
        print(r.stdout, r.stderr, file=sys.stderr)
        raise RuntimeError("veth pair not reachable after setup")
    print(f"netns up: {NETNS_CLI}({IP_CLI}) <-> {NETNS_SRV}({IP_SRV}) via {VETH_CLI}/{VETH_SRV}")


def down(ignore_errors: bool = False) -> None:
    for ns in (NETNS_SRV, NETNS_CLI):
        run(["sudo", "ip", "netns", "del", ns], check=False)
    if not ignore_errors:
        r = run(["ip", "netns", "list"], capture=True, check=False)
        if NETNS_SRV in r.stdout or NETNS_CLI in r.stdout:
            raise RuntimeError(f"netns teardown incomplete: {r.stdout!r}")


def clear_netem() -> None:
    ns_exec(NETNS_CLI, "tc", "qdisc", "del", "dev", VETH_CLI, "root", check=False, capture=True)
    ns_exec(NETNS_SRV, "tc", "qdisc", "del", "dev", VETH_SRV, "root", check=False, capture=True)


def apply_netem(
    rtt_ms: float, jitter_ms: float, loss_pct: float, direction: str,
    gemodel: tuple[float, float, float, float] | None = None,
) -> None:
    """direction in {"uplink", "downlink", "both"}. gemodel, if given,
    overrides loss_pct with `tc netem loss gemodel P R 1-H 1-K` applied to
    whichever side(s) `direction` selects -- same semantics as loss_pct,
    just a burstier loss process instead of i.i.d. loss."""
    clear_netem()
    half_rtt = rtt_ms / 2
    half_jitter = jitter_ms / 2
    client_on = direction in ("uplink", "both")
    server_on = direction in ("downlink", "both")

    def set_one(ns: str, dev: str, lossy: bool) -> None:
        cmd = ["tc", "qdisc", "add", "dev", dev, "root", "netem", "delay", f"{half_rtt:.2f}ms"]
        if half_jitter > 0:
            cmd += [f"{half_jitter:.2f}ms", "distribution", "normal"]
        if lossy:
            if gemodel:
                cmd += ["loss", "gemodel", *[str(x) for x in gemodel]]
            elif loss_pct > 0:
                cmd += ["loss", f"{loss_pct}%"]
        ns_exec(ns, *cmd)

    set_one(NETNS_CLI, VETH_CLI, client_on)
    set_one(NETNS_SRV, VETH_SRV, server_on)


def verify(rtt_ms: float, loss_pct: float, direction: str = "both", n: int = 500,
           gemodel: tuple[float, float, float, float] | None = None) -> dict:
    """Empirical check before trusting apply_netem(): fire n pings
    client->server under the given config and measure actual RTT and loss
    rate against the configured values."""
    apply_netem(rtt_ms, 0, loss_pct, direction, gemodel=gemodel)
    time.sleep(0.2)
    r = ns_exec(
        NETNS_CLI, "ping", "-c", str(n), "-i", "0.01", "-W", "2", IP_SRV,
        capture=True, check=False,
    )
    out = r.stdout
    loss_m = re.search(r"([\d.]+)% packet loss", out)
    measured_loss = float(loss_m.group(1)) if loss_m else None
    rtts = [float(x) for x in re.findall(r"time=([\d.]+) ms", out)]
    result = {
        "configured_rtt_ms": rtt_ms,
        "configured_loss_pct": loss_pct,
        "direction": direction,
        "gemodel": gemodel,
        "measured_loss_pct": measured_loss,
        "measured_rtt_median_ms": statistics.median(rtts) if rtts else None,
        "measured_rtt_n": len(rtts),
        "ping_tail": "\n".join(out.splitlines()[-6:]),
    }
    clear_netem()
    return result


def main() -> None:
    cmd = sys.argv[1]
    if cmd == "up":
        up()
    elif cmd == "down":
        down()
    elif cmd == "clear":
        clear_netem()
    elif cmd == "netem":
        rtt, jitter, loss, direction = float(sys.argv[2]), float(sys.argv[3]), float(sys.argv[4]), sys.argv[5]
        gemodel = tuple(float(x) for x in sys.argv[6].split(",")) if len(sys.argv) > 6 else None
        apply_netem(rtt, jitter, loss, direction, gemodel=gemodel)
    elif cmd == "verify":
        rtt, loss = float(sys.argv[2]), float(sys.argv[3])
        direction = sys.argv[4] if len(sys.argv) > 4 else "both"
        gemodel = tuple(float(x) for x in sys.argv[5].split(",")) if len(sys.argv) > 5 else None
        import json
        print(json.dumps(verify(rtt, loss, direction, gemodel=gemodel), indent=2))
    else:
        print(f"unknown command {cmd}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
