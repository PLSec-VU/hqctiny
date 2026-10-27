"""Core placement and clock target shared by every driver (session CPU,
floods, WAN, McTiny). Pure data. Import, do not run.

The server owns physical core 0. Its SMT sibling (cpu1) is offline. The
flood process, the legitimate probes and the session client each run on
another physical core, so no two measured processes share a core.
"""

import os

SERVER_CORE = int(os.environ.get("SERVER_CORE", "0"))
SIBLING_OFFLINE_CPUS = (1,)
FLOOD_CORE = int(os.environ.get("FLOOD_CORE", "2"))
CLIENT_CORE = int(os.environ.get("CLIENT_CORE", "2"))
LEGIT_CORE = int(os.environ.get("LEGIT_CORE", "4"))
ORCHESTRATOR_CORE = int(os.environ.get("ORCHESTRATOR_CORE", "10"))

TARGET_MHZ = float(os.environ.get("TARGET_MHZ", "3169"))
FREQUENCY_TOLERANCE = 0.02
REQUIRED_GOVERNOR = "performance"

PINNED_CORES = (SERVER_CORE, FLOOD_CORE, LEGIT_CORE)


def description() -> dict:
    return {
        "server_core": SERVER_CORE,
        "offline_sibling_cpus": list(SIBLING_OFFLINE_CPUS),
        "flood_core": FLOOD_CORE,
        "session_and_wan_client_core": CLIENT_CORE,
        "legit_probe_core": LEGIT_CORE,
        "orchestrator_core": ORCHESTRATOR_CORE,
        "target_mhz": TARGET_MHZ,
        "frequency_tolerance": FREQUENCY_TOLERANCE,
    }
