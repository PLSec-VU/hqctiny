#!/usr/bin/env bash
# Runs the whole evaluation: every category, both servers (stateless
# HQCLethe and the stateful baseline), all with ML-KEM server
# authentication. Writes eval/results/<UTC timestamp>/.
#
#   eval/run_all.sh                 full run (hours; needs a native x86_64 AVX2 host)
#   eval/run_all.sh --smoke         a few minutes; checks the setup. Numbers are not for the paper.
#   eval/run_all.sh --categories 4,6 --variant hqc1
#
# Any other argument goes to eval/run.py (see its --help).
# Repetition counts are environment variables, listed in eval/scripts/lib/knobs.py:
#   CPU_SESSIONS CPU_REPS DOS_REPS FLOOD_DURATION LEGIT_INTERVAL_MS SINGLE_HOST_SOCKETS
#   BOTNET_IPS BOTNET_SOCKETS WAN_REPS AUDIT_SESSIONS CRITERION_ARGS SKIP_CALLGRIND
# Other variables: HQC_BACKEND (default avx2; empty for a portable build),
#   STATEFUL_SERVER_ARGS (extra options for the stateful server),
#   DOCKER_DEFAULT_PLATFORM (for example linux/amd64 on an Apple-silicon Mac),
#   EVAL_IMAGE (Docker image name; use a separate name per platform).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

need() {
  command -v "$1" >/dev/null 2>&1 || { echo "error: $1 is not installed" >&2; exit 1; }
}
need docker
need python3
docker compose version >/dev/null 2>&1 || { echo "error: docker compose is not available" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "error: the Docker daemon is not running" >&2; exit 1; }

if [ -r /proc/cpuinfo ] && [ -z "${DOCKER_DEFAULT_PLATFORM:-}" ] && [ "${HQC_BACKEND-avx2}" = "avx2" ]; then
  for flag in avx2 bmi1 pclmulqdq; do
    grep -qw "$flag" /proc/cpuinfo || { echo "error: this CPU lacks $flag. Set HQC_BACKEND= for a portable build." >&2; exit 1; }
  done
fi

if [ "$(uname -m)" != "x86_64" ] && [ "$(uname -m)" != "amd64" ] && [ -z "${DOCKER_DEFAULT_PLATFORM:-}" ]; then
  echo "note: this host is $(uname -m). Run native x86_64 for paper numbers, or set HQC_BACKEND= for a portable build." >&2
fi

exec python3 "$here/run.py" "$@"
