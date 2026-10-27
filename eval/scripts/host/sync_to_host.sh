#!/usr/bin/env bash
# Copies this checkout to a measurement host. A copy has no usable .git, so
# the script first writes eval/GIT_INFO.json (commit, branch, dirty files),
# which the provenance record reads.
#
#   eval/scripts/host/sync_to_host.sh playground hqctiny-sp27-harness
set -euo pipefail

host="${1:?usage: sync_to_host.sh <ssh host> <remote dir>}"
remote_dir="${2:?usage: sync_to_host.sh <ssh host> <remote dir>}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

cd "$root"
python3 - <<'PY' > eval/GIT_INFO.json
import json, subprocess
def git(*a): return subprocess.run(["git", *a], capture_output=True, text=True, check=True).stdout.strip()
dirty = [l for l in git("status", "--porcelain").splitlines() if "GIT_INFO.json" not in l]
print(json.dumps({"commit": git("rev-parse", "HEAD"), "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
                  "dirty": bool(dirty), "dirty_files": dirty}, indent=2))
PY
rsync -a --delete --exclude target --exclude target-linux --exclude results ./ "$host:$remote_dir/"
echo "synced $(python3 -c 'import json;print(json.load(open("eval/GIT_INFO.json"))["commit"])') to $host:$remote_dir"
