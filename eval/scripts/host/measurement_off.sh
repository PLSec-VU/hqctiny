#!/usr/bin/env bash
# Puts back every value measurement_on.sh changed (CPU settings, interrupt
# affinities, irqbalance), in reverse order.
#
#   sudo eval/scripts/host/measurement_off.sh
set -euo pipefail

state_file="${STATE_FILE:-/var/tmp/hqclethe-measurement-state}"

[ "$(id -u)" -eq 0 ] || { echo "error: run as root (sudo)" >&2; exit 1; }
[ -e "$state_file" ] || { echo "nothing to restore: $state_file does not exist"; exit 0; }

onlines=()
others=()
while IFS=$'\t' read -r path value; do
  case "$path" in
    */online) onlines+=("$path"$'\t'"$value") ;;
    *) others+=("$path"$'\t'"$value") ;;
  esac
done < "$state_file"

for entry in "${onlines[@]}"; do
  IFS=$'\t' read -r path value <<< "$entry"
  echo "$value" > "$path"
done
for ((i = ${#others[@]} - 1; i >= 0; i--)); do
  IFS=$'\t' read -r path value <<< "${others[$i]}"
  case "$path" in
    systemctl:*) systemctl start "${path#systemctl:}" || echo "warning: could not start ${path#systemctl:}" >&2 ;;
    *) echo "$value" > "$path" || echo "warning: could not restore $path" >&2 ;;
  esac
done

rm -f "$state_file"
echo "restored the values saved in $state_file"
