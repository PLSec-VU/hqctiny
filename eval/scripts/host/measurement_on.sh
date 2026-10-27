#!/usr/bin/env bash
# Puts a Linux host in measurement state:
#   * every online CPU: governor and energy-performance preference
#     "performance"
#   * boost off
#   * the SMT sibling of the server core (cpu1 next to cpu0) offline, so the
#     server owns its physical core
#   * irqbalance stopped, and every device interrupt that the kernel lets
#     us move pinned to IRQ_CPUS (default 12-15), away from the cores
#     the harness uses
# Every value it changes is saved to $STATE_FILE first.
# eval/scripts/host/measurement_off.sh puts the saved values back.
# Then it measures the clock of the pinned cores under load and fails when
# it is more than 2% from TARGET_MHZ (default 3169).
#
#   sudo eval/scripts/host/measurement_on.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cpu_root=/sys/devices/system/cpu
state_file="${STATE_FILE:-/var/tmp/hqclethe-measurement-state}"
sibling_cpus="${SIBLING_OFFLINE_CPUS:-1}"
governor=performance
irq_cpus="${IRQ_CPUS:-12-15}"
irq_root=/proc/irq

[ "$(id -u)" -eq 0 ] || { echo "error: run as root (sudo)" >&2; exit 1; }
[ -e "$state_file" ] && { echo "error: $state_file exists. Run measurement_off.sh first." >&2; exit 1; }
[ -d "$cpu_root/cpu0/cpufreq" ] || { echo "error: no cpufreq on this host" >&2; exit 1; }

: > "$state_file"

set_value() {
  local path="$1" value="$2"
  [ -w "$path" ] || return 0
  printf '%s\t%s\n' "$path" "$(cat "$path")" >> "$state_file"
  echo "$value" > "$path"
}

move_irq() {
  local path="$1" previous
  previous="$(cat "$path")"
  if echo "$irq_cpus" > "$path" 2>/dev/null; then
    printf '%s\t%s\n' "$path" "$previous" >> "$state_file"
    moved_irqs=$((moved_irqs + 1))
  else
    fixed_irqs+=("$(basename "$(dirname "$path")")")
  fi
}

stop_irqbalance() {
  if systemctl is-active --quiet irqbalance 2>/dev/null; then
    systemctl stop irqbalance
    printf 'systemctl:irqbalance\tactive\n' >> "$state_file"
  fi
}

move_all_irqs() {
  local path
  moved_irqs=0
  fixed_irqs=()
  for path in "$irq_root"/[0-9]*/smp_affinity_list; do
    move_irq "$path"
  done
  echo "moved $moved_irqs interrupts to cpus $irq_cpus; fixed by the kernel: ${fixed_irqs[*]:-none}"
}

stop_irqbalance
move_all_irqs

set_value "$cpu_root/cpufreq/boost" 0

for dir in "$cpu_root"/cpu[0-9]*; do
  [ -d "$dir/cpufreq" ] || continue
  set_value "$dir/cpufreq/scaling_governor" "$governor"
  set_value "$dir/cpufreq/energy_performance_preference" "$governor"
done

for cpu in $sibling_cpus; do
  set_value "$cpu_root/cpu$cpu/online" 0
done

echo "saved previous values in $state_file"
python3 "$here/../lib/host_state.py" --target-mhz "${TARGET_MHZ:-3169}" > /var/tmp/hqclethe-measurement-state.json \
  || { cat /var/tmp/hqclethe-measurement-state.json; echo "FAIL: host is not in measurement state" >&2; exit 3; }
echo "measurement state OK; details in /var/tmp/hqclethe-measurement-state.json"
