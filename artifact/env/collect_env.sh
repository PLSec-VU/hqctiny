#!/bin/sh
# usage: collect_env.sh   Prints the software and hardware environment of the machine it runs on (host or container).
say() { printf '%s: %s\n' "$1" "$2"; }
first_line() { "$@" 2>&1 | head -1; }
os_name() { if [ -r /etc/os-release ]; then . /etc/os-release; echo "$PRETTY_NAME"; else echo "$(sw_vers -productName 2>/dev/null) $(sw_vers -productVersion 2>/dev/null)"; fi; }
cpu_name() {
  if command -v lscpu >/dev/null 2>&1; then lscpu | awk -F: '/Model name/ {gsub(/^ +/, "", $2); print $2; exit}'
  else sysctl -n machdep.cpu.brand_string 2>/dev/null; fi
}
memory_gib() {
  if [ -r /proc/meminfo ]; then awk '/MemTotal/ {printf "%.1f GiB", $2/1048576}' /proc/meminfo
  else echo "$(( $(sysctl -n hw.memsize) / 1073741824 )) GiB"; fi
}
say os "$(os_name)"
say kernel "$(uname -srvm)"
say cpu "$(cpu_name)"
[ -r /proc/device-tree/model ] && say board "$(tr -d '\0' < /proc/device-tree/model)"
say cpu_count "$(nproc 2>/dev/null || sysctl -n hw.ncpu)"
say memory "$(memory_gib)"
for tool in docker rustc cargo gcc clang python3 valgrind make git; do
  command -v $tool >/dev/null 2>&1 && say $tool "$(first_line $tool --version)"
done
cpufreq=/sys/devices/system/cpu/cpu0/cpufreq
[ -d $cpufreq ] && say cpufreq "governor=$(cat $cpufreq/scaling_governor) max_khz=$(cat $cpufreq/scaling_max_freq) driver=$(cat $cpufreq/scaling_driver)"
[ -r /sys/devices/system/cpu/cpufreq/boost ] && say boost "$(cat /sys/devices/system/cpu/cpufreq/boost)"
say online_cpus "$(cat /sys/devices/system/cpu/online 2>/dev/null)"
[ -r /sys/devices/system/cpu/smt/control ] && say smt "$(cat /sys/devices/system/cpu/smt/control)"
