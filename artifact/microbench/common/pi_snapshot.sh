#!/bin/sh
cpu=/sys/devices/system/cpu/cpu0/cpufreq
echo "time=$(date -u +%FT%TZ) governor=$(cat $cpu/scaling_governor) cur_khz=$(cat $cpu/scaling_cur_freq) max_khz=$(cat $cpu/scaling_max_freq) temp_mC=$(cat /sys/class/thermal/thermal_zone0/temp) undervolt_alarm=$(cat /sys/class/hwmon/hwmon1/in0_lcrit_alarm) load=$(cut -d' ' -f1 /proc/loadavg)"
echo "time_in_state_khz_ticks=$(cat $cpu/stats/time_in_state | tr '\n' ' ')"
echo "vcgencmd $(sudo vcgencmd measure_clock arm 2>/dev/null) $(sudo vcgencmd get_throttled 2>/dev/null)"
