#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <sys/types.h>
static int fd = -1;
long long cpucycles_perf(void)
{
  long long result;
  if (fd == -1) {
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof attr);
    attr.size = sizeof attr;
    attr.type = PERF_TYPE_HARDWARE;
    attr.config = PERF_COUNT_HW_CPU_CYCLES;
    fd = syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
    if (fd == -1) return 0;
  }
  if (read(fd, &result, sizeof result) < (ssize_t) sizeof result) return 0;
  return result;
}
long long cpucycles_perf_persecond(void)
{
  FILE *f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq", "r");
  long long khz = 1400000;
  if (f) { if (fscanf(f, "%lld", &khz) != 1) khz = 1400000; fclose(f); }
  return khz * 1000;
}
