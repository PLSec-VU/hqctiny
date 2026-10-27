#ifndef CPUCYCLES_H
#define CPUCYCLES_H
extern long long cpucycles_perf(void);
extern long long cpucycles_perf_persecond(void);
#define cpucycles cpucycles_perf
#define cpucycles_persecond cpucycles_perf_persecond
#define cpucycles_implementation "perfevent"
#endif
