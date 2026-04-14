#ifndef PQC_TIMER_H
#define PQC_TIMER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

uint64_t pqc_timer_now(void);
uint64_t pqc_timer_resolution(void);

double pqc_timer_ns_to_us(uint64_t ns);
double pqc_timer_ns_to_ms(uint64_t ns);
double pqc_timer_ns_to_s(uint64_t ns);

void pqc_timer_stats(const uint64_t *values, size_t count,
                     double *mean, double *stdev, uint64_t *median);

#ifdef __cplusplus
}
#endif

#endif /* PQC_TIMER_H */
