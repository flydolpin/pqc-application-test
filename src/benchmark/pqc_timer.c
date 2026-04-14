#include "pqc/pqc_timer.h"
#include <stdlib.h>
#include <math.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#endif

uint64_t pqc_timer_now(void) {
#ifdef _WIN32
    LARGE_INTEGER counter, frequency;
    QueryPerformanceCounter(&counter);
    QueryPerformanceFrequency(&frequency);
    return (uint64_t)((counter.QuadPart * 1000000000ULL) / frequency.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}

uint64_t pqc_timer_resolution(void) {
#ifdef _WIN32
    LARGE_INTEGER frequency;
    QueryPerformanceFrequency(&frequency);
    return 1000000000ULL / (uint64_t)frequency.QuadPart;
#else
    struct timespec res;
    clock_getres(CLOCK_MONOTONIC, &res);
    return (uint64_t)res.tv_sec * 1000000000ULL + (uint64_t)res.tv_nsec;
#endif
}

double pqc_timer_ns_to_us(uint64_t ns) { return (double)ns / 1e3; }
double pqc_timer_ns_to_ms(uint64_t ns) { return (double)ns / 1e6; }
double pqc_timer_ns_to_s(uint64_t ns)  { return (double)ns / 1e9; }

static int cmp_uint64(const void *a, const void *b) {
    uint64_t va = *(const uint64_t *)a;
    uint64_t vb = *(const uint64_t *)b;
    if (va < vb) return -1;
    if (va > vb) return 1;
    return 0;
}

void pqc_timer_stats(const uint64_t *values, size_t count,
                     double *mean, double *stdev, uint64_t *median) {
    if (count == 0) {
        if (mean)   *mean   = 0.0;
        if (stdev)  *stdev  = 0.0;
        if (median) *median = 0;
        return;
    }

    uint64_t *sorted = malloc(count * sizeof(uint64_t));
    for (size_t i = 0; i < count; i++) sorted[i] = values[i];
    qsort(sorted, count, sizeof(uint64_t), cmp_uint64);

    if (median) {
        if (count % 2 == 0) {
            *median = (sorted[count / 2 - 1] + sorted[count / 2]) / 2;
        } else {
            *median = sorted[count / 2];
        }
    }

    if (mean) {
        double sum = 0.0;
        for (size_t i = 0; i < count; i++) sum += (double)sorted[i];
        *mean = sum / (double)count;

        if (stdev) {
            double variance = 0.0;
            for (size_t i = 0; i < count; i++) {
                double diff = (double)sorted[i] - *mean;
                variance += diff * diff;
            }
            *stdev = sqrt(variance / (double)count);
        }
    }

    free(sorted);
}
