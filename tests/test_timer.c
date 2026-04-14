#include "pqc/pqc_timer.h"
#include <stdio.h>
#include <assert.h>

int main(void) {
    /* Test timer resolution */
    uint64_t res = pqc_timer_resolution();
    printf("Timer resolution: %llu ns\n", (unsigned long long)res);
    assert(res > 0);
    assert(res < 1000000000ULL);

    /* Test timer now */
    uint64_t t1 = pqc_timer_now();
    uint64_t t2 = pqc_timer_now();
    printf("t1=%llu t2=%llu diff=%llu\n",
           (unsigned long long)t1, (unsigned long long)t2,
           (unsigned long long)(t2 - t1));
    assert(t2 >= t1);

    /* Test conversion functions */
    assert(pqc_timer_ns_to_us(1000) == 1.0);
    assert(pqc_timer_ns_to_ms(1000000) == 1.0);
    assert(pqc_timer_ns_to_s(1000000000ULL) == 1.0);

    /* Test stats */
    uint64_t values[] = {100, 200, 300, 400, 500};
    double mean, stdev;
    uint64_t median;
    pqc_timer_stats(values, 5, &mean, &stdev, &median);
    printf("mean=%.1f median=%llu stdev=%.1f\n", mean, (unsigned long long)median, stdev);
    assert(mean == 300.0);
    assert(median == 300);

    printf("All timer tests passed!\n");
    return 0;
}
