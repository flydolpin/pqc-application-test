#include "pqc/pqc_benchmark.h"
#include <stdlib.h>

/*
 * Benchmark orchestrator: reads config, iterates over KEM+SIG pairs,
 * runs handshakes, collects metrics, produces reports.
 * Full implementation will use pqc_tls_client_benchmark() for each pair.
 */

pqc_status_t pqc_benchmark_run(const pqc_bench_config_t *config,
                                void (*on_progress)(const pqc_bench_result_t *,
                                                     void *user_data),
                                void *user_data) {
    if (!config) return PQC_INVALID_PARAM;

    for (size_t ki = 0; ki < config->num_kem_algs; ki++) {
        for (size_t si = 0; si < config->num_sig_algs; si++) {
            pqc_bench_result_t result;
            memset(&result, 0, sizeof(result));
            result.kem_alg = config->kem_algorithms[ki];
            result.sig_alg = config->sig_algorithms[si];

            pqc_status_t rc = pqc_benchmark_run_pair(
                config, config->kem_algorithms[ki],
                config->sig_algorithms[si], &result);

            if (on_progress) on_progress(&result, user_data);
            if (rc != PQC_OK) continue;
        }
    }
    return PQC_OK;
}

pqc_status_t pqc_benchmark_run_pair(const pqc_bench_config_t *config,
                                     const char *kem_alg,
                                     const char *sig_alg,
                                     pqc_bench_result_t *result) {
    /* TODO: Create TLS client, run iterations, collect metrics */
    (void)config; (void)kem_alg; (void)sig_alg; (void)result;
    return PQC_NOT_SUPPORTED;
}
