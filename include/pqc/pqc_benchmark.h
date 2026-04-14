#ifndef PQC_BENCHMARK_H
#define PQC_BENCHMARK_H

#include "pqc_types.h"
#include "pqc_metrics.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    pqc_protocol_t protocol;
    const char *kem_algorithms[32];
    size_t num_kem_algs;
    const char *sig_algorithms[32];
    size_t num_sig_algs;
    const char *server_host;
    uint16_t server_port;
    int iterations;
    size_t throughput_test_bytes;
    int warmup_iterations;
    const char *output_format;
    const char *output_path;
    int parallel_connections;
    const char *ca_cert_path;
    const char *provider_path;
} pqc_bench_config_t;

typedef struct {
    const char *kem_alg;
    const char *sig_alg;
    pqc_aggregate_metrics_t tls_metrics;
    pqc_aggregate_metrics_t quic_metrics;
} pqc_bench_result_t;

pqc_status_t pqc_benchmark_run(const pqc_bench_config_t *config,
                                void (*on_progress)(const pqc_bench_result_t *,
                                                     void *user_data),
                                void *user_data);

pqc_status_t pqc_benchmark_run_pair(const pqc_bench_config_t *config,
                                     const char *kem_alg,
                                     const char *sig_alg,
                                     pqc_bench_result_t *result);

#ifdef __cplusplus
}
#endif

#endif /* PQC_BENCHMARK_H */
