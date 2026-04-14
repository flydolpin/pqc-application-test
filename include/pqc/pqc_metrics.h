#ifndef PQC_METRICS_H
#define PQC_METRICS_H

#include "pqc_types.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    pqc_hs_phase_t phase;
    uint64_t timestamp_ns;
    uint64_t duration_ns;
    size_t bytes_sent;
    size_t bytes_received;
} pqc_phase_metrics_t;

typedef struct {
    uint64_t total_duration_ns;
    uint64_t tcp_connect_ns;

    pqc_phase_metrics_t phases[7];
    size_t num_phases;

    size_t total_bytes_sent;
    size_t total_bytes_received;
    size_t kem_pk_bytes;
    size_t kem_ct_bytes;
    size_t sig_cert_bytes;
    size_t sig_signature_bytes;

    pqc_status_t result;
    const char *kem_alg;
    const char *sig_alg;
    const char *tls_version;

    int zero_rtt_accepted;
    uint64_t quic_handshake_ns;
} pqc_handshake_metrics_t;

typedef struct {
    const char *kem_alg;
    const char *sig_alg;
    pqc_protocol_t protocol;
    int num_iterations;

    double mean_ns;
    double stdev_ns;
    uint64_t min_ns;
    uint64_t max_ns;
    double median_ns;

    double phase_mean_ns[7];
    double phase_stdev_ns[7];

    double avg_bytes_sent;
    double avg_bytes_received;

    int num_success;
    int num_failure;
    double success_rate;
    double packet_loss_rate;

    double throughput_mbps;
    uint64_t throughput_test_bytes;
    uint64_t throughput_test_ns;
} pqc_aggregate_metrics_t;

typedef struct pqc_metrics_collector pqc_metrics_collector_t;

pqc_metrics_collector_t *pqc_metrics_collector_create(int max_iterations);
void pqc_metrics_collector_destroy(pqc_metrics_collector_t *col);

pqc_status_t pqc_metrics_record(pqc_metrics_collector_t *col,
                                 const pqc_handshake_metrics_t *m);
pqc_status_t pqc_metrics_aggregate(const pqc_metrics_collector_t *col,
                                    pqc_aggregate_metrics_t *out);

#ifdef __cplusplus
}
#endif

#endif /* PQC_METRICS_H */
