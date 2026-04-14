#ifndef PQC_TLS_CLIENT_H
#define PQC_TLS_CLIENT_H

#include "pqc_types.h"
#include "pqc_metrics.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pqc_tls_client pqc_tls_client_t;

typedef struct {
    const char *kem_alg;
    const char *sig_alg;
    const char *ca_cert_path;
    const char *client_cert_path;
    const char *client_key_path;
    const char *provider_path;
    int verify_peer;
    int enable_0rtt;
    int tls_debug;
} pqc_tls_client_config_t;

pqc_tls_client_t *pqc_tls_client_create(const pqc_tls_client_config_t *config);
void pqc_tls_client_destroy(pqc_tls_client_t *client);

pqc_status_t pqc_tls_client_connect(pqc_tls_client_t *client,
                                     const char *host, uint16_t port,
                                     pqc_handshake_metrics_t *metrics,
                                     size_t throughput_bytes);

pqc_status_t pqc_tls_client_benchmark(pqc_tls_client_t *client,
                                       const char *host, uint16_t port,
                                       int iterations,
                                       size_t throughput_bytes,
                                       pqc_aggregate_metrics_t *agg);

#ifdef __cplusplus
}
#endif

#endif /* PQC_TLS_CLIENT_H */
