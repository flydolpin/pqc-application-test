#ifndef PQC_QUIC_CLIENT_H
#define PQC_QUIC_CLIENT_H

#include "pqc_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* QUIC/HTTP3 client - Phase 2 implementation */
typedef struct pqc_quic_client pqc_quic_client_t;

typedef struct {
    const char *kem_alg;
    const char *sig_alg;
    const char *ca_cert_path;
    const char *provider_path;
    int verify_peer;
} pqc_quic_client_config_t;

pqc_quic_client_t *pqc_quic_client_create(const pqc_quic_client_config_t *config);
void pqc_quic_client_destroy(pqc_quic_client_t *client);

#ifdef __cplusplus
}
#endif

#endif /* PQC_QUIC_CLIENT_H */
