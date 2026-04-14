#ifndef PQC_QUIC_SERVER_H
#define PQC_QUIC_SERVER_H

#include "pqc_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* QUIC/HTTP3 server - Phase 2 implementation */
typedef struct pqc_quic_server pqc_quic_server_t;

typedef struct {
    const char *kem_alg;
    const char *sig_alg;
    const char *cert_path;
    const char *key_path;
    const char *provider_path;
    uint16_t port;
} pqc_quic_server_config_t;

pqc_quic_server_t *pqc_quic_server_create(const pqc_quic_server_config_t *config);
void pqc_quic_server_destroy(pqc_quic_server_t *server);

#ifdef __cplusplus
}
#endif

#endif /* PQC_QUIC_SERVER_H */
