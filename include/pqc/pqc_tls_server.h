#ifndef PQC_TLS_SERVER_H
#define PQC_TLS_SERVER_H

#include "pqc_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pqc_tls_server pqc_tls_server_t;

typedef struct {
    const char *kem_alg;
    const char *sig_alg;
    const char *cert_path;
    const char *key_path;
    const char *ca_cert_path;
    const char *provider_path;
    uint16_t port;
    int max_connections;
} pqc_tls_server_config_t;

pqc_tls_server_t *pqc_tls_server_create(const pqc_tls_server_config_t *config);
void pqc_tls_server_destroy(pqc_tls_server_t *server);

pqc_status_t pqc_tls_server_start(pqc_tls_server_t *server);
void pqc_tls_server_stop(pqc_tls_server_t *server);

#ifdef __cplusplus
}
#endif

#endif /* PQC_TLS_SERVER_H */
