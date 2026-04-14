#ifndef PQC_TLS_HANDSHAKE_H
#define PQC_TLS_HANDSHAKE_H

#include "pqc_types.h"
#include "pqc_metrics.h"
#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    pqc_phase_metrics_t phases[7];
    size_t num_phases;
    uint64_t handshake_start_ns;
    pqc_handshake_metrics_t *output;
} pqc_hs_tracker_t;

pqc_hs_tracker_t *pqc_hs_tracker_create(pqc_handshake_metrics_t *output);
void pqc_hs_tracker_destroy(pqc_hs_tracker_t *tracker);

pqc_status_t pqc_hs_attach(SSL *ssl, pqc_hs_tracker_t *tracker);
void pqc_hs_info_callback(const SSL *ssl, int type, int val);
pqc_status_t pqc_hs_finalize(pqc_hs_tracker_t *tracker, pqc_status_t result);
int pqc_hs_get_ex_data_index(void);

#ifdef __cplusplus
}
#endif

#endif /* PQC_TLS_HANDSHAKE_H */
