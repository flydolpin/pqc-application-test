#include "pqc/pqc_quic_client.h"
#include <stdlib.h>

struct pqc_quic_client {
    pqc_quic_client_config_t config;
};

pqc_quic_client_t *pqc_quic_client_create(const pqc_quic_client_config_t *config) {
    (void)config;
    return NULL;
}

void pqc_quic_client_destroy(pqc_quic_client_t *client) {
    (void)client;
}
