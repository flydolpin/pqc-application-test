#include "pqc/pqc_quic_server.h"
#include <stdlib.h>

struct pqc_quic_server {
    pqc_quic_server_config_t config;
};

pqc_quic_server_t *pqc_quic_server_create(const pqc_quic_server_config_t *config) {
    (void)config;
    return NULL;
}

void pqc_quic_server_destroy(pqc_quic_server_t *server) {
    (void)server;
}
