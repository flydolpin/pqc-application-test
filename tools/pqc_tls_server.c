#include "pqc/pqc_tls_server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

static volatile int g_running = 1;

static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
}

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  --port <num>        Server port (default 4433)\n");
    fprintf(stderr, "  --cert <path>       Server certificate file\n");
    fprintf(stderr, "  --key <path>        Server private key file\n");
    fprintf(stderr, "  --ca-cert <path>    CA certificate file\n");
    fprintf(stderr, "  --kem <alg>         KEM algorithm name\n");
    fprintf(stderr, "  --sig <alg>         Signature algorithm name\n");
    fprintf(stderr, "  --provider <path>   oqs-provider module path\n");
    fprintf(stderr, "  --max-conn <num>    Max connections before exit (0=unlimited)\n");
}

int main(int argc, char **argv) {
    pqc_tls_server_config_t config;
    memset(&config, 0, sizeof(config));
    config.port = 4433;
    config.max_connections = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            config.port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
            config.cert_path = argv[++i];
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            config.key_path = argv[++i];
        } else if (strcmp(argv[i], "--ca-cert") == 0 && i + 1 < argc) {
            config.ca_cert_path = argv[++i];
        } else if (strcmp(argv[i], "--kem") == 0 && i + 1 < argc) {
            config.kem_alg = argv[++i];
        } else if (strcmp(argv[i], "--sig") == 0 && i + 1 < argc) {
            config.sig_alg = argv[++i];
        } else if (strcmp(argv[i], "--provider") == 0 && i + 1 < argc) {
            config.provider_path = argv[++i];
        } else if (strcmp(argv[i], "--max-conn") == 0 && i + 1 < argc) {
            config.max_connections = atoi(argv[++i]);
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    pqc_tls_server_t *server = pqc_tls_server_create(&config);
    if (!server) {
        fprintf(stderr, "Failed to create TLS server\n");
        return 1;
    }

    printf("Starting PQC TLS server...\n");
    pqc_status_t rc = pqc_tls_server_start(server);

    pqc_tls_server_destroy(server);
    printf("Server shutdown (rc=%d)\n", rc);
    return (rc == PQC_OK) ? 0 : 1;
}
