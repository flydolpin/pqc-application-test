#include "pqc/pqc_crypto_factory.h"
#include "pqc/pqc_benchmark.h"
#include "pqc/pqc_reporter.h"
#include "pqc/pqc_config.h"
#include "pqc/pqc_tls_client.h"
#include "pqc/pqc_metrics.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s --kem <alg> --sig <alg> --host <addr> [options]\n", prog);
    fprintf(stderr, "       %s --config <config.toml> [options]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  --config <path>       TOML configuration file\n");
    fprintf(stderr, "  --kem <alg>           KEM algorithm name (e.g. mlkem768)\n");
    fprintf(stderr, "  --sig <alg>           Signature algorithm name (e.g. mldsa65)\n");
    fprintf(stderr, "  --host <addr>         Server address\n");
    fprintf(stderr, "  --port <num>          Server port (default 4433)\n");
    fprintf(stderr, "  --iterations <num>    Number of handshakes (default 100)\n");
    fprintf(stderr, "  --format <fmt>        Output format: json, csv, console (default)\n");
    fprintf(stderr, "  --output <path>       Output file path (default: stdout)\n");
    fprintf(stderr, "  --ca-cert <path>      CA certificate for server verification\n");
    fprintf(stderr, "  --provider <path>     Path to oqs-provider modules directory\n");
    fprintf(stderr, "  --no-verify           Skip server certificate verification\n");
    fprintf(stderr, "  --throughput <bytes>  Post-handshake throughput test size\n");
}

int main(int argc, char **argv) {
    const char *kem_alg = NULL;
    const char *sig_alg = NULL;
    const char *host = NULL;
    uint16_t port = 4433;
    int iterations = 100;
    const char *format = "console";
    const char *output_path = NULL;
    const char *ca_cert = NULL;
    const char *provider_path = NULL;
    int verify_peer = 1;
    size_t throughput_bytes = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--kem") == 0 && i + 1 < argc) {
            kem_alg = argv[++i];
        } else if (strcmp(argv[i], "--sig") == 0 && i + 1 < argc) {
            sig_alg = argv[++i];
        } else if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) {
            host = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--iterations") == 0 && i + 1 < argc) {
            iterations = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--format") == 0 && i + 1 < argc) {
            format = argv[++i];
        } else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            output_path = argv[++i];
        } else if (strcmp(argv[i], "--ca-cert") == 0 && i + 1 < argc) {
            ca_cert = argv[++i];
        } else if (strcmp(argv[i], "--provider") == 0 && i + 1 < argc) {
            provider_path = argv[++i];
        } else if (strcmp(argv[i], "--no-verify") == 0) {
            verify_peer = 0;
        } else if (strcmp(argv[i], "--throughput") == 0 && i + 1 < argc) {
            throughput_bytes = (size_t)atol(argv[++i]);
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    if (!host) {
        fprintf(stderr, "Error: --host is required\n\n");
        usage(argv[0]);
        return 1;
    }

    /* Configure TLS client */
    pqc_tls_client_config_t client_cfg;
    memset(&client_cfg, 0, sizeof(client_cfg));
    client_cfg.kem_alg = kem_alg;
    client_cfg.sig_alg = sig_alg;
    client_cfg.ca_cert_path = ca_cert;
    client_cfg.provider_path = provider_path;
    client_cfg.verify_peer = verify_peer;

    pqc_tls_client_t *client = pqc_tls_client_create(&client_cfg);
    if (!client) {
        fprintf(stderr, "Failed to create TLS client\n");
        return 1;
    }

    printf("=== PQC TLS Benchmark ===\n");
    printf("KEM: %s  SIG: %s  Server: %s:%d  Iterations: %d\n",
           kem_alg, sig_alg, host, port, iterations);
    printf("---\n");

    /* Run benchmark */
    pqc_aggregate_metrics_t agg;
    memset(&agg, 0, sizeof(agg));
    pqc_status_t rc = pqc_tls_client_benchmark(client, host, port,
                                                 iterations, throughput_bytes, &agg);
    if (rc != PQC_OK) {
        fprintf(stderr, "Benchmark failed (rc=%d)\n", rc);
        pqc_tls_client_destroy(client);
        return 1;
    }

    /* Output results */
    pqc_reporter_write(&agg, format, output_path);

    pqc_tls_client_destroy(client);
    return 0;
}
