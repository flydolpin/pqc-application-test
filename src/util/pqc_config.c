#include "pqc/pqc_config.h"
#include <stdio.h>
#include <string.h>

/*
 * TOML configuration parser.
 * Full implementation will use vendored tomlc99.
 * For now, provides stub that returns a default config.
 */

pqc_status_t pqc_config_load(const char *path, pqc_bench_config_t *config) {
    if (!path || !config) return PQC_INVALID_PARAM;

    memset(config, 0, sizeof(*config));

    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "Cannot open config file: %s\n", path);
        return PQC_CONFIG_ERROR;
    }

    /* TODO: Implement TOML parsing with tomlc99 */
    /* For now, set sensible defaults */
    config->iterations = 100;
    config->warmup_iterations = 10;
    config->throughput_test_bytes = 1048576;
    config->output_format = "console";
    config->server_port = 4433;
    config->parallel_connections = 1;

    fclose(fp);
    return PQC_OK;
}

void pqc_config_free(pqc_bench_config_t *config) {
    (void)config;
}

pqc_status_t pqc_config_validate(const pqc_bench_config_t *config) {
    if (!config) return PQC_INVALID_PARAM;
    if (!config->server_host) return PQC_CONFIG_ERROR;
    if (config->num_kem_algs == 0) return PQC_CONFIG_ERROR;
    if (config->num_sig_algs == 0) return PQC_CONFIG_ERROR;
    return PQC_OK;
}

void pqc_config_print(const pqc_bench_config_t *config) {
    if (!config) return;
    printf("Server: %s:%d\n", config->server_host ? config->server_host : "N/A",
           config->server_port);
    printf("Iterations: %d (warmup: %d)\n",
           config->iterations, config->warmup_iterations);
    printf("KEM algorithms (%zu):\n", config->num_kem_algs);
    for (size_t i = 0; i < config->num_kem_algs; i++)
        printf("  - %s\n", config->kem_algorithms[i]);
    printf("SIG algorithms (%zu):\n", config->num_sig_algs);
    for (size_t i = 0; i < config->num_sig_algs; i++)
        printf("  - %s\n", config->sig_algorithms[i]);
}
