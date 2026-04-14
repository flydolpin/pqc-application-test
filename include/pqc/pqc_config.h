#ifndef PQC_CONFIG_H
#define PQC_CONFIG_H

#include "pqc_benchmark.h"

#ifdef __cplusplus
extern "C" {
#endif

pqc_status_t pqc_config_load(const char *path, pqc_bench_config_t *config);
void pqc_config_free(pqc_bench_config_t *config);
pqc_status_t pqc_config_validate(const pqc_bench_config_t *config);
void pqc_config_print(const pqc_bench_config_t *config);

#ifdef __cplusplus
}
#endif

#endif /* PQC_CONFIG_H */
