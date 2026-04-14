#ifndef PQC_CRYPTO_FACTORY_H
#define PQC_CRYPTO_FACTORY_H

#include "pqc_kem.h"
#include "pqc_sig.h"
#include "pqc_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *alg_name;
    const char *backend_name;
    pqc_alg_family_t family;
    pqc_nist_level_t nist_level;
    int is_kem;
    size_t pk_len;
    size_t sk_len;
    size_t ct_or_sig_len;
    size_t ss_len;
} pqc_alg_desc_t;

pqc_status_t pqc_factory_init(void);
void pqc_factory_destroy(void);

pqc_kem_t *pqc_factory_create_kem(const char *alg_name);
pqc_sig_t *pqc_factory_create_sig(const char *alg_name);

size_t pqc_factory_list_kems(pqc_alg_desc_t *out, size_t max_out);
size_t pqc_factory_list_sigs(pqc_alg_desc_t *out, size_t max_out);

int pqc_factory_kem_available(const char *alg_name);
int pqc_factory_sig_available(const char *alg_name);

#ifdef __cplusplus
}
#endif

#endif /* PQC_CRYPTO_FACTORY_H */
