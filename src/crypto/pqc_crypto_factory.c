#include "pqc/pqc_crypto_factory.h"
#include <stdlib.h>
#include <string.h>

/* Forward declarations from backends */
extern pqc_kem_t *pqc_oqs_kem_create(const char *alg_name);
extern pqc_sig_t *pqc_oqs_sig_create(const char *alg_name);
extern size_t pqc_oqs_kem_list(pqc_alg_desc_t *out, size_t max_out);
extern size_t pqc_oqs_sig_list(pqc_alg_desc_t *out, size_t max_out);
extern pqc_kem_t *pqc_classic_kem_create(const char *alg_name);
extern pqc_sig_t *pqc_classic_sig_create(const char *alg_name);
extern size_t pqc_classic_alg_list(pqc_alg_desc_t *out, size_t max_out);

pqc_status_t pqc_factory_init(void) {
    /* No dynamic state needed — backends are queried on demand */
    return PQC_OK;
}

void pqc_factory_destroy(void) {
    /* Nothing to clean up */
}

pqc_kem_t *pqc_factory_create_kem(const char *alg_name) {
    if (!alg_name) return NULL;

    /* Try OQS backend first */
    pqc_kem_t *kem = pqc_oqs_kem_create(alg_name);
    if (kem) return kem;

    /* Try classic backend */
    kem = pqc_classic_kem_create(alg_name);
    if (kem) return kem;

    return NULL;
}

pqc_sig_t *pqc_factory_create_sig(const char *alg_name) {
    if (!alg_name) return NULL;

    pqc_sig_t *sig = pqc_oqs_sig_create(alg_name);
    if (sig) return sig;

    sig = pqc_classic_sig_create(alg_name);
    if (sig) return sig;

    return NULL;
}

size_t pqc_factory_list_kems(pqc_alg_desc_t *out, size_t max_out) {
    size_t count = 0;
    count += pqc_oqs_kem_list(out + count, max_out - count);
    /* Add classic KEMs */
    pqc_alg_desc_t classics[16];
    size_t nc = pqc_classic_alg_list(classics, 16);
    for (size_t i = 0; i < nc && count < max_out; i++) {
        if (classics[i].is_kem) out[count++] = classics[i];
    }
    return count;
}

size_t pqc_factory_list_sigs(pqc_alg_desc_t *out, size_t max_out) {
    size_t count = 0;
    count += pqc_oqs_sig_list(out + count, max_out - count);
    pqc_alg_desc_t classics[16];
    size_t nc = pqc_classic_alg_list(classics, 16);
    for (size_t i = 0; i < nc && count < max_out; i++) {
        if (!classics[i].is_kem) out[count++] = classics[i];
    }
    return count;
}

int pqc_factory_kem_available(const char *alg_name) {
    pqc_kem_t *kem = pqc_factory_create_kem(alg_name);
    if (kem) { pqc_kem_destroy(kem); return 1; }
    return 0;
}

int pqc_factory_sig_available(const char *alg_name) {
    pqc_sig_t *sig = pqc_factory_create_sig(alg_name);
    if (sig) { pqc_sig_destroy(sig); return 1; }
    return 0;
}
