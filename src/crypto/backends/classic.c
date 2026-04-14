#include "pqc/pqc_kem.h"
#include "pqc/pqc_sig.h"
#include "pqc/pqc_crypto_factory.h"
#include <stdlib.h>
#include <string.h>

/*
 * Classic algorithm stubs (RSA, ECDSA, ECDH via OpenSSL EVP).
 * Full implementation will use EVP_PKEY_keygen, EVP_PKEY_encrypt/decrypt,
 * EVP_DigestSign/EVP_DigestVerify.
 * For now, register placeholder descriptors so the factory can enumerate them.
 */

pqc_kem_t *pqc_classic_kem_create(const char *alg_name) {
    /* TODO: Implement ECDH key exchange via EVP_PKEY */
    (void)alg_name;
    return NULL;
}

pqc_sig_t *pqc_classic_sig_create(const char *alg_name) {
    /* TODO: Implement RSA/ECDSA via EVP_PKEY */
    (void)alg_name;
    return NULL;
}

size_t pqc_classic_alg_list(pqc_alg_desc_t *out, size_t max_out) {
    size_t count = 0;

    static const struct { const char *name; pqc_nist_level_t level; } kems[] = {
        {"X25519",     PQC_NIST_LEVEL_UNKNOWN},
        {"SecP256r1",  PQC_NIST_LEVEL_1},
        {"SecP384r1",  PQC_NIST_LEVEL_3},
        {"SecP521r1",  PQC_NIST_LEVEL_5},
    };
    static const struct { const char *name; pqc_nist_level_t level; } sigs[] = {
        {"RSA-2048",   PQC_NIST_LEVEL_1},
        {"RSA-3072",   PQC_NIST_LEVEL_2},
        {"ECDSA-P256", PQC_NIST_LEVEL_1},
        {"ECDSA-P384", PQC_NIST_LEVEL_3},
        {"ECDSA-P521", PQC_NIST_LEVEL_5},
        {"Ed25519",    PQC_NIST_LEVEL_1},
    };

    for (size_t i = 0; i < sizeof(kems)/sizeof(kems[0]) && count < max_out; i++) {
        out[count].alg_name = kems[i].name;
        out[count].backend_name = "openssl-classic";
        out[count].family = PQC_ALG_FAMILY_CLASSICAL;
        out[count].nist_level = kems[i].level;
        out[count].is_kem = 1;
        out[count].pk_len = 0;
        out[count].sk_len = 0;
        out[count].ct_or_sig_len = 0;
        out[count].ss_len = 0;
        count++;
    }
    for (size_t i = 0; i < sizeof(sigs)/sizeof(sigs[0]) && count < max_out; i++) {
        out[count].alg_name = sigs[i].name;
        out[count].backend_name = "openssl-classic";
        out[count].family = PQC_ALG_FAMILY_CLASSICAL;
        out[count].nist_level = sigs[i].level;
        out[count].is_kem = 0;
        out[count].pk_len = 0;
        out[count].sk_len = 0;
        out[count].ct_or_sig_len = 0;
        out[count].ss_len = 0;
        count++;
    }
    return count;
}
