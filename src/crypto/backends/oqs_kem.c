#include "pqc/pqc_kem.h"
#include "pqc/pqc_crypto_factory.h"
#include <oqs/oqs.h>
#include <stdlib.h>
#include <string.h>

/* --- OQS KEM backend implementation --- */

static const char *oqs_kem_backend_name(void) { return "liboqs"; }

static const char *oqs_kem_alg_name(const pqc_kem_t *kem) {
    OQS_KEM *oqs = (OQS_KEM *)kem->ctx;
    return oqs->method_name;
}

static pqc_nist_level_t oqs_kem_nist_level(const pqc_kem_t *kem) {
    OQS_KEM *oqs = (OQS_KEM *)kem->ctx;
    return (pqc_nist_level_t)oqs->claimed_nist_level;
}

static size_t oqs_kem_pk_len(const pqc_kem_t *kem) {
    return ((OQS_KEM *)kem->ctx)->length_public_key;
}
static size_t oqs_kem_sk_len(const pqc_kem_t *kem) {
    return ((OQS_KEM *)kem->ctx)->length_secret_key;
}
static size_t oqs_kem_ct_len(const pqc_kem_t *kem) {
    return ((OQS_KEM *)kem->ctx)->length_ciphertext;
}
static size_t oqs_kem_ss_len(const pqc_kem_t *kem) {
    return ((OQS_KEM *)kem->ctx)->length_shared_secret;
}

static pqc_status_t oqs_kem_keygen(const pqc_kem_t *kem,
                                    uint8_t *pk, uint8_t *sk) {
    OQS_KEM *oqs = (OQS_KEM *)kem->ctx;
    return (OQS_KEM_keypair(oqs, pk, sk) == OQS_SUCCESS)
           ? PQC_OK : PQC_ERROR;
}

static pqc_status_t oqs_kem_encaps(const pqc_kem_t *kem,
                                    uint8_t *ct, uint8_t *ss,
                                    const uint8_t *pk) {
    OQS_KEM *oqs = (OQS_KEM *)kem->ctx;
    return (OQS_KEM_encaps(oqs, ct, ss, pk) == OQS_SUCCESS)
           ? PQC_OK : PQC_ERROR;
}

static pqc_status_t oqs_kem_decaps(const pqc_kem_t *kem,
                                    uint8_t *ss, const uint8_t *ct,
                                    const uint8_t *sk) {
    OQS_KEM *oqs = (OQS_KEM *)kem->ctx;
    return (OQS_KEM_decaps(oqs, ss, ct, sk) == OQS_SUCCESS)
           ? PQC_OK : PQC_ERROR;
}

static void oqs_kem_destroy(pqc_kem_t *kem) {
    if (kem) {
        if (kem->ctx) OQS_KEM_free((OQS_KEM *)kem->ctx);
        free(kem);
    }
}

static const pqc_kem_vtable_t oqs_kem_vtable = {
    .backend_name    = oqs_kem_backend_name,
    .alg_name        = oqs_kem_alg_name,
    .nist_level      = oqs_kem_nist_level,
    .public_key_len  = oqs_kem_pk_len,
    .secret_key_len  = oqs_kem_sk_len,
    .ciphertext_len  = oqs_kem_ct_len,
    .shared_secret_len = oqs_kem_ss_len,
    .keygen          = oqs_kem_keygen,
    .encaps          = oqs_kem_encaps,
    .decaps          = oqs_kem_decaps,
    .destroy         = oqs_kem_destroy,
};

/* --- Registration helper called by factory --- */

pqc_kem_t *pqc_oqs_kem_create(const char *alg_name) {
    OQS_KEM *oqs = OQS_KEM_new(alg_name);
    if (!oqs) return NULL;

    pqc_kem_t *kem = calloc(1, sizeof(pqc_kem_t));
    if (!kem) { OQS_KEM_free(oqs); return NULL; }

    kem->vtable = &oqs_kem_vtable;
    kem->ctx = oqs;

    /* Classify family based on algorithm name */
    if (strstr(alg_name, "ML-KEM") || strstr(alg_name, "Kyber"))
        kem->family = PQC_ALG_FAMILY_NIST_STANDARD;
    else if (strstr(alg_name, "p256_") || strstr(alg_name, "x25519_"))
        kem->family = PQC_ALG_FAMILY_HYBRID;
    else
        kem->family = PQC_ALG_FAMILY_ALTERNATE;

    return kem;
}

/* Enumerate all liboqs KEM algorithms */
size_t pqc_oqs_kem_list(pqc_alg_desc_t *out, size_t max_out) {
    size_t count = 0;
    for (size_t i = 0; i < OQS_KEM_alg_count() && count < max_out; i++) {
        const char *name = OQS_KEM_alg_identifier(i);
        OQS_KEM *oqs = OQS_KEM_new(name);
        if (!oqs) continue;

        out[count].alg_name = name;
        out[count].backend_name = "liboqs";
        out[count].is_kem = 1;
        out[count].pk_len = oqs->length_public_key;
        out[count].sk_len = oqs->length_secret_key;
        out[count].ct_or_sig_len = oqs->length_ciphertext;
        out[count].ss_len = oqs->length_shared_secret;
        out[count].nist_level = (pqc_nist_level_t)oqs->claimed_nist_level;

        if (strstr(name, "ML-KEM") || strstr(name, "Kyber"))
            out[count].family = PQC_ALG_FAMILY_NIST_STANDARD;
        else if (strstr(name, "p256_") || strstr(name, "x25519_"))
            out[count].family = PQC_ALG_FAMILY_HYBRID;
        else
            out[count].family = PQC_ALG_FAMILY_ALTERNATE;

        OQS_KEM_free(oqs);
        count++;
    }
    return count;
}
