#include "pqc/pqc_sig.h"
#include "pqc/pqc_crypto_factory.h"
#include <oqs/oqs.h>
#include <stdlib.h>
#include <string.h>

static const char *oqs_sig_backend_name(void) { return "liboqs"; }

static const char *oqs_sig_alg_name(const pqc_sig_t *sig) {
    OQS_SIG *oqs = (OQS_SIG *)sig->ctx;
    return oqs->method_name;
}

static pqc_nist_level_t oqs_sig_nist_level(const pqc_sig_t *sig) {
    OQS_SIG *oqs = (OQS_SIG *)sig->ctx;
    return (pqc_nist_level_t)oqs->claimed_nist_level;
}

static size_t oqs_sig_pk_len(const pqc_sig_t *sig) {
    return ((OQS_SIG *)sig->ctx)->length_public_key;
}
static size_t oqs_sig_sk_len(const pqc_sig_t *sig) {
    return ((OQS_SIG *)sig->ctx)->length_secret_key;
}
static size_t oqs_sig_max_sig_len(const pqc_sig_t *sig) {
    return ((OQS_SIG *)sig->ctx)->length_signature;
}

static pqc_status_t oqs_sig_keygen(const pqc_sig_t *sig,
                                    uint8_t *pk, uint8_t *sk) {
    OQS_SIG *oqs = (OQS_SIG *)sig->ctx;
    return (OQS_SIG_keypair(oqs, pk, sk) == OQS_SUCCESS)
           ? PQC_OK : PQC_ERROR;
}

static pqc_status_t oqs_sig_sign_op(const pqc_sig_t *sig,
                                     uint8_t *signature, size_t *sig_len,
                                     const uint8_t *message, size_t msg_len,
                                     const uint8_t *secret_key) {
    OQS_SIG *oqs = (OQS_SIG *)sig->ctx;
    size_t smlen = oqs->length_signature;
    OQS_STATUS rc = OQS_SIG_sign(oqs, signature, &smlen,
                                  message, msg_len, secret_key);
    if (sig_len) *sig_len = smlen;
    return (rc == OQS_SUCCESS) ? PQC_OK : PQC_ERROR;
}

static pqc_status_t oqs_sig_verify_op(const pqc_sig_t *sig,
                                       const uint8_t *message, size_t msg_len,
                                       const uint8_t *signature, size_t sig_len,
                                       const uint8_t *public_key) {
    OQS_SIG *oqs = (OQS_SIG *)sig->ctx;
    return (OQS_SIG_verify(oqs, message, msg_len,
                            signature, sig_len, public_key) == OQS_SUCCESS)
           ? PQC_OK : PQC_ERROR;
}

static void oqs_sig_destroy(pqc_sig_t *sig) {
    if (sig) {
        if (sig->ctx) OQS_SIG_free((OQS_SIG *)sig->ctx);
        free(sig);
    }
}

static const pqc_sig_vtable_t oqs_sig_vtable = {
    .backend_name     = oqs_sig_backend_name,
    .alg_name         = oqs_sig_alg_name,
    .nist_level       = oqs_sig_nist_level,
    .public_key_len   = oqs_sig_pk_len,
    .secret_key_len   = oqs_sig_sk_len,
    .max_signature_len = oqs_sig_max_sig_len,
    .keygen           = oqs_sig_keygen,
    .sign             = oqs_sig_sign_op,
    .verify           = oqs_sig_verify_op,
    .destroy          = oqs_sig_destroy,
};

pqc_sig_t *pqc_oqs_sig_create(const char *alg_name) {
    OQS_SIG *oqs = OQS_SIG_new(alg_name);
    if (!oqs) return NULL;

    pqc_sig_t *sig = calloc(1, sizeof(pqc_sig_t));
    if (!sig) { OQS_SIG_free(oqs); return NULL; }

    sig->vtable = &oqs_sig_vtable;
    sig->ctx = oqs;

    if (strstr(alg_name, "ML-DSA") || strstr(alg_name, "Dilithium"))
        sig->family = PQC_ALG_FAMILY_NIST_STANDARD;
    else if (strstr(alg_name, "p256_") || strstr(alg_name, "rsa3072_"))
        sig->family = PQC_ALG_FAMILY_HYBRID;
    else
        sig->family = PQC_ALG_FAMILY_ALTERNATE;

    return sig;
}

size_t pqc_oqs_sig_list(pqc_alg_desc_t *out, size_t max_out) {
    size_t count = 0;
    for (size_t i = 0; i < OQS_SIG_alg_count() && count < max_out; i++) {
        const char *name = OQS_SIG_alg_identifier(i);
        OQS_SIG *oqs = OQS_SIG_new(name);
        if (!oqs) continue;

        out[count].alg_name = name;
        out[count].backend_name = "liboqs";
        out[count].is_kem = 0;
        out[count].pk_len = oqs->length_public_key;
        out[count].sk_len = oqs->length_secret_key;
        out[count].ct_or_sig_len = oqs->length_signature;
        out[count].ss_len = 0;
        out[count].nist_level = (pqc_nist_level_t)oqs->claimed_nist_level;

        if (strstr(name, "ML-DSA") || strstr(name, "Dilithium"))
            out[count].family = PQC_ALG_FAMILY_NIST_STANDARD;
        else if (strstr(name, "p256_") || strstr(name, "rsa3072_"))
            out[count].family = PQC_ALG_FAMILY_HYBRID;
        else
            out[count].family = PQC_ALG_FAMILY_ALTERNATE;

        OQS_SIG_free(oqs);
        count++;
    }
    return count;
}
