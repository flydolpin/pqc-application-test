#ifndef PQC_SIG_H
#define PQC_SIG_H

#include "pqc_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pqc_sig pqc_sig_t;

typedef struct pqc_sig_vtable {
    const char *(*backend_name)(void);
    const char *(*alg_name)(const pqc_sig_t *sig);
    pqc_nist_level_t (*nist_level)(const pqc_sig_t *sig);
    size_t (*public_key_len)(const pqc_sig_t *sig);
    size_t (*secret_key_len)(const pqc_sig_t *sig);
    size_t (*max_signature_len)(const pqc_sig_t *sig);

    pqc_status_t (*keygen)(const pqc_sig_t *sig,
                           uint8_t *public_key, uint8_t *secret_key);
    pqc_status_t (*sign)(const pqc_sig_t *sig,
                         uint8_t *signature, size_t *sig_len,
                         const uint8_t *message, size_t msg_len,
                         const uint8_t *secret_key);
    pqc_status_t (*verify)(const pqc_sig_t *sig,
                           const uint8_t *message, size_t msg_len,
                           const uint8_t *signature, size_t sig_len,
                           const uint8_t *public_key);

    void (*destroy)(pqc_sig_t *sig);
} pqc_sig_vtable_t;

struct pqc_sig {
    const pqc_sig_vtable_t *vtable;
    void *ctx;
    pqc_alg_family_t family;
};

static inline const char *pqc_sig_alg_name(const pqc_sig_t *sig) {
    return sig->vtable->alg_name(sig);
}
static inline size_t pqc_sig_pk_len(const pqc_sig_t *sig) {
    return sig->vtable->public_key_len(sig);
}
static inline size_t pqc_sig_sk_len(const pqc_sig_t *sig) {
    return sig->vtable->secret_key_len(sig);
}
static inline size_t pqc_sig_max_sig_len(const pqc_sig_t *sig) {
    return sig->vtable->max_signature_len(sig);
}
static inline pqc_status_t pqc_sig_keygen(const pqc_sig_t *sig,
                                           uint8_t *pk, uint8_t *sk) {
    return sig->vtable->keygen(sig, pk, sk);
}
static inline pqc_status_t pqc_sig_sign(const pqc_sig_t *sig,
                                         uint8_t *sig_buf, size_t *sig_len,
                                         const uint8_t *msg, size_t msg_len,
                                         const uint8_t *sk) {
    return sig->vtable->sign(sig, sig_buf, sig_len, msg, msg_len, sk);
}
static inline pqc_status_t pqc_sig_verify(const pqc_sig_t *sig,
                                           const uint8_t *msg, size_t msg_len,
                                           const uint8_t *sig_buf,
                                           size_t sig_len,
                                           const uint8_t *pk) {
    return sig->vtable->verify(sig, msg, msg_len, sig_buf, sig_len, pk);
}
static inline void pqc_sig_destroy(pqc_sig_t *sig) {
    if (sig && sig->vtable && sig->vtable->destroy)
        sig->vtable->destroy(sig);
}

#ifdef __cplusplus
}
#endif

#endif /* PQC_SIG_H */
