#ifndef PQC_KEM_H
#define PQC_KEM_H

#include "pqc_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pqc_kem pqc_kem_t;

typedef struct pqc_kem_vtable {
    const char *(*backend_name)(void);
    const char *(*alg_name)(const pqc_kem_t *kem);
    pqc_nist_level_t (*nist_level)(const pqc_kem_t *kem);
    size_t (*public_key_len)(const pqc_kem_t *kem);
    size_t (*secret_key_len)(const pqc_kem_t *kem);
    size_t (*ciphertext_len)(const pqc_kem_t *kem);
    size_t (*shared_secret_len)(const pqc_kem_t *kem);

    pqc_status_t (*keygen)(const pqc_kem_t *kem,
                           uint8_t *public_key, uint8_t *secret_key);
    pqc_status_t (*encaps)(const pqc_kem_t *kem,
                           uint8_t *ciphertext, uint8_t *shared_secret,
                           const uint8_t *public_key);
    pqc_status_t (*decaps)(const pqc_kem_t *kem,
                           uint8_t *shared_secret, const uint8_t *ciphertext,
                           const uint8_t *secret_key);

    void (*destroy)(pqc_kem_t *kem);
} pqc_kem_vtable_t;

struct pqc_kem {
    const pqc_kem_vtable_t *vtable;
    void *ctx;
    pqc_alg_family_t family;
};

static inline const char *pqc_kem_alg_name(const pqc_kem_t *kem) {
    return kem->vtable->alg_name(kem);
}
static inline size_t pqc_kem_pk_len(const pqc_kem_t *kem) {
    return kem->vtable->public_key_len(kem);
}
static inline size_t pqc_kem_sk_len(const pqc_kem_t *kem) {
    return kem->vtable->secret_key_len(kem);
}
static inline size_t pqc_kem_ct_len(const pqc_kem_t *kem) {
    return kem->vtable->ciphertext_len(kem);
}
static inline size_t pqc_kem_ss_len(const pqc_kem_t *kem) {
    return kem->vtable->shared_secret_len(kem);
}
static inline pqc_status_t pqc_kem_keygen(const pqc_kem_t *kem,
                                           uint8_t *pk, uint8_t *sk) {
    return kem->vtable->keygen(kem, pk, sk);
}
static inline pqc_status_t pqc_kem_encaps(const pqc_kem_t *kem,
                                           uint8_t *ct, uint8_t *ss,
                                           const uint8_t *pk) {
    return kem->vtable->encaps(kem, ct, ss, pk);
}
static inline pqc_status_t pqc_kem_decaps(const pqc_kem_t *kem,
                                           uint8_t *ss, const uint8_t *ct,
                                           const uint8_t *sk) {
    return kem->vtable->decaps(kem, ss, ct, sk);
}
static inline void pqc_kem_destroy(pqc_kem_t *kem) {
    if (kem && kem->vtable && kem->vtable->destroy)
        kem->vtable->destroy(kem);
}

#ifdef __cplusplus
}
#endif

#endif /* PQC_KEM_H */
