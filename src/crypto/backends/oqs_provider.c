#include "pqc/pqc_types.h"
#include <openssl/ssl.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * oqs-provider loading and SSL_CTX creation helpers.
 * Used by both TLS client and server to configure PQC algorithms.
 */

/* Set OPENSSL_MODULES environment variable so oqsprovider.so is found */
static void set_openssl_modules_path(const char *provider_path) {
    if (provider_path && provider_path[0]) {
        char existing[4096] = {0};
        const char *cur = getenv("OPENSSL_MODULES");
        if (cur) snprintf(existing, sizeof(existing), "%s", cur);

        /* Only set if not already set to this path */
        if (!cur || strstr(cur, provider_path) == NULL) {
            char env[4096];
            if (cur && cur[0]) {
                snprintf(env, sizeof(env), "OPENSSL_MODULES=%s:%s", provider_path, cur);
            } else {
                snprintf(env, sizeof(env), "OPENSSL_MODULES=%s", provider_path);
            }
            putenv(env);
        }
    }
}

pqc_status_t pqc_oqs_provider_load(const char *provider_path) {
    set_openssl_modules_path(provider_path);

    /* Load the default provider first */
    OSSL_PROVIDER *defprov = OSSL_PROVIDER_load(NULL, "default");
    if (!defprov) {
        fprintf(stderr, "Failed to load default OpenSSL provider\n");
        ERR_print_errors_fp(stderr);
        return PQC_TLS_ERROR;
    }

    /* Load oqs-provider */
    OSSL_PROVIDER *oqsprov = OSSL_PROVIDER_load(NULL, "oqsprovider");
    if (!oqsprov) {
        fprintf(stderr, "Warning: Failed to load oqsprovider (TLS benchmark will use classical algorithms only)\n");
        ERR_print_errors_fp(stderr);
        /* Not fatal - can still work with classical algorithms */
    }

    return PQC_OK;
}

/*
 * Create an SSL_CTX configured for TLS 1.3 with PQC algorithms.
 * Used by both client and server.
 * Returns NULL on failure.
 */
SSL_CTX *pqc_create_ssl_ctx(int is_server, const char *provider_path) {
    pqc_oqs_provider_load(provider_path);

    const SSL_METHOD *method = is_server ? TLS_server_method() : TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    /* Force TLS 1.3 */
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    return ctx;
}

/*
 * Configure KEM group on SSL_CTX (for key exchange).
 * oqs-provider uses lowercase names: mlkem768, p256_mlkem768, etc.
 */
pqc_status_t pqc_ssl_ctx_set_kem(SSL_CTX *ctx, const char *kem_alg) {
    if (!kem_alg) return PQC_OK;

    if (SSL_CTX_set1_curves_list(ctx, kem_alg) != 1) {
        fprintf(stderr, "Warning: Failed to set KEM group '%s'\n", kem_alg);
        ERR_print_errors_fp(stderr);
        return PQC_NOT_SUPPORTED;
    }
    return PQC_OK;
}

/*
 * Configure signature algorithm on SSL_CTX.
 * oqs-provider uses lowercase names: mldsa65, dilithium3, etc.
 */
pqc_status_t pqc_ssl_ctx_set_sig(SSL_CTX *ctx, const char *sig_alg) {
    if (!sig_alg) return PQC_OK;

    if (SSL_CTX_set1_sigalgs_list(ctx, sig_alg) != 1) {
        fprintf(stderr, "Warning: Failed to set signature algorithm '%s'\n", sig_alg);
        ERR_print_errors_fp(stderr);
        return PQC_NOT_SUPPORTED;
    }
    return PQC_OK;
}
