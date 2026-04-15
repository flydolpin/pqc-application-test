#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>

/* Flush stdout after every printf for container logging */
#define LOG(fmt, ...) do { \
    printf(fmt "\n", ##__VA_ARGS__); \
    fflush(stdout); \
} while(0)

#define ERR_EXIT(msg) do { \
    LOG("FATAL: %s", msg); \
    ERR_print_errors_fp(stderr); \
    fflush(stderr); \
    return 1; \
} while(0)

int main() {
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *ssl_s = NULL, *ssl_c = NULL;
    EVP_PKEY *pkey = NULL;
    X509 *x509 = NULL;
    X509_NAME *name = NULL;
    int sv[2] = {-1, -1};
    int ret;

    /* Install signal handlers for crash diagnosis */
    signal(SIGSEGV, (void(*)(int))_exit);
    signal(SIGABRT, (void(*)(int))_exit);
    signal(SIGKILL, (void(*)(int))_exit);

    LOG("=== ML-DSA TLS 1.3 Test Start ===");

    SSL_library_init();
    OSSL_PROVIDER_load(NULL, "default");
    LOG("OpenSSL initialized, version: %s", OpenSSL_version(OPENSSL_VERSION));

    /* Step 1: Generate ML-DSA-65 key */
    LOG("Generating ML-DSA-65 key...");
    pkey = EVP_PKEY_Q_keygen(NULL, NULL, "ML-DSA-65");
    if (!pkey) ERR_EXIT("ML-DSA-65 key generation failed");

    int pkey_id = EVP_PKEY_get_id(pkey);
    LOG("ML-DSA-65 key generated, id=%d, type=%s",
        pkey_id,
        pkey_id == EVP_PKEY_KEYMGMT ? "EVP_PKEY_KEYMGMT (provider)" : "legacy");

    /* Step 2: Create self-signed certificate */
    LOG("Creating self-signed certificate...");
    x509 = X509_new();
    if (!x509) ERR_EXIT("X509_new failed");

    X509_set_version(x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
    X509_set_pubkey(x509, pkey);

    name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (unsigned char *)"localhost", -1, -1, 0);
    X509_set_subject_name(x509, name);
    X509_set_issuer_name(x509, name);
    X509_NAME_free(name);
    name = NULL;

    ret = X509_sign(x509, pkey, NULL);
    if (ret <= 0) ERR_EXIT("X509_sign failed");
    LOG("Certificate signed with ML-DSA-65 (ret=%d)", ret);

    /* Step 3: Server context */
    LOG("Setting up server SSL_CTX...");
    sctx = SSL_CTX_new(TLS_server_method());
    if (!sctx) ERR_EXIT("SSL_CTX_new (server) failed");

    SSL_CTX_set_min_proto_version(sctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(sctx, TLS1_3_VERSION);
    SSL_CTX_set_security_level(sctx, 0);

    ret = SSL_CTX_use_certificate(sctx, x509);
    LOG("SSL_CTX_use_certificate: %d", ret);
    if (ret != 1) ERR_EXIT("SSL_CTX_use_certificate failed");

    ret = SSL_CTX_use_PrivateKey(sctx, pkey);
    LOG("SSL_CTX_use_PrivateKey: %d", ret);
    if (ret != 1) ERR_EXIT("SSL_CTX_use_PrivateKey failed");

    ret = SSL_CTX_check_private_key(sctx);
    LOG("SSL_CTX_check_private_key: %d", ret);

    /* Step 4: Client context */
    LOG("Setting up client SSL_CTX...");
    cctx = SSL_CTX_new(TLS_client_method());
    if (!cctx) ERR_EXIT("SSL_CTX_new (client) failed");

    SSL_CTX_set_min_proto_version(cctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(cctx, TLS1_3_VERSION);
    SSL_CTX_set_security_level(cctx, 0);
    SSL_CTX_set_verify(cctx, SSL_VERIFY_NONE, NULL);

    /* Step 5: Socket pair (non-blocking for handshake loop) */
    LOG("Creating socketpair...");
    ret = socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv);
    if (ret != 0) ERR_EXIT("socketpair failed");
    LOG("socketpair created: sv[0]=%d, sv[1]=%d", sv[0], sv[1]);

    /* Step 6: SSL objects */
    ssl_s = SSL_new(sctx);
    ssl_c = SSL_new(cctx);
    if (!ssl_s || !ssl_c) ERR_EXIT("SSL_new failed");

    SSL_set_fd(ssl_s, sv[0]);
    SSL_set_fd(ssl_c, sv[1]);
    SSL_set_connect_state(ssl_c);
    SSL_set_accept_state(ssl_s);
    LOG("SSL objects created, starting handshake...");

    /* Step 7: Non-blocking handshake loop */
    int s_done = 0, c_done = 0;
    for (int i = 0; i < 50 && (!s_done || !c_done); i++) {
        if (!c_done) {
            ret = SSL_do_handshake(ssl_c);
            if (ret == 1) {
                LOG("Client handshake COMPLETE");
                c_done = 1;
            } else {
                int err = SSL_get_error(ssl_c, ret);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                    /* expected, continue */
                } else {
                    LOG("Client handshake FAILED, err=%d, ret=%d", err, ret);
                    ERR_print_errors_fp(stderr);
                    fflush(stderr);
                    c_done = 1;
                }
            }
        }
        if (!s_done) {
            ret = SSL_do_handshake(ssl_s);
            if (ret == 1) {
                LOG("Server handshake COMPLETE");
                s_done = 1;
            } else {
                int err = SSL_get_error(ssl_s, ret);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                    /* expected, continue */
                } else {
                    LOG("Server handshake FAILED, err=%d, ret=%d", err, ret);
                    ERR_print_errors_fp(stderr);
                    fflush(stderr);
                    s_done = 1;
                }
            }
        }
    }

    /* Step 8: Results */
    if (s_done == 1 && c_done == 1) {
        LOG("");
        LOG("=== ML-DSA-65 TLS 1.3 handshake SUCCESS ===");
        LOG("Cipher: %s", SSL_get_cipher(ssl_c));
        LOG("Protocol: %s", SSL_get_version(ssl_c));
    } else {
        LOG("");
        LOG("=== ML-DSA-65 TLS 1.3 handshake FAILED (s=%d, c=%d) ===", s_done, c_done);
    }

    /* Cleanup */
    SSL_free(ssl_s);
    SSL_free(ssl_c);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    X509_free(x509);
    EVP_PKEY_free(pkey);
    if (sv[0] >= 0) close(sv[0]);
    if (sv[1] >= 0) close(sv[1]);

    LOG("Cleanup done, exiting with code %d", (s_done == 1 && c_done == 1) ? 0 : 1);
    return (s_done == 1 && c_done == 1) ? 0 : 1;
}
