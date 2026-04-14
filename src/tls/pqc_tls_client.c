#include "pqc/pqc_tls_client.h"
#include "pqc/pqc_tls_handshake.h"
#include "pqc/pqc_metrics.h"
#include "pqc/pqc_timer.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

/* Declare helpers from oqs_provider.c */
extern SSL_CTX *pqc_create_ssl_ctx(int is_server, const char *provider_path);
extern pqc_status_t pqc_ssl_ctx_set_kem(SSL_CTX *ctx, const char *kem_alg);
extern pqc_status_t pqc_ssl_ctx_set_sig(SSL_CTX *ctx, const char *sig_alg);

struct pqc_tls_client {
    pqc_tls_client_config_t config;
    SSL_CTX *ctx;
};

pqc_tls_client_t *pqc_tls_client_create(const pqc_tls_client_config_t *config) {
    if (!config) return NULL;

    pqc_tls_client_t *client = calloc(1, sizeof(pqc_tls_client_t));
    if (!client) return NULL;
    memcpy(&client->config, config, sizeof(*config));

    /* Create SSL_CTX with oqs-provider */
    client->ctx = pqc_create_ssl_ctx(0, config->provider_path);
    if (!client->ctx) {
        fprintf(stderr, "Failed to create client SSL_CTX\n");
        free(client);
        return NULL;
    }

    /* Configure PQC algorithms */
    pqc_ssl_ctx_set_kem(client->ctx, config->kem_alg);
    pqc_ssl_ctx_set_sig(client->ctx, config->sig_alg);

    /* Load CA certificate for server verification */
    if (config->ca_cert_path && config->verify_peer) {
        if (SSL_CTX_load_verify_locations(client->ctx,
                                           config->ca_cert_path, NULL) != 1) {
            fprintf(stderr, "Warning: Failed to load CA cert: %s\n", config->ca_cert_path);
            ERR_print_errors_fp(stderr);
        }
        SSL_CTX_set_verify(client->ctx, SSL_VERIFY_PEER, NULL);
    }

    /* Load client certificate for mTLS */
    if (config->client_cert_path && config->client_key_path) {
        SSL_CTX_use_certificate_file(client->ctx, config->client_cert_path,
                                      SSL_FILETYPE_PEM);
        SSL_CTX_use_PrivateKey_file(client->ctx, config->client_key_path,
                                     SSL_FILETYPE_PEM);
    }

    if (config->tls_debug) {
        SSL_CTX_set_info_callback(client->ctx, NULL);
    }

    return client;
}

void pqc_tls_client_destroy(pqc_tls_client_t *client) {
    if (client) {
        if (client->ctx) SSL_CTX_free(client->ctx);
        free(client);
    }
}

static int tcp_connect(const char *host, uint16_t port, uint64_t *connect_ns) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", port);

    int rc = getaddrinfo(host, port_str, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo(%s): %s\n", host, gai_strerror(rc));
        return -1;
    }

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        return -1;
    }

    uint64_t t0 = pqc_timer_now();
    if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        perror("connect");
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    *connect_ns = pqc_timer_now() - t0;

    freeaddrinfo(res);
    return fd;
}

pqc_status_t pqc_tls_client_connect(pqc_tls_client_t *client,
                                     const char *host, uint16_t port,
                                     pqc_handshake_metrics_t *metrics,
                                     size_t throughput_bytes) {
    if (!client || !client->ctx || !metrics) return PQC_INVALID_PARAM;

    memset(metrics, 0, sizeof(*metrics));
    metrics->kem_alg = client->config.kem_alg;
    metrics->sig_alg = client->config.sig_alg;

    /* TCP connect */
    uint64_t connect_ns = 0;
    int fd = tcp_connect(host, port, &connect_ns);
    if (fd < 0) return PQC_NETWORK_ERROR;
    metrics->tcp_connect_ns = connect_ns;

    /* Create SSL connection */
    SSL *ssl = SSL_new(client->ctx);
    if (!ssl) {
        close(fd);
        return PQC_TLS_ERROR;
    }
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host);

    /* Attach handshake tracker */
    pqc_hs_tracker_t *tracker = pqc_hs_tracker_create(metrics);
    if (tracker) {
        pqc_hs_attach(ssl, tracker);
    }

    /* Perform TLS handshake */
    int ret = SSL_connect(ssl);
    pqc_status_t result;
    if (ret <= 0) {
        int err = SSL_get_error(ssl, ret);
        fprintf(stderr, "SSL_connect failed: error=%d\n", err);
        ERR_print_errors_fp(stderr);
        result = PQC_TLS_ERROR;
    } else {
        result = PQC_OK;

        /* Get actual negotiated cipher info */
        const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
        (void)cipher;
    }

    /* Finalize handshake tracking */
    if (tracker) {
        pqc_hs_finalize(tracker, result);
        pqc_hs_tracker_destroy(tracker);
    }

    /* Post-handshake throughput test */
    if (result == PQC_OK && throughput_bytes > 0) {
        char *buf = malloc(throughput_bytes);
        memset(buf, 'A', throughput_bytes);

        /* Send data */
        uint64_t t0 = pqc_timer_now();
        size_t sent = 0;
        while (sent < throughput_bytes) {
            int n = SSL_write(ssl, buf + sent, throughput_bytes - sent);
            if (n <= 0) break;
            sent += n;
        }

        /* Read response */
        char rbuf[256];
        SSL_read(ssl, rbuf, sizeof(rbuf));

        uint64_t elapsed = pqc_timer_now() - t0;
        if (elapsed > 0) {
            metrics->total_bytes_sent += sent;
        }
        free(buf);
    } else if (result == PQC_OK) {
        /* Send a simple request and read response */
        const char *req = "PING";
        SSL_write(ssl, req, strlen(req));
        char rbuf[256];
        SSL_read(ssl, rbuf, sizeof(rbuf));
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(fd);

    return result;
}

pqc_status_t pqc_tls_client_benchmark(pqc_tls_client_t *client,
                                       const char *host, uint16_t port,
                                       int iterations,
                                       size_t throughput_bytes,
                                       pqc_aggregate_metrics_t *agg) {
    if (!client || !agg) return PQC_INVALID_PARAM;

    pqc_metrics_collector_t *col = pqc_metrics_collector_create(iterations);
    if (!col) return PQC_NO_MEMORY;

    for (int i = 0; i < iterations; i++) {
        pqc_handshake_metrics_t m;
        pqc_status_t rc = pqc_tls_client_connect(client, host, port, &m,
                                                   throughput_bytes);
        if (rc != PQC_OK) {
            m.result = rc;
        }
        pqc_metrics_record(col, &m);
    }

    pqc_status_t rc = pqc_metrics_aggregate(col, agg);
    agg->kem_alg = client->config.kem_alg;
    agg->sig_alg = client->config.sig_alg;

    /* Compute throughput */
    if (agg->throughput_test_bytes > 0 && agg->throughput_test_ns > 0) {
        agg->throughput_mbps = (double)agg->throughput_test_bytes * 8.0 /
                               ((double)agg->throughput_test_ns / 1e9) / 1e6;
    }

    pqc_metrics_collector_destroy(col);
    return rc;
}
