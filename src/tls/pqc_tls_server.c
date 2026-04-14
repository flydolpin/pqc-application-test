#include "pqc/pqc_tls_server.h"
#include "pqc/pqc_metrics.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

/* Declare helpers from oqs_provider.c */
extern SSL_CTX *pqc_create_ssl_ctx(int is_server, const char *provider_path);
extern pqc_status_t pqc_ssl_ctx_set_kem(SSL_CTX *ctx, const char *kem_alg);
extern pqc_status_t pqc_ssl_ctx_set_sig(SSL_CTX *ctx, const char *sig_alg);

struct pqc_tls_server {
    pqc_tls_server_config_t config;
    SSL_CTX *ctx;
    int server_fd;
    volatile int running;
};

pqc_tls_server_t *pqc_tls_server_create(const pqc_tls_server_config_t *config) {
    if (!config) return NULL;

    pqc_tls_server_t *server = calloc(1, sizeof(pqc_tls_server_t));
    if (!server) return NULL;
    memcpy(&server->config, config, sizeof(*config));
    server->server_fd = -1;

    /* Create SSL_CTX with oqs-provider */
    server->ctx = pqc_create_ssl_ctx(1, config->provider_path);
    if (!server->ctx) {
        fprintf(stderr, "Failed to create server SSL_CTX\n");
        free(server);
        return NULL;
    }

    /* Configure PQC algorithms */
    pqc_ssl_ctx_set_kem(server->ctx, config->kem_alg);
    pqc_ssl_ctx_set_sig(server->ctx, config->sig_alg);

    /* Load server certificate and key */
    if (config->cert_path && config->key_path) {
        if (SSL_CTX_use_certificate_file(server->ctx, config->cert_path,
                                          SSL_FILETYPE_PEM) != 1) {
            fprintf(stderr, "Failed to load certificate: %s\n", config->cert_path);
            ERR_print_errors_fp(stderr);
        }
        if (SSL_CTX_use_PrivateKey_file(server->ctx, config->key_path,
                                         SSL_FILETYPE_PEM) != 1) {
            fprintf(stderr, "Failed to load private key: %s\n", config->key_path);
            ERR_print_errors_fp(stderr);
        }
    }

    /* Load CA certificate for client verification */
    if (config->ca_cert_path) {
        SSL_CTX_load_verify_locations(server->ctx, config->ca_cert_path, NULL);
    }

    return server;
}

void pqc_tls_server_destroy(pqc_tls_server_t *server) {
    if (server) {
        if (server->ctx) SSL_CTX_free(server->ctx);
        if (server->server_fd >= 0) close(server->server_fd);
        free(server);
    }
}

pqc_status_t pqc_tls_server_start(pqc_tls_server_t *server) {
    if (!server || !server->ctx) return PQC_INVALID_PARAM;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(server->config.port);
    addr.sin_addr.s_addr = INADDR_ANY;

    server->server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->server_fd < 0) {
        perror("socket");
        return PQC_NETWORK_ERROR;
    }

    int opt = 1;
    setsockopt(server->server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(server->server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server->server_fd);
        server->server_fd = -1;
        return PQC_NETWORK_ERROR;
    }

    if (listen(server->server_fd, 16) < 0) {
        perror("listen");
        close(server->server_fd);
        server->server_fd = -1;
        return PQC_NETWORK_ERROR;
    }

    server->running = 1;
    printf("PQC TLS server listening on port %d (KEM=%s SIG=%s)\n",
           server->config.port,
           server->config.kem_alg ? server->config.kem_alg : "default",
           server->config.sig_alg ? server->config.sig_alg : "default");

    int conn_count = 0;
    int max_conn = server->config.max_connections > 0 ? server->config.max_connections : 0;

    while (server->running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server->server_fd,
                               (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            if (server->running) perror("accept");
            continue;
        }

        SSL *ssl = SSL_new(server->ctx);
        SSL_set_fd(ssl, client_fd);

        if (SSL_accept(ssl) <= 0) {
            fprintf(stderr, "SSL_accept failed\n");
            ERR_print_errors_fp(stderr);
        } else {
            /* Read request and send response */
            char buf[4096];
            int n = SSL_read(ssl, buf, sizeof(buf) - 1);
            if (n > 0) {
                buf[n] = '\0';
                const char *response = "OK";
                SSL_write(ssl, response, strlen(response));
            }
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);

        conn_count++;
        if (max_conn > 0 && conn_count >= max_conn) {
            printf("Reached max connections (%d), shutting down\n", max_conn);
            break;
        }
    }

    return PQC_OK;
}

void pqc_tls_server_stop(pqc_tls_server_t *server) {
    if (server) {
        server->running = 0;
        if (server->server_fd >= 0) {
            close(server->server_fd);
            server->server_fd = -1;
        }
    }
}
