#include "pqc/pqc_crypto_factory.h"
#include "pqc/pqc_timer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int bench_kem(const char *alg_name, int iterations) {
    pqc_kem_t *kem = pqc_factory_create_kem(alg_name);
    if (!kem) {
        fprintf(stderr, "KEM algorithm not available: %s\n", alg_name);
        return -1;
    }

    size_t pk_len = pqc_kem_pk_len(kem);
    size_t sk_len = pqc_kem_sk_len(kem);
    size_t ct_len = pqc_kem_ct_len(kem);
    size_t ss_len = pqc_kem_ss_len(kem);

    uint8_t *pk = malloc(pk_len);
    uint8_t *sk = malloc(sk_len);
    uint8_t *ct = malloc(ct_len);
    uint8_t *ss = malloc(ss_len);

    uint64_t *kg_times = malloc(iterations * sizeof(uint64_t));
    uint64_t *enc_times = malloc(iterations * sizeof(uint64_t));
    uint64_t *dec_times = malloc(iterations * sizeof(uint64_t));

    printf("KEM: %s (PK=%zu CT=%zu SS=%zu)\n", alg_name, pk_len, ct_len, ss_len);

    for (int i = 0; i < iterations; i++) {
        uint64_t t0 = pqc_timer_now();
        pqc_kem_keygen(kem, pk, sk);
        kg_times[i] = pqc_timer_now() - t0;

        t0 = pqc_timer_now();
        pqc_kem_encaps(kem, ct, ss, pk);
        enc_times[i] = pqc_timer_now() - t0;

        t0 = pqc_timer_now();
        pqc_kem_decaps(kem, ss, ct, sk);
        dec_times[i] = pqc_timer_now() - t0;
    }

    double kg_mean, kg_sd, enc_mean, enc_sd, dec_mean, dec_sd;
    pqc_timer_stats(kg_times, iterations, &kg_mean, &kg_sd, NULL);
    pqc_timer_stats(enc_times, iterations, &enc_mean, &enc_sd, NULL);
    pqc_timer_stats(dec_times, iterations, &dec_mean, &dec_sd, NULL);

    printf("  keygen:  mean=%.0f ns (%.3f ms)  stdev=%.0f ns\n",
           kg_mean, kg_mean / 1e6, kg_sd);
    printf("  encaps:  mean=%.0f ns (%.3f ms)  stdev=%.0f ns\n",
           enc_mean, enc_mean / 1e6, enc_sd);
    printf("  decaps:  mean=%.0f ns (%.3f ms)  stdev=%.0f ns\n",
           dec_mean, dec_mean / 1e6, dec_sd);

    free(pk); free(sk); free(ct); free(ss);
    free(kg_times); free(enc_times); free(dec_times);
    pqc_kem_destroy(kem);
    return 0;
}

static int bench_sig(const char *alg_name, int iterations) {
    pqc_sig_t *sig = pqc_factory_create_sig(alg_name);
    if (!sig) {
        fprintf(stderr, "SIG algorithm not available: %s\n", alg_name);
        return -1;
    }

    size_t pk_len = pqc_sig_pk_len(sig);
    size_t sk_len = pqc_sig_sk_len(sig);
    size_t max_sig = pqc_sig_max_sig_len(sig);

    uint8_t *pk = malloc(pk_len);
    uint8_t *sk = malloc(sk_len);
    uint8_t *sig_buf = malloc(max_sig);
    size_t sig_len;
    const uint8_t msg[] = "benchmark test message";

    uint64_t *kg_times = malloc(iterations * sizeof(uint64_t));
    uint64_t *sign_times = malloc(iterations * sizeof(uint64_t));
    uint64_t *verify_times = malloc(iterations * sizeof(uint64_t));

    printf("SIG: %s (PK=%zu SK=%zu MaxSig=%zu)\n",
           alg_name, pk_len, sk_len, max_sig);

    pqc_sig_keygen(sig, pk, sk);

    for (int i = 0; i < iterations; i++) {
        uint64_t t0 = pqc_timer_now();
        if (i == 0) pqc_sig_keygen(sig, pk, sk);
        kg_times[i] = pqc_timer_now() - t0;

        sig_len = max_sig;
        t0 = pqc_timer_now();
        pqc_sig_sign(sig, sig_buf, &sig_len, msg, sizeof(msg), sk);
        sign_times[i] = pqc_timer_now() - t0;

        t0 = pqc_timer_now();
        pqc_sig_verify(sig, msg, sizeof(msg), sig_buf, sig_len, pk);
        verify_times[i] = pqc_timer_now() - t0;
    }

    double kg_mean, kg_sd, sign_mean, sign_sd, verify_mean, verify_sd;
    pqc_timer_stats(kg_times, iterations, &kg_mean, &kg_sd, NULL);
    pqc_timer_stats(sign_times, iterations, &sign_mean, &sign_sd, NULL);
    pqc_timer_stats(verify_times, iterations, &verify_mean, &verify_sd, NULL);

    printf("  keygen:   mean=%.0f ns (%.3f ms)  stdev=%.0f ns\n",
           kg_mean, kg_mean / 1e6, kg_sd);
    printf("  sign:     mean=%.0f ns (%.3f ms)  stdev=%.0f ns\n",
           sign_mean, sign_mean / 1e6, sign_sd);
    printf("  verify:   mean=%.0f ns (%.3f ms)  stdev=%.0f ns\n",
           verify_mean, verify_mean / 1e6, verify_sd);

    free(pk); free(sk); free(sig_buf);
    free(kg_times); free(sign_times); free(verify_times);
    pqc_sig_destroy(sig);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <kem|sig> <algorithm_name> [iterations]\n", argv[0]);
        return 1;
    }

    int iterations = argc > 3 ? atoi(argv[3]) : 100;

    pqc_factory_init();

    int rc;
    if (strcmp(argv[1], "kem") == 0) {
        rc = bench_kem(argv[2], iterations);
    } else if (strcmp(argv[1], "sig") == 0) {
        rc = bench_sig(argv[2], iterations);
    } else {
        fprintf(stderr, "Unknown type: %s (use 'kem' or 'sig')\n", argv[1]);
        rc = 1;
    }

    pqc_factory_destroy();
    return rc;
}
