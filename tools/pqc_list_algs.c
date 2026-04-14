#include "pqc/pqc_crypto_factory.h"
#include <stdio.h>

int main(void) {
    pqc_status_t rc = pqc_factory_init();
    if (rc != PQC_OK) {
        fprintf(stderr, "Failed to initialize PQC factory\n");
        return 1;
    }

    pqc_alg_desc_t kems[64];
    size_t nkems = pqc_factory_list_kems(kems, 64);

    printf("=== Available KEM Algorithms (%zu) ===\n", nkems);
    printf("%-30s %-10s %-8s %8s %8s %8s %8s\n",
           "Name", "Backend", "NIST Lvl", "PK", "SK", "CT", "SS");
    for (size_t i = 0; i < nkems; i++) {
        printf("%-30s %-10s %-8d %8zu %8zu %8zu %8zu\n",
               kems[i].alg_name, kems[i].backend_name,
               kems[i].nist_level,
               kems[i].pk_len, kems[i].sk_len,
               kems[i].ct_or_sig_len, kems[i].ss_len);
    }

    pqc_alg_desc_t sigs[64];
    size_t nsigs = pqc_factory_list_sigs(sigs, 64);

    printf("\n=== Available Signature Algorithms (%zu) ===\n", nsigs);
    printf("%-30s %-10s %-8s %8s %8s %8s\n",
           "Name", "Backend", "NIST Lvl", "PK", "SK", "MaxSig");
    for (size_t i = 0; i < nsigs; i++) {
        printf("%-30s %-10s %-8d %8zu %8zu %8zu\n",
               sigs[i].alg_name, sigs[i].backend_name,
               sigs[i].nist_level,
               sigs[i].pk_len, sigs[i].sk_len,
               sigs[i].ct_or_sig_len);
    }

    pqc_factory_destroy();
    return 0;
}
