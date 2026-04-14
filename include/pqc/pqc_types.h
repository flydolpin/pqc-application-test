#ifndef PQC_TYPES_H
#define PQC_TYPES_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PQC_OK            =  0,
    PQC_ERROR         = -1,
    PQC_NOT_SUPPORTED = -2,
    PQC_INVALID_PARAM = -3,
    PQC_NO_MEMORY     = -4,
    PQC_TLS_ERROR     = -5,
    PQC_NETWORK_ERROR = -6,
    PQC_CONFIG_ERROR  = -7,
} pqc_status_t;

typedef enum {
    PQC_ALG_FAMILY_NIST_STANDARD = 0,
    PQC_ALG_FAMILY_ALTERNATE     = 1,
    PQC_ALG_FAMILY_HYBRID        = 2,
    PQC_ALG_FAMILY_CLASSICAL     = 3,
} pqc_alg_family_t;

typedef enum {
    PQC_NIST_LEVEL_UNKNOWN = 0,
    PQC_NIST_LEVEL_1       = 1,
    PQC_NIST_LEVEL_2       = 2,
    PQC_NIST_LEVEL_3       = 3,
    PQC_NIST_LEVEL_4       = 4,
    PQC_NIST_LEVEL_5       = 5,
} pqc_nist_level_t;

typedef enum {
    PQC_HS_PHASE_CLIENT_HELLO    = 0,
    PQC_HS_PHASE_SERVER_HELLO    = 1,
    PQC_HS_PHASE_CERT_EXCHANGE   = 2,
    PQC_HS_PHASE_CERT_VERIFY     = 3,
    PQC_HS_PHASE_FINISHED        = 4,
    PQC_HS_PHASE_SESSION_TICKETS = 5,
    PQC_HS_PHASE_COMPLETE        = 6,
    PQC_HS_PHASE_COUNT           = 7,
} pqc_hs_phase_t;

typedef enum {
    PQC_PROTOCOL_TLS_1_3 = 0,
    PQC_PROTOCOL_QUIC    = 1,
} pqc_protocol_t;

#define PQC_MAX_ALG_NAME 64
#define PQC_MAX_ALGS     32

#ifdef __cplusplus
}
#endif

#endif /* PQC_TYPES_H */
