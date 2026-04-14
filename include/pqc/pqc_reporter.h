#ifndef PQC_REPORTER_H
#define PQC_REPORTER_H

#include "pqc_metrics.h"

#ifdef __cplusplus
extern "C" {
#endif

pqc_status_t pqc_reporter_write(const pqc_aggregate_metrics_t *metrics,
                                 const char *format, const char *path);

#ifdef __cplusplus
}
#endif

#endif /* PQC_REPORTER_H */
