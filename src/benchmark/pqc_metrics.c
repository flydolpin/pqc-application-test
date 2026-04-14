#include "pqc/pqc_metrics.h"
#include "pqc/pqc_timer.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>

struct pqc_metrics_collector {
    pqc_handshake_metrics_t *records;
    int max_records;
    int count;
};

pqc_metrics_collector_t *pqc_metrics_collector_create(int max_iterations) {
    pqc_metrics_collector_t *col = calloc(1, sizeof(pqc_metrics_collector_t));
    if (!col) return NULL;
    col->records = calloc(max_iterations, sizeof(pqc_handshake_metrics_t));
    if (!col->records) { free(col); return NULL; }
    col->max_records = max_iterations;
    return col;
}

void pqc_metrics_collector_destroy(pqc_metrics_collector_t *col) {
    if (col) {
        free(col->records);
        free(col);
    }
}

pqc_status_t pqc_metrics_record(pqc_metrics_collector_t *col,
                                 const pqc_handshake_metrics_t *m) {
    if (!col || !m) return PQC_INVALID_PARAM;
    if (col->count >= col->max_records) return PQC_ERROR;
    col->records[col->count++] = *m;
    return PQC_OK;
}

pqc_status_t pqc_metrics_aggregate(const pqc_metrics_collector_t *col,
                                    pqc_aggregate_metrics_t *out) {
    if (!col || !out || col->count == 0) return PQC_INVALID_PARAM;

    memset(out, 0, sizeof(*out));
    out->num_iterations = col->count;

    /* Collect durations for stats */
    uint64_t *durations = malloc(col->count * sizeof(uint64_t));
    for (int i = 0; i < col->count; i++) {
        durations[i] = col->records[i].total_duration_ns;
        if (col->records[i].result == PQC_OK)
            out->num_success++;
        else
            out->num_failure++;
        out->avg_bytes_sent += col->records[i].total_bytes_sent;
        out->avg_bytes_received += col->records[i].total_bytes_received;
    }

    pqc_timer_stats(durations, col->count,
                    &out->mean_ns, &out->stdev_ns, &out->median_ns);
    out->min_ns = durations[0]; /* sorted by pqc_timer_stats */
    out->max_ns = durations[col->count - 1];

    out->avg_bytes_sent /= col->count;
    out->avg_bytes_received /= col->count;
    out->success_rate = (double)out->num_success / (double)col->count;

    /* Per-phase stats */
    for (int p = 0; p < 7; p++) {
        uint64_t *phase_durations = malloc(col->count * sizeof(uint64_t));
        int valid = 0;
        for (int i = 0; i < col->count; i++) {
            if (p < (int)col->records[i].num_phases) {
                phase_durations[valid++] = col->records[i].phases[p].duration_ns;
            }
        }
        if (valid > 0) {
            pqc_timer_stats(phase_durations, valid,
                           &out->phase_mean_ns[p], &out->phase_stdev_ns[p], NULL);
        }
        free(phase_durations);
    }

    free(durations);
    return PQC_OK;
}
