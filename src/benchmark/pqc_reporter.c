#include "pqc/pqc_reporter.h"
#include <stdio.h>
#include <string.h>

pqc_status_t pqc_reporter_write(const pqc_aggregate_metrics_t *metrics,
                                 const char *format, const char *path) {
    if (!metrics) return PQC_INVALID_PARAM;

    FILE *fp = stdout;
    if (path && path[0] != '\0') {
        fp = fopen(path, "w");
        if (!fp) return PQC_ERROR;
    }

    if (strcmp(format, "json") == 0) {
        fprintf(fp, "{\n");
        fprintf(fp, "  \"kem_algorithm\": \"%s\",\n", metrics->kem_alg ? metrics->kem_alg : "N/A");
        fprintf(fp, "  \"sig_algorithm\": \"%s\",\n", metrics->sig_alg ? metrics->sig_alg : "N/A");
        fprintf(fp, "  \"iterations\": %d,\n", metrics->num_iterations);
        fprintf(fp, "  \"success_rate\": %.2f,\n", metrics->success_rate);
        fprintf(fp, "  \"handshake_time\": {\n");
        fprintf(fp, "    \"mean_ns\": %.0f,\n", metrics->mean_ns);
        fprintf(fp, "    \"stdev_ns\": %.0f,\n", metrics->stdev_ns);
        fprintf(fp, "    \"median_ns\": %.0f,\n", metrics->median_ns);
        fprintf(fp, "    \"min_ns\": %llu,\n", (unsigned long long)metrics->min_ns);
        fprintf(fp, "    \"max_ns\": %llu\n", (unsigned long long)metrics->max_ns);
        fprintf(fp, "  },\n");
        fprintf(fp, "  \"bytes\": {\n");
        fprintf(fp, "    \"avg_sent\": %.0f,\n", metrics->avg_bytes_sent);
        fprintf(fp, "    \"avg_received\": %.0f\n", metrics->avg_bytes_received);
        fprintf(fp, "  },\n");
        fprintf(fp, "  \"packet_loss_rate\": %.4f,\n", metrics->packet_loss_rate);
        fprintf(fp, "  \"throughput_mbps\": %.2f\n", metrics->throughput_mbps);
        fprintf(fp, "}\n");
    } else if (strcmp(format, "csv") == 0) {
        fprintf(fp, "kem_alg,sig_alg,iterations,success_rate,mean_ns,stdev_ns,median_ns,min_ns,max_ns,avg_bytes_sent,avg_bytes_received,packet_loss_rate,throughput_mbps\n");
        fprintf(fp, "%s,%s,%d,%.4f,%.0f,%.0f,%.0f,%llu,%llu,%.0f,%.0f,%.4f,%.2f\n",
                metrics->kem_alg ? metrics->kem_alg : "N/A",
                metrics->sig_alg ? metrics->sig_alg : "N/A",
                metrics->num_iterations, metrics->success_rate,
                metrics->mean_ns, metrics->stdev_ns, metrics->median_ns,
                (unsigned long long)metrics->min_ns,
                (unsigned long long)metrics->max_ns,
                metrics->avg_bytes_sent, metrics->avg_bytes_received,
                metrics->packet_loss_rate, metrics->throughput_mbps);
    } else {
        /* Console / markdown */
        fprintf(fp, "=== Benchmark Results ===\n");
        fprintf(fp, "KEM: %s  SIG: %s\n",
                metrics->kem_alg ? metrics->kem_alg : "N/A",
                metrics->sig_alg ? metrics->sig_alg : "N/A");
        fprintf(fp, "Iterations: %d  Success: %.1f%%\n",
                metrics->num_iterations, metrics->success_rate * 100);
        fprintf(fp, "Handshake time (ns): mean=%.0f stdev=%.0f median=%.0f min=%llu max=%llu\n",
                metrics->mean_ns, metrics->stdev_ns, metrics->median_ns,
                (unsigned long long)metrics->min_ns,
                (unsigned long long)metrics->max_ns);
        fprintf(fp, "Avg bytes: sent=%.0f received=%.0f\n",
                metrics->avg_bytes_sent, metrics->avg_bytes_received);
        fprintf(fp, "Packet loss: %.2f%%  Throughput: %.2f Mbps\n",
                metrics->packet_loss_rate * 100, metrics->throughput_mbps);
    }

    if (fp != stdout) fclose(fp);
    return PQC_OK;
}
