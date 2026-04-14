#include "pqc/pqc_tls_handshake.h"
#include "pqc/pqc_timer.h"
#include <openssl/ssl.h>
#include <string.h>

static int g_ex_data_index = -1;

int pqc_hs_get_ex_data_index(void) {
    if (g_ex_data_index < 0) {
        g_ex_data_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    }
    return g_ex_data_index;
}

pqc_hs_tracker_t *pqc_hs_tracker_create(pqc_handshake_metrics_t *output) {
    pqc_hs_tracker_t *t = calloc(1, sizeof(pqc_hs_tracker_t));
    if (!t) return NULL;
    t->output = output;
    t->handshake_start_ns = 0;
    return t;
}

void pqc_hs_tracker_destroy(pqc_hs_tracker_t *tracker) {
    free(tracker);
}

/*
 * Message callback for SSL_set_msg_callback.
 * Gets called for every TLS record/message sent or received.
 *
 * Parameters:
 *   write_p: 1 = sending, 0 = receiving
 *   version: TLS version
 *   content_type: SSL3_RT_* for record types
 *   buf/len: the message bytes
 */
static void pqc_hs_msg_callback(int write_p, int version, int content_type,
                                 const void *buf, size_t len,
                                 SSL *ssl, void *arg) {
    (void)version;
    (void)buf;

    pqc_hs_tracker_t *tracker = (pqc_hs_tracker_t *)arg;
    if (!tracker) return;

    /* Only process handshake messages */
    if (content_type != SSL3_RT_HANDSHAKE) return;

    /* Parse the handshake message type (first byte after the record header) */
    const unsigned char *msg = (const unsigned char *)buf;
    if (len < 4) return;
    int hs_type = msg[0];

    uint64_t now = pqc_timer_now();
    if (tracker->handshake_start_ns == 0) {
        tracker->handshake_start_ns = now;
    }

    size_t *n = &tracker->num_phases;
    pqc_phase_metrics_t *phases = tracker->phases;

    /*
     * Map TLS handshake message types to our phases.
     * We track first occurrence of each message type as a phase boundary.
     */
    pqc_hs_phase_t phase = PQC_HS_PHASE_COUNT;
    switch (hs_type) {
    case SSL3_MT_CLIENT_HELLO:
        phase = PQC_HS_PHASE_CLIENT_HELLO;
        break;
    case SSL3_MT_SERVER_HELLO:
        phase = PQC_HS_PHASE_SERVER_HELLO;
        break;
    case SSL3_MT_CERTIFICATE:
    case SSL3_MT_CERTIFICATE_REQUEST:
        phase = PQC_HS_PHASE_CERT_EXCHANGE;
        break;
    case SSL3_MT_CERTIFICATE_VERIFY:
        phase = PQC_HS_PHASE_CERT_VERIFY;
        break;
    case SSL3_MT_FINISHED:
        phase = PQC_HS_PHASE_FINISHED;
        break;
    case SSL3_MT_NEWSESSION_TICKET:
        phase = PQC_HS_PHASE_SESSION_TICKETS;
        break;
    default:
        return;
    }

    /* Record this phase if it's new */
    int found = 0;
    for (size_t i = 0; i < *n; i++) {
        if (phases[i].phase == phase) {
            found = 1;
            /* Update bytes */
            if (write_p) phases[i].bytes_sent += len;
            else phases[i].bytes_received += len;
            break;
        }
    }

    if (!found && *n < PQC_HS_PHASE_COUNT) {
        phases[*n].phase = phase;
        phases[*n].timestamp_ns = now;
        phases[*n].duration_ns = 0;
        if (write_p) phases[*n].bytes_sent = len;
        else phases[*n].bytes_received = len;
        (*n)++;
    }
}

pqc_status_t pqc_hs_attach(SSL *ssl, pqc_hs_tracker_t *tracker) {
    if (!ssl || !tracker) return PQC_INVALID_PARAM;

    int idx = pqc_hs_get_ex_data_index();
    if (idx < 0) return PQC_ERROR;

    SSL_set_ex_data(ssl, idx, tracker);
    SSL_set_msg_callback(ssl, pqc_hs_msg_callback);
    SSL_set_msg_callback_arg(ssl, tracker);

    return PQC_OK;
}

void pqc_hs_info_callback(const SSL *ssl, int type, int val) {
    (void)ssl; (void)type; (void)val;
}

pqc_status_t pqc_hs_finalize(pqc_hs_tracker_t *tracker, pqc_status_t result) {
    if (!tracker || !tracker->output) return PQC_INVALID_PARAM;

    pqc_handshake_metrics_t *out = tracker->output;
    out->result = result;

    /* Compute total duration */
    uint64_t end_ns = pqc_timer_now();
    out->total_duration_ns = end_ns - tracker->handshake_start_ns;

    /* Compute per-phase durations */
    out->num_phases = tracker->num_phases;
    for (size_t i = 0; i < tracker->num_phases; i++) {
        out->phases[i].phase = tracker->phases[i].phase;
        out->phases[i].timestamp_ns = tracker->phases[i].timestamp_ns;
        out->phases[i].bytes_sent = tracker->phases[i].bytes_sent;
        out->phases[i].bytes_received = tracker->phases[i].bytes_received;

        if (i + 1 < tracker->num_phases) {
            out->phases[i].duration_ns =
                tracker->phases[i + 1].timestamp_ns - tracker->phases[i].timestamp_ns;
        } else {
            out->phases[i].duration_ns = end_ns - tracker->phases[i].timestamp_ns;
        }

        out->total_bytes_sent += tracker->phases[i].bytes_sent;
        out->total_bytes_received += tracker->phases[i].bytes_received;
    }

    /* TLS version */
    out->tls_version = "TLSv1.3";

    return PQC_OK;
}
