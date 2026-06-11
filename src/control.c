/* portico-tunnel control channel — HELLO codec + registration handshake (see control.h). */
#include "control.h"

#include <stdio.h>
#include <string.h>

#define HELLO_BUF (64 + 256 * TUNNEL_MAX_HOSTS + 64)

int tunnel_hello_encode(const tunnel_hello_t *h, uint8_t *out, size_t cap) {
    int o = snprintf((char *)out, cap, "%s\n", h->agent_id);
    if (o < 0 || (size_t)o >= cap) return -1;
    size_t off = (size_t)o;
    for (size_t i = 0; i < h->n_hosts; i++) {
        int w = snprintf((char *)out + off, cap - off, "%s\n", h->hostnames[i]);
        if (w < 0 || (size_t)w >= cap - off) return -1;
        off += (size_t)w;
    }
    return (int)off;
}

int tunnel_hello_parse(const uint8_t *p, uint32_t len, tunnel_hello_t *h) {
    memset(h, 0, sizeof *h);
    char buf[HELLO_BUF];
    if (len >= sizeof buf) return -1;            /* oversized / hostile */
    memcpy(buf, p, len);
    buf[len] = '\0';

    char *save = NULL;
    char *line = strtok_r(buf, "\n", &save);
    if (!line) return -1;
    if ((size_t)snprintf(h->agent_id, sizeof h->agent_id, "%s", line) >= sizeof h->agent_id) return -1;

    while ((line = strtok_r(NULL, "\n", &save)) != NULL) {
        if (line[0] == '\0') continue;
        if (h->n_hosts >= TUNNEL_MAX_HOSTS) return -1;
        if ((size_t)snprintf(h->hostnames[h->n_hosts], sizeof h->hostnames[0], "%s", line)
            >= sizeof h->hostnames[0]) return -1;
        h->n_hosts++;
    }
    return 0;
}

static void copy_reason(char *err, size_t cap, const uint8_t *p, uint32_t len) {
    if (!err || !cap) return;
    uint32_t n = (len < cap - 1) ? len : (uint32_t)(cap - 1);
    if (n && p) memcpy(err, p, n);
    err[n] = '\0';
}

int tunnel_agent_register(tunnel_io_t *io, tunnel_decoder_t *dec,
                          const tunnel_hello_t *hello, char *err, size_t errcap) {
    if (err && errcap) err[0] = '\0';

    uint8_t payload[HELLO_BUF];
    int pl = tunnel_hello_encode(hello, payload, sizeof payload);
    if (pl < 0) return -1;
    if (tunnel_io_write_frame(io, TF_HELLO, 0, payload, (uint32_t)pl) != 0) return -1;

    for (;;) {
        tunnel_frame_t f;
        if (tunnel_io_read_frame(io, dec, &f) != 1) return -1;   /* EOF/error before a verdict */
        switch (f.type) {
            case TF_HELLO_OK:  return 0;
            case TF_HELLO_ERR: copy_reason(err, errcap, f.payload, f.len); return -1;
            case TF_PING:      if (tunnel_io_write_frame(io, TF_PONG, 0, NULL, 0) != 0) return -1; break;
            default:           return -1;                        /* unexpected pre-registration frame */
        }
    }
}

static int refuse(tunnel_io_t *io, char *err, size_t errcap, const char *msg) {
    tunnel_io_write_frame(io, TF_HELLO_ERR, 0, msg, (uint32_t)strlen(msg));
    if (err && errcap) snprintf(err, errcap, "%s", msg);
    return -1;
}

int tunnel_relay_accept(tunnel_io_t *io, tunnel_decoder_t *dec, tunnel_hello_t *hello_out,
                        int (*allow)(const char *, const char *, void *),
                        void *ud, char *err, size_t errcap) {
    if (err && errcap) err[0] = '\0';

    for (;;) {
        tunnel_frame_t f;
        if (tunnel_io_read_frame(io, dec, &f) != 1) return -1;
        if (f.type == TF_PING) {
            if (tunnel_io_write_frame(io, TF_PONG, 0, NULL, 0) != 0) return -1;
            continue;
        }
        if (f.type != TF_HELLO) return refuse(io, err, errcap, "expected HELLO");

        tunnel_hello_t h;
        if (tunnel_hello_parse(f.payload, f.len, &h) != 0) return refuse(io, err, errcap, "malformed HELLO");
        /* Zero hostnames is fine — a pure tcp-forward agent declares none (the relay
         * routes by its own config; mTLS is the trust gate). hostnames, when present,
         * are still authorized below. */
        for (size_t i = 0; i < h.n_hosts; i++) {
            if (allow && !allow(h.agent_id, h.hostnames[i], ud)) {
                char m[300];
                snprintf(m, sizeof m, "hostname not allowed: %s", h.hostnames[i]);
                return refuse(io, err, errcap, m);
            }
        }
        if (tunnel_io_write_frame(io, TF_HELLO_OK, 0, NULL, 0) != 0) return -1;
        if (hello_out) *hello_out = h;
        return 0;
    }
}
