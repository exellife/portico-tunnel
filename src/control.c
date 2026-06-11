/* portico-tunnel control channel — HELLO codec + registration handshake (see control.h). */
#include "control.h"

#include <stdio.h>
#include <string.h>

#define HELLO_BUF (64 + 256 * TUNNEL_MAX_HOSTS + 64)
#define FWD_PREFIX "!fwd="                /* hostnames are DNS labels, never start with '!' */

static char kind_char(uint8_t k) { return k == TUNNEL_FWD_SNI ? 's' : 't'; }

int tunnel_hello_encode(const tunnel_hello_t *h, uint8_t *out, size_t cap) {
    int o = snprintf((char *)out, cap, "%s\n", h->agent_id);
    if (o < 0 || (size_t)o >= cap) return -1;
    size_t off = (size_t)o;
    for (size_t i = 0; i < h->n_hosts; i++) {
        int w = snprintf((char *)out + off, cap - off, "%s\n", h->hostnames[i]);
        if (w < 0 || (size_t)w >= cap - off) return -1;
        off += (size_t)w;
    }
    if (h->n_forwards > 0) {                /* M7: declare the forward-kind sequence */
        if (h->n_forwards > TUNNEL_MAX_FORWARDS) return -1;
        int w = snprintf((char *)out + off, cap - off, "%s", FWD_PREFIX);
        if (w < 0 || (size_t)w >= cap - off) return -1;
        off += (size_t)w;
        for (size_t i = 0; i < h->n_forwards; i++) {
            if (off + 1 >= cap) return -1;
            out[off++] = (uint8_t)kind_char(h->forward_kinds[i]);
        }
        if (off + 1 >= cap) return -1;
        out[off++] = '\n';
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
        if (strncmp(line, FWD_PREFIX, sizeof FWD_PREFIX - 1) == 0) {   /* M7: forward-kind line */
            const char *k = line + sizeof FWD_PREFIX - 1;
            for (; *k; k++) {
                if (h->n_forwards >= TUNNEL_MAX_FORWARDS) return -1;
                if (*k != 't' && *k != 's') return -1;
                h->forward_kinds[h->n_forwards++] = (*k == 's') ? TUNNEL_FWD_SNI : TUNNEL_FWD_TCP;
            }
            continue;
        }
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
            case TF_HELLO_OK:
                /* M7: HELLO_OK carries the relay's authoritative forward kinds. If both sides
                 * declared forwards, they must agree (else positional misalignment). */
                if (f.len > 0 && hello->n_forwards > 0) {
                    if (f.len != hello->n_forwards) {
                        if (err && errcap) snprintf(err, errcap, "forward count mismatch: relay %u, agent %zu",
                                                    f.len, hello->n_forwards);
                        return -1;
                    }
                    for (uint32_t i = 0; i < f.len; i++) {
                        uint8_t rk = (f.payload[i] == 's') ? TUNNEL_FWD_SNI : TUNNEL_FWD_TCP;
                        if (rk != hello->forward_kinds[i]) {
                            if (err && errcap) snprintf(err, errcap, "forward %u kind mismatch", i);
                            return -1;
                        }
                    }
                }
                return 0;
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
                        const char *peer_id,
                        const uint8_t *fwd_kinds, size_t n_fwd,
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
        /* H4/M13: authorize on the VERIFIED cert identity (the mTLS subject CN), never the
         * HELLO agent_id, which the agent chooses freely and can spoof. The agent_id stays a
         * cosmetic label. peer_id NULL = non-mTLS transport (unit tests over a socketpair) ->
         * fall back to the HELLO agent_id. */
        const char *identity = peer_id ? peer_id : h.agent_id;
        /* Zero hostnames is fine — a pure tcp-forward agent declares none (the relay
         * routes by its own config; mTLS is the trust gate). hostnames, when present,
         * are still authorized below. */
        for (size_t i = 0; i < h.n_hosts; i++) {
            if (allow && !allow(identity, h.hostnames[i], ud)) {
                char m[300];
                snprintf(m, sizeof m, "hostname not allowed: %s", h.hostnames[i]);
                return refuse(io, err, errcap, m);
            }
        }
        /* M7: if both sides declared forwards, the agent's kind sequence must match the relay's
         * authoritative one (count + kind) — a positional misalignment is a config error that
         * could misroute a public TLS hostname to the wrong local service. */
        if (fwd_kinds && h.n_forwards > 0) {
            if (h.n_forwards != n_fwd) {
                char m[96]; snprintf(m, sizeof m, "forward count mismatch: relay %zu, agent %zu", n_fwd, h.n_forwards);
                return refuse(io, err, errcap, m);
            }
            for (size_t i = 0; i < n_fwd; i++)
                if (h.forward_kinds[i] != fwd_kinds[i]) {
                    char m[64]; snprintf(m, sizeof m, "forward %zu kind mismatch", i);
                    return refuse(io, err, errcap, m);
                }
        }
        /* HELLO_OK echoes the relay's authoritative kinds (empty if the relay doesn't declare). */
        uint8_t okpl[TUNNEL_MAX_FORWARDS]; uint32_t okn = 0;
        if (fwd_kinds) { for (size_t i = 0; i < n_fwd && i < TUNNEL_MAX_FORWARDS; i++) okpl[okn++] = (uint8_t)kind_char(fwd_kinds[i]); }
        if (tunnel_io_write_frame(io, TF_HELLO_OK, 0, okn ? okpl : NULL, okn) != 0) return -1;
        if (hello_out) *hello_out = h;
        return 0;
    }
}
