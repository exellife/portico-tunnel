/* ============================================================================
 * portico-tunnel control channel (docs/spec.md §4/§5): the registration handshake.
 * Transport-agnostic — runs over any tunnel_io_t (raw fd in tests, TLS in prod).
 * ============================================================================ */
#ifndef PORTICO_TUNNEL_CONTROL_H
#define PORTICO_TUNNEL_CONTROL_H

#include "io.h"
#include <stddef.h>

#define TUNNEL_MAX_HOSTS 16

/* The HELLO contents: who the agent is and which hostnames it wants to serve.
 * Wire payload is newline-delimited UTF-8: agent_id, then one hostname per line. */
typedef struct {
    char   agent_id[64];
    char   hostnames[TUNNEL_MAX_HOSTS][256];
    size_t n_hosts;
} tunnel_hello_t;

int tunnel_hello_encode(const tunnel_hello_t *h, uint8_t *out, size_t cap);  /* len / -1 */
int tunnel_hello_parse(const uint8_t *p, uint32_t len, tunnel_hello_t *h);   /* 0 / -1 */

/* Agent side: send HELLO and wait for the verdict, answering PINGs in the meantime.
 * Returns 0 once HELLO_OK is received, or -1 on HELLO_ERR / transport error (the
 * server's reason string, if any, is copied into `err`). */
int tunnel_agent_register(tunnel_io_t *io, tunnel_decoder_t *dec,
                          const tunnel_hello_t *hello, char *err, size_t errcap);

/* Relay side: read the agent's HELLO, authorize EVERY hostname via allow() (returns
 * nonzero to permit), then reply HELLO_OK or HELLO_ERR. Returns 0 on acceptance (with
 * `hello_out` filled), -1 on refusal / error. Answers PINGs while waiting.
 *
 * `peer_id` is the VERIFIED identity (the mTLS client-cert subject CN, from
 * tunnel_tls_t.peer_id). When non-NULL it is the identity passed to allow() — never the
 * agent-supplied HELLO agent_id, which is spoofable — and a HELLO whose agent_id is set
 * but does not match `peer_id` is refused. Pass NULL only on a non-mTLS transport (e.g.
 * unit tests over a socketpair), where allow() falls back to the HELLO agent_id. (H4/M13) */
int tunnel_relay_accept(tunnel_io_t *io, tunnel_decoder_t *dec, tunnel_hello_t *hello_out,
                        const char *peer_id,
                        int (*allow)(const char *identity, const char *hostname, void *ud),
                        void *ud, char *err, size_t errcap);

#endif /* PORTICO_TUNNEL_CONTROL_H */
