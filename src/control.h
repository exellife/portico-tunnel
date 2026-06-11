/* ============================================================================
 * portico-tunnel control channel (docs/spec.md §4/§5): the registration handshake.
 * Transport-agnostic — runs over any tunnel_io_t (raw fd in tests, TLS in prod).
 * ============================================================================ */
#ifndef PORTICO_TUNNEL_CONTROL_H
#define PORTICO_TUNNEL_CONTROL_H

#include "io.h"
#include <stddef.h>

#define TUNNEL_MAX_HOSTS    16
#define TUNNEL_MAX_FORWARDS 16

/* Forward kind (M7): how the relay exposes a forward publicly. The agent declares the kind
 * sequence it expects; the relay declares its authoritative one; a mismatch is a positional
 * misalignment (operator footgun) caught at registration, before any traffic is misrouted. */
enum { TUNNEL_FWD_TCP = 0, TUNNEL_FWD_SNI = 1 };

/* The HELLO contents: who the agent is, which hostnames it wants, and (M7) the kind of each
 * forward it has, by forward_id. Wire payload is newline-delimited UTF-8: agent_id, then one
 * hostname per line, then an optional "!fwd=<kinds>" line (kinds = one 't'/'s' per forward).
 * n_forwards == 0 means the agent does not participate in forward negotiation (legacy). */
typedef struct {
    char    agent_id[64];
    char    hostnames[TUNNEL_MAX_HOSTS][256];
    size_t  n_hosts;
    uint8_t forward_kinds[TUNNEL_MAX_FORWARDS];   /* TUNNEL_FWD_TCP / _SNI, indexed by forward_id */
    size_t  n_forwards;
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
 * unit tests over a socketpair), where allow() falls back to the HELLO agent_id. (H4/M13)
 *
 * M7: `fwd_kinds`/`n_fwd` are the relay's AUTHORITATIVE forward kinds (by forward_id). When
 * `fwd_kinds` is non-NULL and the agent declared its own forwards, the two sequences must
 * match (count + kind) or the agent is refused — catching positional misalignment before any
 * traffic is misrouted. The relay's kinds are echoed in HELLO_OK so the agent re-checks them.
 * Pass NULL to skip negotiation (non-mTLS unit tests / legacy). */
int tunnel_relay_accept(tunnel_io_t *io, tunnel_decoder_t *dec, tunnel_hello_t *hello_out,
                        const char *peer_id,
                        const uint8_t *fwd_kinds, size_t n_fwd,
                        int (*allow)(const char *identity, const char *hostname, void *ud),
                        void *ud, char *err, size_t errcap);

#endif /* PORTICO_TUNNEL_CONTROL_H */
