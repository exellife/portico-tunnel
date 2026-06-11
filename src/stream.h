/* ============================================================================
 * portico-tunnel agent stream engine.
 *
 * Multiplexes many logical streams over the one tunnel connection. On OPEN it dials
 * the forward's local TCP target and bridges the stream to it; DATA flows both ways
 * with coarse backpressure (docs/spec.md §2: stop reading the tunnel while any
 * stream's local side hasn't drained, and stop reading locals while the tunnel write
 * buffer is full); END half-closes a direction, RESET aborts. Single poll loop.
 * ============================================================================ */
#ifndef PORTICO_TUNNEL_STREAM_H
#define PORTICO_TUNNEL_STREAM_H

#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#include <openssl/ssl.h>
#include "control.h"   /* tunnel_hello_t (the forwards the run loop registers) */

/* Where forward_id N points: the local TCP service the agent dials for that forward. */
typedef struct {
    char host[256];
    char port[16];
} tunnel_target_t;

/* Run the agent's stream engine over a connected `tunnel_fd` (carrying the frame
 * protocol — in tests one end of a socketpair; in production the agent wraps this over
 * its TLS connection). On OPEN, dial forwards[forward_id]. Runs until the tunnel
 * closes. Returns 0 on clean tunnel EOF, -1 on error. */
int tunnel_agent_serve(int tunnel_fd, const tunnel_target_t *forwards, size_t n_forwards);

/* Same, but the tunnel is an established TLS connection (the production transport). */
int tunnel_agent_serve_ssl(SSL *tunnel, const tunnel_target_t *forwards, size_t n_forwards);

/* A relay listener (§3.1). When `sni` is 0 it's a tcp port-forward: every connection
 * opens a stream tagged with `forward_id`. When `sni` is 1 it's the shared :443 path:
 * the relay peeks the ClientHello's SNI and routes via the route table below. */
typedef struct {
    int      listen_fd;
    int      sni;            /* 1 = SNI-routed (peek), 0 = tcp port-forward */
    uint32_t forward_id;     /* tcp mode only */
} tunnel_listener_t;

/* An SNI route: an exact hostname -> the forward the agent should dial. */
typedef struct {
    const char *host;
    uint32_t    forward_id;
} tunnel_sni_route_t;

/* Run the relay's stream engine over a connected `tunnel_fd` (toward the agent) plus a
 * set of listeners. tcp listeners open a stream per connection; sni listeners peek the
 * ClientHello, match `routes` by hostname, then open a stream and feed the buffered
 * handshake bytes as its first DATA. Runs until the tunnel closes. Returns 0 / -1. */
int tunnel_relay_serve(int tunnel_fd,
                       const tunnel_listener_t *listeners, size_t n_listeners,
                       const tunnel_sni_route_t *routes, size_t n_routes);

/* Same, but the tunnel toward the agent is an established TLS connection. */
int tunnel_relay_serve_ssl(SSL *tunnel,
                           const tunnel_listener_t *listeners, size_t n_listeners,
                           const tunnel_sni_route_t *routes, size_t n_routes);

/* ---- the self-healing agent run loop ---------------------------------------
 * connect (TLS dial + verify relay + mTLS) -> register (HELLO) -> serve (with
 * heartbeats) -> on any drop, exponential backoff + jitter, redial, re-register.
 * A dynamic-IP change is just a reconnect. Runs until *stop is set. */
typedef struct {
    const char *relay_host, *relay_port;
    const char *ca_file;                 /* verify the relay; NULL = system roots */
    const char *client_cert, *client_key;/* mTLS identity */
    const tunnel_hello_t  *hello;        /* what to register */
    const tunnel_target_t *forwards;     /* forward_id -> local target */
    size_t      n_forwards;
    int         heartbeat_secs;          /* 0 -> 20 */
    int         backoff_min_ms;          /* 0 -> 500 */
    int         backoff_max_ms;          /* 0 -> 30000 */
    atomic_int *stop;                    /* optional: set nonzero to stop the loop */
} tunnel_agent_run_config_t;

int tunnel_agent_run(const tunnel_agent_run_config_t *cfg);

#endif /* PORTICO_TUNNEL_STREAM_H */
