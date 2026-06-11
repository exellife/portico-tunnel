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

/* A relay TCP-forward listener: a listening socket the relay accepts public
 * connections on, each opened as a stream tagged with `forward_id` (§3.1 tcp mode). */
typedef struct {
    int      listen_fd;
    uint32_t forward_id;
} tunnel_listener_t;

/* Run the relay's stream engine over a connected `tunnel_fd` (toward the agent) plus a
 * set of TCP listeners. On a public connection: allocate a stream_id, OPEN it to the
 * agent (with forward_id + client_ip), and splice both ways. Runs until the tunnel
 * closes. Returns 0 on clean tunnel EOF, -1 on error. */
int tunnel_relay_serve(int tunnel_fd, const tunnel_listener_t *listeners, size_t n_listeners);

#endif /* PORTICO_TUNNEL_STREAM_H */
