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

#endif /* PORTICO_TUNNEL_STREAM_H */
