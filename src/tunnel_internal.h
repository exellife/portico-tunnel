/* ============================================================================
 * portico-tunnel — internal core (libtunnel). Built bottom-up; this header
 * accumulates the primitives the relay and agent share. See docs/spec.md.
 * ============================================================================ */
#ifndef PORTICO_TUNNEL_INTERNAL_H
#define PORTICO_TUNNEL_INTERNAL_H

#include <stddef.h>

/* ---- byte pump -------------------------------------------------------------
 * The foundational data mover. Copies bytes BOTH ways between two connected
 * sockets until both directions have closed, on non-blocking fds:
 *   - partial writes and EAGAIN are handled;
 *   - backpressure: a direction stops reading its source while its destination
 *     has not drained (so a slow peer can't make us buffer unboundedly);
 *   - half-close is propagated: EOF on one side -> shutdown(WR) on the other,
 *     so the peer learns the stream ended in that direction.
 * It owns a poll loop and runs until completion — used directly for the relay's
 * public<->tunnel and the agent's tunnel<->origin splices (and the per-direction
 * copy kernel is reused by the muxed stream engine later).
 * Returns the total number of bytes moved, or -1 on a fatal socket error. */
long tunnel_pump(int fd_a, int fd_b);

#endif /* PORTICO_TUNNEL_INTERNAL_H */
