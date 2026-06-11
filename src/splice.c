/* The byte pump — the foundational data mover for both the relay (public<->tunnel)
 * and the agent (tunnel<->origin). Copies bytes both ways between two non-blocking
 * sockets with proper backpressure and half-close propagation. See tunnel_internal.h. */
#include "tunnel_internal.h"

#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>

#define PUMP_BUF 65536

/* One direction src -> dst, with a single in-flight buffer (read only when empty —
 * that is the backpressure: while dst hasn't drained, we don't pull more from src). */
struct half {
    int src, dst;
    unsigned char buf[PUMP_BUF];
    size_t len, off;   /* buffered bytes [off, len) still to write to dst */
    int eof;           /* src returned EOF */
    int shut;          /* dst shutdown(WR); this direction is complete */
};

static void set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl != -1) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

/* Push buffered bytes toward dst. 0 = ok (possibly partial / EAGAIN), -1 = fatal. */
static int half_flush(struct half *h, long *moved) {
    while (h->off < h->len) {
        ssize_t n = send(h->dst, h->buf + h->off, h->len - h->off, MSG_NOSIGNAL);
        if (n > 0) { h->off += (size_t)n; *moved += n; continue; }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        if (n < 0 && errno == EINTR) continue;
        return -1;                       /* EPIPE / ECONNRESET / ... */
    }
    h->off = h->len = 0;                 /* drained -> may read again */
    return 0;
}

/* Read into the (empty) buffer. 0 = ok, -1 = fatal. Sets eof on clean close. */
static int half_fill(struct half *h) {
    ssize_t n = read(h->src, h->buf, PUMP_BUF);
    if (n > 0) { h->len = (size_t)n; h->off = 0; return 0; }
    if (n == 0) { h->eof = 1; return 0; }
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 0;
    return -1;
}

long tunnel_pump(int fd_a, int fd_b) {
    set_nonblock(fd_a);
    set_nonblock(fd_b);
    struct half ab = { .src = fd_a, .dst = fd_b, .len = 0, .off = 0, .eof = 0, .shut = 0 };
    struct half ba = { .src = fd_b, .dst = fd_a, .len = 0, .off = 0, .eof = 0, .shut = 0 };
    long moved = 0;

    for (;;) {
        /* A fully-drained EOF direction half-closes its destination, so the peer
         * learns this stream ended in that direction. */
        if (ab.eof && ab.off == ab.len && !ab.shut) { shutdown(fd_b, SHUT_WR); ab.shut = 1; }
        if (ba.eof && ba.off == ba.len && !ba.shut) { shutdown(fd_a, SHUT_WR); ba.shut = 1; }
        if (ab.shut && ba.shut) break;

        struct pollfd p[2] = { { fd_a, 0, 0 }, { fd_b, 0, 0 } };
        if (!ab.eof && ab.len == 0) p[0].events |= POLLIN;    /* read a  -> ab buffer */
        if (ba.off < ba.len)        p[0].events |= POLLOUT;   /* write ba buffer -> a */
        if (!ba.eof && ba.len == 0) p[1].events |= POLLIN;    /* read b  -> ba buffer */
        if (ab.off < ab.len)        p[1].events |= POLLOUT;   /* write ab buffer -> b */
        if (p[0].events == 0 && p[1].events == 0) break;      /* nothing left to do */

        int pr = poll(p, 2, -1);
        if (pr < 0) { if (errno == EINTR) continue; return -1; }

        if (p[0].revents) {   /* fd_a ready (or HUP/ERR) */
            if (ba.off < ba.len && half_flush(&ba, &moved) < 0) { ba.shut = 1; ab.eof = 1; }
            if (!ab.eof && ab.len == 0 && half_fill(&ab) < 0)    { ab.eof = 1; }
        }
        if (p[1].revents) {   /* fd_b ready (or HUP/ERR) */
            if (ab.off < ab.len && half_flush(&ab, &moved) < 0) { ab.shut = 1; ba.eof = 1; }
            if (!ba.eof && ba.len == 0 && half_fill(&ba) < 0)    { ba.eof = 1; }
        }
    }
    return moved;
}
