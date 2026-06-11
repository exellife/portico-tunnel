/* portico-tunnel agent stream engine (see stream.h). One poll loop multiplexes the
 * tunnel fd + all local stream fds. Coarse flow control keeps memory bounded. */
#include "stream.h"
#include "frame.h"

#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <netdb.h>
#include <sys/socket.h>

#define MAX_STREAMS 64
#define TW_CAP      (4 * (TUNNEL_FRAME_HDR + TUNNEL_MAX_FRAME))   /* shared tunnel-out buffer */

struct stream {
    int      active;
    uint32_t sid;
    int      fd;                            /* local TCP socket (non-blocking) */
    unsigned char tobuf[TUNNEL_MAX_FRAME];  /* bytes pending toward the local fd */
    size_t   tolen, tooff;
    int      remote_eof;                    /* got END from the tunnel */
    int      local_eof;                     /* local hit EOF, we sent END */
    int      wr_shut;                       /* shutdown(fd, WR) already done */
};

static void set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl != -1) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static uint32_t be32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static int dial_local(const tunnel_target_t *t) {
    struct addrinfo hints = {0}, *res = NULL, *ai;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(t->host, t->port, &hints, &res) != 0) return -1;
    int fd = -1;
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;   /* local target -> instant */
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    if (fd >= 0) set_nonblock(fd);
    return fd;
}

static struct stream *find_stream(struct stream *st, uint32_t sid) {
    for (int i = 0; i < MAX_STREAMS; i++) if (st[i].active && st[i].sid == sid) return &st[i];
    return NULL;
}
static struct stream *alloc_stream(struct stream *st, uint32_t sid) {
    for (int i = 0; i < MAX_STREAMS; i++)
        if (!st[i].active) { memset(&st[i], 0, sizeof st[i]); st[i].active = 1; st[i].sid = sid; st[i].fd = -1; return &st[i]; }
    return NULL;
}

/* Append a frame to the shared tunnel-out buffer. Returns 0, or -1 if it won't fit. */
static int tw_frame(unsigned char *tw, size_t *twlen, uint8_t type, uint32_t sid,
                    const void *payload, uint32_t len) {
    int n = tunnel_frame_encode(type, sid, payload, len, tw + *twlen, TW_CAP - *twlen);
    if (n < 0) return -1;
    *twlen += (size_t)n;
    return 0;
}

static void close_stream(struct stream *s) {
    if (s->fd >= 0) close(s->fd);
    s->active = 0;
}

int tunnel_agent_serve(int tfd, const tunnel_target_t *fwd, size_t nfwd) {
    set_nonblock(tfd);
    tunnel_decoder_t dec; tunnel_decoder_reset(&dec);
    struct stream st[MAX_STREAMS]; memset(st, 0, sizeof st);
    unsigned char tw[TW_CAP]; size_t twlen = 0, twoff = 0;
    int rc = 0;

    for (;;) {
        /* Backpressure: don't accept more tunnel frames while any stream still owes
         * its local side bytes (its tobuf isn't drained). */
        int backpressured = 0;
        for (int i = 0; i < MAX_STREAMS; i++)
            if (st[i].active && st[i].tooff < st[i].tolen) { backpressured = 1; break; }

        struct pollfd p[1 + MAX_STREAMS];
        struct stream *map[1 + MAX_STREAMS];
        p[0].fd = tfd; p[0].events = 0; p[0].revents = 0; map[0] = NULL;
        if (!backpressured)   p[0].events |= POLLIN;       /* room to take frames */
        if (twoff < twlen)    p[0].events |= POLLOUT;      /* pending tunnel output */
        int np = 1;
        for (int i = 0; i < MAX_STREAMS; i++) {
            if (!st[i].active || st[i].fd < 0) continue;
            short ev = 0;
            if (st[i].tooff < st[i].tolen) ev |= POLLOUT;  /* pending local output */
            /* read local only if there's room for a whole DATA frame in the tunnel-out buffer */
            if (!st[i].local_eof && twlen + TUNNEL_FRAME_HDR + TUNNEL_MAX_FRAME <= TW_CAP) ev |= POLLIN;
            if (ev == 0) continue;
            p[np].fd = st[i].fd; p[np].events = ev; p[np].revents = 0; map[np] = &st[i]; np++;
        }
        if (p[0].events == 0 && np == 1) break;            /* nothing to wait on */

        if (poll(p, (nfds_t)np, -1) < 0) { if (errno == EINTR) continue; rc = -1; break; }

        /* --- tunnel output --- */
        if (p[0].revents & POLLOUT) {
            ssize_t w = write(tfd, tw + twoff, twlen - twoff);
            if (w > 0) { twoff += (size_t)w; if (twoff == twlen) twoff = twlen = 0; }
            else if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) { rc = -1; break; }
        }
        /* --- tunnel input --- */
        if (p[0].revents & (POLLIN | POLLHUP)) {
            unsigned char tmp[TUNNEL_RECV_CHUNK];
            ssize_t n = read(tfd, tmp, sizeof tmp);
            if (n == 0) { rc = 0; break; }                 /* tunnel closed */
            if (n < 0) { if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) { rc = -1; break; } }
            else {
                size_t pushed = 0;
                while (pushed < (size_t)n) {
                    size_t c = tunnel_decoder_push(&dec, tmp + pushed, (size_t)n - pushed);
                    if (c == 0) { rc = -1; goto done; }
                    pushed += c;
                }
            }
        }
        /* Drain frames while not backpressured (re-check as DATA may create it). */
        for (;;) {
            int bp = 0;
            for (int i = 0; i < MAX_STREAMS; i++)
                if (st[i].active && st[i].tooff < st[i].tolen) { bp = 1; break; }
            if (bp) break;
            tunnel_frame_t f;
            int r = tunnel_decoder_next(&dec, &f);
            if (r == 0) break;
            if (r < 0) { rc = -1; goto done; }

            if (f.type == TF_PING) { if (tw_frame(tw, &twlen, TF_PONG, 0, NULL, 0) < 0) { rc = -1; goto done; } continue; }
            if (f.type == TF_OPEN) {
                uint32_t fid = (f.len >= 4) ? be32(f.payload) : 0xffffffffu;
                struct stream *s = alloc_stream(st, f.stream_id);
                if (!s || fid >= nfwd) { tw_frame(tw, &twlen, TF_RESET, f.stream_id, NULL, 0); if (s) s->active = 0; continue; }
                int lfd = dial_local(&fwd[fid]);
                if (lfd < 0) { tw_frame(tw, &twlen, TF_RESET, f.stream_id, NULL, 0); s->active = 0; continue; }
                s->fd = lfd;
                continue;
            }
            struct stream *s = find_stream(st, f.stream_id);
            if (f.type == TF_DATA) {
                if (!s) continue;                          /* unknown stream -> drop */
                memcpy(s->tobuf, f.payload, f.len);        /* tobuf empty by the backpressure invariant */
                s->tolen = f.len; s->tooff = 0;
                ssize_t w = (f.len ? write(s->fd, s->tobuf, s->tolen) : 0);
                if (w > 0) { s->tooff += (size_t)w; if (s->tooff == s->tolen) s->tooff = s->tolen = 0; }
                else if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                    tw_frame(tw, &twlen, TF_RESET, s->sid, NULL, 0); close_stream(s);
                }
            } else if (f.type == TF_END) {
                if (s) { s->remote_eof = 1;
                    if (s->tooff == s->tolen && !s->wr_shut) { shutdown(s->fd, SHUT_WR); s->wr_shut = 1; } }
            } else if (f.type == TF_RESET) {
                if (s) close_stream(s);
            }
        }

        /* --- per-stream local I/O --- */
        for (int k = 1; k < np; k++) {
            struct stream *s = map[k];
            if (!s->active) continue;
            if (p[k].revents & POLLOUT) {
                ssize_t w = write(s->fd, s->tobuf + s->tooff, s->tolen - s->tooff);
                if (w > 0) { s->tooff += (size_t)w; if (s->tooff == s->tolen) {
                        s->tooff = s->tolen = 0;
                        if (s->remote_eof && !s->wr_shut) { shutdown(s->fd, SHUT_WR); s->wr_shut = 1; } } }
                else if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                    tw_frame(tw, &twlen, TF_RESET, s->sid, NULL, 0); close_stream(s); continue;
                }
            }
            if (s->active && (p[k].revents & (POLLIN | POLLHUP))) {
                unsigned char tmp[TUNNEL_MAX_FRAME];
                ssize_t n = read(s->fd, tmp, sizeof tmp);
                if (n > 0) { if (tw_frame(tw, &twlen, TF_DATA, s->sid, tmp, (uint32_t)n) < 0) { rc = -1; goto done; } }
                else if (n == 0) { tw_frame(tw, &twlen, TF_END, s->sid, NULL, 0); s->local_eof = 1; }
                else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                    tw_frame(tw, &twlen, TF_RESET, s->sid, NULL, 0); close_stream(s);
                }
            }
        }

        /* --- reap finished streams (both directions done, local drained) --- */
        for (int i = 0; i < MAX_STREAMS; i++)
            if (st[i].active && st[i].local_eof && st[i].remote_eof && st[i].tooff == st[i].tolen)
                close_stream(&st[i]);
    }

done:
    for (int i = 0; i < MAX_STREAMS; i++) if (st[i].active) close_stream(&st[i]);
    return rc;
}
