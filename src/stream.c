/* portico-tunnel stream engine (see stream.h). One poll loop multiplexes the tunnel fd
 * + all endpoint fds. The agent and relay share it — only how a stream is BORN differs:
 *   - agent: an incoming OPEN -> dial the forward's local target;
 *   - relay: a public connection accepted on a listener -> allocate a stream + send OPEN.
 * Everything after (DATA both ways, END/RESET, backpressure, reaping) is identical. */
#include "stream.h"
#include "frame.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_STREAMS   64
#define MAX_LISTENERS 16
#define TW_CAP        (4 * (TUNNEL_FRAME_HDR + TUNNEL_MAX_FRAME))   /* shared tunnel-out buffer */
#define OPEN_HDR      96                                           /* room reserved for an OPEN frame */

struct stream {
    int      active;
    uint32_t sid;
    int      fd;                            /* endpoint socket (local origin / public peer) */
    unsigned char tobuf[TUNNEL_MAX_FRAME];  /* bytes pending toward the endpoint fd */
    size_t   tolen, tooff;
    int      remote_eof;                    /* got END from the tunnel */
    int      local_eof;                     /* endpoint hit EOF, we sent END */
    int      wr_shut;                       /* shutdown(fd, WR) already done */
};

static void set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl != -1) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}
static uint32_t be32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static void put_be32(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v >> 24); p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);  p[3] = (unsigned char)v;
}

static int dial_local(const tunnel_target_t *t) {
    struct addrinfo hints = {0}, *res = NULL, *ai;
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
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

static void peer_ip(int fd, char *out, size_t cap) {
    struct sockaddr_storage ss; socklen_t sl = sizeof ss;
    out[0] = '\0';
    if (getpeername(fd, (struct sockaddr *)&ss, &sl) != 0) { snprintf(out, cap, "?"); return; }
    if (ss.ss_family == AF_INET)
        inet_ntop(AF_INET, &((struct sockaddr_in *)&ss)->sin_addr, out, (socklen_t)cap);
    else if (ss.ss_family == AF_INET6)
        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&ss)->sin6_addr, out, (socklen_t)cap);
    else snprintf(out, cap, "?");
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

static int serve_loop(int tfd, int is_relay,
                      const tunnel_listener_t *lis, size_t nlis,
                      const tunnel_target_t *fwd, size_t nfwd) {
    set_nonblock(tfd);
    if (is_relay) for (size_t i = 0; i < nlis; i++) set_nonblock(lis[i].listen_fd);

    tunnel_decoder_t dec; tunnel_decoder_reset(&dec);
    struct stream st[MAX_STREAMS]; memset(st, 0, sizeof st);
    unsigned char tw[TW_CAP]; size_t twlen = 0, twoff = 0;
    uint32_t next_sid = 1;                  /* relay allocates stream ids */
    int rc = 0;

    for (;;) {
        int backpressured = 0, has_free = 0;
        for (int i = 0; i < MAX_STREAMS; i++) {
            if (st[i].active && st[i].tooff < st[i].tolen) backpressured = 1;
            if (!st[i].active) has_free = 1;
        }
        int can_accept = is_relay && has_free && !backpressured &&
                         (twlen + TUNNEL_FRAME_HDR + OPEN_HDR <= TW_CAP);

        struct pollfd p[1 + MAX_LISTENERS + MAX_STREAMS];
        struct stream *smap[1 + MAX_LISTENERS + MAX_STREAMS];
        p[0].fd = tfd; p[0].events = 0; p[0].revents = 0;
        if (!backpressured) p[0].events |= POLLIN;
        if (twoff < twlen)  p[0].events |= POLLOUT;
        int np = 1, lis_start = 1;
        if (can_accept)
            for (size_t i = 0; i < nlis; i++) { p[np].fd = lis[i].listen_fd; p[np].events = POLLIN; p[np].revents = 0; np++; }
        int lis_end = np;
        for (int i = 0; i < MAX_STREAMS; i++) {
            if (!st[i].active || st[i].fd < 0) continue;
            short ev = 0;
            if (st[i].tooff < st[i].tolen) ev |= POLLOUT;
            if (!st[i].local_eof && twlen + TUNNEL_FRAME_HDR + TUNNEL_MAX_FRAME <= TW_CAP) ev |= POLLIN;
            if (ev == 0) continue;
            p[np].fd = st[i].fd; p[np].events = ev; p[np].revents = 0; smap[np] = &st[i]; np++;
        }
        if (p[0].events == 0 && np == lis_end && lis_end == lis_start) break;   /* nothing to wait on */

        if (poll(p, (nfds_t)np, -1) < 0) { if (errno == EINTR) continue; rc = -1; break; }

        /* --- tunnel out / in --- */
        if (p[0].revents & POLLOUT) {
            ssize_t w = send(tfd, tw + twoff, twlen - twoff, MSG_NOSIGNAL);
            if (w > 0) { twoff += (size_t)w; if (twoff == twlen) twoff = twlen = 0; }
            else if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) { rc = -1; break; }
        }
        if (p[0].revents & (POLLIN | POLLHUP)) {
            unsigned char tmp[TUNNEL_RECV_CHUNK];
            ssize_t n = read(tfd, tmp, sizeof tmp);
            if (n == 0) { rc = 0; break; }
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

        /* --- drain frames (while not backpressured) --- */
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
                if (is_relay) continue;     /* relay opens streams; it doesn't receive OPEN */
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
                if (!s) continue;
                memcpy(s->tobuf, f.payload, f.len);
                s->tolen = f.len; s->tooff = 0;
                ssize_t w = (f.len ? send(s->fd, s->tobuf, s->tolen, MSG_NOSIGNAL) : 0);
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

        /* --- relay: accept new public connections -> open streams --- */
        if (can_accept) {
            for (int idx = lis_start; idx < lis_end; idx++) {
                if (!(p[idx].revents & POLLIN)) continue;
                const tunnel_listener_t *L = &lis[idx - lis_start];
                for (;;) {
                    int c = accept(L->listen_fd, NULL, NULL);
                    if (c < 0) break;
                    struct stream *s = alloc_stream(st, next_sid);
                    if (!s) { close(c); break; }
                    set_nonblock(c); s->fd = c;
                    char ip[64]; peer_ip(c, ip, sizeof ip);
                    unsigned char pl[OPEN_HDR]; put_be32(pl, L->forward_id);
                    size_t il = strlen(ip); if (il > OPEN_HDR - 4) il = OPEN_HDR - 4;
                    memcpy(pl + 4, ip, il);
                    if (tw_frame(tw, &twlen, TF_OPEN, s->sid, pl, (uint32_t)(4 + il)) < 0) { close_stream(s); break; }
                    next_sid++;
                    if (twlen + TUNNEL_FRAME_HDR + OPEN_HDR > TW_CAP) break;   /* out of tunnel-out room */
                }
            }
        }

        /* --- per-stream endpoint I/O --- */
        for (int k = lis_end; k < np; k++) {
            struct stream *s = smap[k];
            if (!s->active) continue;
            if (p[k].revents & POLLOUT) {
                ssize_t w = send(s->fd, s->tobuf + s->tooff, s->tolen - s->tooff, MSG_NOSIGNAL);
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

        /* --- reap finished streams --- */
        for (int i = 0; i < MAX_STREAMS; i++)
            if (st[i].active && st[i].local_eof && st[i].remote_eof && st[i].tooff == st[i].tolen)
                close_stream(&st[i]);
    }

done:
    for (int i = 0; i < MAX_STREAMS; i++) if (st[i].active) close_stream(&st[i]);
    return rc;
}

int tunnel_agent_serve(int tunnel_fd, const tunnel_target_t *forwards, size_t n_forwards) {
    return serve_loop(tunnel_fd, 0, NULL, 0, forwards, n_forwards);
}

int tunnel_relay_serve(int tunnel_fd, const tunnel_listener_t *listeners, size_t n_listeners) {
    if (n_listeners > MAX_LISTENERS) n_listeners = MAX_LISTENERS;
    return serve_loop(tunnel_fd, 1, listeners, n_listeners, NULL, 0);
}
