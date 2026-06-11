/* portico-tunnel stream engine (see stream.h). One poll loop multiplexes the tunnel fd
 * + listeners + per-stream endpoint fds (+ relay SNI "peekers"). The agent and relay
 * share it — only how a stream is BORN differs:
 *   - agent: an incoming OPEN -> dial the forward's local target;
 *   - relay tcp: a public connection accepted -> allocate stream + send OPEN;
 *   - relay sni: accept -> buffer the ClientHello -> SNI route -> open + feed buffer.
 * Everything after (DATA both ways, END/RESET, backpressure, reaping) is identical. */
#include "stream.h"
#include "frame.h"
#include "sni.h"
#include "conn.h"
#include "tls.h"
#include "control.h"

#include <time.h>
#include <sys/time.h>

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
#define MAX_PEEKERS   32
#define PEEK_CAP      (TUNNEL_MAX_FRAME + 512)   /* max ClientHello + a little slack */
#define TW_CAP        (4 * (TUNNEL_FRAME_HDR + TUNNEL_MAX_FRAME))
#define OPEN_HDR      96
/* room needed in the tunnel-out buffer to resolve a peeker: OPEN + up to two DATA. */
#define PEEK_ROOM     (OPEN_HDR + 2 * (TUNNEL_FRAME_HDR + TUNNEL_MAX_FRAME))

struct stream {
    int      active;
    uint32_t sid;
    int      fd;
    unsigned char tobuf[TUNNEL_MAX_FRAME];
    size_t   tolen, tooff;
    int      remote_eof, local_eof, wr_shut;
};

struct peeker {                                  /* relay: accepted, awaiting SNI */
    int      active;
    int      fd;
    unsigned char buf[PEEK_CAP];
    size_t   len;
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
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
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
static int sni_lookup(const tunnel_sni_route_t *routes, size_t n, const char *host, uint32_t *fid) {
    for (size_t i = 0; i < n; i++)
        if (routes[i].host && strcmp(routes[i].host, host) == 0) { *fid = routes[i].forward_id; return 1; }
    return 0;
}

/* Open a stream for an accepted public fd, sending OPEN{forward_id, client_ip}. The
 * caller has reserved tw room. Returns the stream, or NULL (slot/room exhausted; fd
 * closed). If `prefix`/`plen` is given (SNI peeker buffer), it is fed as initial DATA. */
static struct stream *open_public(struct stream *st, uint32_t *next_sid, int fd, uint32_t fid,
                                  const unsigned char *prefix, size_t plen,
                                  unsigned char *tw, size_t *twlen) {
    struct stream *s = alloc_stream(st, *next_sid);
    if (!s) { close(fd); return NULL; }
    s->fd = fd;
    char ip[64]; peer_ip(fd, ip, sizeof ip);
    unsigned char pl[OPEN_HDR]; put_be32(pl, fid);
    size_t il = strlen(ip); if (il > OPEN_HDR - 4) il = OPEN_HDR - 4;
    memcpy(pl + 4, ip, il);
    if (tw_frame(tw, twlen, TF_OPEN, s->sid, pl, (uint32_t)(4 + il)) < 0) { close_stream(s); return NULL; }
    (*next_sid)++;
    for (size_t off = 0; off < plen; ) {
        size_t c = plen - off; if (c > TUNNEL_MAX_FRAME) c = TUNNEL_MAX_FRAME;
        if (tw_frame(tw, twlen, TF_DATA, s->sid, prefix + off, (uint32_t)c) < 0) break;
        off += c;
    }
    return s;
}

static int serve_loop(tunnel_conn_t *conn, int is_relay,
                      const tunnel_listener_t *lis, size_t nlis,
                      const tunnel_target_t *fwd, size_t nfwd,
                      const tunnel_sni_route_t *routes, size_t nroutes,
                      int heartbeat_secs) {
    if (is_relay) for (size_t i = 0; i < nlis; i++) set_nonblock(lis[i].listen_fd);

    tunnel_decoder_t dec; tunnel_decoder_reset(&dec);
    struct stream st[MAX_STREAMS]; memset(st, 0, sizeof st);
    struct peeker pk[MAX_PEEKERS]; memset(pk, 0, sizeof pk);
    unsigned char tw[TW_CAP]; size_t twlen = 0, twoff = 0;
    uint32_t next_sid = 1;
    int rc = 0, missed = 0;

    for (;;) {
        int backpressured = 0, has_free = 0, has_peeker = 0;
        for (int i = 0; i < MAX_STREAMS; i++) {
            if (st[i].active && st[i].tooff < st[i].tolen) backpressured = 1;
            if (!st[i].active) has_free = 1;
        }
        for (int i = 0; i < MAX_PEEKERS; i++) if (!pk[i].active) { has_peeker = 1; break; }
        int can_accept = is_relay && has_free && has_peeker && !backpressured &&
                         (twlen + TUNNEL_FRAME_HDR + OPEN_HDR <= TW_CAP);
        int can_peek = has_free && (twlen + PEEK_ROOM <= TW_CAP);

        struct pollfd p[1 + MAX_LISTENERS + MAX_STREAMS + MAX_PEEKERS];
        struct stream *smap[1 + MAX_LISTENERS + MAX_STREAMS + MAX_PEEKERS];
        struct peeker *pmap[1 + MAX_LISTENERS + MAX_STREAMS + MAX_PEEKERS];
        int ssl_more = !backpressured && tunnel_conn_pending(conn);
        p[0].fd = conn->fd; p[0].events = 0; p[0].revents = 0;
        if (!backpressured || conn->want_rd)  p[0].events |= POLLIN;
        if (twoff < twlen   || conn->want_wr) p[0].events |= POLLOUT;
        int np = 1, lis_start = 1;
        if (can_accept)
            for (size_t i = 0; i < nlis; i++) { p[np].fd = lis[i].listen_fd; p[np].events = POLLIN; p[np].revents = 0; np++; }
        int lis_end = np, str_start = np;
        for (int i = 0; i < MAX_STREAMS; i++) {
            if (!st[i].active || st[i].fd < 0) continue;
            short ev = 0;
            if (st[i].tooff < st[i].tolen) ev |= POLLOUT;
            if (!st[i].local_eof && twlen + TUNNEL_FRAME_HDR + TUNNEL_MAX_FRAME <= TW_CAP) ev |= POLLIN;
            if (ev == 0) continue;
            p[np].fd = st[i].fd; p[np].events = ev; p[np].revents = 0; smap[np] = &st[i]; np++;
        }
        int str_end = np;
        if (can_peek)
            for (int i = 0; i < MAX_PEEKERS; i++) {
                if (!pk[i].active || pk[i].fd < 0) continue;
                p[np].fd = pk[i].fd; p[np].events = POLLIN; p[np].revents = 0; pmap[np] = &pk[i]; np++;
            }
        int pk_end = np;
        if (p[0].events == 0 && np == lis_end && lis_end == lis_start && heartbeat_secs <= 0) break;

        int timeout = ssl_more ? 0 : (heartbeat_secs > 0 ? heartbeat_secs * 1000 : -1);
        int pr = poll(p, (nfds_t)np, timeout);
        if (pr < 0) { if (errno == EINTR) continue; rc = -1; break; }
        if (pr == 0 && heartbeat_secs > 0 && !ssl_more) {       /* idle interval elapsed */
            if (++missed > 2) { rc = -1; break; }               /* no traffic for ~2 intervals -> dead */
            if (tw_frame(tw, &twlen, TF_PING, 0, NULL, 0) < 0) { rc = -1; break; }
        }

        /* --- tunnel out: always try to flush pending bytes (non-blocking) --- */
        if (twoff < twlen) {
            long w = tunnel_conn_write(conn, tw + twoff, twlen - twoff);
            if (w > 0) { twoff += (size_t)w; if (twoff == twlen) twoff = twlen = 0; }
            else if (w == -1) { rc = -1; break; }
        }
        /* --- tunnel in --- */
        if (!backpressured && (ssl_more || (p[0].revents & (POLLIN | POLLOUT | POLLHUP | POLLERR)))) {
            unsigned char tmp[TUNNEL_RECV_CHUNK];
            long n = tunnel_conn_read(conn, tmp, sizeof tmp);
            if (n == 0) { rc = 0; break; }
            else if (n == -1) { rc = -1; break; }
            else if (n > 0) {
                missed = 0;                                     /* any traffic = peer is alive */
                size_t pushed = 0;
                while (pushed < (size_t)n) {
                    size_t c = tunnel_decoder_push(&dec, tmp + pushed, (size_t)n - pushed);
                    if (c == 0) { rc = -1; goto done; }
                    pushed += c;
                }
            }
        }

        /* --- drain frames --- */
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
                if (is_relay) continue;
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

        /* --- relay: accept new public connections --- */
        if (can_accept) {
            for (int idx = lis_start; idx < lis_end; idx++) {
                if (!(p[idx].revents & POLLIN)) continue;
                const tunnel_listener_t *L = &lis[idx - lis_start];
                for (;;) {
                    int c = accept(L->listen_fd, NULL, NULL);
                    if (c < 0) break;
                    set_nonblock(c);
                    if (L->sni) {                                  /* defer until ClientHello peeked */
                        int placed = 0;
                        for (int j = 0; j < MAX_PEEKERS; j++)
                            if (!pk[j].active) { pk[j].active = 1; pk[j].fd = c; pk[j].len = 0; placed = 1; break; }
                        if (!placed) { close(c); break; }
                    } else if (!open_public(st, &next_sid, c, L->forward_id, NULL, 0, tw, &twlen)) {
                        break;
                    }
                    if (twlen + TUNNEL_FRAME_HDR + OPEN_HDR > TW_CAP) break;
                }
            }
        }

        /* --- per-stream endpoint I/O --- */
        for (int k = str_start; k < str_end; k++) {
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

        /* --- relay: feed SNI peekers, resolve to streams --- */
        for (int k = str_end; k < pk_end; k++) {
            struct peeker *q = pmap[k];
            if (!q->active || !(p[k].revents & (POLLIN | POLLHUP))) continue;
            ssize_t n = read(q->fd, q->buf + q->len, PEEK_CAP - q->len);
            if (n <= 0) { if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) { close(q->fd); q->active = 0; } continue; }
            q->len += (size_t)n;
            char host[256];
            int r = tunnel_sni_peek(q->buf, q->len, host, sizeof host);
            if (r == 0) { if (q->len >= PEEK_CAP) { close(q->fd); q->active = 0; } continue; }
            if (r < 0) { close(q->fd); q->active = 0; continue; }
            uint32_t fid;
            if (!sni_lookup(routes, nroutes, host, &fid)) { close(q->fd); q->active = 0; continue; }
            int fd = q->fd;
            q->active = 0; q->fd = -1;                       /* fd ownership moves to the stream */
            open_public(st, &next_sid, fd, fid, q->buf, q->len, tw, &twlen);
        }

        /* --- reap finished streams --- */
        for (int i = 0; i < MAX_STREAMS; i++)
            if (st[i].active && st[i].local_eof && st[i].remote_eof && st[i].tooff == st[i].tolen)
                close_stream(&st[i]);
    }

done:
    for (int i = 0; i < MAX_STREAMS; i++) if (st[i].active) close_stream(&st[i]);
    for (int i = 0; i < MAX_PEEKERS; i++) if (pk[i].active && pk[i].fd >= 0) close(pk[i].fd);
    return rc;
}

int tunnel_agent_serve(int tunnel_fd, const tunnel_target_t *forwards, size_t n_forwards) {
    tunnel_conn_t conn; tunnel_conn_fd(&conn, tunnel_fd);
    return serve_loop(&conn, 0, NULL, 0, forwards, n_forwards, NULL, 0, 0);
}
int tunnel_agent_serve_ssl(SSL *tunnel, const tunnel_target_t *forwards, size_t n_forwards) {
    tunnel_conn_t conn; tunnel_conn_ssl(&conn, tunnel);
    return serve_loop(&conn, 0, NULL, 0, forwards, n_forwards, NULL, 0, 0);
}

int tunnel_relay_serve(int tunnel_fd,
                       const tunnel_listener_t *listeners, size_t n_listeners,
                       const tunnel_sni_route_t *routes, size_t n_routes) {
    if (n_listeners > MAX_LISTENERS) n_listeners = MAX_LISTENERS;
    tunnel_conn_t conn; tunnel_conn_fd(&conn, tunnel_fd);
    return serve_loop(&conn, 1, listeners, n_listeners, NULL, 0, routes, n_routes, 0);
}
int tunnel_relay_serve_ssl(SSL *tunnel,
                           const tunnel_listener_t *listeners, size_t n_listeners,
                           const tunnel_sni_route_t *routes, size_t n_routes) {
    if (n_listeners > MAX_LISTENERS) n_listeners = MAX_LISTENERS;
    tunnel_conn_t conn; tunnel_conn_ssl(&conn, tunnel);
    return serve_loop(&conn, 1, listeners, n_listeners, NULL, 0, routes, n_routes, 0);
}

/* ---- the agent run loop: connect -> register -> serve -> reconnect ---------- */

static int stopped(const tunnel_agent_run_config_t *cfg) {
    return cfg->stop && atomic_load(cfg->stop);
}

/* Sleep `ms`, in small slices so the stop flag is observed promptly. */
static void backoff_sleep(int ms, const tunnel_agent_run_config_t *cfg) {
    while (ms > 0 && !stopped(cfg)) {
        int slice = ms > 100 ? 100 : ms;
        struct timespec ts = { slice / 1000, (long)(slice % 1000) * 1000000L };
        nanosleep(&ts, NULL);
        ms -= slice;
    }
}

int tunnel_relay_run(const tunnel_relay_run_config_t *cfg) {
    int hb   = cfg->heartbeat_secs > 0 ? cfg->heartbeat_secs : 20;
    int hsto = cfg->handshake_timeout_ms > 0 ? cfg->handshake_timeout_ms : 10000;
    while (!(cfg->stop && atomic_load(cfg->stop))) {
        struct pollfd pf = { cfg->control_fd, POLLIN, 0 };
        int pr = poll(&pf, 1, 500);                  /* timeout -> re-check the stop flag */
        if (pr <= 0) continue;
        int c = accept(cfg->control_fd, NULL, NULL);
        if (c < 0) continue;

        /* Bound the TLS handshake AND the HELLO read so a stalled/idle peer cannot
         * freeze the (serial) control path. Both run as blocking ops on this fd until
         * serve makes it non-blocking, so a recv/send timeout caps them. */
        struct timeval tv = { hsto / 1000, (hsto % 1000) * 1000 };
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

        tunnel_tls_t tls;
        if (tunnel_tls_accept(c, cfg->cert, cfg->key, cfg->client_ca, &tls) != 0) { close(c); continue; }
        tunnel_io_t io = tunnel_io_tls(&tls);
        tunnel_decoder_t rdec; tunnel_decoder_reset(&rdec);
        tunnel_hello_t h; char err[256];
        if (tunnel_relay_accept(&io, &rdec, &h, cfg->allow, cfg->allow_ud, err, sizeof err) == 0) {
            tunnel_conn_t conn; tunnel_conn_ssl(&conn, tls.ssl);
            serve_loop(&conn, 1, cfg->listeners, cfg->n_listeners, NULL, 0, cfg->routes, cfg->n_routes, hb);
        } else {
            fprintf(stderr, "relay: agent rejected: %s\n", err);
        }
        tunnel_tls_free(&tls);                        /* agent gone — accept the next one */
    }
    return 0;
}

int tunnel_agent_run(const tunnel_agent_run_config_t *cfg) {
    int hb   = cfg->heartbeat_secs  > 0 ? cfg->heartbeat_secs  : 20;
    int bmin = cfg->backoff_min_ms  > 0 ? cfg->backoff_min_ms  : 500;
    int bmax = cfg->backoff_max_ms  > 0 ? cfg->backoff_max_ms  : 30000;
    unsigned rng = (unsigned)time(NULL) ^ (unsigned)(uintptr_t)cfg;
    int backoff = bmin;

    while (!stopped(cfg)) {
        tunnel_tls_t tls;
        if (tunnel_tls_dial(cfg->relay_host, cfg->relay_port, cfg->ca_file,
                            cfg->client_cert, cfg->client_key, &tls) != 0)
            goto retry;

        /* Bound the HELLO exchange so a dialed-but-mute relay can't pin the agent
         * forever (bypassing reconnect/backoff). Cleared when serve makes the fd
         * non-blocking. */
        int rto = cfg->register_timeout_ms > 0 ? cfg->register_timeout_ms : 10000;
        struct timeval rtv = { rto / 1000, (rto % 1000) * 1000 };
        setsockopt(tls.fd, SOL_SOCKET, SO_RCVTIMEO, &rtv, sizeof rtv);
        setsockopt(tls.fd, SOL_SOCKET, SO_SNDTIMEO, &rtv, sizeof rtv);

        tunnel_io_t io = tunnel_io_tls(&tls);
        tunnel_decoder_t rdec; tunnel_decoder_reset(&rdec);
        char err[256];
        if (tunnel_agent_register(&io, &rdec, cfg->hello, err, sizeof err) != 0) {
            tunnel_tls_free(&tls);
            goto retry;
        }
        /* Registered — drop the blocking timeout; serve drives the fd non-blocking. */
        struct timeval zero = { 0, 0 };
        setsockopt(tls.fd, SOL_SOCKET, SO_RCVTIMEO, &zero, sizeof zero);
        setsockopt(tls.fd, SOL_SOCKET, SO_SNDTIMEO, &zero, sizeof zero);
        backoff = bmin;                              /* a real session resets the backoff */

        tunnel_conn_t conn; tunnel_conn_ssl(&conn, tls.ssl);
        serve_loop(&conn, 0, NULL, 0, cfg->forwards, cfg->n_forwards, NULL, 0, hb);
        tunnel_tls_free(&tls);                        /* tunnel ended — reconnect */

    retry:
        if (stopped(cfg)) break;
        rng = rng * 1103515245u + 12345u;            /* LCG; jitter need not be strong */
        int jitter = (backoff / 4 > 0) ? (int)(rng % (unsigned)(backoff / 4)) : 0;
        backoff_sleep(backoff + jitter, cfg);
        backoff = backoff * 2 > bmax ? bmax : backoff * 2;
    }
    return 0;
}
