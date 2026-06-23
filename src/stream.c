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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <sys/epoll.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_STREAMS   4096   /* concurrent multiplexed streams per agent tunnel. Heap-allocated
                              * (16 KB/stream tobuf) — too big for the stack. Raising it is RAM-bounded
                              * (~16 KB each), but poll() is O(n) so the single serve_loop thread tops
                              * out on poll-scan + mux cost before RAM does (see tests/stress_test). */
#define MAX_LISTENERS 16
#define MAX_PEEKERS   256    /* connections allowed mid-SNI-handshake at once (heap-allocated) */
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
    int      connecting;       /* agent: the local target connect() is still in flight */
    long     connect_deadline; /* monotonic ms by which the connect must complete */
    long     last_activity;    /* monotonic ms of the last byte moved (or creation) */
    long     last_flush;       /* monotonic ms tobuf was last empty or made send progress */
    int      activated;        /* has any byte ever flowed on this stream? */
    int      pending_end;      /* owe the peer a TF_END but tw was full — retry until sent */
    int      pending_reset;    /* tombstone: fd closed, owe the peer a TF_RESET — retry, then free */
    int      ep_armed;         /* epoll: event mask currently registered for this fd (0 = not in epoll) */
    short    ep_rev;           /* epoll: events reported for this fd this iteration (poll-revents analogue) */
};

#define CONNECT_TIMEOUT_MS 10000
#define STABLE_SESSION_MS  5000    /* a served session this long counts as useful (resets backoff) */

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

struct peeker {                                  /* relay: accepted, awaiting SNI */
    int      active;
    int      fd;
    unsigned char buf[PEEK_CAP];
    size_t   len;
    long     since;                              /* monotonic ms of accept / last byte */
    int      ep_armed;                           /* epoll: registered event mask (0 = not in epoll) */
    short    ep_rev;                             /* epoll: events reported this iteration */
};

/* epoll readiness is mapped back to the right object via the event's user tag:
 * kind in the top byte, array index in the low 32 bits. */
#define EPK_TUN  0
#define EPK_LIS  1
#define EPK_STR  2
#define EPK_PEEK 3
#define EPTAG(kind, idx) (((uint64_t)(kind) << 56) | (uint32_t)(idx))
#define EPKIND(u)        ((int)((u) >> 56))
#define EPIDX(u)         ((int)((u) & 0xffffffffu))

/* Register/modify/remove `fd`'s interest, but only when it actually changed — `*armed`
 * caches the last registered mask (0 = not registered) so a stable interest costs no
 * syscall. A closed fd is auto-removed from epoll, so we never DEL a dead fd. */
static void ep_arm(int ep, int fd, uint64_t tag, int *armed, uint32_t want) {
    if ((uint32_t)*armed == want) return;
    struct epoll_event ev; ev.events = want; ev.data.u64 = tag;
    int op = (*armed == 0) ? EPOLL_CTL_ADD : (want == 0 ? EPOLL_CTL_DEL : EPOLL_CTL_MOD);
    epoll_ctl(ep, op, fd, &ev);
    *armed = (int)want;
}

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

/* Start a NON-BLOCKING connect to the forward's local target. Returns the fd with
 * *connecting=1 if the connect is in flight (EINPROGRESS) or 0 if it completed
 * immediately; -1 on failure. Never blocks the event loop — a slow/black-holed target
 * (e.g. from a malicious relay's OPEN) no longer stalls every other stream. */
static int dial_local(const tunnel_target_t *t, int *connecting) {
    struct addrinfo hints = {0}, *res = NULL, *ai;
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(t->host, t->port, &hints, &res) != 0) return -1;
    int fd = -1;
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        set_nonblock(fd);
        int r = connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (r == 0) { *connecting = 0; break; }                     /* connected immediately */
        if (r < 0 && errno == EINPROGRESS) { *connecting = 1; break; }
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
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
        if (!st[i].active) {
            memset(&st[i], 0, sizeof st[i]);
            st[i].active = 1; st[i].sid = sid; st[i].fd = -1;
            st[i].last_activity = st[i].last_flush = now_ms();
            return &st[i];
        }
    return NULL;
}
/* Pick a stream_id for a new relay stream: never 0 (reserved for control frames like
 * PING/PONG) and never one already live. With at most MAX_STREAMS active, a free id is
 * always within a short scan — this hardens against a next_sid wrap silently reusing a
 * live id and corrupting that stream (L4). Returns 0 if the table is full. */
static uint32_t alloc_sid(struct stream *st, uint32_t *next_sid) {
    for (int t = 0; t <= MAX_STREAMS; t++) {
        uint32_t s = (*next_sid)++;
        if (s != 0 && !find_stream(st, s)) return s;
    }
    return 0;
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
/* Teardown frames must reach the peer or its matching stream leaks (half-open forever).
 * tw may be full at the moment we need to tear down, so these never fire-and-forget:
 *  - END half-closes our write side; if it can't be queued now, remember it (pending_end).
 *  - RESET aborts the stream; close the local fd immediately but keep the slot as a
 *    tombstone (pending_reset) until the RESET is actually flushed, then free it.
 * A small retry pass each iteration drains the pending frames as soon as tw has room. */
static void send_end(struct stream *s, unsigned char *tw, size_t *twlen) {
    if (s->local_eof) return;
    s->local_eof = 1;
    if (tw_frame(tw, twlen, TF_END, s->sid, NULL, 0) < 0) s->pending_end = 1;
}
static void send_reset(struct stream *s, unsigned char *tw, size_t *twlen) {
    if (s->fd >= 0) { close(s->fd); s->fd = -1; }
    s->connecting = 0; s->pending_end = 0; s->tooff = s->tolen = 0;   /* tombstone, no more I/O */
    if (tw_frame(tw, twlen, TF_RESET, s->sid, NULL, 0) == 0) s->active = 0;   /* delivered -> free */
    else s->pending_reset = 1;                                               /* retry until flushed */
}
static void flush_pending_teardown(struct stream *st, unsigned char *tw, size_t *twlen) {
    for (int i = 0; i < MAX_STREAMS; i++) {
        struct stream *s = &st[i];
        if (!s->active) continue;
        if (s->pending_reset) { if (tw_frame(tw, twlen, TF_RESET, s->sid, NULL, 0) == 0) s->active = 0; }
        else if (s->pending_end) { if (tw_frame(tw, twlen, TF_END, s->sid, NULL, 0) == 0) s->pending_end = 0; }
    }
}
static int sni_lookup(const tunnel_sni_route_t *routes, size_t n, const char *host, uint32_t *fid) {
    for (size_t i = 0; i < n; i++)
        if (routes[i].host && strcmp(routes[i].host, host) == 0) { *fid = routes[i].forward_id; return 1; }
    return 0;
}

/* Open a stream for an accepted public fd, sending OPEN{forward_id, client_ip} followed
 * by the buffered SNI ClientHello (`prefix`/`plen`) as initial DATA. ATOMIC (M1): either
 * the whole OPEN+prefix is committed to tw, or nothing is — a half-sent ClientHello would
 * wedge the origin's TLS handshake forever. Returns the stream on success. On failure
 * returns NULL: if `*again` is set the tw buffer simply lacks room right now and NOTHING
 * was touched (fd still open — the caller should retry once tw drains); otherwise the
 * stream slot was exhausted and the fd has been closed. */
static struct stream *open_public(struct stream *st, uint32_t *next_sid, int fd, uint32_t fid,
                                  const unsigned char *prefix, size_t plen,
                                  unsigned char *tw, size_t *twlen, int *again) {
    if (again) *again = 0;
    char ip[64]; peer_ip(fd, ip, sizeof ip);
    size_t il = strlen(ip); if (il > OPEN_HDR - 4) il = OPEN_HDR - 4;

    /* exact bytes this open will append to tw — checked up front so no frame is dropped */
    size_t need = TUNNEL_FRAME_HDR + 4 + il;
    if (plen) { size_t nf = (plen + TUNNEL_MAX_FRAME - 1) / TUNNEL_MAX_FRAME; need += plen + nf * TUNNEL_FRAME_HDR; }
    if (*twlen + need > TW_CAP) { if (again) { *again = 1; return NULL; } close(fd); return NULL; }

    uint32_t sid = alloc_sid(st, next_sid);
    struct stream *s = sid ? alloc_stream(st, sid) : NULL;
    if (!s) { close(fd); return NULL; }                       /* slot / id space exhausted */
    s->fd = fd;
    unsigned char pl[OPEN_HDR]; put_be32(pl, fid); memcpy(pl + 4, ip, il);
    tw_frame(tw, twlen, TF_OPEN, s->sid, pl, (uint32_t)(4 + il));   /* room pre-checked: cannot fail */
    for (size_t off = 0; off < plen; ) {
        size_t c = plen - off; if (c > TUNNEL_MAX_FRAME) c = TUNNEL_MAX_FRAME;
        tw_frame(tw, twlen, TF_DATA, s->sid, prefix + off, (uint32_t)c);
        off += c;
    }
    return s;
}

static int serve_loop(tunnel_conn_t *conn, int is_relay,
                      const tunnel_listener_t *lis, size_t nlis,
                      const tunnel_target_t *fwd, size_t nfwd,
                      const tunnel_sni_route_t *routes, size_t nroutes,
                      int heartbeat_secs, int idle_timeout_ms,
                      const tunnel_decoder_t *seed, atomic_int *stop) {
    if (is_relay) for (size_t i = 0; i < nlis; i++) set_nonblock(lis[i].listen_fd);

    /* M6: carry over the registration decoder. The HELLO/HELLO_OK read may have pulled
     * a pipelined frame (e.g. an immediate OPEN) into its buffer; a fresh decoder would
     * silently drop those bytes. seed != NULL inherits them; otherwise start clean. */
    tunnel_decoder_t dec; if (seed) dec = *seed; else tunnel_decoder_reset(&dec);
    /* Heap, not stack: MAX_STREAMS * 16 KB tobuf would blow the thread stack. calloc
     * zero-inits (replacing the old memset). The poll-set arrays below stay on the stack
     * — they're pointer/pollfd-sized, small even at MAX_STREAMS. */
    struct stream *st = calloc(MAX_STREAMS, sizeof *st);
    struct peeker *pk = calloc(MAX_PEEKERS, sizeof *pk);
    int ep = epoll_create1(EPOLL_CLOEXEC);
    if (!st || !pk || ep < 0) { if (ep >= 0) close(ep); free(st); free(pk); return -1; }
    int tun_armed = 0, lis_armed[MAX_LISTENERS] = {0};   /* cached epoll interest masks (0 = not registered) */
    short tun_rev = 0; short lis_rev[MAX_LISTENERS] = {0};
    unsigned char tw[TW_CAP]; size_t twlen = 0, twoff = 0;
    uint32_t next_sid = 1;
    int rc = 0, missed = 0;
    long last_ping = 0;       /* ms of our last heartbeat probe — gates probes to one per interval */
    int seeded = (seed && seed->have > seed->pending);   /* drain carried-over frames first */

    for (;;) {
        if (stop && atomic_load(stop)) { rc = 0; break; }   /* M9: leave a live session promptly on stop */
        int backpressured = 0, has_free = 0, has_peeker = 0, any_connecting = 0;
        for (int i = 0; i < MAX_STREAMS; i++) {
            if (st[i].active && st[i].tooff < st[i].tolen) backpressured = 1;
            if (!st[i].active) has_free = 1;
            if (st[i].active && st[i].connecting) any_connecting = 1;
        }
        for (int i = 0; i < MAX_PEEKERS; i++) if (!pk[i].active) { has_peeker = 1; break; }
        int tw_room_open = (twlen + TUNNEL_FRAME_HDR + OPEN_HDR <= TW_CAP);
        /* M4: accepting a NEW public connection is independent of whether some OTHER stream's
         * local sink is stalled — a slow client on one stream must not stop the relay taking
         * new ingress. Gate only on a free slot + room for the OPEN, not the global flag. */
        int can_accept_tcp = is_relay && has_free && tw_room_open;
        int can_accept_sni = can_accept_tcp && has_peeker;   /* sni needs a peeker slot; tcp does not */
        int can_peek = has_free && (twlen + PEEK_ROOM <= TW_CAP);

        struct stream *smap[1 + MAX_LISTENERS + MAX_STREAMS + MAX_PEEKERS];
        struct peeker *pmap[1 + MAX_LISTENERS + MAX_STREAMS + MAX_PEEKERS];
        int            lmap[1 + MAX_LISTENERS + MAX_STREAMS + MAX_PEEKERS];   /* slot -> listener index */
        int ssl_more = !backpressured && tunnel_conn_pending(conn);

        /* Arm the tunnel fd. ep_arm only syscalls when the interest actually changed, so a
         * steady connection (and thousands of idle streams below) cost no epoll_ctl churn. */
        short tun_want = 0;
        if (!backpressured || conn->want_rd)  tun_want |= POLLIN;
        if (twoff < twlen   || conn->want_wr) tun_want |= POLLOUT;
        ep_arm(ep, conn->fd, EPTAG(EPK_TUN, 0), &tun_armed, tun_want);
        tun_rev = 0;

        int np = 0, lis_start = 0;
        for (size_t i = 0; i < nlis; i++) {
            int gate = lis[i].sni ? can_accept_sni : can_accept_tcp;   /* tcp forwards don't need a free peeker */
            ep_arm(ep, lis[i].listen_fd, EPTAG(EPK_LIS, i), &lis_armed[i], gate ? POLLIN : 0);
            lis_rev[i] = 0;
            if (gate) { lmap[np] = (int)i; np++; }
        }
        int lis_end = np, str_start = np;
        for (int i = 0; i < MAX_STREAMS; i++) {
            if (!st[i].active || st[i].fd < 0) continue;
            short ev = 0;
            if (st[i].connecting) {
                ev = POLLOUT;                            /* wait for the local connect to complete */
            } else {
                if (st[i].tooff < st[i].tolen) ev |= POLLOUT;
                if (!st[i].local_eof && twlen + TUNNEL_FRAME_HDR + TUNNEL_MAX_FRAME <= TW_CAP) ev |= POLLIN;
            }
            ep_arm(ep, st[i].fd, EPTAG(EPK_STR, i), &st[i].ep_armed, (uint32_t)ev);   /* ev==0 -> DEL */
            st[i].ep_rev = 0;
            if (ev) { smap[np] = &st[i]; np++; }
        }
        int str_end = np;
        for (int i = 0; i < MAX_PEEKERS; i++) {
            if (!pk[i].active || pk[i].fd < 0) continue;
            short ev = can_peek ? POLLIN : 0;
            ep_arm(ep, pk[i].fd, EPTAG(EPK_PEEK, i), &pk[i].ep_armed, (uint32_t)ev);
            pk[i].ep_rev = 0;
            if (ev) { pmap[np] = &pk[i]; np++; }
        }
        int pk_end = np;
        if (tun_want == 0 && np == 0 && heartbeat_secs <= 0) break;   /* nothing left to wait on */

        int base = heartbeat_secs > 0 ? heartbeat_secs * 1000 : -1;
        if (any_connecting && (base < 0 || base > 250)) base = 250;   /* wake to enforce connect deadlines */
        if (idle_timeout_ms > 0) {                                    /* wake to run the idle/slowloris sweep */
            int sweep = idle_timeout_ms / 2; if (sweep < 100) sweep = 100; if (sweep > 1000) sweep = 1000;
            if (base < 0 || base > sweep) base = sweep;
        }
        if (stop && (base < 0 || base > 250)) base = 250;             /* wake to poll the stop flag (M9) */
        int timeout = (ssl_more || seeded) ? 0 : base;
        struct epoll_event evs[1 + MAX_LISTENERS + MAX_STREAMS + MAX_PEEKERS];
        int pr = epoll_wait(ep, evs, (int)(sizeof evs / sizeof *evs), timeout);
        if (pr < 0) { if (errno == EINTR) continue; rc = -1; break; }
        for (int e = 0; e < pr; e++) {                               /* scatter readiness back to each object */
            uint64_t u = evs[e].data.u64; short re = (short)evs[e].events;
            switch (EPKIND(u)) {
                case EPK_TUN:  tun_rev = re; break;
                case EPK_LIS:  lis_rev[EPIDX(u)] = re; break;
                case EPK_STR:  st[EPIDX(u)].ep_rev = re; break;
                case EPK_PEEK: pk[EPIDX(u)].ep_rev = re; break;
            }
        }
        /* Heartbeat only when genuinely idle: nothing queued for the peer (twoff==twlen)
         * and not blocked on a local sink (!backpressured). Under backpressure the tunnel
         * is busy, not dead — probing or counting a miss there would kill a live tunnel (M8).
         *
         * Two corrections so this actually detects a HALF-OPEN peer (data path dead while
         * TCP stays ESTABLISHED — the peer's kernel ACKs but its app answers nothing):
         *   - by WALL CLOCK, not poll count: the poll timeout is clamped short (~250ms) by
         *     the idle sweep / stop-flag wake, so a per-timeout counter would fire far faster
         *     than `heartbeat_secs`. Probe (and count a miss) at most once per interval.
         *   - `missed` counts only UNANSWERED intervals: it is reset solely by INBOUND bytes
         *     (a PONG / any frame, below), never by our own successful writes — a half-open
         *     peer accepts writes forever, so resetting on write let a dead path look alive. */
        if (pr == 0 && heartbeat_secs > 0 && !ssl_more && !backpressured && twoff == twlen) {
            long now = now_ms();
            if (now - last_ping >= (long)heartbeat_secs * 1000) {
                if (++missed > 2) { rc = -1; break; }           /* ~3 intervals with no reply -> dead */
                tw_frame(tw, &twlen, TF_PING, 0, NULL, 0);
                last_ping = now;
            }
        }

        /* --- tunnel out: always try to flush pending bytes (non-blocking) --- */
        if (twoff < twlen) {
            long w = tunnel_conn_write(conn, tw + twoff, twlen - twoff);
            if (w > 0) { twoff += (size_t)w;                    /* a successful write only means our local
                         * send buffer accepted bytes — NOT that the peer received them. A half-open
                         * conn (peer TCP ACKs but its app is dead) keeps accepting writes, so resetting
                         * `missed` here let a dead data path masquerade as live forever. Liveness is
                         * proven only by INBOUND bytes (a PONG, below) — reset `missed` there, not here. */
                         if (twoff == twlen) twoff = twlen = 0; }
            else if (w == -1) { rc = -1; break; }
        }
        /* --- tunnel in --- */
        if (!backpressured && (ssl_more || (tun_rev & (POLLIN | POLLOUT | POLLHUP | POLLERR)))) {
            unsigned char tmp[TUNNEL_RECV_CHUNK];
            long n = tunnel_conn_read(conn, tmp, sizeof tmp);
            if (n == 0) { rc = 0; break; }
            else if (n == -1) { rc = -1; break; }
            else if (n > 0) {
                missed = 0;                                     /* inbound bytes (PONG/data) = the ONLY proof
                                                                 * the peer is alive — the sole reset of missed */
                size_t pushed = 0;
                while (pushed < (size_t)n) {
                    size_t c = tunnel_decoder_push(&dec, tmp + pushed, (size_t)n - pushed);
                    if (c == 0) { rc = -1; goto done; }
                    pushed += c;
                }
            }
        }

        /* --- drain frames --- */
        /* Coarse backpressure (M4): stop draining while any local sink is stalled, so the
         * next DATA frame can't overwrite an undrained tobuf. The O(n) scan that proves it
         * is gated behind `maybe_bp` — false in the common (nothing-stalled) case, so the
         * per-frame check is O(1); a partial local send (below) flips it on to force a verify. */
        int maybe_bp = backpressured;
        for (;;) {
            if (maybe_bp) {
                int bp = 0;
                for (int i = 0; i < MAX_STREAMS; i++)
                    if (st[i].active && st[i].tooff < st[i].tolen) { bp = 1; break; }
                if (bp) break;
                maybe_bp = 0;                           /* nothing stalled after all */
            }
            tunnel_frame_t f;
            int r = tunnel_decoder_next(&dec, &f);
            if (r == 0) break;
            if (r < 0) { rc = -1; goto done; }

            if (f.type == TF_PING) { if (tw_frame(tw, &twlen, TF_PONG, 0, NULL, 0) < 0) { rc = -1; goto done; } continue; }
            if (f.type == TF_OPEN) {
                if (is_relay) continue;
                struct stream *dup = find_stream(st, f.stream_id);
                if (dup) { send_reset(dup, tw, &twlen); continue; }   /* M11: stream_id in use -> abort, don't double-open */
                uint32_t fid = (f.len >= 4) ? be32(f.payload) : 0xffffffffu;
                struct stream *s = alloc_stream(st, f.stream_id);
                if (!s) { tw_frame(tw, &twlen, TF_RESET, f.stream_id, NULL, 0); continue; }  /* no slot: best effort */
                if (fid >= nfwd) { send_reset(s, tw, &twlen); continue; }                    /* unknown forward */
                int connecting = 0;
                int lfd = dial_local(&fwd[fid], &connecting);       /* non-blocking */
                if (lfd < 0) { send_reset(s, tw, &twlen); continue; }
                s->fd = lfd;
                s->connecting = connecting;
                if (connecting) s->connect_deadline = now_ms() + CONNECT_TIMEOUT_MS;
                continue;
            }
            struct stream *s = find_stream(st, f.stream_id);
            if (f.type == TF_DATA) {
                if (!s || s->fd < 0) continue;                      /* unknown or tombstoned */
                s->last_activity = now_ms(); s->activated = 1;
                memcpy(s->tobuf, f.payload, f.len);
                s->tolen = f.len; s->tooff = 0;
                ssize_t w = (f.len ? send(s->fd, s->tobuf, s->tolen, MSG_NOSIGNAL) : 0);
                if (w >= 0) { s->tooff += (size_t)w; s->last_flush = now_ms(); if (s->tooff == s->tolen) s->tooff = s->tolen = 0; }
                else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                    send_reset(s, tw, &twlen);
                }
                if (s->fd >= 0 && s->tooff < s->tolen) maybe_bp = 1;   /* this sink is now stalled */
            } else if (f.type == TF_END) {
                if (s && s->fd >= 0) { s->remote_eof = 1;
                    if (s->tooff == s->tolen && !s->wr_shut) { shutdown(s->fd, SHUT_WR); s->wr_shut = 1; } }
            } else if (f.type == TF_RESET) {
                if (s) { s->pending_end = s->pending_reset = 0; close_stream(s); }
            }
        }

        seeded = 0;                 /* carried-over frames have now been drained */

        /* retry any teardown frame that couldn't be queued earlier (tw was full) */
        flush_pending_teardown(st, tw, &twlen);

        /* --- relay: accept new public connections (per-listener gated in the poll-set) --- */
        {
            for (int idx = lis_start; idx < lis_end; idx++) {
                if (!(lis_rev[lmap[idx]] & POLLIN)) continue;
                const tunnel_listener_t *L = &lis[lmap[idx]];
                for (;;) {
                    int c = accept(L->listen_fd, NULL, NULL);
                    if (c < 0) break;
                    set_nonblock(c);
                    if (L->sni) {                                  /* defer until ClientHello peeked */
                        int placed = 0;
                        for (int j = 0; j < MAX_PEEKERS; j++)
                            if (!pk[j].active) { pk[j].active = 1; pk[j].fd = c; pk[j].len = 0; pk[j].since = now_ms();
                                                 pk[j].ep_armed = 0; pk[j].ep_rev = 0;   /* fresh fd: not yet in epoll */
                                                 placed = 1; break; }
                        if (!placed) { close(c); break; }
                    } else if (!open_public(st, &next_sid, c, L->forward_id, NULL, 0, tw, &twlen, NULL)) {
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
            if (s->connecting) {                          /* non-blocking connect completion */
                if (s->ep_rev & (POLLOUT | POLLERR | POLLHUP)) {
                    int err = 0; socklen_t el = sizeof err;
                    getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &err, &el);
                    if (err == 0) s->connecting = 0;      /* connected — normal I/O resumes next loop */
                    else send_reset(s, tw, &twlen);
                }
                continue;                                 /* no data I/O while still connecting */
            }
            if (s->ep_rev & POLLOUT) {
                ssize_t w = send(s->fd, s->tobuf + s->tooff, s->tolen - s->tooff, MSG_NOSIGNAL);
                if (w > 0) { s->tooff += (size_t)w; s->last_flush = now_ms(); if (s->tooff == s->tolen) {
                        s->tooff = s->tolen = 0;
                        if (s->remote_eof && !s->wr_shut) { shutdown(s->fd, SHUT_WR); s->wr_shut = 1; } } }
                else if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                    send_reset(s, tw, &twlen); continue;
                }
            }
            if (s->active && s->fd >= 0 && (s->ep_rev & (POLLIN | POLLHUP))) {
                unsigned char tmp[TUNNEL_MAX_FRAME];
                ssize_t n = read(s->fd, tmp, sizeof tmp);
                if (n > 0) { s->last_activity = now_ms(); s->activated = 1;
                    if (tw_frame(tw, &twlen, TF_DATA, s->sid, tmp, (uint32_t)n) < 0) { rc = -1; goto done; } }
                else if (n == 0) send_end(s, tw, &twlen);
                else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) send_reset(s, tw, &twlen);
            }
        }

        /* --- relay: feed SNI peekers (read newly-arrived ClientHello bytes) --- */
        for (int k = str_end; k < pk_end; k++) {
            struct peeker *q = pmap[k];
            if (!q->active || !(q->ep_rev & (POLLIN | POLLHUP))) continue;
            ssize_t n = read(q->fd, q->buf + q->len, PEEK_CAP - q->len);
            if (n <= 0) { if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) { close(q->fd); q->active = 0; } continue; }
            q->len += (size_t)n; q->since = now_ms();
        }
        /* Resolve+open any buffered peeker. Decoupled from POLLIN so a peeker that could
         * not be opened last iteration for lack of tw room (open_public *again*) is retried
         * once the tunnel drains — not stranded waiting for bytes that will never come. */
        for (int i = 0; i < MAX_PEEKERS; i++) {
            struct peeker *q = &pk[i];
            if (!q->active || q->len == 0) continue;
            char host[256];
            int r = tunnel_sni_peek(q->buf, q->len, host, sizeof host);
            if (r == 0) { if (q->len >= PEEK_CAP) { close(q->fd); q->active = 0; } continue; }  /* need more bytes */
            if (r < 0) { close(q->fd); q->active = 0; continue; }
            uint32_t fid;
            if (!sni_lookup(routes, nroutes, host, &fid)) { close(q->fd); q->active = 0; continue; }
            int again = 0;
            int pfd = q->fd;
            struct stream *s = open_public(st, &next_sid, q->fd, fid, q->buf, q->len, tw, &twlen, &again);
            if (s) {                                         /* fd ownership moved to the stream */
                if (q->ep_armed) epoll_ctl(ep, EPOLL_CTL_DEL, pfd, NULL);   /* drop the peeker registration; the
                                                              * stream re-ADDs the same fd under its tag next loop */
                q->ep_armed = 0; q->active = 0; q->fd = -1;
            }
            else if (!again) q->active = 0;                  /* slot exhausted: open_public closed the fd */
            /* else: no tw room yet — keep the peeker and retry next iteration */
        }

        /* --- reap: finished streams, stuck connects, idle peekers, and stuck streams
         *     (never-active or half-closed-lingering). A fully-open stream that has had
         *     activity and is merely quiet is NEVER reaped (legit idle, e.g. SSH). --- */
        long now = (any_connecting || idle_timeout_ms > 0) ? now_ms() : 0;
        for (int i = 0; i < MAX_STREAMS; i++) {
            if (!st[i].active || st[i].pending_reset) continue;       /* tombstones drain via flush */
            if (st[i].connecting) {                                   /* local target never came up */
                if (now >= st[i].connect_deadline) send_reset(&st[i], tw, &twlen);
                continue;
            }
            if (st[i].local_eof && st[i].remote_eof && st[i].tooff == st[i].tolen) { close_stream(&st[i]); continue; }
            /* M4: a stream whose local sink has refused every byte for idle_timeout_ms while data
             * is queued (tooff<tolen) is stuck — its backpressure holds up the shared tunnel for
             * every other stream. Reset it. A merely-slow-but-progressing sink keeps last_flush
             * fresh and is NOT reset; this is distinct from the quiet-but-healthy case below. */
            if (idle_timeout_ms > 0 && st[i].tooff < st[i].tolen && now - st[i].last_flush > idle_timeout_ms) {
                send_reset(&st[i], tw, &twlen); continue;
            }
            if (idle_timeout_ms > 0 && now - st[i].last_activity > idle_timeout_ms) {
                int half_closed = (st[i].remote_eof != st[i].local_eof);
                if (half_closed || !st[i].activated) send_reset(&st[i], tw, &twlen);   /* stuck, not legit-idle */
            }
        }
        if (idle_timeout_ms > 0)
            for (int i = 0; i < MAX_PEEKERS; i++)
                if (pk[i].active && now - pk[i].since > idle_timeout_ms) { close(pk[i].fd); pk[i].active = 0; }
    }

done:
    for (int i = 0; i < MAX_STREAMS; i++) if (st[i].active) close_stream(&st[i]);
    for (int i = 0; i < MAX_PEEKERS; i++) if (pk[i].active && pk[i].fd >= 0) close(pk[i].fd);
    close(ep); free(st); free(pk);
    return rc;
}

int tunnel_agent_serve(int tunnel_fd, const tunnel_target_t *forwards, size_t n_forwards) {
    tunnel_conn_t conn; tunnel_conn_fd(&conn, tunnel_fd);
    return serve_loop(&conn, 0, NULL, 0, forwards, n_forwards, NULL, 0, 0, 0, NULL, NULL);
}
int tunnel_agent_serve_ssl(SSL *tunnel, const tunnel_target_t *forwards, size_t n_forwards) {
    tunnel_conn_t conn; tunnel_conn_ssl(&conn, tunnel);
    return serve_loop(&conn, 0, NULL, 0, forwards, n_forwards, NULL, 0, 0, 0, NULL, NULL);
}

int tunnel_relay_serve(int tunnel_fd,
                       const tunnel_listener_t *listeners, size_t n_listeners,
                       const tunnel_sni_route_t *routes, size_t n_routes) {
    if (n_listeners > MAX_LISTENERS) n_listeners = MAX_LISTENERS;
    tunnel_conn_t conn; tunnel_conn_fd(&conn, tunnel_fd);
    return serve_loop(&conn, 1, listeners, n_listeners, NULL, 0, routes, n_routes, 0, 0, NULL, NULL);
}
int tunnel_relay_serve_ssl(SSL *tunnel,
                           const tunnel_listener_t *listeners, size_t n_listeners,
                           const tunnel_sni_route_t *routes, size_t n_routes) {
    if (n_listeners > MAX_LISTENERS) n_listeners = MAX_LISTENERS;
    tunnel_conn_t conn; tunnel_conn_ssl(&conn, tunnel);
    return serve_loop(&conn, 1, listeners, n_listeners, NULL, 0, routes, n_routes, 0, 0, NULL, NULL);
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
        if (tunnel_relay_accept(&io, &rdec, &h, tls.peer_id, cfg->forward_kinds, cfg->n_forwards,
                                cfg->allow, cfg->allow_ud, err, sizeof err) == 0) {
            /* H4: serve only the SNI routes THIS agent's verified identity is authorized for,
             * not the relay's whole table — so one tenant can't receive (and MITM) another
             * tenant's hostnames. With allow_all every route passes (single-tenant default). */
            tunnel_sni_route_t aroutes[64]; size_t naroutes = 0;
            for (size_t i = 0; i < cfg->n_routes && naroutes < 64; i++)
                if (!cfg->allow || cfg->allow(tls.peer_id, cfg->routes[i].host, cfg->allow_ud))
                    aroutes[naroutes++] = cfg->routes[i];
            tunnel_conn_t conn; tunnel_conn_ssl(&conn, tls.ssl);
            int idle = cfg->idle_timeout_ms > 0 ? cfg->idle_timeout_ms : 30000;
            serve_loop(&conn, 1, cfg->listeners, cfg->n_listeners, NULL, 0, aroutes, naroutes, hb, idle, &rdec, cfg->stop);
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

        tunnel_conn_t conn; tunnel_conn_ssl(&conn, tls.ssl);
        int idle = cfg->idle_timeout_ms > 0 ? cfg->idle_timeout_ms : 60000;
        long t0 = now_ms();
        serve_loop(&conn, 0, NULL, 0, cfg->forwards, cfg->n_forwards, NULL, 0, hb, idle, &rdec, cfg->stop);
        tunnel_tls_free(&tls);                        /* tunnel ended — reconnect */
        /* M10: only a session that actually stayed up resets the backoff. Registering and
         * then being dropped immediately is NOT progress — a flapping relay must not be
         * hammered at the floor interval; let the backoff keep growing. */
        if (now_ms() - t0 >= STABLE_SESSION_MS) backoff = bmin;

    retry:
        if (stopped(cfg)) break;
        rng = rng * 1103515245u + 12345u;            /* LCG; jitter need not be strong */
        int jitter = (backoff / 4 > 0) ? (int)(rng % (unsigned)(backoff / 4)) : 0;
        backoff_sleep(backoff + jitter, cfg);
        backoff = backoff * 2 > bmax ? bmax : backoff * 2;
    }
    return 0;
}
