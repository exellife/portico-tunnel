/* Single-thread ceiling probe (NOT a pass/fail unit test). One relay serve_loop + one
 * agent serve_loop (each its own thread, joined by a socketpair tunnel — no TLS, so this
 * isolates the stream-engine mux/poll cost) feed a poll-based echo backend. We then:
 *   Pass 1 (concurrency): ramp L concurrent persistent connections through the tcp-forward
 *           path, hold them all open, round-trip a small message on each. Reports the
 *           connection-open rate and per-stream round-trip latency at each L.
 *   Pass 2 (throughput): a handful of connections pumping bulk data full-duplex; reports
 *           aggregate MB/s carried by the single relay+agent threads.
 * Loopback, so relay/agent/echo/clients all share the box — on a many-core host each loop
 * gets its own core, so the number you see is ~the single-thread ceiling. Run:
 *   ./stress_test [max_conns]    (default 4000; MAX_STREAMS caps it at 4096)
 */
#include "stream.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <poll.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define ECHO_MAX  4200
#define ECHO_BUF  16384

static void on_alarm(int s) { (void)s; const char *m = "\n[watchdog] timed out — exiting\n"; if (write(2, m, strlen(m))) {} _exit(2); }
static long now_us(void) { struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return ts.tv_sec * 1000000L + ts.tv_nsec / 1000; }
static void set_nonblock(int fd) { int fl = fcntl(fd, F_GETFL, 0); if (fl != -1) fcntl(fd, F_SETFL, fl | O_NONBLOCK); }
static int write_all(int fd, const void *b, size_t n) { const unsigned char *p = b; size_t o = 0;
    while (o < n) { ssize_t w = write(fd, p + o, n - o); if (w <= 0) { if (w < 0 && (errno == EINTR)) continue; return -1; } o += (size_t)w; } return 0; }
static int read_n(int fd, void *b, size_t n) { unsigned char *p = b; size_t g = 0;
    while (g < n) { ssize_t r = read(fd, p + g, n - g); if (r <= 0) { if (r < 0 && errno == EINTR) continue; break; } g += (size_t)r; } return (int)g; }

/* ---- poll-based echo: one thread, many connections, backpressure-correct ---- */
struct econn { int fd; unsigned char buf[ECHO_BUF]; size_t off, len; };
struct echo { int lfd; volatile int stop; struct sockaddr_in addr; };
static void *echo_poll(void *p) {
    struct echo *e = p; set_nonblock(e->lfd);
    struct econn *cs = calloc(ECHO_MAX, sizeof *cs);
    struct pollfd *pf = calloc(ECHO_MAX + 1, sizeof *pf);
    int *map = calloc(ECHO_MAX + 1, sizeof *map);
    for (int i = 0; i < ECHO_MAX; i++) cs[i].fd = -1;
    while (!e->stop) {
        int n = 0;
        pf[n].fd = e->lfd; pf[n].events = POLLIN; pf[n].revents = 0; map[n] = -1; n++;
        for (int i = 0; i < ECHO_MAX; i++) {
            if (cs[i].fd < 0) continue;
            pf[n].fd = cs[i].fd; pf[n].events = (cs[i].len > cs[i].off) ? POLLOUT : POLLIN; pf[n].revents = 0; map[n] = i; n++;
        }
        if (poll(pf, n, 200) <= 0) continue;
        if (pf[0].revents & POLLIN)
            for (;;) { int c = accept(e->lfd, NULL, NULL); if (c < 0) break; set_nonblock(c);
                int s = -1; for (int i = 0; i < ECHO_MAX; i++) if (cs[i].fd < 0) { s = i; break; }
                if (s < 0) { close(c); continue; } cs[s].fd = c; cs[s].off = cs[s].len = 0; }
        for (int k = 1; k < n; k++) {
            struct econn *q = &cs[map[k]];
            if (q->fd < 0) continue;
            if (pf[k].revents & POLLOUT) {
                ssize_t w = write(q->fd, q->buf + q->off, q->len - q->off);
                if (w > 0) { q->off += (size_t)w; if (q->off == q->len) q->off = q->len = 0; }
                else if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK) { close(q->fd); q->fd = -1; }
            } else if (pf[k].revents & (POLLIN | POLLHUP)) {
                ssize_t r = read(q->fd, q->buf, sizeof q->buf);
                if (r > 0) { q->len = (size_t)r; q->off = 0; }
                else if (r == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) { close(q->fd); q->fd = -1; }
            }
        }
    }
    for (int i = 0; i < ECHO_MAX; i++) if (cs[i].fd >= 0) close(cs[i].fd);
    free(cs); free(pf); free(map); return NULL;
}

static int listen_lo(char *port, size_t cap, struct sockaddr_in *addr, int backlog) {
    int fd = socket(AF_INET, SOCK_STREAM, 0); int one = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {0}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&a, sizeof a) || listen(fd, backlog)) { close(fd); return -1; }
    socklen_t al = sizeof a; getsockname(fd, (struct sockaddr *)&a, &al);
    if (port) snprintf(port, cap, "%d", ntohs(a.sin_port)); if (addr) *addr = a; return fd;
}
static int connect_lo(const char *port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {0}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = htons((uint16_t)atoi(port));
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) { close(fd); return -1; }
    struct timeval tv = { 3, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);   /* never hang on a stuck stream */
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);   /* incl. a blocking writer */
    return fd;
}

static tunnel_target_t g_fwd[1];
static void *agent_thread(void *p) { tunnel_agent_serve((int)(intptr_t)p, g_fwd, 1); return NULL; }
struct relay_ctx { int tfd, lfd; };
static void *relay_thread(void *p) {
    struct relay_ctx *r = p;
    tunnel_listener_t ls[1] = { { .listen_fd = r->lfd, .sni = 0, .forward_id = 0 } };
    tunnel_relay_serve(r->tfd, ls, 1, NULL, 0); return NULL;
}

/* ---- Pass 2 throughput: per-conn writer + reader of M bytes ---- */
struct pump { const char *port; int fd; size_t bytes; };
static void *pump_writer(void *p) { struct pump *w = p; unsigned char b[16384]; memset(b, 0x5a, sizeof b);
    size_t s = 0; while (s < w->bytes) { size_t c = w->bytes - s < sizeof b ? w->bytes - s : sizeof b; if (write_all(w->fd, b, c)) break; s += c; } return NULL; }
static void *pump_reader(void *p) { struct pump *r = p; unsigned char b[16384]; size_t g = 0;
    while (g < r->bytes) { ssize_t n = read(r->fd, b, sizeof b); if (n <= 0) break; g += (size_t)n; } r->bytes = g; return NULL; }

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGALRM, on_alarm); alarm(90);   /* hard watchdog: a wedged path must never hang the probe */
    setvbuf(stdout, NULL, _IONBF, 0);   /* progress visible live even when piped */
    int maxc = argc > 1 ? atoi(argv[1]) : 4000;
    if (maxc > 4096) maxc = 4096;

    struct rlimit lim; getrlimit(RLIMIT_NOFILE, &lim);
    lim.rlim_cur = lim.rlim_max; setrlimit(RLIMIT_NOFILE, &lim);
    printf("== portico-tunnel stress probe ==  (fd limit %lu, max conns %d)\n", (unsigned long)lim.rlim_cur, maxc);

    struct echo echo = {0}; char eport[16];
    echo.lfd = listen_lo(eport, sizeof eport, &echo.addr, 4096);   /* deep backlog: agent dials one per stream */
    pthread_t et; pthread_create(&et, NULL, echo_poll, &echo);
    snprintf(g_fwd[0].host, sizeof g_fwd[0].host, "127.0.0.1");
    snprintf(g_fwd[0].port, sizeof g_fwd[0].port, "%s", eport);

    int tun[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, tun);
    pthread_t ag; pthread_create(&ag, NULL, agent_thread, (void *)(intptr_t)tun[1]);
    char pport[16]; int plfd = listen_lo(pport, sizeof pport, NULL, 4096);
    struct relay_ctx rc = { .tfd = tun[0], .lfd = plfd };
    pthread_t rl; pthread_create(&rl, NULL, relay_thread, &rc);
    usleep(100000);

    /* ---- Pass 1: concurrency ramp ---- */
    printf("\n-- concurrency: hold L streams open, round-trip 8B on each --\n");
    printf("  %8s %8s %10s %12s %12s\n", "target", "opened", "open_ms", "open/s", "rtt_avg_us");
    int levels[] = { 64, 256, 1024, 2048, maxc };
    int *fds = calloc(maxc, sizeof *fds);
    for (size_t li = 0; li < sizeof levels / sizeof *levels; li++) {
        int L = levels[li]; if (L > maxc) L = maxc;
        long t0 = now_us(); int opened = 0;
        for (int i = 0; i < L; i++) { int f = connect_lo(pport); if (f >= 0) fds[opened++] = f; }
        long t1 = now_us();
        /* round-trip a small message on each open stream (all L held open meanwhile) */
        int ok = 0; long rtt_sum = 0;
        for (int i = 0; i < opened; i++) {
            unsigned char m[8]; for (int j = 0; j < 8; j++) m[j] = (unsigned char)(i + j);
            long r0 = now_us();
            if (write_all(fds[i], m, 8) == 0) { unsigned char b[8]; if (read_n(fds[i], b, 8) == 8 && memcmp(b, m, 8) == 0) ok++; }
            rtt_sum += now_us() - r0;
        }
        for (int i = 0; i < opened; i++) close(fds[i]);
        double open_ms = (t1 - t0) / 1000.0;
        printf("  %8d %8d %10.1f %12.0f %12.1f   (%s rt %d/%d)\n",
               L, opened, open_ms, opened / ((t1 - t0) / 1e6), opened ? (double)rtt_sum / opened : 0,
               ok == opened ? "ok" : "PARTIAL", ok, opened);
        usleep(200000);   /* let streams fully drain/close between levels */
    }
    free(fds);

    /* ---- Pass 2: throughput. NOTE: K concurrent FULL-DUPLEX bulk streams expose the
     * engine's COARSE global backpressure — it stops reading the tunnel for ALL streams
     * whenever ANY one stream's local sink stalls, so concurrent bulk head-of-line-blocks
     * (K>=4 stalls). Single-stream is the clean per-stream throughput number; this is a
     * non-issue for small-message / request-response / WS traffic (see Pass 1 at 4000). ---- */
    printf("\n-- throughput: K concurrent full-duplex bulk streams (coarse-backpressure regime) --\n");
    int Ks[] = { 1, 2, 4 }; size_t M = 8u * 1024 * 1024;   /* per-conn bytes */
    for (size_t ki = 0; ki < sizeof Ks / sizeof *Ks; ki++) {
        int K = Ks[ki];
        usleep(1000000);   /* let the previous level's streams fully tear down before reusing the path */
        struct pump pw[32], prr[32]; pthread_t wt[32], rt[32]; int nok = 0, alive = 0;
        for (int i = 0; i < K; i++) { int f = connect_lo(pport); pw[i].fd = prr[i].fd = f; pw[i].bytes = prr[i].bytes = M; if (f >= 0) nok++; }
        for (int i = 0; i < K; i++) {   /* sanity: is the stream actually alive before we bulk-pump? */
            if (pw[i].fd < 0) continue;
            unsigned char m[8] = "ping!!!\n", b[8];
            if (write_all(pw[i].fd, m, 8) == 0 && read_n(pw[i].fd, b, 8) == 8) alive++;
        }
        long t0 = now_us();
        for (int i = 0; i < K; i++) { pthread_create(&rt[i], NULL, pump_reader, &prr[i]); pthread_create(&wt[i], NULL, pump_writer, &pw[i]); }
        for (int i = 0; i < K; i++) { pthread_join(wt[i], NULL); pthread_join(rt[i], NULL); }
        long t1 = now_us();
        size_t got = 0; for (int i = 0; i < K; i++) { got += prr[i].bytes; if (pw[i].fd >= 0) close(pw[i].fd); }
        double sec = (t1 - t0) / 1e6, mb = got / (1024.0 * 1024.0);
        printf("  K=%-3d (%2d conn, %2d alive)  %.0f MB in %.2fs  =>  %.0f MB/s  (%.2f Gbit/s)\n", K, nok, alive, mb, sec, sec > 0 ? mb / sec : 0, sec > 0 ? mb * 8 / 1024 / sec : 0);
        usleep(300000);
    }

    shutdown(tun[0], SHUT_RDWR); shutdown(tun[1], SHUT_RDWR);
    pthread_join(rl, NULL); pthread_join(ag, NULL);
    close(tun[0]); close(tun[1]); close(plfd);
    echo.stop = 1; pthread_join(et, NULL); close(echo.lfd);
    printf("\ndone.\n");
    return 0;
}
