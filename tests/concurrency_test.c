/* Regression for Phase 1 (per-stream flow control), modelled on the Phase 0 scenario:
 * N concurrent bulk DOWNLOADS must all complete and SHARE bandwidth — not collapse the way
 * coarse global backpressure did (Phase 0: 43 Mbit/s single-stream dropped to ~0 with 2+
 * concurrent; the loopback stress probe reproduced it). Path: client -> relay -> tunnel ->
 * agent -> bulk-source -> back, over a socketpair tunnel (no TLS, isolates the engine). Each
 * stream's agent dials a backend that blasts MBYTES down; the client just reads. With the
 * pre-Phase-1 engine the concurrent streams stall/collapse; fixed, all N complete. */
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

#define NSTREAMS  8
#define MBYTES    (4u * 1024 * 1024)    /* bytes each stream downloads */
#define BMAX      64
#define BBUF      16384

static int ok = 0, fail = 0;
static void chk(const char *n, int c) { printf("  %-5s %s\n", c ? "ok" : "FAIL", n); if (c) ok++; else fail++; }
static void on_alarm(int s) { (void)s; const char *m = "\n[watchdog] timed out — a collapse/deadlock\n"; if (write(2, m, strlen(m))) {} _exit(2); }
static long now_us(void) { struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return ts.tv_sec * 1000000L + ts.tv_nsec / 1000; }
static void set_nonblock(int fd) { int fl = fcntl(fd, F_GETFL, 0); if (fl != -1) fcntl(fd, F_SETFL, fl | O_NONBLOCK); }

/* ---- poll-based bulk SOURCE: on accept, blast MBYTES down each conn, then close ---- */
struct bconn { int fd; size_t sent; };
struct blast { int lfd; volatile int stop; };
static void *blast_send(void *p) {
    struct blast *e = p; set_nonblock(e->lfd);
    struct bconn *cs = calloc(BMAX, sizeof *cs); struct pollfd *pf = calloc(BMAX + 1, sizeof *pf); int *map = calloc(BMAX + 1, sizeof *map);
    unsigned char buf[BBUF]; memset(buf, 0xa5, sizeof buf);
    for (int i = 0; i < BMAX; i++) cs[i].fd = -1;
    while (!e->stop) {
        int n = 0; pf[0].fd = e->lfd; pf[0].events = POLLIN; pf[0].revents = 0; map[0] = -1; n++;
        for (int i = 0; i < BMAX; i++) { if (cs[i].fd < 0) continue; pf[n].fd = cs[i].fd; pf[n].events = POLLOUT; pf[n].revents = 0; map[n] = i; n++; }
        if (poll(pf, n, 200) <= 0) continue;
        if (pf[0].revents & POLLIN) for (;;) { int c = accept(e->lfd, NULL, NULL); if (c < 0) break; set_nonblock(c);
            int s = -1; for (int i = 0; i < BMAX; i++) if (cs[i].fd < 0) { s = i; break; }
            if (s < 0) { close(c); continue; } cs[s].fd = c; cs[s].sent = 0; }
        for (int k = 1; k < n; k++) { struct bconn *q = &cs[map[k]]; if (q->fd < 0) continue;
            if (pf[k].revents & POLLOUT) { size_t left = (size_t)MBYTES - q->sent; size_t c = left < sizeof buf ? left : sizeof buf;
                ssize_t w = write(q->fd, buf, c);
                if (w > 0) { q->sent += (size_t)w; if (q->sent >= (size_t)MBYTES) { close(q->fd); q->fd = -1; } }
                else if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) { close(q->fd); q->fd = -1; } } }
    }
    for (int i = 0; i < BMAX; i++) if (cs[i].fd >= 0) close(cs[i].fd);
    free(cs); free(pf); free(map); return NULL;
}

static int listen_lo(char *port, size_t cap, int backlog) {
    int fd = socket(AF_INET, SOCK_STREAM, 0); int one = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {0}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&a, sizeof a) || listen(fd, backlog)) { close(fd); return -1; }
    socklen_t al = sizeof a; getsockname(fd, (struct sockaddr *)&a, &al);
    if (port) snprintf(port, cap, "%d", ntohs(a.sin_port)); return fd;
}
static int connect_lo(const char *port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {0}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = htons((uint16_t)atoi(port));
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) { close(fd); return -1; }
    struct timeval tv = { 10, 0 }; setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    return fd;
}

static tunnel_target_t g_fwd[1];
static void *agent_thread(void *p) { tunnel_agent_serve((int)(intptr_t)p, g_fwd, 1); return NULL; }
struct relay_ctx { int tfd, lfd; };
static void *relay_thread(void *p) { struct relay_ctx *r = p;
    tunnel_listener_t ls[1] = { { .listen_fd = r->lfd, .sni = 0, .forward_id = 0 } };
    tunnel_relay_serve(r->tfd, ls, 1, NULL, 0); return NULL; }

struct dl { int fd; size_t got; };
static void *reader(void *p) { struct dl *d = p; unsigned char b[16384]; size_t g = 0;
    while (g < MBYTES) { ssize_t n = read(d->fd, b, sizeof b); if (n <= 0) {
        if (n < 0) fprintf(stderr, "  [reader fd=%d got=%zu] read=%zd errno=%d (%s)\n", d->fd, g, n, errno, strerror(errno)); break; } g += (size_t)n; }
    d->got = g; return NULL; }

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGALRM, on_alarm); alarm(45);          /* a collapse/deadlock must fail, not hang CI */
    setvbuf(stdout, NULL, _IONBF, 0);
    struct rlimit lim; getrlimit(RLIMIT_NOFILE, &lim); lim.rlim_cur = lim.rlim_max; setrlimit(RLIMIT_NOFILE, &lim);
    printf("== concurrency: %d simultaneous bulk downloads, %u MB each ==\n", NSTREAMS, MBYTES / 1024 / 1024);

    struct blast bk = {0}; char bport[16];
    bk.lfd = listen_lo(bport, sizeof bport, 64);
    pthread_t bt; pthread_create(&bt, NULL, blast_send, &bk);
    snprintf(g_fwd[0].host, sizeof g_fwd[0].host, "127.0.0.1");
    snprintf(g_fwd[0].port, sizeof g_fwd[0].port, "%s", bport);

    int tun[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, tun);
    pthread_t ag; pthread_create(&ag, NULL, agent_thread, (void *)(intptr_t)tun[1]);
    char pport[16]; int plfd = listen_lo(pport, sizeof pport, 64);
    struct relay_ctx rc = { .tfd = tun[0], .lfd = plfd };
    pthread_t rl; pthread_create(&rl, NULL, relay_thread, &rc);
    usleep(100000);

    struct dl d[NSTREAMS]; pthread_t rt[NSTREAMS]; int conns = 0;
    for (int i = 0; i < NSTREAMS; i++) { d[i].fd = connect_lo(pport); d[i].got = 0; if (d[i].fd >= 0) conns++; }
    chk("all streams connected", conns == NSTREAMS);

    long t0 = now_us();
    for (int i = 0; i < NSTREAMS; i++) pthread_create(&rt[i], NULL, reader, &d[i]);
    for (int i = 0; i < NSTREAMS; i++) pthread_join(rt[i], NULL);
    long t1 = now_us();

    int done = 0; for (int i = 0; i < NSTREAMS; i++) { if (d[i].got == MBYTES) done++; if (d[i].fd >= 0) close(d[i].fd); }
    chk("all streams downloaded their full payload concurrently (no collapse)", done == NSTREAMS);
    double sec = (t1 - t0) / 1e6, mb = (double)NSTREAMS * MBYTES / (1024 * 1024);
    printf("  -> %d/%d streams, %.0f MB in %.2fs = %.0f MB/s aggregate\n", done, NSTREAMS, mb, sec, sec > 0 ? mb / sec : 0);

    shutdown(tun[0], SHUT_RDWR); shutdown(tun[1], SHUT_RDWR);
    pthread_join(rl, NULL); pthread_join(ag, NULL); close(tun[0]); close(tun[1]); close(plfd);
    bk.stop = 1; pthread_join(bt, NULL); close(bk.lfd);
    printf("\n%s  (%d ok, %d failed)\n", fail ? "FAIL" : "PASS", ok, fail);
    return fail ? 1 : 0;
}
