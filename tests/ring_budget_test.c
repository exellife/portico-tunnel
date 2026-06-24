/* #49: the global ring-memory budget caps total receive-ring memory across ALL streams and is
 * deadlock-safe. Without a budget, N bulk streams over a real-RTT path each auto-tune their
 * window upward and would collectively allocate N × (multi-MB) of ring — unbounded by stream
 * count. With the budget, once total ring memory hits the cap, window GROWTH is denied; streams
 * keep their current window and still COMPLETE (denial throttles, never wedges).
 *
 * We set a deliberately tiny budget, run N concurrent downloads through a delay bridge (so the
 * credit loop has an RTT and the streams actually try to grow), and assert: (1) every stream
 * finishes intact (no deadlock from the gate), and (2) peak total ring memory stayed within a
 * small multiple of the budget — far below the tens of MB the same load reaches ungated. */
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
#include <netinet/in.h>
#include <arpa/inet.h>

#define NSTREAMS 6
#define XFER     (2u * 1024 * 1024)    /* bytes each stream downloads */
#define BUDGET   (2u * 1024 * 1024)    /* tiny global ring budget for the test */
#define RTT_MS   100
#define DELAY_MS (RTT_MS / 2)
#define DNBYTE   0x5a

static int ok = 0, fail = 0;
static void chk(const char *n, int c) { printf("  %-5s %s\n", c ? "ok" : "FAIL", n); if (c) ok++; else fail++; }
static void on_alarm(int s) { (void)s; const char *m = "\n[watchdog] timed out — budget gate deadlocked a stream\n"; if (write(2, m, strlen(m))) {} _exit(2); }
static long now_ms2(void) { struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return ts.tv_sec * 1000L + ts.tv_nsec / 1000000; }
static void set_nonblock(int fd) { int fl = fcntl(fd, F_GETFL, 0); if (fl != -1) fcntl(fd, F_SETFL, fl | O_NONBLOCK); }

/* ---- delay bridge (same shape as window_autotune_test): shuttle bytes with a fixed per-dir delay ---- */
#define DCHUNK 16384
#define DQCAP  1200
struct dchunk { unsigned char buf[DCHUNK]; size_t len, off; long release; };
struct dir { int src, dst; struct dchunk *q; int head, count; int src_eof; };
struct bridge { struct dir d[2]; volatile int stop; };
static void dir_init(struct dir *d, int src, int dst) { d->src = src; d->dst = dst; d->q = calloc(DQCAP, sizeof *d->q); d->head = d->count = 0; d->src_eof = 0; set_nonblock(src); set_nonblock(dst); }
static void *bridge_run(void *p) {
    struct bridge *b = p;
    while (!b->stop) {
        struct pollfd pf[4]; int map[4]; int n = 0; long now = now_ms2(); int timeout = 50;
        for (int i = 0; i < 2; i++) { struct dir *d = &b->d[i];
            if (!d->src_eof && d->count < DQCAP) { pf[n].fd = d->src; pf[n].events = POLLIN; pf[n].revents = 0; map[n] = i * 2; n++; }
            if (d->count > 0) { struct dchunk *h = &d->q[d->head]; long wait = h->release - now;
                if (wait <= 0) { pf[n].fd = d->dst; pf[n].events = POLLOUT; pf[n].revents = 0; map[n] = i * 2 + 1; n++; }
                else if (wait < timeout) timeout = (int)wait; } }
        if (n == 0 && b->stop) break;
        if (poll(pf, n, timeout) < 0 && errno != EINTR) break;
        now = now_ms2();
        for (int k = 0; k < n; k++) { struct dir *d = &b->d[map[k] / 2];
            if ((map[k] & 1) == 0) { if (!(pf[k].revents & (POLLIN | POLLHUP | POLLERR)) || d->count >= DQCAP) continue;
                int tail = (d->head + d->count) % DQCAP; struct dchunk *c = &d->q[tail];
                ssize_t r = read(d->src, c->buf, DCHUNK);
                if (r > 0) { c->len = (size_t)r; c->off = 0; c->release = now + DELAY_MS; d->count++; }
                else if (r == 0) d->src_eof = 1;
                else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) d->src_eof = 1;
            } else { if (!(pf[k].revents & POLLOUT)) continue;
                while (d->count > 0) { struct dchunk *h = &d->q[d->head]; if (h->release > now) break;
                    ssize_t w = write(d->dst, h->buf + h->off, h->len - h->off);
                    if (w > 0) { h->off += (size_t)w; if (h->off == h->len) { d->head = (d->head + 1) % DQCAP; d->count--; } }
                    else break; } } }
    }
    free(b->d[0].q); free(b->d[1].q); return NULL;
}

static int listen_lo(char *port, size_t cap) {
    int fd = socket(AF_INET, SOCK_STREAM, 0); int one = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {0}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&a, sizeof a) || listen(fd, 64)) { close(fd); return -1; }
    socklen_t al = sizeof a; getsockname(fd, (struct sockaddr *)&a, &al);
    if (port) snprintf(port, cap, "%d", ntohs(a.sin_port)); return fd;
}
static int connect_lo(const char *port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {0}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = htons((uint16_t)atoi(port));
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) { close(fd); return -1; } return fd;
}

/* bulk source: blast XFER bytes down each accepted conn */
struct blast { int lfd; volatile int stop; };
static void *backend(void *p) {
    struct blast *e = p; set_nonblock(e->lfd);
    int fds[NSTREAMS]; size_t sent[NSTREAMS]; int nf = 0;
    unsigned char buf[DCHUNK]; memset(buf, DNBYTE, sizeof buf);
    while (!e->stop) {
        struct pollfd pf[NSTREAMS + 1]; int n = 0; pf[n].fd = e->lfd; pf[n].events = POLLIN; pf[n].revents = 0; n++;
        for (int i = 0; i < nf; i++) { if (fds[i] < 0) continue; pf[n].fd = fds[i]; pf[n].events = POLLOUT; pf[n].revents = 0; n++; }
        if (poll(pf, n, 100) <= 0) continue;
        if (pf[0].revents & POLLIN) { int c; while ((c = accept(e->lfd, NULL, NULL)) >= 0 && nf < NSTREAMS) { set_nonblock(c); fds[nf] = c; sent[nf] = 0; nf++; } }
        int pi = 1;
        for (int i = 0; i < nf; i++) { if (fds[i] < 0) continue; struct pollfd *q = &pf[pi++];
            if (q->revents & POLLOUT) { size_t left = XFER - sent[i]; size_t c = left < sizeof buf ? left : sizeof buf;
                if (c) { ssize_t w = write(fds[i], buf, c); if (w > 0) sent[i] += (size_t)w; }
                if (sent[i] >= XFER) { close(fds[i]); fds[i] = -1; } } }
    }
    for (int i = 0; i < nf; i++) if (fds[i] >= 0) close(fds[i]); return NULL;
}

static tunnel_target_t g_fwd[1];
static void *agent_thread(void *p) { tunnel_agent_serve((int)(intptr_t)p, g_fwd, 1); return NULL; }
struct relay_ctx { int tfd, lfd; };
static void *relay_thread(void *p) { struct relay_ctx *r = p;
    tunnel_listener_t ls[1] = { { .listen_fd = r->lfd, .sni = 0, .forward_id = 0 } };
    tunnel_relay_serve(r->tfd, ls, 1, NULL, 0); return NULL; }

struct dl { int fd; size_t got; };
static void *reader(void *p) { struct dl *d = p; unsigned char b[65536];
    while (d->got < XFER) { ssize_t n = read(d->fd, b, sizeof b); if (n <= 0) break; d->got += (size_t)n; } return NULL; }

static volatile int g_mon_stop; static volatile size_t g_peak;
static void *monitor(void *p) { (void)p; while (!g_mon_stop) { size_t b = tunnel_debug_committed_bytes(); if (b > g_peak) g_peak = b; usleep(2000); } return NULL; }

int main(void) {
    signal(SIGPIPE, SIG_IGN); signal(SIGALRM, on_alarm); alarm(60);
    setvbuf(stdout, NULL, _IONBF, 0);
    tunnel_debug_set_ring_budget(BUDGET);     /* tiny budget so the gate engages under this load */
    printf("== ring budget: %d downloads x %uMB over %dms RTT, budget %uMB ==\n",
           NSTREAMS, XFER / 1024 / 1024, RTT_MS, BUDGET / 1024 / 1024);

    struct blast bk = {0}; char bport[16]; bk.lfd = listen_lo(bport, sizeof bport);
    pthread_t bt; pthread_create(&bt, NULL, backend, &bk);
    snprintf(g_fwd[0].host, sizeof g_fwd[0].host, "127.0.0.1");
    snprintf(g_fwd[0].port, sizeof g_fwd[0].port, "%s", bport);

    int ra[2], ag[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, ra); socketpair(AF_UNIX, SOCK_STREAM, 0, ag);
    struct bridge br = {0}; dir_init(&br.d[0], ra[1], ag[1]); dir_init(&br.d[1], ag[1], ra[1]);
    pthread_t brt; pthread_create(&brt, NULL, bridge_run, &br);
    pthread_t ag_t; pthread_create(&ag_t, NULL, agent_thread, (void *)(intptr_t)ag[0]);
    char pport[16]; int plfd = listen_lo(pport, sizeof pport);
    struct relay_ctx rc = { .tfd = ra[0], .lfd = plfd };
    pthread_t rl; pthread_create(&rl, NULL, relay_thread, &rc);
    pthread_t mon; pthread_create(&mon, NULL, monitor, NULL);
    usleep(100000);

    struct dl d[NSTREAMS]; pthread_t rt[NSTREAMS]; int conns = 0;
    for (int i = 0; i < NSTREAMS; i++) { d[i].fd = connect_lo(pport); d[i].got = 0; if (d[i].fd >= 0) conns++; }
    chk("all streams connected", conns == NSTREAMS);
    for (int i = 0; i < NSTREAMS; i++) pthread_create(&rt[i], NULL, reader, &d[i]);
    for (int i = 0; i < NSTREAMS; i++) pthread_join(rt[i], NULL);

    int done = 0; for (int i = 0; i < NSTREAMS; i++) { if (d[i].got == XFER) done++; if (d[i].fd >= 0) close(d[i].fd); }
    chk("all streams completed under the budget (gate never deadlocks)", done == NSTREAMS);
    g_mon_stop = 1; pthread_join(mon, NULL);
    /* Ungated, 6 streams over 100ms RTT each ratchet their window toward WND_MAX (8MB) = ~48MB
     * committed. The gate must hold committed near the budget — allow slack for the in-flight
     * grant that pushed it over, but assert it's far below the ungated total. */
    size_t bound = 4u * BUDGET;
    printf("  -> peak committed window credit: %zu KB (budget %u KB, assert < %zu KB)\n", g_peak / 1024, BUDGET / 1024, bound / 1024);
    chk("peak committed window credit stayed within the budget bound", g_peak < bound);

    shutdown(ra[0], SHUT_RDWR); shutdown(ag[0], SHUT_RDWR);
    pthread_join(rl, NULL); pthread_join(ag_t, NULL);
    br.stop = 1; shutdown(ra[1], SHUT_RDWR); shutdown(ag[1], SHUT_RDWR); pthread_join(brt, NULL);
    bk.stop = 1; pthread_join(bt, NULL); close(bk.lfd); close(plfd);
    close(ra[0]); close(ra[1]); close(ag[0]); close(ag[1]);
    printf("\n%s  (%d ok, %d failed)\n", fail ? "FAIL" : "PASS", ok, fail);
    return fail ? 1 : 0;
}
