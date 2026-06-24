/* #48 regression: the per-stream window AUTO-TUNES to the bandwidth-delay product.
 *
 * On loopback (concurrency_test) the RTT is ~0, so a stream never starves and the window
 * never grows — that path can't prove autotuning. Here we splice a DELAY BRIDGE between the
 * relay and agent tunnel fds (a thread that shuttles bytes with a fixed per-direction delay),
 * giving the credit loop a real RTT. A single bulk download then runs through
 * client -> relay -> [delay] -> agent -> source. With a FIXED WND_INIT window the throughput
 * ceiling is wnd/RTT; only if the window grows past WND_INIT can the transfer beat that floor.
 * So: assert the transfer completes far faster than the fixed-window floor allows (proving the
 * window climbed toward the BDP) AND that the bytes are intact. The sink (client) is fast, so
 * the receiver's grow-gate (ring near-empty) is satisfied — exactly the window-limited case. */
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

#define XFER     (12u * 1024 * 1024)   /* bytes to download */
#define RTT_MS   100                   /* injected round trip (50 ms each direction) */
#define DELAY_MS (RTT_MS / 2)
/* Fixed-WND_INIT (256 KB) ceiling is wnd/RTT = 256 KB / 0.1 s = 2.56 MB/s -> 12 MB takes >=4.6 s.
 * Growth toward the multi-MB cap blows past that. A 2.5 s bar sits well under the no-growth floor
 * yet far above the ~0.5 s a grown window needs — proving growth without being timing-fragile. */
#define MAX_SEC  2.5

static int ok = 0, fail = 0;
static void chk(const char *n, int c) { printf("  %-5s %s\n", c ? "ok" : "FAIL", n); if (c) ok++; else fail++; }
static void on_alarm(int s) { (void)s; const char *m = "\n[watchdog] timed out — credit deadlock or window never grew\n"; if (write(2, m, strlen(m))) {} _exit(2); }
static long now_us(void) { struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return ts.tv_sec * 1000000L + ts.tv_nsec / 1000; }
static long now_ms2(void) { return now_us() / 1000; }
static void set_nonblock(int fd) { int fl = fcntl(fd, F_GETFL, 0); if (fl != -1) fcntl(fd, F_SETFL, fl | O_NONBLOCK); }

/* ---- delay bridge: shuttle bytes src->dst, each chunk released DELAY_MS after it arrived ---- */
#define DCHUNK 16384
#define DQCAP  1200                    /* 1200 * 16 KB ~= 18 MB in flight — covers a grown window */
struct dchunk { unsigned char buf[DCHUNK]; size_t len, off; long release; };
struct dir { int src, dst; struct dchunk *q; int head, count; int src_eof; };
struct bridge { struct dir d[2]; volatile int stop; };

static void dir_init(struct dir *d, int src, int dst) {
    d->src = src; d->dst = dst; d->q = calloc(DQCAP, sizeof *d->q); d->head = d->count = 0; d->src_eof = 0;
    set_nonblock(src); set_nonblock(dst);
}
static void *bridge_run(void *p) {
    struct bridge *b = p;
    while (!b->stop) {
        struct pollfd pf[4]; int map[4]; int n = 0; long now = now_ms2(); int timeout = 50;
        for (int i = 0; i < 2; i++) {
            struct dir *d = &b->d[i];
            if (!d->src_eof && d->count < DQCAP) { pf[n].fd = d->src; pf[n].events = POLLIN; pf[n].revents = 0; map[n] = i * 2; n++; }
            if (d->count > 0) {                                  /* head waiting to be written */
                struct dchunk *h = &d->q[d->head];
                long wait = h->release - now;
                if (wait <= 0) { pf[n].fd = d->dst; pf[n].events = POLLOUT; pf[n].revents = 0; map[n] = i * 2 + 1; n++; }
                else if (wait < timeout) timeout = (int)wait;    /* wake when the head is due */
            }
        }
        if (n == 0 && b->stop) break;
        if (poll(pf, n, timeout) < 0 && errno != EINTR) break;
        now = now_ms2();
        for (int k = 0; k < n; k++) {
            struct dir *d = &b->d[map[k] / 2];
            if ((map[k] & 1) == 0) {                             /* readable: enqueue a delayed chunk */
                if (!(pf[k].revents & (POLLIN | POLLHUP | POLLERR)) || d->count >= DQCAP) continue;
                int tail = (d->head + d->count) % DQCAP; struct dchunk *c = &d->q[tail];
                ssize_t r = read(d->src, c->buf, DCHUNK);
                if (r > 0) { c->len = (size_t)r; c->off = 0; c->release = now + DELAY_MS; d->count++; }
                else if (r == 0) d->src_eof = 1;
                else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) d->src_eof = 1;
            } else {                                             /* writable: flush any due head chunks */
                if (!(pf[k].revents & POLLOUT)) continue;
                while (d->count > 0) {
                    struct dchunk *h = &d->q[d->head];
                    if (h->release > now) break;
                    ssize_t w = write(d->dst, h->buf + h->off, h->len - h->off);
                    if (w > 0) { h->off += (size_t)w; if (h->off == h->len) { d->head = (d->head + 1) % DQCAP; d->count--; } }
                    else break;                                  /* EAGAIN: POLLOUT will refire */
                }
            }
        }
    }
    free(b->d[0].q); free(b->d[1].q); return NULL;
}

static int listen_lo(char *port, size_t cap) {
    int fd = socket(AF_INET, SOCK_STREAM, 0); int one = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {0}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&a, sizeof a) || listen(fd, 16)) { close(fd); return -1; }
    socklen_t al = sizeof a; getsockname(fd, (struct sockaddr *)&a, &al);
    if (port) snprintf(port, cap, "%d", ntohs(a.sin_port)); return fd;
}
static int connect_lo(const char *port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {0}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = htons((uint16_t)atoi(port));
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) { close(fd); return -1; }
    return fd;
}

/* ---- bulk SOURCE: accept one conn, blast XFER bytes of 0xa5 (blocking writes) ---- */
struct blast { int lfd; };
static void *blast_send(void *p) {
    struct blast *e = p; int c = accept(e->lfd, NULL, NULL); if (c < 0) return NULL;
    unsigned char buf[DCHUNK]; memset(buf, 0xa5, sizeof buf); size_t sent = 0;
    while (sent < XFER) { size_t left = XFER - sent; size_t want = left < sizeof buf ? left : sizeof buf;
        ssize_t w = write(c, buf, want); if (w <= 0) { if (errno == EINTR) continue; break; } sent += (size_t)w; }
    close(c); return NULL;
}

static tunnel_target_t g_fwd[1];
static void *agent_thread(void *p) { tunnel_agent_serve((int)(intptr_t)p, g_fwd, 1); return NULL; }
struct relay_ctx { int tfd, lfd; };
static void *relay_thread(void *p) { struct relay_ctx *r = p;
    tunnel_listener_t ls[1] = { { .listen_fd = r->lfd, .sni = 0, .forward_id = 0 } };
    tunnel_relay_serve(r->tfd, ls, 1, NULL, 0); return NULL; }

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGALRM, on_alarm); alarm(20);
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("== window autotune: %u MB single download over a %d ms RTT bridge ==\n", XFER / 1024 / 1024, RTT_MS);

    struct blast bk = {0}; char bport[16];
    bk.lfd = listen_lo(bport, sizeof bport);
    pthread_t bt; pthread_create(&bt, NULL, blast_send, &bk);
    snprintf(g_fwd[0].host, sizeof g_fwd[0].host, "127.0.0.1");
    snprintf(g_fwd[0].port, sizeof g_fwd[0].port, "%s", bport);

    /* relay tunnel fd = ra[0]; agent tunnel fd = ag[0]; bridge delays ra[1] <-> ag[1]. */
    int ra[2], ag[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, ra); socketpair(AF_UNIX, SOCK_STREAM, 0, ag);
    struct bridge br = {0};
    dir_init(&br.d[0], ra[1], ag[1]);    /* relay -> agent (carries grants/WNDREQ replies) */
    dir_init(&br.d[1], ag[1], ra[1]);    /* agent -> relay (carries the bulk DATA) */
    pthread_t brt; pthread_create(&brt, NULL, bridge_run, &br);

    pthread_t ag_t; pthread_create(&ag_t, NULL, agent_thread, (void *)(intptr_t)ag[0]);
    char pport[16]; int plfd = listen_lo(pport, sizeof pport);
    struct relay_ctx rc = { .tfd = ra[0], .lfd = plfd };
    pthread_t rl; pthread_create(&rl, NULL, relay_thread, &rc);
    usleep(100000);

    int cfd = connect_lo(pport);
    chk("client connected", cfd >= 0);

    long t0 = now_us(); size_t got = 0; int bad = 0; unsigned char b[65536];
    while (got < XFER) { ssize_t n = read(cfd, b, sizeof b); if (n <= 0) break;
        for (ssize_t i = 0; i < n; i++) if (b[i] != 0xa5) { bad = 1; break; } got += (size_t)n; }
    double sec = (now_us() - t0) / 1e6;

    chk("full payload downloaded", got == XFER);
    chk("bytes intact (ring growth/wrap correct)", bad == 0);
    double mbps = sec > 0 ? (double)XFER / (1024 * 1024) / sec : 0;
    double floor_mbps = 256.0 / 1024.0 / (RTT_MS / 1000.0);   /* WND_INIT/RTT, the no-growth ceiling */
    printf("  -> %u MB in %.2fs = %.1f MB/s (fixed-WND_INIT ceiling ~%.1f MB/s)\n",
           XFER / 1024 / 1024, sec, mbps, floor_mbps);
    chk("beat the fixed-window floor (window auto-tuned up to the BDP)", sec < MAX_SEC);

    if (cfd >= 0) close(cfd);
    shutdown(ra[0], SHUT_RDWR); shutdown(ag[0], SHUT_RDWR);
    pthread_join(rl, NULL); pthread_join(ag_t, NULL);
    br.stop = 1; shutdown(ra[1], SHUT_RDWR); shutdown(ag[1], SHUT_RDWR); pthread_join(brt, NULL);
    pthread_join(bt, NULL); close(bk.lfd); close(plfd);
    close(ra[0]); close(ra[1]); close(ag[0]); close(ag[1]);
    printf("\n%s  (%d ok, %d failed)\n", fail ? "FAIL" : "PASS", ok, fail);
    return fail ? 1 : 0;
}
