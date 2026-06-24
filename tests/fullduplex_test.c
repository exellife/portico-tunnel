/* #46: does the engine handle concurrent FULL-DUPLEX bulk (large up AND down at once on the
 * same stream)? The earlier stall in tests/concurrency_test's full-duplex variant was suspected
 * to be a half-duplex ECHO harness artifact (a backend that reads X fully *then* writes X back
 * deadlocks against a client that writes X fully *then* reads — pure application coupling, no
 * tunnel involved). This isolates the engine: BOTH ends are genuinely full-duplex (concurrent
 * read+write), so the only thing that can stall is the tunnel itself.
 *
 *   client[i] writer  --0xa5 x MB-->  relay -> tunnel -> agent -> backend (drains + verifies)
 *   client[i] reader  <--0x5a x MB--  relay <- tunnel <- agent <- backend (blasts down)
 *
 * Each of the N streams must move MB up AND MB down. A real conn-level deadlock (e.g. tw/credit
 * head-of-line) hangs -> the watchdog fails the test. Success = every direction completes intact. */
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define NSTREAMS 8
#define MBYTES   (4u * 1024 * 1024)    /* bytes each stream moves in EACH direction */
#define UPBYTE   0xa5                  /* client -> backend */
#define DNBYTE   0x5a                  /* backend -> client */
#define BMAX     64
#define BBUF     16384

static int ok = 0, fail = 0;
static void chk(const char *n, int c) { printf("  %-5s %s\n", c ? "ok" : "FAIL", n); if (c) ok++; else fail++; }

/* live progress, so a hang shows WHERE each direction stalled (set in main) */
struct cli { int fd; volatile size_t up, down; int down_bad; };
static struct cli *g_c; static int g_n; static volatile size_t g_backend_recv;
static void on_alarm(int s) { (void)s;
    char buf[512]; int o = snprintf(buf, sizeof buf, "\n[watchdog] STALL @ %u MB target. backend_recv=%zuKB\n",
                                    MBYTES / 1024 / 1024, g_backend_recv / 1024);
    for (int i = 0; i < g_n && o < (int)sizeof buf - 64; i++)
        o += snprintf(buf + o, sizeof buf - o, "  stream %d: up=%zuKB down=%zuKB\n", i, g_c[i].up / 1024, g_c[i].down / 1024);
    if (write(2, buf, o)) {} _exit(2); }
static void set_nonblock(int fd) { int fl = fcntl(fd, F_GETFL, 0); if (fl != -1) fcntl(fd, F_SETFL, fl | O_NONBLOCK); }

/* ---- full-duplex backend: per conn, simultaneously drain+verify the upload AND blast the download ---- */
struct bconn { int fd; size_t sent, recv; int wr_done, rd_done, bad; };
struct blast { int lfd; volatile int stop; size_t up_total, up_bad; };
static void *backend(void *p) {
    struct blast *e = p; set_nonblock(e->lfd);
    struct bconn *cs = calloc(BMAX, sizeof *cs); struct pollfd *pf = calloc(BMAX + 1, sizeof *pf); int *map = calloc(BMAX + 1, sizeof *map);
    unsigned char out[BBUF]; memset(out, DNBYTE, sizeof out); unsigned char in[BBUF];
    for (int i = 0; i < BMAX; i++) cs[i].fd = -1;
    while (!e->stop) {
        int n = 0; pf[0].fd = e->lfd; pf[0].events = POLLIN; pf[0].revents = 0; map[0] = -1; n++;
        for (int i = 0; i < BMAX; i++) { if (cs[i].fd < 0) continue; short ev = 0;
            if (!cs[i].rd_done) ev |= POLLIN; if (!cs[i].wr_done) ev |= POLLOUT;
            if (!ev) continue; pf[n].fd = cs[i].fd; pf[n].events = ev; pf[n].revents = 0; map[n] = i; n++; }
        if (poll(pf, n, 200) <= 0) continue;
        if (pf[0].revents & POLLIN) for (;;) { int c = accept(e->lfd, NULL, NULL); if (c < 0) break; set_nonblock(c);
            int s = -1; for (int i = 0; i < BMAX; i++) if (cs[i].fd < 0) { s = i; break; }
            if (s < 0) { close(c); continue; } cs[s] = (struct bconn){ .fd = c }; }
        for (int k = 1; k < n; k++) { struct bconn *q = &cs[map[k]]; if (q->fd < 0) continue;
            if (pf[k].revents & POLLOUT) { size_t left = (size_t)MBYTES - q->sent; size_t c = left < sizeof out ? left : sizeof out;
                if (c) { ssize_t w = write(q->fd, out, c);
                    if (w > 0) q->sent += (size_t)w;
                    else if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) { q->wr_done = 1; } }
                if (q->sent >= (size_t)MBYTES && !q->wr_done) { shutdown(q->fd, SHUT_WR); q->wr_done = 1; } }
            if (pf[k].revents & (POLLIN | POLLHUP)) { ssize_t r = read(q->fd, in, sizeof in);
                if (r > 0) { for (ssize_t i = 0; i < r; i++) if (in[i] != UPBYTE) { q->bad = 1; break; } q->recv += (size_t)r; g_backend_recv += (size_t)r; }
                else if (r == 0) q->rd_done = 1;
                else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) q->rd_done = 1; }
            if (q->wr_done && q->rd_done) { e->up_total += q->recv; e->up_bad += q->bad; close(q->fd); q->fd = -1; } }
    }
    for (int i = 0; i < BMAX; i++) if (cs[i].fd >= 0) { e->up_total += cs[i].recv; e->up_bad += cs[i].bad; close(cs[i].fd); }
    free(cs); free(pf); free(map); return NULL;
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
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) { close(fd); return -1; }
    return fd;
}

static tunnel_target_t g_fwd[1];
static void *agent_thread(void *p) { tunnel_agent_serve((int)(intptr_t)p, g_fwd, 1); return NULL; }
struct relay_ctx { int tfd, lfd; };
static void *relay_thread(void *p) { struct relay_ctx *r = p;
    tunnel_listener_t ls[1] = { { .listen_fd = r->lfd, .sni = 0, .forward_id = 0 } };
    tunnel_relay_serve(r->tfd, ls, 1, NULL, 0); return NULL; }

/* ---- client: a writer thread (blast up) + a reader thread (drain+verify down) per stream ---- */
static void *cli_writer(void *p) { struct cli *c = p; unsigned char b[BBUF]; memset(b, UPBYTE, sizeof b);
    while (c->up < MBYTES) { size_t left = MBYTES - c->up; size_t w = left < sizeof b ? left : sizeof b;
        ssize_t n = write(c->fd, b, w); if (n <= 0) { if (n < 0 && errno == EINTR) continue; break; } c->up += (size_t)n; }
    shutdown(c->fd, SHUT_WR); return NULL; }
static void *cli_reader(void *p) { struct cli *c = p; unsigned char b[BBUF];
    while (c->down < MBYTES) { ssize_t n = read(c->fd, b, sizeof b); if (n <= 0) break;
        for (ssize_t i = 0; i < n; i++) if (b[i] != DNBYTE) { c->down_bad = 1; break; } c->down += (size_t)n; }
    return NULL; }

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGALRM, on_alarm); alarm(15);
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("== full-duplex: %d streams, %u MB UP + %u MB DOWN each, concurrently ==\n",
           NSTREAMS, MBYTES / 1024 / 1024, MBYTES / 1024 / 1024);

    struct blast bk = {0}; char bport[16];
    bk.lfd = listen_lo(bport, sizeof bport);
    pthread_t bt; pthread_create(&bt, NULL, backend, &bk);
    snprintf(g_fwd[0].host, sizeof g_fwd[0].host, "127.0.0.1");
    snprintf(g_fwd[0].port, sizeof g_fwd[0].port, "%s", bport);

    int tun[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, tun);
    pthread_t ag; pthread_create(&ag, NULL, agent_thread, (void *)(intptr_t)tun[1]);
    char pport[16]; int plfd = listen_lo(pport, sizeof pport);
    struct relay_ctx rc = { .tfd = tun[0], .lfd = plfd };
    pthread_t rl; pthread_create(&rl, NULL, relay_thread, &rc);
    usleep(100000);

    struct cli c[NSTREAMS]; pthread_t wr[NSTREAMS], rd[NSTREAMS]; int conns = 0;
    g_c = c; g_n = NSTREAMS;
    for (int i = 0; i < NSTREAMS; i++) { memset(&c[i], 0, sizeof c[i]); c[i].fd = connect_lo(pport); if (c[i].fd >= 0) conns++; }
    chk("all streams connected", conns == NSTREAMS);

    for (int i = 0; i < NSTREAMS; i++) { pthread_create(&wr[i], NULL, cli_writer, &c[i]); pthread_create(&rd[i], NULL, cli_reader, &c[i]); }
    for (int i = 0; i < NSTREAMS; i++) { pthread_join(wr[i], NULL); pthread_join(rd[i], NULL); }

    int up_ok = 0, dn_ok = 0, dn_bad = 0;
    for (int i = 0; i < NSTREAMS; i++) { if (c[i].up == MBYTES) up_ok++; if (c[i].down == MBYTES) dn_ok++; if (c[i].down_bad) dn_bad++; if (c[i].fd >= 0) close(c[i].fd); }
    chk("all streams uploaded their full payload (no stall)", up_ok == NSTREAMS);
    chk("all streams downloaded their full payload (no stall)", dn_ok == NSTREAMS);
    chk("downloaded bytes intact", dn_bad == 0);

    shutdown(tun[0], SHUT_RDWR); shutdown(tun[1], SHUT_RDWR);
    pthread_join(rl, NULL); pthread_join(ag, NULL); close(tun[0]); close(tun[1]); close(plfd);
    bk.stop = 1; pthread_join(bt, NULL); close(bk.lfd);
    chk("backend received every uploaded byte intact", bk.up_total == (size_t)NSTREAMS * MBYTES && bk.up_bad == 0);

    printf("\n%s  (%d ok, %d failed)\n", fail ? "FAIL" : "PASS", ok, fail);
    return fail ? 1 : 0;
}
