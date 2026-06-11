/* End-to-end: a public client connects to the RELAY's tcp-forward port; the relay
 * opens a stream over the tunnel to the AGENT, which dials a local echo server. So
 * bytes travel  client -> relay -> tunnel -> agent -> echo -> ... all the way back.
 * Both halves of portico-tunnel running together. Covers a single request + half-close
 * propagation across both engines, two concurrent clients, and a 256 KiB transfer. */
#include "stream.h"

#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>

static int ok = 0, fail = 0;
static void chk(const char *n, int c) {
    printf("  %-5s %s\n", c ? "ok" : "FAIL", n);
    if (c) ok++; else fail++;
}

static int write_all(int fd, const void *b, size_t n) {
    const unsigned char *p = b; size_t off = 0;
    while (off < n) { ssize_t w = write(fd, p + off, n - off); if (w <= 0) return -1; off += (size_t)w; }
    return 0;
}
static int read_n(int fd, void *b, size_t n) {
    unsigned char *p = b; size_t got = 0;
    while (got < n) { ssize_t r = read(fd, p + got, n - got); if (r <= 0) break; got += (size_t)r; }
    return (int)got;
}

/* ---- local echo server (the agent's forward target) ---- */
struct echo_srv { int lfd; pthread_t acc; pthread_t conns[64]; int nconn;
                  struct sockaddr_in addr; volatile int stop; };
static void *echo_conn(void *p) {
    int c = (int)(intptr_t)p; unsigned char b[8192]; ssize_t n;
    while ((n = read(c, b, sizeof b)) > 0) if (write_all(c, b, (size_t)n) != 0) break;
    shutdown(c, SHUT_WR); close(c); return NULL;
}
static void *echo_acc(void *p) {
    struct echo_srv *s = p;
    for (;;) { int c = accept(s->lfd, NULL, NULL); if (c < 0) break;
        if (s->stop) { close(c); break; }
        if (s->nconn < 64) { pthread_create(&s->conns[s->nconn], NULL, echo_conn, (void *)(intptr_t)c); s->nconn++; }
        else close(c); }
    return NULL;
}

/* Bind 127.0.0.1:0, return fd + port. */
static int listen_loopback(char *port, size_t cap, struct sockaddr_in *addr) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&a, sizeof a) || listen(fd, 16)) { close(fd); return -1; }
    socklen_t al = sizeof a; getsockname(fd, (struct sockaddr *)&a, &al);
    if (port) snprintf(port, cap, "%d", ntohs(a.sin_port));
    if (addr) *addr = a;
    return fd;
}
static int connect_loopback(const char *port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = htons((uint16_t)atoi(port));
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) { close(fd); return -1; }
    return fd;
}

/* Drive OpenSSL just far enough to emit a ClientHello with `sni`; capture the bytes. */
static int capture_clienthello(const char *sni, unsigned char *out, size_t cap) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL *ssl = SSL_new(ctx);
    int sp[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
    fcntl(sp[0], F_SETFL, O_NONBLOCK);
    SSL_set_fd(ssl, sp[0]);
    if (sni) SSL_set_tlsext_host_name(ssl, sni);
    SSL_connect(ssl);
    ssize_t n = read(sp[1], out, cap);
    SSL_free(ssl); SSL_CTX_free(ctx); close(sp[0]); close(sp[1]);
    return (int)n;
}

static tunnel_target_t g_fwd[1];
static void *agent_thread(void *p) { tunnel_agent_serve((int)(intptr_t)p, g_fwd, 1); return NULL; }
struct relay_ctx { int tfd, tcp_lfd, sni_lfd; };
static void *relay_thread(void *p) {
    struct relay_ctx *r = p;
    tunnel_listener_t ls[2] = {
        { .listen_fd = r->tcp_lfd, .sni = 0, .forward_id = 0 },   /* tcp port-forward */
        { .listen_fd = r->sni_lfd, .sni = 1, .forward_id = 0 },   /* SNI-routed */
    };
    tunnel_sni_route_t routes[1] = { { .host = "sni.test", .forward_id = 0 } };
    tunnel_relay_serve(r->tfd, ls, 2, routes, 1);
    return NULL;
}

struct cli_wr { int fd; size_t n; };
static void *cli_writer(void *p) {
    struct cli_wr *w = p; unsigned char b[16384]; size_t sent = 0;
    while (sent < w->n) {
        size_t c = (w->n - sent < sizeof b) ? (w->n - sent) : sizeof b;
        for (size_t i = 0; i < c; i++) b[i] = (unsigned char)((sent + i) & 0xff);
        if (write_all(w->fd, b, c) != 0) break;
        sent += c;
    }
    return NULL;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    printf("== tunnel relay end-to-end ==\n");

    /* echo (agent's target) */
    struct echo_srv echo = {0};
    char eport[16];
    echo.lfd = listen_loopback(eport, sizeof eport, &echo.addr);
    pthread_create(&echo.acc, NULL, echo_acc, &echo);
    snprintf(g_fwd[0].host, sizeof g_fwd[0].host, "127.0.0.1");
    snprintf(g_fwd[0].port, sizeof g_fwd[0].port, "%s", eport);

    /* tunnel (socketpair) + agent + relay (public listener) */
    int tun[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, tun);
    pthread_t ag; pthread_create(&ag, NULL, agent_thread, (void *)(intptr_t)tun[1]);
    char pport[16], snport[16];
    int plfd  = listen_loopback(pport, sizeof pport, NULL);    /* tcp forward */
    int snlfd = listen_loopback(snport, sizeof snport, NULL);  /* SNI-routed */
    struct relay_ctx rc = { .tfd = tun[0], .tcp_lfd = plfd, .sni_lfd = snlfd };
    pthread_t rl; pthread_create(&rl, NULL, relay_thread, &rc);

    /* ---- 1. single request, full round trip + half-close all the way back ---- */
    {
        int c = connect_loopback(pport);
        const char *msg = "end to end!"; size_t ml = strlen(msg);
        write_all(c, msg, ml);
        char buf[64];
        int r = read_n(c, buf, ml);
        chk("client <-> relay <-> tunnel <-> agent <-> echo", r == (int)ml && memcmp(buf, msg, ml) == 0);
        shutdown(c, SHUT_WR);                       /* client half-closes */
        int e = (int)read(c, buf, sizeof buf);      /* EOF must propagate back end-to-end */
        chk("close propagates through both engines", e == 0);
        close(c);
    }

    /* ---- 2. two concurrent clients (two streams) stay independent ---- */
    {
        int c1 = connect_loopback(pport), c2 = connect_loopback(pport);
        write_all(c1, "AAAA", 4); write_all(c2, "BBBBBB", 6);
        char b1[16], b2[16];
        int r1 = read_n(c1, b1, 4), r2 = read_n(c2, b2, 6);
        chk("two public clients routed independently",
            r1 == 4 && memcmp(b1, "AAAA", 4) == 0 && r2 == 6 && memcmp(b2, "BBBBBB", 6) == 0);
        close(c1); close(c2);
    }

    /* ---- 3. 256 KiB through the whole path, byte-exact ---- */
    {
        int c = connect_loopback(pport);
        size_t N = 256u * 1024;
        struct cli_wr w = { .fd = c, .n = N };
        pthread_t wt; pthread_create(&wt, NULL, cli_writer, &w);
        size_t got = 0; int bad = 0; unsigned char b[16384];
        while (got < N) {
            ssize_t r = read(c, b, sizeof b);
            if (r <= 0) break;
            for (ssize_t i = 0; i < r; i++) if (b[i] != (unsigned char)((got + (size_t)i) & 0xff)) { bad = 1; break; }
            got += (size_t)r;
        }
        chk("256 KiB end-to-end, intact", got == N && !bad);
        pthread_join(wt, NULL);
        close(c);
    }

    /* ---- 4. SNI routing: a ClientHello with a known SNI reaches the forward ---- */
    {
        int c = connect_loopback(snport);
        unsigned char ch[4096];
        int chn = capture_clienthello("sni.test", ch, sizeof ch);
        write_all(c, ch, (size_t)chn);                 /* relay peeks SNI, routes, feeds bytes */
        unsigned char back[4096];
        int got = read_n(c, back, (size_t)chn);        /* echo returns the same bytes */
        chk("SNI-routed ClientHello bytes round-trip via the matched forward",
            chn > 0 && got == chn && memcmp(back, ch, (size_t)chn) == 0);
        close(c);
    }

    /* ---- 5. a ClientHello whose SNI matches no route is dropped ---- */
    {
        int c = connect_loopback(snport);
        unsigned char ch[4096];
        int chn = capture_clienthello("nope.test", ch, sizeof ch);
        write_all(c, ch, (size_t)chn);
        unsigned char back[64];
        int got = (int)read(c, back, sizeof back);     /* relay closes -> EOF */
        chk("unmatched SNI -> relay drops the connection", got == 0);
        close(c);
    }

    /* teardown: shutdown the tunnel (wakes both engines), join, then echo */
    shutdown(tun[0], SHUT_RDWR); shutdown(tun[1], SHUT_RDWR);
    pthread_join(rl, NULL); pthread_join(ag, NULL);
    close(tun[0]); close(tun[1]); close(plfd); close(snlfd);

    echo.stop = 1;
    int d = socket(AF_INET, SOCK_STREAM, 0);
    if (d >= 0) connect(d, (struct sockaddr *)&echo.addr, sizeof echo.addr);
    pthread_join(echo.acc, NULL);
    if (d >= 0) close(d);
    close(echo.lfd);
    for (int i = 0; i < echo.nconn; i++) pthread_join(echo.conns[i], NULL);

    printf("\n%s  (%d ok, %d failed)\n", fail ? "FAIL" : "PASS", ok, fail);
    return fail ? 1 : 0;
}
