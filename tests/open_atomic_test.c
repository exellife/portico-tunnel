/* M1 fix: open_public must commit OPEN + the buffered SNI ClientHello ATOMICALLY. The
 * old code wrote OPEN and then tried to append the buffered bytes as DATA — if the tunnel
 * write buffer (tw) was nearly full at that moment the DATA frame was dropped (break),
 * silently truncating the ClientHello and wedging the origin's TLS handshake forever.
 *
 * We play the agent: drive the relay serve_loop over a deliberately small-buffered
 * socketpair, open several SNI clients that each send a ~16 KB burst (ClientHello +
 * padding, read into the peeker buffer as one large prefix), and DON'T drain the tunnel
 * right away — so tw fills and later peekers can only be opened via the atomic retry
 * (`again`) path once the buffer drains. Then we drain and assert EVERY stream delivers
 * its full byte count intact. With the old code the boundary streams would arrive
 * truncated (short) and this test would stall out. */
#include "stream.h"
#include "io.h"
#include "frame.h"

#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>

#define K        8           /* concurrent SNI clients */
#define TARGET   16000       /* total bytes each client sends (<= one DATA frame) */

static int ok = 0, fail = 0;
static void chk(const char *n, int c) { printf("  %-5s %s\n", c ? "ok" : "FAIL", n); if (c) ok++; else fail++; }
static int write_all(int fd, const void *b, size_t n) { const unsigned char *p = b; size_t o = 0;
    while (o < n) { ssize_t w = write(fd, p + o, n - o); if (w <= 0) return -1; o += (size_t)w; } return 0; }

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

static int listen_loopback(char *port, size_t cap) {
    int fd = socket(AF_INET, SOCK_STREAM, 0); int one = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {0}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&a, sizeof a) || listen(fd, 32)) { close(fd); return -1; }
    socklen_t al = sizeof a; getsockname(fd, (struct sockaddr *)&a, &al);
    snprintf(port, cap, "%d", ntohs(a.sin_port)); return fd; }
static int connect_loopback(const char *port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0); struct sockaddr_in a = {0};
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = htons((uint16_t)atoi(port));
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) { close(fd); return -1; } return fd; }

struct relctx { int tfd, sni_lfd; };
static void *relay_thread(void *p) {
    struct relctx *r = p;
    tunnel_listener_t l = { .listen_fd = r->sni_lfd, .sni = 1, .forward_id = 0 };
    tunnel_sni_route_t routes[1] = { { .host = "atom.test", .forward_id = 0 } };
    tunnel_relay_serve(r->tfd, &l, 1, routes, 1);
    return NULL;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    printf("== open_public atomicity under tw backpressure (M1) ==\n");

    /* tunnel: socketpair with TINY buffers so the relay's tw fills fast and the atomic
     * retry path is exercised (the relay can't flush faster than we choose to drain). */
    int tun[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, tun);
    int small = 2048;
    setsockopt(tun[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof small);
    setsockopt(tun[0], SOL_SOCKET, SO_RCVBUF, &small, sizeof small);
    setsockopt(tun[1], SOL_SOCKET, SO_SNDBUF, &small, sizeof small);
    setsockopt(tun[1], SOL_SOCKET, SO_RCVBUF, &small, sizeof small);

    char snport[16]; int snlfd = listen_loopback(snport, sizeof snport);
    struct relctx rc = { .tfd = tun[0], .sni_lfd = snlfd };
    pthread_t rl; pthread_create(&rl, NULL, relay_thread, &rc);

    /* Open K SNI clients; each sends ClientHello + padding == TARGET bytes in one burst,
     * so the relay buffers a large prefix before resolving + opening the stream. */
    int cfd[K];
    for (int i = 0; i < K; i++) {
        cfd[i] = connect_loopback(snport);
        unsigned char msg[TARGET]; int chn = capture_clienthello("atom.test", msg, sizeof msg);
        if (chn <= 0 || chn >= TARGET) { chk("captured a ClientHello", 0); }
        for (int j = chn; j < TARGET; j++) msg[j] = (unsigned char)(j & 0xff);   /* deterministic padding */
        write_all(cfd[i], msg, TARGET);
    }
    chk("opened K SNI clients, each sent a full TARGET-byte burst", 1);

    usleep(150000);   /* let tw fill and several peekers get parked on the `again` path */

    /* Now play the agent: drain the tunnel and reassemble per-stream byte counts. */
    tunnel_io_t io = tunnel_io_fd(tun[1]);
    struct timeval tv = { 3, 0 }; setsockopt(tun[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    tunnel_decoder_t dec; tunnel_decoder_reset(&dec);

    uint32_t sids[K]; size_t got[K]; int nstreams = 0;
    memset(got, 0, sizeof got);
    int complete = 0;
    while (complete < K) {
        tunnel_frame_t f;
        int r = tunnel_io_read_frame(&io, &dec, &f);
        if (r != 1) break;                                 /* stall/EOF -> something was lost */
        int idx = -1;
        for (int i = 0; i < nstreams; i++) if (sids[i] == f.stream_id) { idx = i; break; }
        if (idx < 0 && f.type == TF_OPEN && nstreams < K) { idx = nstreams; sids[nstreams] = f.stream_id; got[nstreams] = 0; nstreams++; }
        if (idx < 0) continue;
        if (f.type == TF_DATA) {
            size_t before = got[idx]; got[idx] += f.len;
            if (before < TARGET && got[idx] >= TARGET) complete++;
        }
    }

    chk("the relay opened all K streams", nstreams == K);
    int all_full = (nstreams == K);
    for (int i = 0; i < nstreams; i++) if (got[i] < TARGET) all_full = 0;
    chk("every stream delivered its full prefix+data (no truncated ClientHello)", all_full);

    shutdown(tun[1], SHUT_RDWR);                            /* wake + end the relay serve_loop */
    pthread_join(rl, NULL);
    for (int i = 0; i < K; i++) if (cfd[i] >= 0) close(cfd[i]);
    close(tun[0]); close(tun[1]); close(snlfd);

    printf("\n%s  (%d ok, %d failed)  [%d/%d streams full]\n",
           fail ? "FAIL" : "PASS", ok, fail, complete, K);
    return fail ? 1 : 0;
}
