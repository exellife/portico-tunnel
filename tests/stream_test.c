/* Agent stream engine: a stub relay (over a socketpair) opens streams and exchanges
 * DATA; the agent dials a real local echo server and bridges. Covers single-stream
 * echo + half-close (END), two concurrent streams, and a chunked 128 KiB transfer
 * (DATA framing + backpressure). Threaded loopback; no TLS. */
#include "stream.h"
#include "io.h"
#include "frame.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int ok = 0, fail = 0;
static void chk(const char *n, int c) {
    printf("  %-5s %s\n", c ? "ok" : "FAIL", n);
    if (c) ok++; else fail++;
}

/* ---- local echo server ---- */
struct echo_srv { int lfd; pthread_t acc; pthread_t conns[32]; int nconn;
                  struct sockaddr_in addr; volatile int stop; };

static void *echo_conn(void *p) {
    int c = (int)(intptr_t)p;
    unsigned char b[8192]; ssize_t n;
    while ((n = read(c, b, sizeof b)) > 0) {
        size_t off = 0;
        while (off < (size_t)n) { ssize_t w = write(c, b + off, (size_t)n - off); if (w <= 0) goto end; off += (size_t)w; }
    }
end:
    shutdown(c, SHUT_WR); close(c); return NULL;
}
static void *echo_acc(void *p) {
    struct echo_srv *s = p;
    for (;;) {
        int c = accept(s->lfd, NULL, NULL);
        if (c < 0) break;
        if (s->stop) { close(c); break; }     /* woken by the teardown self-connect */
        if (s->nconn < 32) { pthread_create(&s->conns[s->nconn], NULL, echo_conn, (void *)(intptr_t)c); s->nconn++; }
        else close(c);
    }
    return NULL;
}
static int echo_start(struct echo_srv *s, char *port, size_t cap) {
    s->lfd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1; setsockopt(s->lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = 0;
    if (bind(s->lfd, (struct sockaddr *)&a, sizeof a) || listen(s->lfd, 8)) return -1;
    socklen_t al = sizeof a; getsockname(s->lfd, (struct sockaddr *)&a, &al);
    snprintf(port, cap, "%d", ntohs(a.sin_port));
    s->addr = a; s->nconn = 0; s->stop = 0;
    pthread_create(&s->acc, NULL, echo_acc, s);
    return 0;
}
static void echo_stop(struct echo_srv *s) {
    s->stop = 1;
    int d = socket(AF_INET, SOCK_STREAM, 0);   /* self-connect to unblock accept() */
    if (d >= 0) connect(d, (struct sockaddr *)&s->addr, sizeof s->addr);
    pthread_join(s->acc, NULL);
    if (d >= 0) close(d);
    close(s->lfd);
    for (int i = 0; i < s->nconn; i++) pthread_join(s->conns[i], NULL);
}

/* ---- agent under test ---- */
static tunnel_target_t g_fwd[1];
static void *agent_thread(void *p) {
    tunnel_agent_serve((int)(intptr_t)p, g_fwd, 1);
    return NULL;
}

static void send_open(tunnel_io_t *io, uint32_t sid, uint32_t fid, const char *ip) {
    unsigned char pl[64];
    pl[0] = (unsigned char)(fid >> 24); pl[1] = (unsigned char)(fid >> 16);
    pl[2] = (unsigned char)(fid >> 8);  pl[3] = (unsigned char)fid;
    size_t il = strlen(ip); memcpy(pl + 4, ip, il);
    tunnel_io_write_frame(io, TF_OPEN, sid, pl, (uint32_t)(4 + il));
}

/* writer thread for the bulk test: stream sid, pattern byte k = k & 0xff */
struct wr { int fd; uint32_t sid; size_t n; };
static void *wr_thread(void *p) {
    struct wr *w = p;
    tunnel_io_t io = tunnel_io_fd(w->fd);
    unsigned char b[16384]; size_t sent = 0;
    while (sent < w->n) {
        size_t c = (w->n - sent < sizeof b) ? (w->n - sent) : sizeof b;
        for (size_t i = 0; i < c; i++) b[i] = (unsigned char)((sent + i) & 0xff);
        if (tunnel_io_write_frame(&io, TF_DATA, w->sid, b, (uint32_t)c) != 0) break;
        sent += c;
    }
    return NULL;
}

int main(void) {
    printf("== tunnel agent stream engine ==\n");

    struct echo_srv echo;
    char port[16];
    if (echo_start(&echo, port, sizeof port) != 0) { perror("echo_start"); return 1; }
    snprintf(g_fwd[0].host, sizeof g_fwd[0].host, "127.0.0.1");
    snprintf(g_fwd[0].port, sizeof g_fwd[0].port, "%s", port);

    /* ---- 1. single stream: echo + half-close ---- */
    {
        int sv[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
        pthread_t ag; pthread_create(&ag, NULL, agent_thread, (void *)(intptr_t)sv[1]);
        tunnel_io_t io = tunnel_io_fd(sv[0]);
        tunnel_decoder_t dec; tunnel_decoder_reset(&dec);

        send_open(&io, 1, 0, "203.0.113.5");
        const char *msg = "hello portico-tunnel"; size_t ml = strlen(msg);
        tunnel_io_write_frame(&io, TF_DATA, 1, msg, (uint32_t)ml);

        unsigned char got[64]; size_t gl = 0;
        tunnel_frame_t f;
        while (gl < ml && tunnel_io_read_frame(&io, &dec, &f) == 1)
            if (f.type == TF_DATA && f.stream_id == 1) { memcpy(got + gl, f.payload, f.len); gl += f.len; }
        chk("stream bridges to local + echoes data back", gl == ml && memcmp(got, msg, ml) == 0);

        tunnel_io_write_frame(&io, TF_END, 1, NULL, 0);     /* half-close from the public side */
        int got_end = 0;
        while (tunnel_io_read_frame(&io, &dec, &f) == 1)
            if (f.type == TF_END && f.stream_id == 1) { got_end = 1; break; }
        chk("END round-trips (local EOF -> END back)", got_end);

        close(sv[0]); pthread_join(ag, NULL); close(sv[1]);
    }

    /* ---- 2. two concurrent streams stay independent ---- */
    {
        int sv[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
        pthread_t ag; pthread_create(&ag, NULL, agent_thread, (void *)(intptr_t)sv[1]);
        tunnel_io_t io = tunnel_io_fd(sv[0]);
        tunnel_decoder_t dec; tunnel_decoder_reset(&dec);

        send_open(&io, 10, 0, "a"); send_open(&io, 20, 0, "b");
        const char *m1 = "stream-ten", *m2 = "STREAM-TWENTY";
        tunnel_io_write_frame(&io, TF_DATA, 10, m1, (uint32_t)strlen(m1));
        tunnel_io_write_frame(&io, TF_DATA, 20, m2, (uint32_t)strlen(m2));

        char b10[64], b20[64]; size_t l10 = 0, l20 = 0;
        tunnel_frame_t f;
        while ((l10 < strlen(m1) || l20 < strlen(m2)) && tunnel_io_read_frame(&io, &dec, &f) == 1) {
            if (f.type != TF_DATA) continue;
            if (f.stream_id == 10) { memcpy(b10 + l10, f.payload, f.len); l10 += f.len; }
            else if (f.stream_id == 20) { memcpy(b20 + l20, f.payload, f.len); l20 += f.len; }
        }
        chk("two streams echo independently, no cross-talk",
            l10 == strlen(m1) && memcmp(b10, m1, l10) == 0 &&
            l20 == strlen(m2) && memcmp(b20, m2, l20) == 0);

        close(sv[0]); pthread_join(ag, NULL); close(sv[1]);
    }

    /* ---- 3. chunked bulk: 128 KiB through the engine, integrity + backpressure ---- */
    {
        int sv[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
        pthread_t ag; pthread_create(&ag, NULL, agent_thread, (void *)(intptr_t)sv[1]);
        tunnel_io_t io = tunnel_io_fd(sv[0]);
        tunnel_decoder_t dec; tunnel_decoder_reset(&dec);

        send_open(&io, 7, 0, "bulk");
        size_t N = 128u * 1024;
        struct wr w = { .fd = sv[0], .sid = 7, .n = N };
        pthread_t wt; pthread_create(&wt, NULL, wr_thread, &w);

        size_t gl = 0; int bad = 0;
        tunnel_frame_t f;
        while (gl < N && tunnel_io_read_frame(&io, &dec, &f) == 1) {
            if (f.type != TF_DATA || f.stream_id != 7) continue;
            for (uint32_t i = 0; i < f.len; i++)
                if (f.payload[i] != (unsigned char)((gl + i) & 0xff)) { bad = 1; break; }
            gl += f.len;
        }
        chk("128 KiB stream intact (chunked DATA + backpressure)", gl == N && !bad);

        pthread_join(wt, NULL);
        close(sv[0]); pthread_join(ag, NULL); close(sv[1]);
    }

    echo_stop(&echo);
    printf("\n%s  (%d ok, %d failed)\n", fail ? "FAIL" : "PASS", ok, fail);
    return fail ? 1 : 0;
}
