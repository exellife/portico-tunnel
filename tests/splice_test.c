/* tunnel_pump: bytes flow both ways, backpressure holds under a large transfer, and a
 * half-close on one side propagates EOF to the other. socketpairs only — no network. */
#include "tunnel_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>

static int ok = 0, fail = 0;
static void chk(const char *n, int c) {
    printf("  %-5s %s\n", c ? "ok" : "FAIL", n);
    if (c) ok++; else fail++;
}

static int write_n(int fd, const unsigned char *b, size_t n) {
    size_t put = 0;
    while (put < n) { ssize_t w = write(fd, b + put, n - put); if (w <= 0) break; put += (size_t)w; }
    return (int)put;
}
static int read_n(int fd, unsigned char *b, size_t n) {
    size_t got = 0;
    while (got < n) { ssize_t r = read(fd, b + got, n - got); if (r <= 0) break; got += (size_t)r; }
    return (int)got;
}

struct pump_args { int a, b; long moved; };
static void *pump_thread(void *p) {
    struct pump_args *pa = p;
    pa->moved = tunnel_pump(pa->a, pa->b);
    return NULL;
}

/* Writes `n` bytes of a known pattern (byte k = k & 0xff), then half-closes. */
struct wargs { int fd; size_t n; };
static void *writer_thread(void *p) {
    struct wargs *w = p;
    unsigned char *b = malloc(65536);
    size_t sent = 0;
    while (sent < w->n) {
        size_t c = (w->n - sent < 65536) ? (w->n - sent) : 65536;
        for (size_t i = 0; i < c; i++) b[i] = (unsigned char)((sent + i) & 0xff);
        if (write_n(w->fd, b, c) < (int)c) break;
        sent += c;
    }
    free(b);
    shutdown(w->fd, SHUT_WR);
    return NULL;
}

int main(void) {
    printf("== tunnel byte pump ==\n");

    /* ---- 1. bidirectional delivery + half-close propagation ---- */
    {
        int P[2], Q[2];   /* P[0]=client | P[1]==pump==Q[0] | Q[1]=server */
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, P) || socketpair(AF_UNIX, SOCK_STREAM, 0, Q)) {
            perror("socketpair"); return 1;
        }
        struct pump_args pa = { .a = P[1], .b = Q[0] };
        pthread_t th; pthread_create(&th, NULL, pump_thread, &pa);

        const char *m1 = "hello portico-tunnel";
        const char *m2 = "echo back!";
        unsigned char rb[64];

        write_n(P[0], (const unsigned char *)m1, strlen(m1));
        int r = read_n(Q[1], rb, strlen(m1));
        chk("client->server bytes delivered", r == (int)strlen(m1) && memcmp(rb, m1, (size_t)r) == 0);

        write_n(Q[1], (const unsigned char *)m2, strlen(m2));
        r = read_n(P[0], rb, strlen(m2));
        chk("server->client bytes delivered", r == (int)strlen(m2) && memcmp(rb, m2, (size_t)r) == 0);

        shutdown(P[0], SHUT_WR);                 /* client half-closes */
        r = (int)read(Q[1], rb, sizeof rb);
        chk("half-close propagates EOF to peer", r == 0);

        shutdown(Q[1], SHUT_WR);                 /* server half-closes -> pump completes */
        pthread_join(th, NULL);
        chk("pump returns once both sides closed", pa.moved == (long)(strlen(m1) + strlen(m2)));

        close(P[0]); close(P[1]); close(Q[0]); close(Q[1]);
    }

    /* ---- 2. bulk integrity + backpressure (4 MiB through a 64 KiB buffer) ---- */
    {
        int A[2], B[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, A) || socketpair(AF_UNIX, SOCK_STREAM, 0, B)) {
            perror("socketpair"); return 1;
        }
        size_t N = 4u * 1024 * 1024;
        struct pump_args pa = { .a = A[1], .b = B[0] };
        pthread_t th; pthread_create(&th, NULL, pump_thread, &pa);

        struct wargs wa = { .fd = A[0], .n = N };
        pthread_t wt; pthread_create(&wt, NULL, writer_thread, &wa);

        unsigned char *buf = malloc(65536);
        size_t got = 0; int corrupt = 0;
        for (;;) {
            ssize_t r = read(B[1], buf, 65536);
            if (r <= 0) break;
            for (ssize_t i = 0; i < r; i++)
                if (buf[i] != (unsigned char)((got + (size_t)i) & 0xff)) { corrupt = 1; break; }
            got += (size_t)r;
        }
        free(buf);
        chk("4 MiB transferred intact (ordered, no corruption)", got == N && !corrupt);

        pthread_join(wt, NULL);
        shutdown(B[1], SHUT_WR);
        pthread_join(th, NULL);
        chk("pump byte count matches payload", pa.moved == (long)N);

        close(A[0]); close(A[1]); close(B[0]); close(B[1]);
    }

    printf("\n%s  (%d ok, %d failed)\n", fail ? "FAIL" : "PASS", ok, fail);
    return fail ? 1 : 0;
}
