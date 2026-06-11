/* M11 fix: an OPEN for a stream_id that is already active must be rejected, not turned into
 * a second stream sharing the same id. The old code called alloc_stream() unconditionally,
 * so a duplicate OPEN created two slots with the same sid — find_stream() then routed all
 * DATA to whichever it found first and the other was orphaned (state corruption a buggy or
 * hostile relay could trigger). The fix aborts the stream (RESET) on a duplicate OPEN.
 *
 * We play the relay/peer over a socketpair driving the agent. Open stream 1, confirm it
 * echoes, then send a SECOND OPEN for stream 1 and assert the agent replies with a RESET
 * for stream 1 (and does not silently double-open). */
#include "stream.h"
#include "io.h"
#include "frame.h"

#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int ok = 0, fail = 0;
static void chk(const char *n, int c) { printf("  %-5s %s\n", c ? "ok" : "FAIL", n); if (c) ok++; else fail++; }
static int write_all(int fd, const void *b, size_t n) { const unsigned char *p = b; size_t o = 0;
    while (o < n) { ssize_t w = write(fd, p + o, n - o); if (w <= 0) return -1; o += (size_t)w; } return 0; }

/* echo server = forward 0 */
struct echo_srv { int lfd; pthread_t acc; pthread_t conns[8]; int nconn; struct sockaddr_in addr; volatile int stop; };
static void *echo_conn(void *p) { int c = (int)(intptr_t)p; unsigned char b[4096]; ssize_t n;
    while ((n = read(c, b, sizeof b)) > 0) if (write_all(c, b, (size_t)n) != 0) break;
    shutdown(c, SHUT_WR); close(c); return NULL; }
static void *echo_acc(void *p) { struct echo_srv *s = p;
    for (;;) { int c = accept(s->lfd, NULL, NULL); if (c < 0) break; if (s->stop) { close(c); break; }
        if (s->nconn < 8) { pthread_create(&s->conns[s->nconn], NULL, echo_conn, (void *)(intptr_t)c); s->nconn++; } else close(c); }
    return NULL; }
static int echo_start(struct echo_srv *s, char *port, size_t cap) {
    s->lfd = socket(AF_INET, SOCK_STREAM, 0); int one = 1; setsockopt(s->lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {0}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = 0;
    if (bind(s->lfd, (struct sockaddr *)&a, sizeof a) || listen(s->lfd, 8)) return -1;
    socklen_t al = sizeof a; getsockname(s->lfd, (struct sockaddr *)&a, &al);
    snprintf(port, cap, "%d", ntohs(a.sin_port)); s->addr = a; s->nconn = 0; s->stop = 0;
    pthread_create(&s->acc, NULL, echo_acc, s); return 0; }
static void echo_stop(struct echo_srv *s) {
    s->stop = 1; int d = socket(AF_INET, SOCK_STREAM, 0);
    if (d >= 0) connect(d, (struct sockaddr *)&s->addr, sizeof s->addr);
    pthread_join(s->acc, NULL); if (d >= 0) close(d); close(s->lfd);
    for (int i = 0; i < s->nconn; i++) pthread_join(s->conns[i], NULL); }

static tunnel_target_t g_fwd[1];
static void *agent_thread(void *p) { tunnel_agent_serve((int)(intptr_t)p, g_fwd, 1); return NULL; }

static void send_open(tunnel_io_t *io, uint32_t sid, uint32_t fid) {
    unsigned char pl[4]; pl[0] = (unsigned char)(fid >> 24); pl[1] = (unsigned char)(fid >> 16);
    pl[2] = (unsigned char)(fid >> 8); pl[3] = (unsigned char)fid;
    tunnel_io_write_frame(io, TF_OPEN, sid, pl, 4);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    printf("== duplicate stream_id OPEN is rejected (M11) ==\n");

    struct echo_srv echo = {0}; char eport[16]; echo_start(&echo, eport, sizeof eport);
    snprintf(g_fwd[0].host, sizeof g_fwd[0].host, "127.0.0.1");
    snprintf(g_fwd[0].port, sizeof g_fwd[0].port, "%s", eport);

    int sv[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    pthread_t ag; pthread_create(&ag, NULL, agent_thread, (void *)(intptr_t)sv[1]);
    tunnel_io_t io = tunnel_io_fd(sv[0]);
    struct timeval tv = { 3, 0 }; setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    tunnel_decoder_t dec; tunnel_decoder_reset(&dec);
    tunnel_frame_t f;

    /* open stream 1 and confirm it echoes */
    send_open(&io, 1, 0);
    tunnel_io_write_frame(&io, TF_DATA, 1, "aaa", 3);
    unsigned char got[8]; size_t gl = 0;
    while (gl < 3) { int r = tunnel_io_read_frame(&io, &dec, &f); if (r != 1) break;
        if (f.type == TF_DATA && f.stream_id == 1) { memcpy(got + gl, f.payload, f.len); gl += f.len; } }
    chk("stream 1 established and echoes", gl == 3 && memcmp(got, "aaa", 3) == 0);

    /* duplicate OPEN for the SAME stream_id -> agent must RESET it, not double-open */
    send_open(&io, 1, 0);
    int got_reset = 0;
    for (int i = 0; i < 8; i++) { int r = tunnel_io_read_frame(&io, &dec, &f); if (r != 1) break;
        if (f.type == TF_RESET && f.stream_id == 1) { got_reset = 1; break; } }
    chk("duplicate OPEN for an active stream_id is rejected with RESET", got_reset);

    close(sv[0]); pthread_join(ag, NULL); close(sv[1]);
    echo_stop(&echo);
    printf("\n%s  (%d ok, %d failed)\n", fail ? "FAIL" : "PASS", ok, fail);
    return fail ? 1 : 0;
}
