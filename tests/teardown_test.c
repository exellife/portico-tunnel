/* M2 fix: teardown frames (END/RESET) must never be silently dropped. The old code
 * fire-and-forgot them via tw_frame() and closed the stream locally even when tw was full,
 * so under backpressure the peer never learned the stream ended and leaked its half
 * (half-open forever). The fix routes every teardown through send_end()/send_reset(),
 * which defer an un-queueable frame (pending_end / pending_reset, a closed-fd tombstone
 * for RESET) and a per-iteration flush retries it until it lands.
 *
 * We play the tunnel peer driving a relay serve_loop over a small-buffered socketpair. Many
 * public clients open concurrently, each sends a short burst then half-closes; we drain the
 * tunnel slowly to keep the relay backpressured while all those streams close at once. We
 * assert EVERY opened stream delivers its full byte count AND a matching END — none lost.
 * (Per-stream payloads are kept small: the current relay tears the whole tunnel down if
 * concurrent local reads overflow tw in one iteration — the separate backpressure rework,
 * task #91. This test stays within that limit while still closing many streams at once.) */
#include "stream.h"
#include "io.h"
#include "frame.h"

#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define N        24
#define BURST    400

static int ok = 0, fail = 0;
static void chk(const char *n, int c) { printf("  %-5s %s\n", c ? "ok" : "FAIL", n); if (c) ok++; else fail++; }
static int write_all(int fd, const void *b, size_t n) { const unsigned char *p = b; size_t o = 0;
    while (o < n) { ssize_t w = write(fd, p + o, n - o); if (w <= 0) return -1; o += (size_t)w; } return 0; }

static int listen_loopback(char *port, size_t cap) {
    int fd = socket(AF_INET, SOCK_STREAM, 0); int one = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {0}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&a, sizeof a) || listen(fd, 64)) { close(fd); return -1; }
    socklen_t al = sizeof a; getsockname(fd, (struct sockaddr *)&a, &al);
    snprintf(port, cap, "%d", ntohs(a.sin_port)); return fd; }
static int connect_loopback(const char *port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0); struct sockaddr_in a = {0};
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = htons((uint16_t)atoi(port));
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) { close(fd); return -1; } return fd; }

struct relctx { int tfd, tcp_lfd; };
static void *relay_thread(void *p) {
    struct relctx *r = p;
    tunnel_listener_t l = { .listen_fd = r->tcp_lfd, .sni = 0, .forward_id = 0 };
    tunnel_relay_serve(r->tfd, &l, 1, NULL, 0);
    return NULL;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    printf("== teardown frames survive backpressure (M2) ==\n");

    int tun[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, tun);
    int small = 2048;                                  /* tiny tunnel buffers -> real backpressure */
    setsockopt(tun[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof small);
    setsockopt(tun[1], SOL_SOCKET, SO_RCVBUF, &small, sizeof small);

    char tport[16]; int tcp = listen_loopback(tport, sizeof tport);
    struct relctx rc = { .tfd = tun[0], .tcp_lfd = tcp };
    pthread_t rl; pthread_create(&rl, NULL, relay_thread, &rc);

    /* Open all N, send each one's short burst, then half-close them ALL — a burst of
     * simultaneous teardowns while the tunnel is congested. */
    int cfd[N];
    unsigned char msg[BURST]; for (int i = 0; i < BURST; i++) msg[i] = (unsigned char)i;
    for (int i = 0; i < N; i++) { cfd[i] = connect_loopback(tport); write_all(cfd[i], msg, BURST); }
    usleep(50000);
    for (int i = 0; i < N; i++) shutdown(cfd[i], SHUT_WR);

    /* Play the peer: drain the tunnel SLOWLY so tw stays pressured while streams close. */
    tunnel_io_t io = tunnel_io_fd(tun[1]);
    struct timeval tv = { 4, 0 }; setsockopt(tun[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    tunnel_decoder_t dec; tunnel_decoder_reset(&dec);

    uint32_t sids[N]; size_t got[N]; int ended[N]; int nstreams = 0;
    memset(got, 0, sizeof got); memset(ended, 0, sizeof ended);
    int done = 0, frames = 0;
    while (done < N) {
        tunnel_frame_t f;
        int r = tunnel_io_read_frame(&io, &dec, &f);
        if (r != 1) break;                              /* stall -> a teardown (or data) was lost */
        if ((++frames % 5) == 0) usleep(400);           /* throttle the drain to hold backpressure */
        int idx = -1;
        for (int i = 0; i < nstreams; i++) if (sids[i] == f.stream_id) { idx = i; break; }
        if (idx < 0 && f.type == TF_OPEN && nstreams < N) { idx = nstreams; sids[nstreams] = f.stream_id; nstreams++; }
        if (idx < 0) continue;
        if (f.type == TF_DATA) got[idx] += f.len;
        else if ((f.type == TF_END || f.type == TF_RESET) && !ended[idx]) {
            ended[idx] = 1;
            if (got[idx] == BURST) done++;              /* fully delivered AND cleanly torn down */
        }
    }

    chk("relay opened all N streams", nstreams == N);
    int all_data = (nstreams == N), all_end = (nstreams == N);
    for (int i = 0; i < nstreams; i++) { if (got[i] != BURST) all_data = 0; if (!ended[i]) all_end = 0; }
    chk("every stream delivered its full byte count under backpressure", all_data);
    chk("every stream's END reached the peer (no teardown dropped)", all_end);

    shutdown(tun[1], SHUT_RDWR);
    pthread_join(rl, NULL);
    for (int i = 0; i < N; i++) close(cfd[i]);
    close(tun[0]); close(tun[1]); close(tcp);

    printf("\n%s  (%d ok, %d failed)  [%d/%d streams torn down cleanly]\n",
           fail ? "FAIL" : "PASS", ok, fail, done, N);
    return fail ? 1 : 0;
}
