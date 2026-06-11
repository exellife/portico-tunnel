/* W2 fix (H2/H3/M3/M12): the relay must reap genuinely-stuck work so a slowloris can't
 * exhaust it — but must NOT kill a healthy stream merely because it is quiet.
 *
 * We stand up a real relay run loop (short idle_timeout_ms) with a tcp listener and an
 * sni listener, plus a real agent whose one forward is a local echo. Then we assert:
 *   1. a normal tcp forward round-trips (the pipe works);
 *   2. silent SNI peekers (a ClientHello that never arrives) are reaped after the
 *      idle timeout — and a tcp forward STILL works while the peeker table is full,
 *      proving tcp accepts are decoupled from peeker exhaustion;
 *   3. NEGATIVE CONTROL: a stream that exchanged bytes and then went quiet past the
 *      idle timeout is NOT reaped (legit idle, e.g. an SSH session at rest). */
#include "stream.h"
#include "tls.h"
#include "control.h"
#include "io.h"

#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

static int ok = 0, fail = 0;
static void chk(const char *n, int c) { printf("  %-5s %s\n", c ? "ok" : "FAIL", n); if (c) ok++; else fail++; }
static int write_all(int fd, const void *b, size_t n) { const unsigned char *p = b; size_t o = 0;
    while (o < n) { ssize_t w = write(fd, p + o, n - o); if (w <= 0) return -1; o += (size_t)w; } return 0; }

static EVP_PKEY *gen_key(void) { return EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256"); }
static X509 *mk_cert(EVP_PKEY *key, const char *cn, int ca, EVP_PKEY *ik, X509 *ic, const char *san, long sn) {
    X509 *x = X509_new(); X509_set_version(x, 2); ASN1_INTEGER_set(X509_get_serialNumber(x), sn);
    X509_gmtime_adj(X509_getm_notBefore(x), 0); X509_gmtime_adj(X509_getm_notAfter(x), 3600);
    X509_set_pubkey(x, key);
    X509_NAME *nm = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC, (const unsigned char *)cn, -1, -1, 0);
    X509_set_issuer_name(x, ic ? X509_get_subject_name(ic) : nm);
    X509V3_CTX v; X509V3_set_ctx(&v, ic ? ic : x, x, NULL, NULL, 0);
    if (ca)  { X509_EXTENSION *e = X509V3_EXT_conf_nid(NULL, &v, NID_basic_constraints, "critical,CA:TRUE"); if (e) { X509_add_ext(x, e, -1); X509_EXTENSION_free(e); } }
    if (san) { X509_EXTENSION *e = X509V3_EXT_conf_nid(NULL, &v, NID_subject_alt_name, san); if (e) { X509_add_ext(x, e, -1); X509_EXTENSION_free(e); } }
    X509_sign(x, ik, EVP_sha256()); return x;
}
static void wr_cert(const char *p, X509 *x) { FILE *f = fopen(p, "w"); PEM_write_X509(f, x); fclose(f); }
static void wr_key(const char *p, EVP_PKEY *k) { FILE *f = fopen(p, "w"); PEM_write_PrivateKey(f, k, NULL, NULL, 0, NULL, NULL); fclose(f); }

static int listen_lo(char *port, size_t cap, struct sockaddr_in *addr) {
    int fd = socket(AF_INET, SOCK_STREAM, 0); int one = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {0}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&a, sizeof a) || listen(fd, 64)) { close(fd); return -1; }
    socklen_t al = sizeof a; getsockname(fd, (struct sockaddr *)&a, &al);
    snprintf(port, cap, "%d", ntohs(a.sin_port)); if (addr) *addr = a; return fd; }
static int connect_lo(const char *port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0); struct sockaddr_in a = {0};
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = htons((uint16_t)atoi(port));
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) { close(fd); return -1; } return fd; }
/* send `msg`, read exactly strlen(msg) bytes back, compare. */
static int echo_rt(int fd, const char *msg) {
    size_t n = strlen(msg); if (write_all(fd, msg, n) != 0) return 0;
    char buf[64]; size_t got = 0;
    struct timeval tv = { 2, 0 }; setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    while (got < n) { ssize_t r = read(fd, buf + got, n - got); if (r <= 0) return 0; got += (size_t)r; }
    return memcmp(buf, msg, n) == 0;
}

/* echo server (the agent's local forward target) */
struct echo_srv { int lfd; pthread_t acc; pthread_t conns[32]; int nconn; struct sockaddr_in addr; volatile int stop; };
static void *echo_conn(void *p) { int c = (int)(intptr_t)p; unsigned char b[4096]; ssize_t n;
    while ((n = read(c, b, sizeof b)) > 0) if (write_all(c, b, (size_t)n) != 0) break;
    shutdown(c, SHUT_WR); close(c); return NULL; }
static void *echo_acc(void *p) { struct echo_srv *s = p;
    for (;;) { int c = accept(s->lfd, NULL, NULL); if (c < 0) break; if (s->stop) { close(c); break; }
        if (s->nconn < 32) { pthread_create(&s->conns[s->nconn], NULL, echo_conn, (void *)(intptr_t)c); s->nconn++; } else close(c); }
    return NULL; }
static int echo_start(struct echo_srv *s, char *port, size_t cap) {
    s->lfd = socket(AF_INET, SOCK_STREAM, 0); int one = 1; setsockopt(s->lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {0}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = 0;
    if (bind(s->lfd, (struct sockaddr *)&a, sizeof a) || listen(s->lfd, 32)) return -1;
    socklen_t al = sizeof a; getsockname(s->lfd, (struct sockaddr *)&a, &al);
    snprintf(port, cap, "%d", ntohs(a.sin_port)); s->addr = a; s->nconn = 0; s->stop = 0;
    pthread_create(&s->acc, NULL, echo_acc, s); return 0; }
static void echo_stop(struct echo_srv *s) {
    s->stop = 1; int d = socket(AF_INET, SOCK_STREAM, 0);
    if (d >= 0) connect(d, (struct sockaddr *)&s->addr, sizeof s->addr);
    pthread_join(s->acc, NULL); if (d >= 0) close(d); close(s->lfd);
    for (int i = 0; i < s->nconn; i++) pthread_join(s->conns[i], NULL); }

static int allow_all(const char *a, const char *h, void *u) { (void)a; (void)h; (void)u; return 1; }

/* relay run loop: tcp listener (forward 0) + sni listener, short idle timeout. */
struct relctx { int ctrl_fd, tcp_fd, sni_fd; const char *crt, *key, *ca; atomic_int stop; };
static void *relay_thread(void *p) {
    struct relctx *r = p;
    tunnel_listener_t ls[2] = {
        { .listen_fd = r->tcp_fd, .sni = 0, .forward_id = 0 },
        { .listen_fd = r->sni_fd, .sni = 1, .forward_id = 0 },
    };
    tunnel_relay_run_config_t cfg = {
        .control_fd = r->ctrl_fd, .cert = r->crt, .key = r->key, .client_ca = r->ca,
        .listeners = ls, .n_listeners = 2, .routes = NULL, .n_routes = 0, .allow = allow_all,
        .handshake_timeout_ms = 1000, .idle_timeout_ms = 300, .stop = &r->stop,
    };
    tunnel_relay_run(&cfg);
    return NULL;
}

/* The agent peer: dial+register happens on the main thread (so we own the TLS fd and can
 * shut it down to tear the whole pipe down cleanly — serve_loop has no in-session stop),
 * then this thread just serves OPEN->echo over it. */
struct agserve { SSL *ssl; const tunnel_target_t *fwd; size_t n; };
static void *agent_serve_thread(void *p) { struct agserve *a = p; tunnel_agent_serve_ssl(a->ssl, a->fwd, a->n); return NULL; }

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    printf("== idle reaping: slowloris reaped, healthy-idle preserved (W2) ==\n");

    char dir[] = "/tmp/tunidleXXXXXX"; if (!mkdtemp(dir)) { perror("mkdtemp"); return 1; }
    char ca[256], scrt[256], skey[256], ccrt[256], ckey[256];
    snprintf(ca, sizeof ca, "%s/ca.pem", dir); snprintf(scrt, sizeof scrt, "%s/s.crt", dir);
    snprintf(skey, sizeof skey, "%s/s.key", dir); snprintf(ccrt, sizeof ccrt, "%s/c.crt", dir);
    snprintf(ckey, sizeof ckey, "%s/c.key", dir);
    EVP_PKEY *cak = gen_key(), *sk = gen_key(), *clk = gen_key();
    X509 *cac = mk_cert(cak, "CA", 1, cak, NULL, NULL, 1);
    X509 *sc = mk_cert(sk, "localhost", 0, cak, cac, "DNS:localhost", 2);
    X509 *cc = mk_cert(clk, "agent", 0, cak, cac, NULL, 3);
    wr_cert(ca, cac); wr_cert(scrt, sc); wr_key(skey, sk); wr_cert(ccrt, cc); wr_key(ckey, clk);

    struct echo_srv echo = {0}; char eport[16]; echo_start(&echo, eport, sizeof eport);

    char cport[16], tport[16], sport[16];
    int ctrl = listen_lo(cport, sizeof cport, NULL);
    int tcp  = listen_lo(tport, sizeof tport, NULL);
    int sni  = listen_lo(sport, sizeof sport, NULL);
    struct relctx rc = { .ctrl_fd = ctrl, .tcp_fd = tcp, .sni_fd = sni, .crt = scrt, .key = skey, .ca = ca };
    atomic_init(&rc.stop, 0);
    pthread_t rl; pthread_create(&rl, NULL, relay_thread, &rc);

    static tunnel_target_t fwd; snprintf(fwd.host, sizeof fwd.host, "127.0.0.1");
    snprintf(fwd.port, sizeof fwd.port, "%s", eport);

    /* dial + register the agent on this thread (keep the TLS so we can shut it down later) */
    tunnel_tls_t tls;
    int dr = tunnel_tls_dial("localhost", cport, ca, ccrt, ckey, &tls);
    chk("agent dialed the relay", dr == 0);
    int rr = -1;
    if (dr == 0) {
        tunnel_io_t io = tunnel_io_tls(&tls);
        tunnel_decoder_t dec; tunnel_decoder_reset(&dec);
        tunnel_hello_t hello; memset(&hello, 0, sizeof hello);
        snprintf(hello.agent_id, sizeof hello.agent_id, "idle");
        char err[128];
        rr = tunnel_agent_register(&io, &dec, &hello, err, sizeof err);
    }
    chk("agent registered with the relay", rr == 0);
    if (rr != 0) { atomic_store(&rc.stop, 1); pthread_join(rl, NULL); return 1; }

    struct agserve as = { .ssl = tls.ssl, .fwd = &fwd, .n = 1 };
    pthread_t at; pthread_create(&at, NULL, agent_serve_thread, &as);
    usleep(150000);   /* let the relay enter serve_loop */

    /* (1) a normal tcp forward round-trips */
    int c1 = connect_lo(tport);
    chk("tcp forward opened", c1 >= 0);
    chk("tcp forward round-trips through the agent's echo", c1 >= 0 && echo_rt(c1, "alpha"));
    /* c1 is now active; it will sit quiet through the reaping window (negative control). */

    /* (2) flood the relay with silent SNI peekers (ClientHello never sent) */
    enum { NPK = 32 };
    int pkfd[NPK];
    for (int i = 0; i < NPK; i++) pkfd[i] = connect_lo(sport);
    int opened = 0; for (int i = 0; i < NPK; i++) if (pkfd[i] >= 0) opened++;
    chk("opened a flood of silent SNI peekers", opened == NPK);
    usleep(120000);   /* let the relay accept them into peeker slots */

    /* tcp must STILL work while the peeker table is saturated (decoupling) */
    int c2 = connect_lo(tport);
    chk("tcp forward still works while peeker table is full", c2 >= 0 && echo_rt(c2, "beta"));
    if (c2 >= 0) close(c2);

    /* wait past the idle timeout, then the silent peekers must be reaped (closed) */
    usleep(700000);
    int reaped = 0;
    for (int i = 0; i < NPK; i++) {
        if (pkfd[i] < 0) continue;
        struct timeval tv = { 1, 0 }; setsockopt(pkfd[i], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        char j[4]; ssize_t r = read(pkfd[i], j, sizeof j);
        if (r == 0) reaped++;        /* relay closed it */
        close(pkfd[i]);
    }
    chk("silent SNI peekers were reaped after the idle timeout", reaped == opened);

    /* (3) NEGATIVE CONTROL: c1 went active then quiet for >2x the idle timeout — it must
     *     NOT have been reaped (a healthy stream at rest is not a slowloris). */
    chk("active-then-quiet stream survives the idle window (not reaped)", c1 >= 0 && echo_rt(c1, "gamma"));
    if (c1 >= 0) close(c1);

    /* Teardown: serve_loop has no in-session stop, so force EOF by shutting the agent's
     * TLS socket — both serve_loops then unwind, and the relay run loop sees rc.stop. */
    atomic_store(&rc.stop, 1);
    shutdown(tls.fd, SHUT_RDWR);
    pthread_join(at, NULL);
    pthread_join(rl, NULL);
    tunnel_tls_free(&tls);
    echo_stop(&echo);
    close(ctrl); close(tcp); close(sni);
    EVP_PKEY_free(cak); EVP_PKEY_free(sk); EVP_PKEY_free(clk); X509_free(cac); X509_free(sc); X509_free(cc);
    unlink(ca); unlink(scrt); unlink(skey); unlink(ccrt); unlink(ckey); rmdir(dir);

    printf("\n%s  (%d ok, %d failed)  [%d/%d peekers reaped]\n", fail ? "FAIL" : "PASS", ok, fail, reaped, opened);
    return fail ? 1 : 0;
}
