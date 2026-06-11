/* The whole thing over a REAL mutually-authenticated TLS tunnel: a public client ->
 * relay -> (mTLS tunnel) -> agent -> echo and back. Exercises the non-blocking OpenSSL
 * transport (conn.c) inside the stream engine under a single request and a 256 KiB
 * bulk transfer (partial TLS records, want-read/want-write, backpressure). */
#include "stream.h"
#include "tls.h"

#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

static int ok = 0, fail = 0;
static void chk(const char *n, int c) { printf("  %-5s %s\n", c ? "ok" : "FAIL", n); if (c) ok++; else fail++; }

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

/* ---- minimal CA + certs ---- */
static EVP_PKEY *gen_key(void) { return EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256"); }
static X509 *mk_cert(EVP_PKEY *key, const char *cn, int ca, EVP_PKEY *ik, X509 *ic, const char *san, long sn) {
    X509 *x = X509_new(); X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), sn);
    X509_gmtime_adj(X509_getm_notBefore(x), 0); X509_gmtime_adj(X509_getm_notAfter(x), 3600);
    X509_set_pubkey(x, key);
    X509_NAME *nm = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC, (const unsigned char *)cn, -1, -1, 0);
    X509_set_issuer_name(x, ic ? X509_get_subject_name(ic) : nm);
    X509V3_CTX v; X509V3_set_ctx(&v, ic ? ic : x, x, NULL, NULL, 0);
    if (ca) { X509_EXTENSION *e = X509V3_EXT_conf_nid(NULL, &v, NID_basic_constraints, "critical,CA:TRUE"); if (e) { X509_add_ext(x, e, -1); X509_EXTENSION_free(e); } }
    if (san) { X509_EXTENSION *e = X509V3_EXT_conf_nid(NULL, &v, NID_subject_alt_name, san); if (e) { X509_add_ext(x, e, -1); X509_EXTENSION_free(e); } }
    X509_sign(x, ik, EVP_sha256()); return x;
}
static void wr_cert(const char *p, X509 *x) { FILE *f = fopen(p, "w"); PEM_write_X509(f, x); fclose(f); }
static void wr_key(const char *p, EVP_PKEY *k) { FILE *f = fopen(p, "w"); PEM_write_PrivateKey(f, k, NULL, NULL, 0, NULL, NULL); fclose(f); }

/* ---- echo (agent's local target) ---- */
struct echo_srv { int lfd; pthread_t acc; pthread_t conns[64]; int nconn; struct sockaddr_in addr; volatile int stop; };
static void *echo_conn(void *p) { int c = (int)(intptr_t)p; unsigned char b[8192]; ssize_t n;
    while ((n = read(c, b, sizeof b)) > 0) if (write_all(c, b, (size_t)n) != 0) break;
    shutdown(c, SHUT_WR); close(c); return NULL; }
static void *echo_acc(void *p) { struct echo_srv *s = p;
    for (;;) { int c = accept(s->lfd, NULL, NULL); if (c < 0) break; if (s->stop) { close(c); break; }
        if (s->nconn < 64) { pthread_create(&s->conns[s->nconn], NULL, echo_conn, (void *)(intptr_t)c); s->nconn++; } else close(c); }
    return NULL; }
static int listen_lo(char *port, size_t cap, struct sockaddr_in *addr) {
    int fd = socket(AF_INET, SOCK_STREAM, 0); int one = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {0}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&a, sizeof a) || listen(fd, 16)) { close(fd); return -1; }
    socklen_t al = sizeof a; getsockname(fd, (struct sockaddr *)&a, &al);
    if (port) snprintf(port, cap, "%d", ntohs(a.sin_port)); if (addr) *addr = a; return fd; }
static int connect_lo(const char *port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0); struct sockaddr_in a = {0};
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = htons((uint16_t)atoi(port));
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) { close(fd); return -1; } return fd; }

/* ---- agent + relay threads, serving over TLS ---- */
static tunnel_target_t g_fwd[1];
struct agent_ctx { char host[16], port[16]; const char *ca, *crt, *key; atomic_int sockfd; atomic_int up; };
static void *agent_thread(void *p) {
    struct agent_ctx *a = p;
    tunnel_tls_t tls;
    if (tunnel_tls_dial("localhost", a->port, a->ca, a->crt, a->key, &tls) == 0) {
        a->sockfd = tls.fd; a->up = 1;
        tunnel_agent_serve_ssl(tls.ssl, g_fwd, 1);
        tunnel_tls_free(&tls);
    }
    return NULL;
}
struct relay_ctx { int ctrl_lfd, pub_lfd; const char *crt, *key, *ca; atomic_int up; };
static void *relay_thread(void *p) {
    struct relay_ctx *r = p;
    int c = accept(r->ctrl_lfd, NULL, NULL);
    if (c < 0) return NULL;
    tunnel_tls_t tls;
    if (tunnel_tls_accept(c, r->crt, r->key, r->ca, &tls) == 0) {
        r->up = 1;
        tunnel_listener_t l = { .listen_fd = r->pub_lfd, .sni = 0, .forward_id = 0 };
        tunnel_relay_serve_ssl(tls.ssl, &l, 1, NULL, 0);
        tunnel_tls_free(&tls);
    } else close(c);
    return NULL;
}

struct cli_wr { int fd; size_t n; };
static void *cli_writer(void *p) {
    struct cli_wr *w = p; unsigned char b[16384]; size_t sent = 0;
    while (sent < w->n) { size_t c = (w->n - sent < sizeof b) ? (w->n - sent) : sizeof b;
        for (size_t i = 0; i < c; i++) b[i] = (unsigned char)((sent + i) & 0xff);
        if (write_all(w->fd, b, c) != 0) break; sent += c; }
    return NULL;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    printf("== tunnel end-to-end over mTLS ==\n");

    char dir[] = "/tmp/tunmtlsXXXXXX"; if (!mkdtemp(dir)) { perror("mkdtemp"); return 1; }
    char ca[256], scrt[256], skey[256], ccrt[256], ckey[256];
    snprintf(ca, sizeof ca, "%s/ca.pem", dir); snprintf(scrt, sizeof scrt, "%s/s.crt", dir);
    snprintf(skey, sizeof skey, "%s/s.key", dir); snprintf(ccrt, sizeof ccrt, "%s/c.crt", dir);
    snprintf(ckey, sizeof ckey, "%s/c.key", dir);
    EVP_PKEY *cak = gen_key(), *sk = gen_key(), *clk = gen_key();
    X509 *cac = mk_cert(cak, "tunnel CA", 1, cak, NULL, NULL, 1);
    X509 *sc = mk_cert(sk, "localhost", 0, cak, cac, "DNS:localhost", 2);
    X509 *cc = mk_cert(clk, "agent", 0, cak, cac, NULL, 3);
    wr_cert(ca, cac); wr_cert(scrt, sc); wr_key(skey, sk); wr_cert(ccrt, cc); wr_key(ckey, clk);

    struct echo_srv echo = {0}; char eport[16];
    echo.lfd = listen_lo(eport, sizeof eport, &echo.addr);
    pthread_create(&echo.acc, NULL, echo_acc, &echo);
    snprintf(g_fwd[0].host, sizeof g_fwd[0].host, "127.0.0.1");
    snprintf(g_fwd[0].port, sizeof g_fwd[0].port, "%s", eport);

    char cport[16], pport[16];
    int ctrl_lfd = listen_lo(cport, sizeof cport, NULL);   /* agent dials here */
    int pub_lfd  = listen_lo(pport, sizeof pport, NULL);   /* public clients */

    struct relay_ctx rctx = { .ctrl_lfd = ctrl_lfd, .pub_lfd = pub_lfd, .crt = scrt, .key = skey, .ca = ca };
    pthread_t rl; pthread_create(&rl, NULL, relay_thread, &rctx);
    struct agent_ctx actx = { .ca = ca, .crt = ccrt, .key = ckey, .sockfd = -1 };
    snprintf(actx.port, sizeof actx.port, "%s", cport);
    pthread_t ag; pthread_create(&ag, NULL, agent_thread, &actx);

    for (int i = 0; i < 200 && !(rctx.up && actx.up); i++) usleep(5000);  /* wait for the tunnel */
    chk("mTLS tunnel established (relay + agent)", rctx.up && actx.up);

    /* ---- single request over TLS ---- */
    {
        int c = connect_lo(pport);
        const char *m = "hello over tls"; size_t ml = strlen(m);
        write_all(c, m, ml);
        char buf[64]; int r = read_n(c, buf, ml);
        chk("request round-trips through the mTLS tunnel", r == (int)ml && memcmp(buf, m, ml) == 0);
        close(c);
    }
    /* ---- 256 KiB over TLS (partial records, backpressure, want-rd/want-wr) ---- */
    {
        int c = connect_lo(pport);
        size_t N = 256u * 1024;
        struct cli_wr w = { .fd = c, .n = N }; pthread_t wt; pthread_create(&wt, NULL, cli_writer, &w);
        size_t got = 0; int bad = 0; unsigned char b[16384];
        while (got < N) { ssize_t r = read(c, b, sizeof b); if (r <= 0) break;
            for (ssize_t i = 0; i < r; i++) if (b[i] != (unsigned char)((got + (size_t)i) & 0xff)) { bad = 1; break; }
            got += (size_t)r; }
        chk("256 KiB streams through TLS, byte-exact", got == N && !bad);
        pthread_join(wt, NULL); close(c);
    }

    /* teardown: drop the agent's socket -> both engines see EOF and return */
    if (actx.sockfd >= 0) shutdown(actx.sockfd, SHUT_RDWR);
    pthread_join(ag, NULL); pthread_join(rl, NULL);
    close(ctrl_lfd); close(pub_lfd);
    echo.stop = 1; int d = socket(AF_INET, SOCK_STREAM, 0);
    if (d >= 0) connect(d, (struct sockaddr *)&echo.addr, sizeof echo.addr);
    pthread_join(echo.acc, NULL); if (d >= 0) close(d); close(echo.lfd);
    for (int i = 0; i < echo.nconn; i++) pthread_join(echo.conns[i], NULL);
    EVP_PKEY_free(cak); EVP_PKEY_free(sk); EVP_PKEY_free(clk); X509_free(cac); X509_free(sc); X509_free(cc);
    unlink(ca); unlink(scrt); unlink(skey); unlink(ccrt); unlink(ckey); rmdir(dir);

    printf("\n%s  (%d ok, %d failed)\n", fail ? "FAIL" : "PASS", ok, fail);
    return fail ? 1 : 0;
}
