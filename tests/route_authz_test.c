/* H4 fix: the relay must serve each agent only the SNI routes its verified identity is
 * authorized for, not the relay's entire route table. Otherwise any authenticated agent
 * receives (and can MITM) every tenant's hostnames.
 *
 * The relay is configured with two routes (a.test, b.test) but an allow() policy that grants
 * this agent ONLY a.test. We drive a real relay run loop + a manual agent (forward 0 = echo)
 * and assert: an SNI ClientHello for a.test round-trips to the echo, while one for b.test is
 * dropped (no authorized route for this agent). */
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
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

static int ok = 0, fail = 0;
static void chk(const char *n, int c) { printf("  %-5s %s\n", c ? "ok" : "FAIL", n); if (c) ok++; else fail++; }
static int write_all(int fd, const void *b, size_t n) { const unsigned char *p = b; size_t o = 0;
    while (o < n) { ssize_t w = write(fd, p + o, n - o); if (w <= 0) return -1; o += (size_t)w; } return 0; }
static int read_n(int fd, void *b, size_t n) { unsigned char *p = b; size_t g = 0;
    while (g < n) { ssize_t r = read(fd, p + g, n - g); if (r <= 0) break; g += (size_t)r; } return (int)g; }

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
    if (bind(fd, (struct sockaddr *)&a, sizeof a) || listen(fd, 16)) { close(fd); return -1; }
    socklen_t al = sizeof a; getsockname(fd, (struct sockaddr *)&a, &al);
    snprintf(port, cap, "%d", ntohs(a.sin_port)); if (addr) *addr = a; return fd; }
static int connect_lo(const char *port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0); struct sockaddr_in a = {0};
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = htons((uint16_t)atoi(port));
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) { close(fd); return -1; } return fd; }

/* drive OpenSSL just far enough to emit a ClientHello with `sni` */
static int capture_clienthello(const char *sni, unsigned char *out, size_t cap) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method()); SSL *ssl = SSL_new(ctx);
    int sp[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, sp); fcntl(sp[0], F_SETFL, O_NONBLOCK);
    SSL_set_fd(ssl, sp[0]); if (sni) SSL_set_tlsext_host_name(ssl, sni); SSL_connect(ssl);
    ssize_t n = read(sp[1], out, cap);
    SSL_free(ssl); SSL_CTX_free(ctx); close(sp[0]); close(sp[1]); return (int)n; }

/* echo (the agent's forward 0) */
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

/* allow only a.test for any identity (the per-agent policy under test) */
static int allow_a_only(const char *identity, const char *host, void *ud) {
    (void)identity; (void)ud; return strcmp(host, "a.test") == 0; }

struct relctx { int ctrl_fd, sni_fd; const char *crt, *key, *ca; atomic_int stop; };
static void *relay_thread(void *p) {
    struct relctx *r = p;
    tunnel_listener_t l = { .listen_fd = r->sni_fd, .sni = 1, .forward_id = 0 };
    tunnel_sni_route_t routes[2] = { { .host = "a.test", .forward_id = 0 }, { .host = "b.test", .forward_id = 0 } };
    tunnel_relay_run_config_t cfg = {
        .control_fd = r->ctrl_fd, .cert = r->crt, .key = r->key, .client_ca = r->ca,
        .listeners = &l, .n_listeners = 1, .routes = routes, .n_routes = 2, .allow = allow_a_only,
        .handshake_timeout_ms = 1000, .idle_timeout_ms = 30000, .stop = &r->stop,
    };
    tunnel_relay_run(&cfg);
    return NULL;
}

struct agserve { SSL *ssl; const tunnel_target_t *fwd; };
static void *agent_serve_thread(void *p) { struct agserve *a = p; tunnel_agent_serve_ssl(a->ssl, a->fwd, 1); return NULL; }

/* connect to the relay's SNI port, send a ClientHello for `sni`, return 1 if the echo
 * round-trips the handshake bytes, 0 if dropped. */
static int sni_probe(const char *sport, const char *sni) {
    unsigned char ch[4096]; int chn = capture_clienthello(sni, ch, sizeof ch);
    if (chn <= 0) return -1;
    int c = connect_lo(sport); if (c < 0) return -1;
    struct timeval tv = { 2, 0 }; setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    write_all(c, ch, (size_t)chn);
    unsigned char back[4096]; int got = read_n(c, back, (size_t)chn);
    int rt = (got == chn && memcmp(back, ch, (size_t)chn) == 0);
    close(c); return rt;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    printf("== relay serves only the agent's authorized SNI routes (H4) ==\n");

    char dir[] = "/tmp/tunraXXXXXX"; if (!mkdtemp(dir)) { perror("mkdtemp"); return 1; }
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

    char cport[16], sport[16];
    int ctrl = listen_lo(cport, sizeof cport, NULL);
    int sni  = listen_lo(sport, sizeof sport, NULL);
    struct relctx rc = { .ctrl_fd = ctrl, .sni_fd = sni, .crt = scrt, .key = skey, .ca = ca };
    atomic_init(&rc.stop, 0);
    pthread_t rl; pthread_create(&rl, NULL, relay_thread, &rc);

    tunnel_tls_t tls;
    int dr = tunnel_tls_dial("localhost", cport, ca, ccrt, ckey, &tls);
    chk("agent dialed the relay", dr == 0);
    int rr = -1;
    if (dr == 0) {
        tunnel_io_t io = tunnel_io_tls(&tls);
        tunnel_decoder_t dec; tunnel_decoder_reset(&dec);
        tunnel_hello_t hello; memset(&hello, 0, sizeof hello);
        snprintf(hello.agent_id, sizeof hello.agent_id, "agent");   /* no hostnames: pure forward */
        char err[128];
        rr = tunnel_agent_register(&io, &dec, &hello, err, sizeof err);
    }
    chk("agent registered", rr == 0);
    if (rr != 0) { atomic_store(&rc.stop, 1); pthread_join(rl, NULL); return 1; }

    static tunnel_target_t fwd; snprintf(fwd.host, sizeof fwd.host, "127.0.0.1");
    snprintf(fwd.port, sizeof fwd.port, "%s", eport);
    struct agserve as = { .ssl = tls.ssl, .fwd = &fwd };
    pthread_t at; pthread_create(&at, NULL, agent_serve_thread, &as);
    usleep(200000);

    chk("authorized SNI (a.test) round-trips to the agent's forward", sni_probe(sport, "a.test") == 1);
    chk("unauthorized SNI (b.test) is dropped (no route for this agent)", sni_probe(sport, "b.test") == 0);

    shutdown(tls.fd, SHUT_RDWR);
    atomic_store(&rc.stop, 1);
    pthread_join(at, NULL); pthread_join(rl, NULL);
    tunnel_tls_free(&tls); echo_stop(&echo); close(ctrl); close(sni);
    EVP_PKEY_free(cak); EVP_PKEY_free(sk); EVP_PKEY_free(clk); X509_free(cac); X509_free(sc); X509_free(cc);
    unlink(ca); unlink(scrt); unlink(skey); unlink(ccrt); unlink(ckey); rmdir(dir);

    printf("\n%s  (%d ok, %d failed)\n", fail ? "FAIL" : "PASS", ok, fail);
    return fail ? 1 : 0;
}
