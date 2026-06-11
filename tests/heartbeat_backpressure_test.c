/* M8 fix: heartbeats must not tear down a live-but-backpressured tunnel. When a serve loop
 * is backpressured (a local sink has stalled) it stops reading the tunnel — so it cannot
 * receive PONGs either. The old code still counted those as "missed" heartbeats and declared
 * the peer dead after ~2 intervals, resetting a perfectly healthy tunnel. The fix only runs
 * the heartbeat when genuinely idle (nothing queued for the peer AND not backpressured).
 *
 * We exercise the AGENT side. A relay stub registers the agent, opens one stream, then floods
 * it with DATA. The agent's forward is a black-hole that never reads, so the agent backs up
 * and stops reading the tunnel — it can no longer answer PINGs. We run the agent with a 1s
 * heartbeat for several intervals and assert it does NOT reconnect (the stub accepts exactly
 * once). With the old code the agent kills its own tunnel and redials -> the stub accepts
 * again. */
#include "stream.h"
#include "tls.h"
#include "control.h"
#include "io.h"
#include "frame.h"

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
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

static int ok = 0, fail = 0;
static void chk(const char *n, int c) { printf("  %-5s %s\n", c ? "ok" : "FAIL", n); if (c) ok++; else fail++; }

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

static int allow_all(const char *a, const char *h, void *u) { (void)a; (void)h; (void)u; return 1; }

/* black-hole forward 0: accept and never read until released (then drain so teardown unwinds) */
static atomic_int g_release;
struct hole { int lfd; pthread_t acc; pthread_t conns[8]; int nconn; atomic_int stop; struct sockaddr_in addr; };
static void *hole_conn(void *p) { int c = (int)(intptr_t)p; unsigned char b[8192];
    while (!atomic_load(&g_release)) usleep(10000);          /* hold: never read -> agent backs up */
    for (;;) { ssize_t n = read(c, b, sizeof b); if (n <= 0) break; }
    close(c); return NULL; }
static void *hole_acc(void *p) { struct hole *s = p;
    for (;;) { int c = accept(s->lfd, NULL, NULL); if (c < 0) break; if (atomic_load(&s->stop)) { close(c); break; }
        if (s->nconn < 8) { pthread_create(&s->conns[s->nconn], NULL, hole_conn, (void *)(intptr_t)c); s->nconn++; } else close(c); }
    return NULL; }
static int hole_start(struct hole *s, char *port, size_t cap) {
    s->lfd = socket(AF_INET, SOCK_STREAM, 0); int one = 1; setsockopt(s->lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {0}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = 0;
    if (bind(s->lfd, (struct sockaddr *)&a, sizeof a) || listen(s->lfd, 16)) return -1;
    socklen_t al = sizeof a; getsockname(s->lfd, (struct sockaddr *)&a, &al);
    snprintf(port, cap, "%d", ntohs(a.sin_port)); s->addr = a; s->nconn = 0; atomic_init(&s->stop, 0);
    pthread_create(&s->acc, NULL, hole_acc, s); return 0; }
static void hole_stop(struct hole *s) {
    atomic_store(&s->stop, 1); atomic_store(&g_release, 1); int d = socket(AF_INET, SOCK_STREAM, 0);
    if (d >= 0) connect(d, (struct sockaddr *)&s->addr, sizeof s->addr);
    pthread_join(s->acc, NULL); if (d >= 0) close(d);
    for (int i = 0; i < s->nconn; i++) pthread_join(s->conns[i], NULL); close(s->lfd); }

/* relay stub: register the agent (counting each registration), open a stream, flood it. */
struct stub { int lfd; const char *crt, *key, *ca; atomic_int accepts, stop; struct sockaddr_in addr; };
static void *stub_thread(void *p) {
    struct stub *s = p;
    while (!atomic_load(&s->stop)) {
        int c = accept(s->lfd, NULL, NULL);
        if (c < 0) break;
        if (atomic_load(&s->stop)) { close(c); break; }
        tunnel_tls_t tls;
        if (tunnel_tls_accept(c, s->crt, s->key, s->ca, &tls) != 0) { close(c); continue; }
        tunnel_io_t io = tunnel_io_tls(&tls);
        tunnel_decoder_t d; tunnel_decoder_reset(&d);
        tunnel_hello_t h; char err[128];
        if (tunnel_relay_accept(&io, &d, &h, allow_all, NULL, err, sizeof err) != 0) { tunnel_tls_free(&tls); continue; }
        atomic_fetch_add(&s->accepts, 1);
        unsigned char fid[4] = { 0, 0, 0, 0 };
        tunnel_io_write_frame(&io, TF_OPEN, 1, fid, 4);
        unsigned char buf[16384]; memset(buf, 'x', sizeof buf);
        while (!atomic_load(&s->stop)) {                     /* flood until the agent backs up / drops */
            if (tunnel_io_write_frame(&io, TF_DATA, 1, buf, sizeof buf) != 0) break;
        }
        tunnel_tls_free(&tls);
    }
    return NULL;
}

struct agctx { tunnel_agent_run_config_t cfg; };
static void *agent_thread(void *p) { tunnel_agent_run(&((struct agctx *)p)->cfg); return NULL; }

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    printf("== heartbeat must not kill a backpressured tunnel (M8) ==\n");
    atomic_init(&g_release, 0);

    char dir[] = "/tmp/tunhbXXXXXX"; if (!mkdtemp(dir)) { perror("mkdtemp"); return 1; }
    char ca[256], scrt[256], skey[256], ccrt[256], ckey[256];
    snprintf(ca, sizeof ca, "%s/ca.pem", dir); snprintf(scrt, sizeof scrt, "%s/s.crt", dir);
    snprintf(skey, sizeof skey, "%s/s.key", dir); snprintf(ccrt, sizeof ccrt, "%s/c.crt", dir);
    snprintf(ckey, sizeof ckey, "%s/c.key", dir);
    EVP_PKEY *cak = gen_key(), *sk = gen_key(), *clk = gen_key();
    X509 *cac = mk_cert(cak, "CA", 1, cak, NULL, NULL, 1);
    X509 *sc = mk_cert(sk, "localhost", 0, cak, cac, "DNS:localhost", 2);
    X509 *cc = mk_cert(clk, "agent", 0, cak, cac, NULL, 3);
    wr_cert(ca, cac); wr_cert(scrt, sc); wr_key(skey, sk); wr_cert(ccrt, cc); wr_key(ckey, clk);

    struct hole hole = {0}; char hport[16]; hole_start(&hole, hport, sizeof hport);

    char cport[16];
    struct stub st = { .crt = scrt, .key = skey, .ca = ca };
    st.lfd = listen_lo(cport, sizeof cport, &st.addr);
    atomic_init(&st.accepts, 0); atomic_init(&st.stop, 0);
    pthread_t stub; pthread_create(&stub, NULL, stub_thread, &st);

    static tunnel_hello_t hello; memset(&hello, 0, sizeof hello);
    snprintf(hello.agent_id, sizeof hello.agent_id, "hb");
    static tunnel_target_t fwd; snprintf(fwd.host, sizeof fwd.host, "127.0.0.1");
    snprintf(fwd.port, sizeof fwd.port, "%s", hport);
    static atomic_int agent_stop; atomic_init(&agent_stop, 0);
    struct agctx ag; memset(&ag, 0, sizeof ag);
    ag.cfg.relay_host = "localhost"; ag.cfg.relay_port = cport;
    ag.cfg.ca_file = ca; ag.cfg.client_cert = ccrt; ag.cfg.client_key = ckey;
    ag.cfg.hello = &hello; ag.cfg.forwards = &fwd; ag.cfg.n_forwards = 1;
    ag.cfg.backoff_min_ms = 40; ag.cfg.backoff_max_ms = 120;
    ag.cfg.register_timeout_ms = 1000; ag.cfg.heartbeat_secs = 1; ag.cfg.stop = &agent_stop;
    pthread_t at; pthread_create(&at, NULL, agent_thread, &ag);

    sleep(5);                                               /* several heartbeat intervals under backpressure */
    int accepts = atomic_load(&st.accepts);
    chk("agent registered (the stream is flooding the black-hole forward)", accepts >= 1);
    chk("agent did NOT reconnect: heartbeat left the backpressured tunnel up", accepts == 1);

    /* teardown: release the hole + stop the stub so the agent's session ends, then stop agent */
    atomic_store(&agent_stop, 1); atomic_store(&st.stop, 1); atomic_store(&g_release, 1);
    int d = socket(AF_INET, SOCK_STREAM, 0);
    if (d >= 0) { connect(d, (struct sockaddr *)&st.addr, sizeof st.addr); close(d); }
    pthread_join(at, NULL); pthread_join(stub, NULL);
    hole_stop(&hole); close(st.lfd);
    EVP_PKEY_free(cak); EVP_PKEY_free(sk); EVP_PKEY_free(clk); X509_free(cac); X509_free(sc); X509_free(cc);
    unlink(ca); unlink(scrt); unlink(skey); unlink(ccrt); unlink(ckey); rmdir(dir);

    printf("\n%s  (%d ok, %d failed)  [%d registrations]\n", fail ? "FAIL" : "PASS", ok, fail, accepts);
    return fail ? 1 : 0;
}
