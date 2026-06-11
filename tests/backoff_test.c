/* M10 fix: the agent must reset its reconnect backoff only after a session that actually
 * stayed up — not the instant registration succeeds. The old code reset backoff right after
 * HELLO_OK, so a relay that registers an agent and then immediately drops it would be
 * hammered at the floor interval forever (a flapping relay / thundering herd). The fix
 * resets backoff only once a served session has lasted a useful minimum.
 *
 * A relay stub registers the agent and then drops the tunnel immediately, over and over.
 * We record the time of each registration and assert the intervals GROW (exponential
 * backoff) instead of staying pinned at the floor. */
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
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

static int ok = 0, fail = 0;
static void chk(const char *n, int c) { printf("  %-5s %s\n", c ? "ok" : "FAIL", n); if (c) ok++; else fail++; }
static long now_ms(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1000 + t.tv_nsec / 1000000; }

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

/* relay stub: register the agent then DROP the tunnel immediately, recording each time. */
#define WANT 6
struct stub { int lfd; const char *crt, *key, *ca; long t[WANT]; atomic_int n, stop; struct sockaddr_in addr; };
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
        if (tunnel_relay_accept(&io, &d, &h, tls.peer_id, NULL, 0, allow_all, NULL, err, sizeof err) == 0) {
            int i = atomic_load(&s->n);
            if (i < WANT) { s->t[i] = now_ms(); atomic_store(&s->n, i + 1); }
        }
        tunnel_tls_free(&tls);                          /* drop immediately -> useless session */
    }
    return NULL;
}

struct agctx { tunnel_agent_run_config_t cfg; };
static void *agent_thread(void *p) { tunnel_agent_run(&((struct agctx *)p)->cfg); return NULL; }

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    printf("== backoff grows when sessions are instantly dropped (M10) ==\n");

    char dir[] = "/tmp/tunboXXXXXX"; if (!mkdtemp(dir)) { perror("mkdtemp"); return 1; }
    char ca[256], scrt[256], skey[256], ccrt[256], ckey[256];
    snprintf(ca, sizeof ca, "%s/ca.pem", dir); snprintf(scrt, sizeof scrt, "%s/s.crt", dir);
    snprintf(skey, sizeof skey, "%s/s.key", dir); snprintf(ccrt, sizeof ccrt, "%s/c.crt", dir);
    snprintf(ckey, sizeof ckey, "%s/c.key", dir);
    EVP_PKEY *cak = gen_key(), *sk = gen_key(), *clk = gen_key();
    X509 *cac = mk_cert(cak, "CA", 1, cak, NULL, NULL, 1);
    X509 *sc = mk_cert(sk, "localhost", 0, cak, cac, "DNS:localhost", 2);
    X509 *cc = mk_cert(clk, "agent", 0, cak, cac, NULL, 3);
    wr_cert(ca, cac); wr_cert(scrt, sc); wr_key(skey, sk); wr_cert(ccrt, cc); wr_key(ckey, clk);

    char cport[16];
    struct stub st = { .crt = scrt, .key = skey, .ca = ca };
    st.lfd = listen_lo(cport, sizeof cport, &st.addr);
    atomic_init(&st.n, 0); atomic_init(&st.stop, 0);
    pthread_t stub; pthread_create(&stub, NULL, stub_thread, &st);

    static tunnel_hello_t hello; memset(&hello, 0, sizeof hello);
    snprintf(hello.agent_id, sizeof hello.agent_id, "bo");
    static tunnel_target_t fwd = { "127.0.0.1", "9" };
    static atomic_int agent_stop; atomic_init(&agent_stop, 0);
    struct agctx ag; memset(&ag, 0, sizeof ag);
    ag.cfg.relay_host = "localhost"; ag.cfg.relay_port = cport;
    ag.cfg.ca_file = ca; ag.cfg.client_cert = ccrt; ag.cfg.client_key = ckey;
    ag.cfg.hello = &hello; ag.cfg.forwards = &fwd; ag.cfg.n_forwards = 1;
    ag.cfg.backoff_min_ms = 100; ag.cfg.backoff_max_ms = 5000; ag.cfg.register_timeout_ms = 500;
    ag.cfg.stop = &agent_stop;
    pthread_t at; pthread_create(&at, NULL, agent_thread, &ag);

    for (int i = 0; i < 1000 && atomic_load(&st.n) < WANT; i++) usleep(10000);   /* up to ~10s */
    int n = atomic_load(&st.n);
    chk("agent kept reconnecting through repeated instant drops", n >= WANT);

    int grew = 0;
    if (n >= WANT) {
        long g_first = st.t[1] - st.t[0];                 /* first reconnect interval */
        long g_last  = st.t[WANT - 1] - st.t[WANT - 2];   /* latest reconnect interval */
        grew = g_last >= 4 * g_first;                     /* exponential growth, not pinned at floor */
        printf("  first interval=%ldms last interval=%ldms\n", g_first, g_last);
    }
    chk("reconnect interval grew (backoff not reset after useless sessions)", grew);

    atomic_store(&agent_stop, 1); atomic_store(&st.stop, 1);
    int d = socket(AF_INET, SOCK_STREAM, 0);
    if (d >= 0) { connect(d, (struct sockaddr *)&st.addr, sizeof st.addr); close(d); }
    pthread_join(at, NULL); pthread_join(stub, NULL); close(st.lfd);
    EVP_PKEY_free(cak); EVP_PKEY_free(sk); EVP_PKEY_free(clk); X509_free(cac); X509_free(sc); X509_free(cc);
    unlink(ca); unlink(scrt); unlink(skey); unlink(ccrt); unlink(ckey); rmdir(dir);

    printf("\n%s  (%d ok, %d failed)\n", fail ? "FAIL" : "PASS", ok, fail);
    return fail ? 1 : 0;
}
