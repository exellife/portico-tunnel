/* Heartbeat liveness against a HALF-OPEN peer. The relay accepts + registers each
 * agent then holds the tunnel open but goes completely SILENT — it never reads and
 * never answers a PING. TCP stays ESTABLISHED (the kernel ACKs the agent's writes),
 * so the agent's writes keep succeeding; only an inbound PONG can prove the peer is
 * actually alive. The agent's heartbeat must notice the missing PONGs, tear the dead
 * session down, and reconnect.
 *
 * Regression for the bug where `missed` was reset on every successful tunnel WRITE
 * ("peer is accepting our bytes -> alive"): a half-open conn accepts writes forever,
 * so `missed` never climbed and a dead data path masqueraded as live. With that bug
 * this test's relay registers exactly ONCE and the agent hangs in serve_loop forever
 * (conns stays at 1). Fixed, the agent re-establishes repeatedly. */
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
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

static int ok = 0, fail = 0;
static void chk(const char *n, int c) { printf("  %-5s %s\n", c ? "ok" : "FAIL", n); if (c) ok++; else fail++; }

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
    if (port) snprintf(port, cap, "%d", ntohs(a.sin_port)); if (addr) *addr = a; return fd;
}

static int allow_all(const char *a, const char *h, void *u) { (void)a; (void)h; (void)u; return 1; }

/* Relay that registers each agent then HOLDS the session open and silent (never reads,
 * never PONGs). Stashes the TLS so the fd stays alive — the wedge the agent must detect. */
struct relctx { int lfd; const char *crt, *key, *ca; atomic_int conns; atomic_int stop;
                tunnel_tls_t held[32]; int nheld; };
static void *relay_silent_thread(void *p) {
    struct relctx *r = p;
    while (!atomic_load(&r->stop)) {
        int c = accept(r->lfd, NULL, NULL);
        if (c < 0) break;
        if (atomic_load(&r->stop)) { close(c); break; }
        tunnel_tls_t tls;
        if (tunnel_tls_accept(c, r->crt, r->key, r->ca, &tls) == 0) {
            tunnel_io_t io = tunnel_io_tls(&tls);
            tunnel_decoder_t dec; tunnel_decoder_reset(&dec);
            tunnel_hello_t h;
            if (tunnel_relay_accept(&io, &dec, &h, tls.peer_id, NULL, 0, allow_all, NULL, NULL, 0) == 0) {
                atomic_fetch_add(&r->conns, 1);
                /* hold it open + silent (no read, no PONG); the agent's heartbeat must kill it */
                if (r->nheld < (int)(sizeof r->held / sizeof r->held[0])) r->held[r->nheld++] = tls;
                else tunnel_tls_free(&tls);
            } else {
                tunnel_tls_free(&tls);
            }
        } else {
            close(c);
        }
    }
    for (int i = 0; i < r->nheld; i++) tunnel_tls_free(&r->held[i]);
    return NULL;
}

struct runarg { tunnel_agent_run_config_t cfg; };
static void *agent_run_thread(void *p) { tunnel_agent_run(&((struct runarg *)p)->cfg); return NULL; }

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    printf("== tunnel heartbeat (half-open detection) ==\n");

    char dir[] = "/tmp/tunhbXXXXXX"; if (!mkdtemp(dir)) { perror("mkdtemp"); return 1; }
    char ca[256], scrt[256], skey[256], ccrt[256], ckey[256];
    snprintf(ca, sizeof ca, "%s/ca.pem", dir); snprintf(scrt, sizeof scrt, "%s/s.crt", dir);
    snprintf(skey, sizeof skey, "%s/s.key", dir); snprintf(ccrt, sizeof ccrt, "%s/c.crt", dir);
    snprintf(ckey, sizeof ckey, "%s/c.key", dir);
    EVP_PKEY *cak = gen_key(), *sk = gen_key(), *clk = gen_key();
    X509 *cac = mk_cert(cak, "CA", 1, cak, NULL, NULL, 1);
    X509 *sc  = mk_cert(sk, "localhost", 0, cak, cac, "DNS:localhost", 2);
    X509 *cc  = mk_cert(clk, "agent", 0, cak, cac, NULL, 3);
    wr_cert(ca, cac); wr_cert(scrt, sc); wr_key(skey, sk); wr_cert(ccrt, cc); wr_key(ckey, clk);

    char cport[16]; struct sockaddr_in caddr;
    int ctrl_lfd = listen_lo(cport, sizeof cport, &caddr);

    struct relctx rc = { .lfd = ctrl_lfd, .crt = scrt, .key = skey, .ca = ca };
    atomic_init(&rc.conns, 0); atomic_init(&rc.stop, 0);
    pthread_t rl; pthread_create(&rl, NULL, relay_silent_thread, &rc);

    static tunnel_hello_t hello;
    snprintf(hello.agent_id, sizeof hello.agent_id, "hb-agent");
    snprintf(hello.hostnames[0], sizeof hello.hostnames[0], "x.test");
    hello.n_hosts = 1;
    static tunnel_target_t fwd = { "127.0.0.1", "9" };   /* unused: no stream is ever opened */
    atomic_int agent_stop; atomic_init(&agent_stop, 0);

    struct runarg ra; memset(&ra, 0, sizeof ra);
    ra.cfg.relay_host = "localhost"; ra.cfg.relay_port = cport;
    ra.cfg.ca_file = ca; ra.cfg.client_cert = ccrt; ra.cfg.client_key = ckey;
    ra.cfg.hello = &hello; ra.cfg.forwards = &fwd; ra.cfg.n_forwards = 1;
    ra.cfg.heartbeat_secs = 1;                            /* fast: ~3 missed beats -> ~3s to detect */
    ra.cfg.backoff_min_ms = 30; ra.cfg.backoff_max_ms = 120; ra.cfg.stop = &agent_stop;
    pthread_t ag; pthread_create(&ag, NULL, agent_run_thread, &ra);

    /* The buggy code registers once and hangs forever (conns == 1). The fix detects each
     * silent session via the heartbeat and reconnects, so conns climbs. Allow ~16s. */
    for (int i = 0; i < 1600 && atomic_load(&rc.conns) < 2; i++) usleep(10000);
    int got = atomic_load(&rc.conns);
    chk("agent heartbeat kills a silent half-open session and reconnects (conns>=2)", got >= 2);

    /* It must still stop promptly even while mid-session on a silent peer. */
    atomic_store(&agent_stop, 1);
    struct timespec t0; clock_gettime(CLOCK_MONOTONIC, &t0);
    pthread_join(ag, NULL);
    struct timespec t1; clock_gettime(CLOCK_MONOTONIC, &t1);
    double ms = (t1.tv_sec - t0.tv_sec) * 1000.0 + (t1.tv_nsec - t0.tv_nsec) / 1e6;
    chk("agent run loop stops promptly when asked", ms < 1500.0);

    atomic_store(&rc.stop, 1);
    int d = socket(AF_INET, SOCK_STREAM, 0);
    if (d >= 0) { connect(d, (struct sockaddr *)&caddr, sizeof caddr); }
    pthread_join(rl, NULL);
    if (d >= 0) close(d);
    close(ctrl_lfd);

    EVP_PKEY_free(cak); EVP_PKEY_free(sk); EVP_PKEY_free(clk); X509_free(cac); X509_free(sc); X509_free(cc);
    unlink(ca); unlink(scrt); unlink(skey); unlink(ccrt); unlink(ckey); rmdir(dir);

    printf("\n%s  (%d ok, %d failed)  [%d sessions registered]\n", fail ? "FAIL" : "PASS", ok, fail, got);
    return fail ? 1 : 0;
}
