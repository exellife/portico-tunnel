/* M6 fix: the bytes the registration read pulls past HELLO_OK must not be lost. A relay
 * may pipeline the first OPEN (and its DATA) into the very same TLS record as HELLO_OK; the
 * agent's register decoder then holds those frames, and a fresh serve-loop decoder would
 * silently drop them — the stream would never open. The run loop now seeds serve_loop with
 * the registration decoder.
 *
 * Relay stub: complete the mTLS handshake, read the agent's HELLO, then write HELLO_OK +
 * OPEN(stream 1, forward 0) + DATA(stream 1, "ping") in ONE SSL_write so they share a
 * record. The agent must dial forward 0 (a local echo) and echo "ping" back over stream 1.
 * Without the seed the OPEN/DATA are stranded in the discarded decoder and nothing comes
 * back. */
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
    if (bind(fd, (struct sockaddr *)&a, sizeof a) || listen(fd, 16)) { close(fd); return -1; }
    socklen_t al = sizeof a; getsockname(fd, (struct sockaddr *)&a, &al);
    snprintf(port, cap, "%d", ntohs(a.sin_port)); if (addr) *addr = a; return fd; }

/* echo server = the agent's forward 0 */
struct echo_srv { int lfd; pthread_t acc; pthread_t conns[8]; int nconn; struct sockaddr_in addr; volatile int stop; };
static void *echo_conn(void *p) { int c = (int)(intptr_t)p; unsigned char b[1024]; ssize_t n;
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

struct stub { int lfd; const char *crt, *key, *ca; atomic_int got, stop; };
static void *stub_thread(void *p) {
    struct stub *s = p;
    int c = accept(s->lfd, NULL, NULL);
    if (c < 0) return NULL;
    tunnel_tls_t tls;
    if (tunnel_tls_accept(c, s->crt, s->key, s->ca, &tls) != 0) { close(c); return NULL; }
    struct timeval tv = { 3, 0 }; setsockopt(tls.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    tunnel_io_t io = tunnel_io_tls(&tls);
    tunnel_decoder_t d; tunnel_decoder_reset(&d);
    tunnel_frame_t f;

    /* read the agent's HELLO */
    int saw_hello = 0;
    for (int i = 0; i < 8; i++) { int r = tunnel_io_read_frame(&io, &d, &f); if (r != 1) break; if (f.type == TF_HELLO) { saw_hello = 1; break; } }
    if (saw_hello) {
        /* HELLO_OK + OPEN(1, fwd 0) + DATA(1,"ping") in ONE SSL_write -> one record */
        unsigned char buf[128]; int off = 0, n;
        n = tunnel_frame_encode(TF_HELLO_OK, 0, NULL, 0, buf + off, sizeof buf - off); off += n;
        unsigned char fid[4] = { 0, 0, 0, 0 };
        n = tunnel_frame_encode(TF_OPEN, 1, fid, 4, buf + off, sizeof buf - off); off += n;
        n = tunnel_frame_encode(TF_DATA, 1, "ping", 4, buf + off, sizeof buf - off); off += n;
        SSL_write(tls.ssl, buf, off);

        /* the agent must dial the echo and send "ping" back on stream 1 */
        for (int i = 0; i < 16; i++) {
            int r = tunnel_io_read_frame(&io, &d, &f);
            if (r != 1) break;
            if (f.type == TF_DATA && f.stream_id == 1 && f.len == 4 && memcmp(f.payload, "ping", 4) == 0) {
                atomic_store(&s->got, 1); break;
            }
        }
    }
    while (!atomic_load(&s->stop)) usleep(10000);   /* hold the session until the test ends it */
    tunnel_tls_free(&tls);
    return NULL;
}

struct agctx { tunnel_agent_run_config_t cfg; };
static void *agent_thread(void *p) { tunnel_agent_run(&((struct agctx *)p)->cfg); return NULL; }

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    printf("== registration decoder handoff (M6) ==\n");

    char dir[] = "/tmp/tunhoXXXXXX"; if (!mkdtemp(dir)) { perror("mkdtemp"); return 1; }
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

    char cport[16];
    struct stub st = { .crt = scrt, .key = skey, .ca = ca };
    st.lfd = listen_lo(cport, sizeof cport, NULL);
    atomic_init(&st.got, 0); atomic_init(&st.stop, 0);
    pthread_t stub; pthread_create(&stub, NULL, stub_thread, &st);

    static tunnel_hello_t hello; memset(&hello, 0, sizeof hello);
    snprintf(hello.agent_id, sizeof hello.agent_id, "ho");
    static tunnel_target_t fwd; snprintf(fwd.host, sizeof fwd.host, "127.0.0.1");
    snprintf(fwd.port, sizeof fwd.port, "%s", eport);
    static atomic_int agent_stop; atomic_init(&agent_stop, 0);
    struct agctx ag; memset(&ag, 0, sizeof ag);
    ag.cfg.relay_host = "localhost"; ag.cfg.relay_port = cport;
    ag.cfg.ca_file = ca; ag.cfg.client_cert = ccrt; ag.cfg.client_key = ckey;
    ag.cfg.hello = &hello; ag.cfg.forwards = &fwd; ag.cfg.n_forwards = 1;
    ag.cfg.backoff_min_ms = 40; ag.cfg.backoff_max_ms = 120; ag.cfg.register_timeout_ms = 1000;
    ag.cfg.stop = &agent_stop;
    pthread_t at; pthread_create(&at, NULL, agent_thread, &ag);

    for (int i = 0; i < 300 && !atomic_load(&st.got); i++) usleep(10000);   /* up to ~3s */
    chk("agent processed the OPEN+DATA pipelined after HELLO_OK (echoed back)", atomic_load(&st.got));

    atomic_store(&agent_stop, 1); atomic_store(&st.stop, 1);
    pthread_join(at, NULL); pthread_join(stub, NULL);
    echo_stop(&echo); close(st.lfd);
    EVP_PKEY_free(cak); EVP_PKEY_free(sk); EVP_PKEY_free(clk); X509_free(cac); X509_free(sc); X509_free(cc);
    unlink(ca); unlink(scrt); unlink(skey); unlink(ccrt); unlink(ckey); rmdir(dir);

    printf("\n%s  (%d ok, %d failed)\n", fail ? "FAIL" : "PASS", ok, fail);
    return fail ? 1 : 0;
}
