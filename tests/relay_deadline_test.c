/* H1 fix: the relay control path must not be frozen by a peer that connects and then
 * stalls the TLS handshake / never sends HELLO. We park a silent connection on the
 * control port, then a REAL agent must still dial + register (proving the relay timed
 * the staller out instead of blocking forever). Negative control: the stalled
 * connection is itself dropped by the relay after the deadline. */
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

static int listen_lo(char *port, size_t cap) {
    int fd = socket(AF_INET, SOCK_STREAM, 0); int one = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {0}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&a, sizeof a) || listen(fd, 16)) { close(fd); return -1; }
    socklen_t al = sizeof a; getsockname(fd, (struct sockaddr *)&a, &al);
    snprintf(port, cap, "%d", ntohs(a.sin_port)); return fd; }
static int connect_lo(const char *port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0); struct sockaddr_in a = {0};
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = htons((uint16_t)atoi(port));
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) { close(fd); return -1; } return fd; }

static int allow_all(const char *a, const char *h, void *u) { (void)a; (void)h; (void)u; return 1; }

struct relctx { int ctrl_fd, pub_fd; const char *crt, *key, *ca; atomic_int stop; };
static void *relay_thread(void *p) {
    struct relctx *r = p;
    tunnel_listener_t l = { .listen_fd = r->pub_fd, .sni = 0, .forward_id = 0 };
    tunnel_relay_run_config_t cfg = {
        .control_fd = r->ctrl_fd, .cert = r->crt, .key = r->key, .client_ca = r->ca,
        .listeners = &l, .n_listeners = 1, .allow = allow_all,
        .handshake_timeout_ms = 300, .stop = &r->stop,
    };
    tunnel_relay_run(&cfg);
    return NULL;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    printf("== relay control-handshake deadline (H1) ==\n");

    char dir[] = "/tmp/tundlXXXXXX"; if (!mkdtemp(dir)) { perror("mkdtemp"); return 1; }
    char ca[256], scrt[256], skey[256], ccrt[256], ckey[256];
    snprintf(ca, sizeof ca, "%s/ca.pem", dir); snprintf(scrt, sizeof scrt, "%s/s.crt", dir);
    snprintf(skey, sizeof skey, "%s/s.key", dir); snprintf(ccrt, sizeof ccrt, "%s/c.crt", dir);
    snprintf(ckey, sizeof ckey, "%s/c.key", dir);
    EVP_PKEY *cak = gen_key(), *sk = gen_key(), *clk = gen_key();
    X509 *cac = mk_cert(cak, "CA", 1, cak, NULL, NULL, 1);
    X509 *sc = mk_cert(sk, "localhost", 0, cak, cac, "DNS:localhost", 2);
    X509 *cc = mk_cert(clk, "agent", 0, cak, cac, NULL, 3);
    wr_cert(ca, cac); wr_cert(scrt, sc); wr_key(skey, sk); wr_cert(ccrt, cc); wr_key(ckey, clk);

    char cport[16], pport[16];
    int ctrl = listen_lo(cport, sizeof cport);
    int pub  = listen_lo(pport, sizeof pport);
    struct relctx rc = { .ctrl_fd = ctrl, .pub_fd = pub, .crt = scrt, .key = skey, .ca = ca };
    atomic_init(&rc.stop, 0);
    pthread_t rl; pthread_create(&rl, NULL, relay_thread, &rc);

    /* Park a silent connection on the control port (send NOTHING). Without the deadline
     * this freezes the relay's blocking SSL_accept forever. */
    int staller = connect_lo(cport);
    chk("stalled connection opened on the control port", staller >= 0);
    usleep(50000);   /* let the relay accept it and enter the (now bounded) handshake */

    /* A real agent must still get past the staller: dial + register. */
    tunnel_tls_t tls;
    int dr = tunnel_tls_dial("localhost", cport, ca, ccrt, ckey, &tls);   /* waits out the staller */
    chk("real agent completes the mTLS dial despite the staller", dr == 0);

    int rr = -1;
    if (dr == 0) {
        tunnel_io_t io = tunnel_io_tls(&tls);
        tunnel_decoder_t dec; tunnel_decoder_reset(&dec);
        tunnel_hello_t hello; memset(&hello, 0, sizeof hello);
        snprintf(hello.agent_id, sizeof hello.agent_id, "real");
        char err[128];
        rr = tunnel_agent_register(&io, &dec, &hello, err, sizeof err);
        tunnel_tls_free(&tls);                       /* end this session cleanly */
    }
    chk("relay registered the real agent (control path not frozen)", rr == 0);

    /* Negative control: the staller was dropped by the relay after the deadline. */
    struct timeval tv = { 2, 0 }; setsockopt(staller, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    char junk[8]; ssize_t sr = read(staller, junk, sizeof junk);
    chk("staller was reaped (relay closed it after the deadline)", sr == 0);
    close(staller);

    atomic_store(&rc.stop, 1); pthread_join(rl, NULL);
    close(ctrl); close(pub);
    EVP_PKEY_free(cak); EVP_PKEY_free(sk); EVP_PKEY_free(clk); X509_free(cac); X509_free(sc); X509_free(cc);
    unlink(ca); unlink(scrt); unlink(skey); unlink(ccrt); unlink(ckey); rmdir(dir);

    printf("\n%s  (%d ok, %d failed)\n", fail ? "FAIL" : "PASS", ok, fail);
    return fail ? 1 : 0;
}
