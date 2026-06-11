/* H4/M13 fix: the relay must authorize on the VERIFIED mTLS client-cert identity (subject
 * CN), not the agent-supplied HELLO agent_id, which the agent picks freely. Otherwise any
 * holder of a CA-signed leaf could assert any identity and inherit another tenant's
 * authorization.
 *
 * The agent presents a client cert with CN "real-id" but sends a HELLO claiming agent_id
 * "spoofed-id". We record the identity tunnel_relay_accept hands to the authorization
 * callback and assert it is the cert CN, never the spoofed HELLO value. */
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

static int listen_lo(char *port, size_t cap) {
    int fd = socket(AF_INET, SOCK_STREAM, 0); int one = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {0}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&a, sizeof a) || listen(fd, 16)) { close(fd); return -1; }
    socklen_t al = sizeof a; getsockname(fd, (struct sockaddr *)&a, &al);
    snprintf(port, cap, "%d", ntohs(a.sin_port)); return fd; }

static char g_seen[256];
static int allow_record(const char *identity, const char *host, void *ud) {
    (void)host; (void)ud;
    snprintf(g_seen, sizeof g_seen, "%s", identity ? identity : "(null)");
    return 1;   /* permit — the test only inspects WHICH identity authz was given */
}

struct stub { int lfd; const char *crt, *key, *ca; atomic_int done; };
static void *stub_thread(void *p) {
    struct stub *s = p;
    int c = accept(s->lfd, NULL, NULL);
    if (c < 0) return NULL;
    tunnel_tls_t tls;
    if (tunnel_tls_accept(c, s->crt, s->key, s->ca, &tls) == 0) {
        tunnel_io_t io = tunnel_io_tls(&tls);
        tunnel_decoder_t d; tunnel_decoder_reset(&d);
        tunnel_hello_t h; char err[128];
        tunnel_relay_accept(&io, &d, &h, tls.peer_id, NULL, 0, allow_record, NULL, err, sizeof err);
        tunnel_tls_free(&tls);
    } else { close(c); }
    atomic_store(&s->done, 1);
    return NULL;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    printf("== authz keys on the verified cert identity, not HELLO (H4/M13) ==\n");

    char dir[] = "/tmp/tunidXXXXXX"; if (!mkdtemp(dir)) { perror("mkdtemp"); return 1; }
    char ca[256], scrt[256], skey[256], ccrt[256], ckey[256];
    snprintf(ca, sizeof ca, "%s/ca.pem", dir); snprintf(scrt, sizeof scrt, "%s/s.crt", dir);
    snprintf(skey, sizeof skey, "%s/s.key", dir); snprintf(ccrt, sizeof ccrt, "%s/c.crt", dir);
    snprintf(ckey, sizeof ckey, "%s/c.key", dir);
    EVP_PKEY *cak = gen_key(), *sk = gen_key(), *clk = gen_key();
    X509 *cac = mk_cert(cak, "CA", 1, cak, NULL, NULL, 1);
    X509 *sc = mk_cert(sk, "localhost", 0, cak, cac, "DNS:localhost", 2);
    X509 *cc = mk_cert(clk, "real-id", 0, cak, cac, NULL, 3);   /* the VERIFIED identity */
    wr_cert(ca, cac); wr_cert(scrt, sc); wr_key(skey, sk); wr_cert(ccrt, cc); wr_key(ckey, clk);

    char cport[16];
    struct stub st = { .crt = scrt, .key = skey, .ca = ca };
    st.lfd = listen_lo(cport, sizeof cport); atomic_init(&st.done, 0);
    pthread_t stub; pthread_create(&stub, NULL, stub_thread, &st);

    /* agent: claim a DIFFERENT agent_id than the cert, declare a hostname so authz runs */
    tunnel_tls_t tls;
    int dr = tunnel_tls_dial("localhost", cport, ca, ccrt, ckey, &tls);
    chk("agent dialed the relay", dr == 0);
    int rr = -1;
    if (dr == 0) {
        tunnel_io_t io = tunnel_io_tls(&tls);
        tunnel_decoder_t dec; tunnel_decoder_reset(&dec);
        tunnel_hello_t hello; memset(&hello, 0, sizeof hello);
        snprintf(hello.agent_id, sizeof hello.agent_id, "spoofed-id");
        snprintf(hello.hostnames[0], sizeof hello.hostnames[0], "app.example.com");
        hello.n_hosts = 1;
        char err[128];
        rr = tunnel_agent_register(&io, &dec, &hello, err, sizeof err);
        tunnel_tls_free(&tls);
    }
    chk("agent registered", rr == 0);

    for (int i = 0; i < 200 && !atomic_load(&st.done); i++) usleep(10000);
    pthread_join(stub, NULL);

    printf("  authz saw identity: '%s'\n", g_seen);
    chk("authz received the VERIFIED cert CN ('real-id')", strcmp(g_seen, "real-id") == 0);
    chk("authz did NOT receive the spoofed HELLO agent_id", strcmp(g_seen, "spoofed-id") != 0);

    close(st.lfd);
    EVP_PKEY_free(cak); EVP_PKEY_free(sk); EVP_PKEY_free(clk); X509_free(cac); X509_free(sc); X509_free(cc);
    unlink(ca); unlink(scrt); unlink(skey); unlink(ccrt); unlink(ckey); rmdir(dir);

    printf("\n%s  (%d ok, %d failed)\n", fail ? "FAIL" : "PASS", ok, fail);
    return fail ? 1 : 0;
}
