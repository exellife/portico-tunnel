/* The control handshake over real TLS with mutual auth. A throwaway CA (minted in
 * process) signs a server cert (SAN localhost) and an agent client cert. Positive:
 * the agent verifies the relay, presents its cert, and registers. Negative controls
 * (prove the checks are enforced, not decorative): an untrusted relay cert is
 * rejected by the agent; an agent with no client cert is rejected by the relay. */
#include "tls.h"
#include "control.h"

#include <stdio.h>
#include <string.h>
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
static void chk(const char *n, int c) {
    printf("  %-5s %s\n", c ? "ok" : "FAIL", n);
    if (c) ok++; else fail++;
}

/* ---- tiny in-process CA / cert minting ---- */
static EVP_PKEY *gen_key(void) { return EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256"); }

static X509 *mk_cert(EVP_PKEY *key, const char *cn, int is_ca,
                     EVP_PKEY *issuer_key, X509 *issuer_cert, const char *san, long serial) {
    X509 *x = X509_new();
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), serial);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 3600);
    X509_set_pubkey(x, key);
    X509_NAME *nm = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC, (const unsigned char *)cn, -1, -1, 0);
    X509_set_issuer_name(x, issuer_cert ? X509_get_subject_name(issuer_cert) : nm);

    X509V3_CTX vc;
    X509V3_set_ctx(&vc, issuer_cert ? issuer_cert : x, x, NULL, NULL, 0);
    if (is_ca) {
        X509_EXTENSION *e = X509V3_EXT_conf_nid(NULL, &vc, NID_basic_constraints, "critical,CA:TRUE");
        if (e) { X509_add_ext(x, e, -1); X509_EXTENSION_free(e); }
    }
    if (san) {
        X509_EXTENSION *e = X509V3_EXT_conf_nid(NULL, &vc, NID_subject_alt_name, san);
        if (e) { X509_add_ext(x, e, -1); X509_EXTENSION_free(e); }
    }
    X509_sign(x, issuer_key, EVP_sha256());
    return x;
}

static int wr_cert(const char *p, X509 *x) {
    FILE *f = fopen(p, "w"); if (!f) return -1;
    int r = PEM_write_X509(f, x); fclose(f); return r ? 0 : -1;
}
static int wr_key(const char *p, EVP_PKEY *k) {
    FILE *f = fopen(p, "w"); if (!f) return -1;
    int r = PEM_write_PrivateKey(f, k, NULL, NULL, 0, NULL, NULL); fclose(f); return r ? 0 : -1;
}

/* ---- relay-side helpers ---- */
static int allow_one(const char *agent_id, const char *host, void *ud) {
    (void)agent_id; return strcmp(host, (const char *)ud) == 0;
}

struct srv {
    int listen_fd;
    const char *crt, *key, *ca, *allowed;
    int accepted, registered;
};
static void *srv_thread(void *p) {
    struct srv *s = p;
    int c = accept(s->listen_fd, NULL, NULL);
    if (c < 0) return NULL;
    tunnel_tls_t tls;
    if (tunnel_tls_accept(c, s->crt, s->key, s->ca, &tls) == 0) {
        s->accepted = 1;
        tunnel_io_t io = tunnel_io_tls(&tls);
        tunnel_decoder_t dec; tunnel_decoder_reset(&dec);
        tunnel_hello_t h;
        if (tunnel_relay_accept(&io, &dec, &h, allow_one, (void *)s->allowed, NULL, 0) == 0)
            s->registered = 1;
        tunnel_tls_free(&tls);
    } else {
        close(c);
    }
    return NULL;
}

/* Bind 127.0.0.1:0, return the fd and the chosen port string. */
static int make_listener(char *port_out, size_t cap) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&a, sizeof a) || listen(fd, 4)) { close(fd); return -1; }
    socklen_t al = sizeof a; getsockname(fd, (struct sockaddr *)&a, &al);
    snprintf(port_out, cap, "%d", ntohs(a.sin_port));
    return fd;
}

int main(void) {
    printf("== tunnel control over mTLS ==\n");

    /* Mint CA, server (SAN localhost), and agent client certs into a temp dir. */
    char dir[] = "/tmp/tuntlsXXXXXX";
    if (!mkdtemp(dir)) { perror("mkdtemp"); return 1; }
    char ca_pem[256], srv_crt[256], srv_key[256], cli_crt[256], cli_key[256];
    snprintf(ca_pem,  sizeof ca_pem,  "%s/ca.pem", dir);
    snprintf(srv_crt, sizeof srv_crt, "%s/srv.crt", dir);
    snprintf(srv_key, sizeof srv_key, "%s/srv.key", dir);
    snprintf(cli_crt, sizeof cli_crt, "%s/cli.crt", dir);
    snprintf(cli_key, sizeof cli_key, "%s/cli.key", dir);

    EVP_PKEY *cak = gen_key(), *srk = gen_key(), *clk = gen_key();
    X509 *cac = mk_cert(cak, "portico-tunnel test CA", 1, cak, NULL, NULL, 1);
    X509 *src = mk_cert(srk, "localhost", 0, cak, cac, "DNS:localhost", 2);
    X509 *clc = mk_cert(clk, "agent-1", 0, cak, cac, NULL, 3);
    wr_cert(ca_pem, cac);
    wr_cert(srv_crt, src); wr_key(srv_key, srk);
    wr_cert(cli_crt, clc); wr_key(cli_key, clk);
    chk("minted CA + server + client certs",
        cak && srk && clk && cac && src && clc);

    /* ---- positive: mutual auth + registration ---- */
    {
        char port[16];
        int lfd = make_listener(port, sizeof port);
        struct srv s = { .listen_fd = lfd, .crt = srv_crt, .key = srv_key, .ca = ca_pem,
                         .allowed = "ok.example.com" };
        pthread_t th; pthread_create(&th, NULL, srv_thread, &s);

        tunnel_tls_t tls;
        int dr = tunnel_tls_dial("localhost", port, ca_pem, cli_crt, cli_key, &tls);
        chk("agent dials + verifies relay cert + mTLS handshake", dr == 0);

        int rc = -1;
        if (dr == 0) {
            tunnel_io_t io = tunnel_io_tls(&tls);
            tunnel_decoder_t dec; tunnel_decoder_reset(&dec);
            tunnel_hello_t ah = {0};
            snprintf(ah.agent_id, sizeof ah.agent_id, "agent-1");
            snprintf(ah.hostnames[0], sizeof ah.hostnames[0], "ok.example.com");
            ah.n_hosts = 1;
            char err[128];
            rc = tunnel_agent_register(&io, &dec, &ah, err, sizeof err);
            tunnel_tls_free(&tls);
        }
        pthread_join(th, NULL);
        chk("registered over the TLS tunnel", rc == 0);
        chk("relay completed mTLS + accepted", s.accepted && s.registered);
        close(lfd);
    }

    /* ---- negative 1: relay cert NOT trusted by the agent's CA -> dial refused ---- */
    {
        char port[16];
        int lfd = make_listener(port, sizeof port);
        struct srv s = { .listen_fd = lfd, .crt = srv_crt, .key = srv_key, .ca = ca_pem,
                         .allowed = "ok.example.com" };
        pthread_t th; pthread_create(&th, NULL, srv_thread, &s);

        /* trust the CLIENT leaf as the CA -> it did not sign the server cert. The agent
         * validates the server cert DURING the handshake, so the dial itself fails. */
        tunnel_tls_t tls;
        int dr = tunnel_tls_dial("localhost", port, cli_crt, cli_crt, cli_key, &tls);
        chk("untrusted relay cert is rejected by the agent", dr == -1);
        if (dr == 0) tunnel_tls_free(&tls);
        pthread_join(th, NULL);
        chk("relay did not register an unverified peer", s.registered == 0);
        close(lfd);
    }

    /* ---- negative 2: agent presents NO client cert -> relay rejects (mTLS enforced) ---- */
    {
        char port[16];
        int lfd = make_listener(port, sizeof port);
        struct srv s = { .listen_fd = lfd, .crt = srv_crt, .key = srv_key, .ca = ca_pem,
                         .allowed = "ok.example.com" };
        pthread_t th; pthread_create(&th, NULL, srv_thread, &s);

        /* No client cert. Under TLS 1.3 the client handshake can complete before the
         * server processes (and rejects) the missing cert, so the refusal surfaces as a
         * failed exchange, not a failed dial — assert the agent never registers and the
         * relay never accepts. */
        tunnel_tls_t tls;
        int dr = tunnel_tls_dial("localhost", port, ca_pem, NULL, NULL, &tls);
        int registered = 0;
        if (dr == 0) {
            tunnel_io_t io = tunnel_io_tls(&tls);
            tunnel_decoder_t dec; tunnel_decoder_reset(&dec);
            tunnel_hello_t ah = {0};
            snprintf(ah.agent_id, sizeof ah.agent_id, "agent-x");
            snprintf(ah.hostnames[0], sizeof ah.hostnames[0], "ok.example.com");
            ah.n_hosts = 1;
            registered = (tunnel_agent_register(&io, &dec, &ah, NULL, 0) == 0);
            tunnel_tls_free(&tls);
        }
        pthread_join(th, NULL);
        chk("agent with no client cert never registers (mTLS enforced)", registered == 0);
        chk("relay did not accept the certless agent", s.accepted == 0);
        close(lfd);
    }

    EVP_PKEY_free(cak); EVP_PKEY_free(srk); EVP_PKEY_free(clk);
    X509_free(cac); X509_free(src); X509_free(clc);
    unlink(ca_pem); unlink(srv_crt); unlink(srv_key); unlink(cli_crt); unlink(cli_key); rmdir(dir);

    printf("\n%s  (%d ok, %d failed)\n", fail ? "FAIL" : "PASS", ok, fail);
    return fail ? 1 : 0;
}
