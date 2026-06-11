/* portico-tunnel TLS transport (see tls.h). Blocking sockets; one connection per
 * tunnel_tls_t. The security-critical parts: the agent verifies the relay's chain AND
 * hostname (SSL_set1_host), and the relay requires + verifies the agent's client cert. */
#include "tls.h"

#include <string.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <openssl/err.h>

/* ---- tunnel_io_t over SSL ---- */

static long ssl_recv(void *ctx, void *buf, size_t n) {
    SSL *ssl = ctx;
    int want = (n > INT_MAX) ? INT_MAX : (int)n;
    for (;;) {
        int r = SSL_read(ssl, buf, want);
        if (r > 0) return r;
        int e = SSL_get_error(ssl, r);
        if (e == SSL_ERROR_ZERO_RETURN) return 0;                 /* clean close_notify */
        /* On a blocking socket, a WANT/SYSCALL with EAGAIN means an SO_RCVTIMEO deadline
         * fired — return error instead of spinning (this is how the handshake/HELLO/
         * register timeouts are enforced). Genuine WANT on a blocking fd never carries
         * EAGAIN, so this does not affect normal reads. */
        if ((e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_SYSCALL)
            && (errno == EAGAIN || errno == EWOULDBLOCK)) return -1;
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) continue;
        if (e == SSL_ERROR_SYSCALL && errno == EINTR) continue;
        return -1;
    }
}

static long ssl_send(void *ctx, const void *buf, size_t n) {
    SSL *ssl = ctx;
    const unsigned char *p = buf;
    size_t off = 0;
    while (off < n) {
        int want = (n - off > INT_MAX) ? INT_MAX : (int)(n - off);
        int w = SSL_write(ssl, p + off, want);
        if (w > 0) { off += (size_t)w; continue; }
        int e = SSL_get_error(ssl, w);
        if ((e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_SYSCALL)
            && (errno == EAGAIN || errno == EWOULDBLOCK)) return -1;   /* SO_SNDTIMEO deadline */
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) continue;
        if (e == SSL_ERROR_SYSCALL && errno == EINTR) continue;
        return -1;
    }
    return (long)n;
}

tunnel_io_t tunnel_io_tls(tunnel_tls_t *t) {
    tunnel_io_t io;
    io.ctx  = t->ssl;
    io.recv = ssl_recv;
    io.send = ssl_send;
    return io;
}

/* ---- dial / accept ---- */

static int tcp_connect(const char *host, const char *port) {
    struct addrinfo hints = {0}, *res = NULL, *ai;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;
    int fd = -1;
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

int tunnel_tls_dial(const char *host, const char *port, const char *ca_file,
                    const char *client_cert, const char *client_key, tunnel_tls_t *out) {
    memset(out, 0, sizeof *out);
    out->fd = -1;

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return -1;
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    int ok = 0;
    do {
        int trust = ca_file ? SSL_CTX_load_verify_locations(ctx, ca_file, NULL)
                            : SSL_CTX_set_default_verify_paths(ctx);
        if (trust != 1) break;
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);          /* fail handshake on bad chain */
        if (client_cert && client_key) {                         /* mTLS identity */
            if (SSL_CTX_use_certificate_file(ctx, client_cert, SSL_FILETYPE_PEM) != 1) break;
            if (SSL_CTX_use_PrivateKey_file(ctx, client_key, SSL_FILETYPE_PEM) != 1) break;
        }
        int fd = tcp_connect(host, port);
        if (fd < 0) break;
        SSL *ssl = SSL_new(ctx);
        if (!ssl) { close(fd); break; }
        SSL_set_fd(ssl, fd);
        SSL_set_tlsext_host_name(ssl, host);                     /* SNI */
        if (SSL_set1_host(ssl, host) != 1) { SSL_free(ssl); close(fd); break; }  /* verify hostname */
        if (SSL_connect(ssl) != 1) { SSL_free(ssl); close(fd); break; }          /* handshake + verify */
        out->ssl = ssl; out->ctx = ctx; out->fd = fd; ok = 1;
    } while (0);

    if (!ok) { SSL_CTX_free(ctx); return -1; }
    return 0;
}

int tunnel_tls_accept(int fd, const char *server_cert, const char *server_key,
                      const char *client_ca, tunnel_tls_t *out) {
    memset(out, 0, sizeof *out);
    out->fd = -1;

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) return -1;
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    int ok = 0;
    do {
        if (SSL_CTX_use_certificate_file(ctx, server_cert, SSL_FILETYPE_PEM) != 1) break;
        if (SSL_CTX_use_PrivateKey_file(ctx, server_key, SSL_FILETYPE_PEM) != 1) break;
        if (client_ca) {                                         /* require + verify client cert */
            if (SSL_CTX_load_verify_locations(ctx, client_ca, NULL) != 1) break;
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
            STACK_OF(X509_NAME) *list = SSL_load_client_CA_file(client_ca);
            if (list) SSL_CTX_set_client_CA_list(ctx, list);     /* tell the client which CA to send */
        }
        SSL *ssl = SSL_new(ctx);
        if (!ssl) break;
        SSL_set_fd(ssl, fd);
        if (SSL_accept(ssl) != 1) { SSL_free(ssl); break; }      /* handshake + client-cert verify */
        out->ssl = ssl; out->ctx = ctx; out->fd = fd; ok = 1;
    } while (0);

    if (!ok) { SSL_CTX_free(ctx); return -1; }
    return 0;
}

void tunnel_tls_free(tunnel_tls_t *t) {
    if (!t) return;
    if (t->ssl) { SSL_shutdown(t->ssl); SSL_free(t->ssl); }       /* SSL_free does not close fd */
    if (t->ctx) SSL_CTX_free(t->ctx);
    if (t->fd >= 0) close(t->fd);
    memset(t, 0, sizeof *t);
    t->fd = -1;
}
