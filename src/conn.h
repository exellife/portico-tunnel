/* ============================================================================
 * portico-tunnel non-blocking tunnel transport for the event loop.
 *
 * The stream engine drives the tunnel through this: a plain fd (tests/loopback) or
 * an SSL connection (production), with OpenSSL's want-read/want-write handled here so
 * the engine stays transport-agnostic. All ops are non-blocking.
 * ============================================================================ */
#ifndef PORTICO_TUNNEL_CONN_H
#define PORTICO_TUNNEL_CONN_H

#include <stddef.h>
#include <openssl/ssl.h>

typedef struct {
    int  fd;                 /* the socket to poll */
    SSL *ssl;                /* NULL = plain fd */
    int  want_rd, want_wr;   /* SSL needs the socket readable/writable to make progress */
} tunnel_conn_t;

void tunnel_conn_fd(tunnel_conn_t *c, int fd);      /* plain (fd set non-blocking) */
void tunnel_conn_ssl(tunnel_conn_t *c, SSL *ssl);   /* TLS (socket set non-blocking) */

/* Non-blocking read/write. Return: >0 bytes moved, 0 = clean EOF (read only), -1 =
 * fatal, -2 = would block (poll the socket per want_rd/want_wr, then retry). */
long tunnel_conn_read(tunnel_conn_t *c, void *buf, size_t n);
long tunnel_conn_write(tunnel_conn_t *c, const void *buf, size_t n);

/* Decrypted bytes already buffered in the SSL object — read again without polling. */
int  tunnel_conn_pending(tunnel_conn_t *c);

#endif /* PORTICO_TUNNEL_CONN_H */
