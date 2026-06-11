/* ============================================================================
 * portico-tunnel TLS transport. Provides a tunnel_io_t backed by OpenSSL, plus the
 * agent's verifying dial and the relay's mutually-authenticated accept. The control
 * and stream logic above is unchanged — TLS is just another tunnel_io_t backend.
 * ============================================================================ */
#ifndef PORTICO_TUNNEL_TLS_H
#define PORTICO_TUNNEL_TLS_H

#include "io.h"
#include <openssl/ssl.h>

/* A live TLS connection (owns the SSL, its SSL_CTX, and the socket). */
typedef struct {
    SSL     *ssl;
    SSL_CTX *ctx;
    int      fd;
} tunnel_tls_t;

/* tunnel_io_t over an established connection (SSL_read/SSL_write). */
tunnel_io_t tunnel_io_tls(tunnel_tls_t *t);

/* Agent side: TCP-dial host:port, TLS-handshake as client, VERIFY the relay's cert
 * against `ca_file` (chain + hostname == host) and present a client cert for mTLS
 * (client_cert/client_key may be NULL to skip — the relay will then reject it).
 * `ca_file` NULL verifies against the system roots. Returns 0 / -1. */
int tunnel_tls_dial(const char *host, const char *port, const char *ca_file,
                    const char *client_cert, const char *client_key, tunnel_tls_t *out);

/* Relay side: TLS-handshake as server over an already-accepted `fd`, presenting
 * server_cert/key and REQUIRING a client cert signed by `client_ca` (mTLS). On
 * success the connection owns `fd`; on failure the caller still owns/closes `fd`.
 * Returns 0 / -1. */
int tunnel_tls_accept(int fd, const char *server_cert, const char *server_key,
                      const char *client_ca, tunnel_tls_t *out);

void tunnel_tls_free(tunnel_tls_t *t);

#endif /* PORTICO_TUNNEL_TLS_H */
