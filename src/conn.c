/* portico-tunnel non-blocking tunnel transport (see conn.h). */
#include "conn.h"

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <sys/socket.h>

static void set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl != -1) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

void tunnel_conn_fd(tunnel_conn_t *c, int fd) {
    c->fd = fd; c->ssl = NULL; c->want_rd = c->want_wr = 0;
    set_nonblock(fd);
}

void tunnel_conn_ssl(tunnel_conn_t *c, SSL *ssl) {
    c->ssl = ssl; c->fd = SSL_get_fd(ssl); c->want_rd = c->want_wr = 0;
    set_nonblock(c->fd);
}

long tunnel_conn_read(tunnel_conn_t *c, void *buf, size_t n) {
    c->want_rd = c->want_wr = 0;
    int want = (n > INT_MAX) ? INT_MAX : (int)n;
    if (!c->ssl) {
        ssize_t r = read(c->fd, buf, (size_t)want);
        if (r > 0) return r;
        if (r == 0) return 0;
        if (errno == EAGAIN || errno == EWOULDBLOCK) { c->want_rd = 1; return -2; }
        if (errno == EINTR) return -2;
        return -1;
    }
    int r = SSL_read(c->ssl, buf, want);
    if (r > 0) return r;
    switch (SSL_get_error(c->ssl, r)) {
        case SSL_ERROR_ZERO_RETURN: return 0;                       /* peer close_notify */
        case SSL_ERROR_WANT_READ:   c->want_rd = 1; return -2;
        case SSL_ERROR_WANT_WRITE:  c->want_wr = 1; return -2;      /* read needs to write */
        default:                    return -1;
    }
}

long tunnel_conn_write(tunnel_conn_t *c, const void *buf, size_t n) {
    c->want_rd = c->want_wr = 0;
    int want = (n > INT_MAX) ? INT_MAX : (int)n;
    if (!c->ssl) {
        ssize_t w = send(c->fd, buf, (size_t)want, MSG_NOSIGNAL);
        if (w >= 0) return w;
        if (errno == EAGAIN || errno == EWOULDBLOCK) { c->want_wr = 1; return -2; }
        if (errno == EINTR) return -2;
        return -1;
    }
    int w = SSL_write(c->ssl, buf, want);
    if (w > 0) return w;
    switch (SSL_get_error(c->ssl, w)) {
        case SSL_ERROR_WANT_WRITE: c->want_wr = 1; return -2;
        case SSL_ERROR_WANT_READ:  c->want_rd = 1; return -2;       /* write needs to read */
        default:                   return -1;
    }
}

int tunnel_conn_pending(tunnel_conn_t *c) {
    return c->ssl ? SSL_pending(c->ssl) : 0;
}
