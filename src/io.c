/* portico-tunnel I/O abstraction + framed read/write (see io.h). */
#include "io.h"

#include <unistd.h>
#include <errno.h>
#include <string.h>

/* ---- raw fd backend ---- */

static long fd_recv(void *ctx, void *buf, size_t n) {
    int fd = (int)(intptr_t)ctx;
    ssize_t r;
    do { r = read(fd, buf, n); } while (r < 0 && errno == EINTR);
    return (long)r;
}

static long fd_send(void *ctx, const void *buf, size_t n) {
    int fd = (int)(intptr_t)ctx;
    const unsigned char *p = buf;
    size_t off = 0;
    while (off < n) {
        ssize_t w;
        do { w = write(fd, p + off, n - off); } while (w < 0 && errno == EINTR);
        if (w <= 0) return -1;
        off += (size_t)w;
    }
    return (long)n;
}

tunnel_io_t tunnel_io_fd(int fd) {
    tunnel_io_t io;
    io.ctx  = (void *)(intptr_t)fd;
    io.recv = fd_recv;
    io.send = fd_send;
    return io;
}

/* ---- framed read/write ---- */

int tunnel_io_write_frame(tunnel_io_t *io, uint8_t type, uint32_t sid,
                          const void *payload, uint32_t len) {
    if (len > TUNNEL_MAX_FRAME) return -1;
    unsigned char h[TUNNEL_FRAME_HDR];
    h[0] = type;
    h[1] = (unsigned char)(sid >> 24); h[2] = (unsigned char)(sid >> 16);
    h[3] = (unsigned char)(sid >> 8);  h[4] = (unsigned char)(sid);
    h[5] = (unsigned char)(len >> 24); h[6] = (unsigned char)(len >> 16);
    h[7] = (unsigned char)(len >> 8);  h[8] = (unsigned char)(len);
    if (io->send(io->ctx, h, TUNNEL_FRAME_HDR) != (long)TUNNEL_FRAME_HDR) return -1;
    if (len && io->send(io->ctx, payload, len) != (long)len) return -1;
    return 0;
}

int tunnel_io_read_frame(tunnel_io_t *io, tunnel_decoder_t *dec, tunnel_frame_t *out) {
    int r = tunnel_decoder_next(dec, out);
    if (r != 0) return r;                       /* 1 = already buffered, -1 = protocol error */
    for (;;) {
        unsigned char tmp[TUNNEL_RECV_CHUNK];
        long n = io->recv(io->ctx, tmp, sizeof tmp);
        if (n == 0) return 0;                   /* clean EOF */
        if (n < 0) return -1;
        /* The decoder is sized so a whole recv chunk fits atop a partial frame. */
        size_t pushed = 0;
        while (pushed < (size_t)n) {
            size_t c = tunnel_decoder_push(dec, tmp + pushed, (size_t)n - pushed);
            if (c == 0) return -1;              /* unreachable with the sized buffer */
            pushed += c;
        }
        r = tunnel_decoder_next(dec, out);
        if (r != 0) return r;
    }
}
