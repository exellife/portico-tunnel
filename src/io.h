/* ============================================================================
 * portico-tunnel I/O abstraction + framed read/write.
 *
 * The control and stream logic is written against tunnel_io_t, so it is identical
 * over a raw fd (tests / loopback) and over TLS (production — an SSL* backend drops
 * in here later with no change to the protocol code above it).
 * ============================================================================ */
#ifndef PORTICO_TUNNEL_IO_H
#define PORTICO_TUNNEL_IO_H

#include "frame.h"
#include <stddef.h>
#include <stdint.h>

typedef struct tunnel_io {
    void *ctx;
    long (*recv)(void *ctx, void *buf, size_t n);        /* >0 bytes, 0 = EOF, -1 = error */
    long (*send)(void *ctx, const void *buf, size_t n);  /* sends ALL n bytes, or returns -1 */
} tunnel_io_t;

/* Raw blocking-fd backend (the fd is stored in ctx). */
tunnel_io_t tunnel_io_fd(int fd);

/* Write one complete frame (header + payload). Returns 0 / -1. */
int tunnel_io_write_frame(tunnel_io_t *io, uint8_t type, uint32_t stream_id,
                          const void *payload, uint32_t len);

/* Read one complete frame, draining `dec` and recv'ing as needed. Returns 1 with
 * `out` filled (payload valid until the next read on this decoder), 0 on clean EOF,
 * -1 on transport or protocol error. */
int tunnel_io_read_frame(tunnel_io_t *io, tunnel_decoder_t *dec, tunnel_frame_t *out);

#endif /* PORTICO_TUNNEL_IO_H */
