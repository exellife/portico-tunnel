/* ============================================================================
 * portico-tunnel wire frames (docs/spec.md §3).
 *
 *   +0  u8   type
 *   +1  u32  stream_id   (big-endian; 0 = connection-level / control)
 *   +5  u32  length      (big-endian; payload bytes, <= TUNNEL_MAX_FRAME)
 *   +9  u8   payload[length]
 *
 * Two layers: pure encode/parse over a byte span, and a streaming decoder that
 * reassembles frames from arbitrary chunk boundaries (TLS reads don't respect
 * frame edges). Pure and allocation-free.
 * ============================================================================ */
#ifndef PORTICO_TUNNEL_FRAME_H
#define PORTICO_TUNNEL_FRAME_H

#include <stdint.h>
#include <stddef.h>

#define TUNNEL_FRAME_HDR  9u       /* fixed header size */
#define TUNNEL_MAX_FRAME  16384u   /* max payload bytes per frame (DATA is chunked to this) */
#define TUNNEL_RECV_CHUNK 4096u    /* framed-read recv granularity (see decoder sizing) */

enum tunnel_frame_type {
    TF_HELLO     = 0x01,   /* A->R: agent_id, auth, hostnames */
    TF_HELLO_OK  = 0x02,   /* R->A */
    TF_HELLO_ERR = 0x03,   /* R->A: reason */
    TF_PING      = 0x04,   /* both */
    TF_PONG      = 0x05,   /* both */
    TF_OPEN      = 0x10,   /* R->A: new stream; hostname, client_ip */
    TF_DATA      = 0x11,   /* both: stream bytes */
    TF_END       = 0x12,   /* both: sender half-closed this stream direction */
    TF_RESET     = 0x13    /* both: abort stream */
};

typedef struct {
    uint8_t        type;
    uint32_t       stream_id;
    const uint8_t *payload;   /* into the caller's / decoder's buffer; NULL if len==0 */
    uint32_t       len;
} tunnel_frame_t;

/* Encode one frame into `out` (needs TUNNEL_FRAME_HDR + len bytes). Returns the
 * encoded length, or -1 if len > TUNNEL_MAX_FRAME or outcap is too small. */
int tunnel_frame_encode(uint8_t type, uint32_t stream_id,
                        const void *payload, uint32_t len,
                        uint8_t *out, size_t outcap);

/* Parse one frame from the front of in[0..n). Returns bytes consumed (header +
 * payload) with `out` filled (out->payload points into `in`); 0 if more bytes are
 * needed; -1 on a protocol error (length field exceeds TUNNEL_MAX_FRAME). */
long tunnel_frame_parse(const uint8_t *in, size_t n, tunnel_frame_t *out);

/* ---- streaming decoder ----------------------------------------------------
 * Push received bytes, pull complete frames. A returned frame's payload points
 * into the decoder and is valid until the next push/next call. */
typedef struct {
    /* Sized to hold one max frame PLUS a recv chunk, so a framed read can always push
     * a whole recv() result on top of a partial frame without splitting it. */
    uint8_t buf[TUNNEL_FRAME_HDR + TUNNEL_MAX_FRAME + TUNNEL_RECV_CHUNK];
    size_t  have;
    size_t  pending;   /* bytes of an already-returned frame, dropped on next op */
} tunnel_decoder_t;

void   tunnel_decoder_reset(tunnel_decoder_t *d);
/* Copy up to n bytes in; returns bytes accepted (< n only if the buffer is full
 * mid-frame — drain with _next, then push the remainder). */
size_t tunnel_decoder_push(tunnel_decoder_t *d, const uint8_t *in, size_t n);
/* 1 = got `out`, 0 = need more, -1 = protocol error. */
int    tunnel_decoder_next(tunnel_decoder_t *d, tunnel_frame_t *out);

#endif /* PORTICO_TUNNEL_FRAME_H */
