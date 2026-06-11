/* portico-tunnel frame codec — see frame.h / docs/spec.md §3. Pure + allocation-free;
 * all multi-byte fields are big-endian (network order). */
#include "frame.h"

#include <string.h>

static void put_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}
static uint32_t get_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

int tunnel_frame_encode(uint8_t type, uint32_t stream_id,
                        const void *payload, uint32_t len,
                        uint8_t *out, size_t outcap) {
    if (len > TUNNEL_MAX_FRAME) return -1;
    if (outcap < (size_t)TUNNEL_FRAME_HDR + len) return -1;
    out[0] = type;
    put_u32(out + 1, stream_id);
    put_u32(out + 5, len);
    if (len && payload) memcpy(out + TUNNEL_FRAME_HDR, payload, len);
    return (int)(TUNNEL_FRAME_HDR + len);
}

long tunnel_frame_parse(const uint8_t *in, size_t n, tunnel_frame_t *out) {
    if (n < TUNNEL_FRAME_HDR) return 0;            /* not even a header yet */
    uint32_t len = get_u32(in + 5);
    if (len > TUNNEL_MAX_FRAME) return -1;         /* malformed / hostile length */
    if (n < (size_t)TUNNEL_FRAME_HDR + len) return 0;  /* header present, payload not yet */
    out->type      = in[0];
    out->stream_id = get_u32(in + 1);
    out->len       = len;
    out->payload   = len ? in + TUNNEL_FRAME_HDR : NULL;
    return (long)(TUNNEL_FRAME_HDR + len);
}

/* ---- streaming decoder ---- */

void tunnel_decoder_reset(tunnel_decoder_t *d) {
    d->have = 0;
    d->pending = 0;
}

static void drop_pending(tunnel_decoder_t *d) {
    if (d->pending) {
        memmove(d->buf, d->buf + d->pending, d->have - d->pending);
        d->have -= d->pending;
        d->pending = 0;
    }
}

size_t tunnel_decoder_push(tunnel_decoder_t *d, const uint8_t *in, size_t n) {
    drop_pending(d);
    size_t space = sizeof d->buf - d->have;
    size_t c = n < space ? n : space;
    memcpy(d->buf + d->have, in, c);
    d->have += c;
    return c;
}

int tunnel_decoder_next(tunnel_decoder_t *d, tunnel_frame_t *out) {
    drop_pending(d);                               /* free the previously-returned frame */
    long r = tunnel_frame_parse(d->buf, d->have, out);
    if (r <= 0) return (int)r;                      /* 0 = need more, -1 = error */
    d->pending = (size_t)r;                          /* keep frame valid until next op */
    return 1;
}
