/* Frame codec: encode/parse roundtrip, exact big-endian wire bytes, length/cap edge
 * cases, and the streaming decoder reassembling frames across arbitrary (1-byte and
 * odd) chunk boundaries. Pure — no network. */
#include "frame.h"

#include <stdio.h>
#include <string.h>

static int ok = 0, fail = 0;
static void chk(const char *n, int c) {
    printf("  %-5s %s\n", c ? "ok" : "FAIL", n);
    if (c) ok++; else fail++;
}

static int frame_eq(const tunnel_frame_t *f, uint8_t type, uint32_t sid,
                    const void *payload, uint32_t len) {
    if (f->type != type || f->stream_id != sid || f->len != len) return 0;
    if (len == 0) return f->payload == NULL;
    return f->payload && memcmp(f->payload, payload, len) == 0;
}

int main(void) {
    printf("== tunnel frame codec ==\n");
    uint8_t buf[TUNNEL_FRAME_HDR + TUNNEL_MAX_FRAME];

    /* ---- roundtrip across types + payload sizes ---- */
    struct { uint8_t type; uint32_t sid; const char *p; uint32_t len; } cases[] = {
        { TF_PING,      0, "",                0 },
        { TF_PONG,      0, "",                0 },
        { TF_HELLO,     0, "agent-1;host=a",  14 },
        { TF_HELLO_OK,  0, "lease=600",       9 },
        { TF_OPEN,      7, "example.com|203.0.113.9", 23 },
        { TF_DATA,      7, "the quick brown fox", 19 },
        { TF_END,       7, "",                0 },
        { TF_RESET,    42, "",                0 },
    };
    int all = 1;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        int enc = tunnel_frame_encode(cases[i].type, cases[i].sid, cases[i].p, cases[i].len, buf, sizeof buf);
        tunnel_frame_t f;
        long con = tunnel_frame_parse(buf, (size_t)enc, &f);
        if (enc != (int)(TUNNEL_FRAME_HDR + cases[i].len) ||
            con != enc ||
            !frame_eq(&f, cases[i].type, cases[i].sid, cases[i].p, cases[i].len)) { all = 0; }
    }
    chk("encode/parse roundtrip for all frame types", all);

    /* ---- exact big-endian wire bytes ---- */
    int enc = tunnel_frame_encode(TF_DATA, 0x01020304u, "AB", 2, buf, sizeof buf);
    chk("wire layout is big-endian + correct",
        enc == 11 &&
        buf[0] == 0x11 &&
        buf[1] == 0x01 && buf[2] == 0x02 && buf[3] == 0x03 && buf[4] == 0x04 &&  /* stream_id */
        buf[5] == 0x00 && buf[6] == 0x00 && buf[7] == 0x00 && buf[8] == 0x02 &&  /* length */
        buf[9] == 'A' && buf[10] == 'B');

    /* ---- max-size payload ---- */
    static uint8_t big[TUNNEL_MAX_FRAME];
    for (size_t i = 0; i < sizeof big; i++) big[i] = (uint8_t)(i & 0xff);
    enc = tunnel_frame_encode(TF_DATA, 9, big, TUNNEL_MAX_FRAME, buf, sizeof buf);
    tunnel_frame_t mf;
    chk("max-size payload roundtrips",
        enc == (int)(TUNNEL_FRAME_HDR + TUNNEL_MAX_FRAME) &&
        tunnel_frame_parse(buf, (size_t)enc, &mf) == enc &&
        frame_eq(&mf, TF_DATA, 9, big, TUNNEL_MAX_FRAME));

    /* ---- encode rejects oversize + short buffer ---- */
    chk("encode rejects len > MAX", tunnel_frame_encode(TF_DATA, 1, big, TUNNEL_MAX_FRAME + 1, buf, sizeof buf) == -1);
    chk("encode rejects short outcap", tunnel_frame_encode(TF_DATA, 1, "hello", 5, buf, 8) == -1);

    /* ---- parse: incomplete -> 0 (need more) ---- */
    enc = tunnel_frame_encode(TF_OPEN, 3, "abcdef", 6, buf, sizeof buf);   /* 15 bytes */
    tunnel_frame_t pf;
    chk("parse: partial header -> 0", tunnel_frame_parse(buf, 5, &pf) == 0);
    chk("parse: header but partial payload -> 0", tunnel_frame_parse(buf, 12, &pf) == 0);
    chk("parse: full frame -> consumed", tunnel_frame_parse(buf, (size_t)enc, &pf) == enc);

    /* ---- parse: hostile length field -> -1 ---- */
    uint8_t bad[TUNNEL_FRAME_HDR];
    bad[0] = TF_DATA; bad[1]=bad[2]=bad[3]=bad[4]=0;
    bad[5]=0x00; bad[6]=0x01; bad[7]=0x00; bad[8]=0x00;   /* length = 65536 > MAX */
    chk("parse rejects oversize length field", tunnel_frame_parse(bad, sizeof bad, &pf) == -1);

    /* ---- streaming decoder: reassemble 3 frames fed ONE BYTE AT A TIME ---- */
    uint8_t blob[1 << 16]; size_t bl = 0;
    bl += (size_t)tunnel_frame_encode(TF_HELLO, 0, "agent-1", 7, blob + bl, sizeof blob - bl);
    bl += (size_t)tunnel_frame_encode(TF_OPEN, 7, "example.com|198.51.100.2", 24, blob + bl, sizeof blob - bl);
    bl += (size_t)tunnel_frame_encode(TF_DATA, 7, big, TUNNEL_MAX_FRAME, blob + bl, sizeof blob - bl);

    struct { uint8_t type; uint32_t sid; const void *p; uint32_t len; } exp[] = {
        { TF_HELLO, 0, "agent-1", 7 },
        { TF_OPEN,  7, "example.com|198.51.100.2", 24 },
        { TF_DATA,  7, big, TUNNEL_MAX_FRAME },
    };

    tunnel_decoder_t d; tunnel_decoder_reset(&d);
    int got = 0, mismatch = 0;
    for (size_t i = 0; i < bl; i++) {
        size_t c = tunnel_decoder_push(&d, blob + i, 1);
        if (c != 1) { mismatch = 1; break; }
        tunnel_frame_t f;
        while (tunnel_decoder_next(&d, &f) == 1) {
            if (got >= 3 || !frame_eq(&f, exp[got].type, exp[got].sid, exp[got].p, exp[got].len)) mismatch = 1;
            got++;
        }
    }
    chk("decoder reassembles 3 frames from 1-byte feeds", got == 3 && !mismatch);

    /* ---- decoder: realistic push/drain loop (buffer holds one max frame, so a
     * caller pushes what fits, drains, pushes the remainder — like a real transport
     * reading in chunks). Exercises the boundary where a frame spans two pushes. ---- */
    tunnel_decoder_reset(&d);
    got = 0; mismatch = 0;
    size_t pushed = 0;
    tunnel_frame_t f;
    while (pushed < bl) {
        size_t c = tunnel_decoder_push(&d, blob + pushed, bl - pushed);
        if (c == 0) { mismatch = 1; break; }   /* no progress would mean a stuck buffer */
        pushed += c;
        while (tunnel_decoder_next(&d, &f) == 1) {
            if (got >= 3 || !frame_eq(&f, exp[got].type, exp[got].sid, exp[got].p, exp[got].len)) mismatch = 1;
            got++;
        }
    }
    chk("decoder handles chunked push/drain (frame spanning pushes)", got == 3 && !mismatch);

    /* ---- decoder surfaces a protocol error ---- */
    tunnel_decoder_reset(&d);
    tunnel_decoder_push(&d, bad, sizeof bad);
    chk("decoder returns -1 on a bad frame", tunnel_decoder_next(&d, &f) == -1);

    printf("\n%s  (%d ok, %d failed)\n", fail ? "FAIL" : "PASS", ok, fail);
    return fail ? 1 : 0;
}
