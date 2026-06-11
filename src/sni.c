/* TLS SNI peek (see sni.h). A defensive walk of the ClientHello: TLS record header →
 * handshake header → skip version/random/session_id/cipher_suites/compression →
 * extensions → server_name (type 0) → first host_name entry. Every field length is
 * checked against the enclosing bound before use. No allocation. */
#include "sni.h"

#include <string.h>

#define MAX_CH 16384u   /* a ClientHello larger than this is treated as hostile */

static unsigned u16(const uint8_t *p) { return ((unsigned)p[0] << 8) | p[1]; }

int tunnel_sni_peek(const uint8_t *p, size_t n, char *host, size_t hostcap) {
    /* TLS record header (5) + handshake header (4). */
    if (n < 5) return 0;
    if (p[0] != 0x16) return -1;                 /* not a handshake record */
    size_t i = 5;
    if (n < i + 4) return 0;
    if (p[i] != 0x01) return -1;                 /* not a ClientHello */
    size_t hs_len = ((size_t)p[i+1] << 16) | ((size_t)p[i+2] << 8) | p[i+3];
    i += 4;
    if (hs_len > MAX_CH) return -1;
    size_t end = i + hs_len;                     /* end of the ClientHello body */
    if (n < end) return 0;                       /* not fully buffered yet */

    if (i + 2 > end) return -1;                          /* client_version */
    i += 2;
    if (i + 32 > end) return -1;                         /* random */
    i += 32;
    if (i + 1 > end) return -1;                          /* session_id */
    size_t sid = p[i]; i += 1;
    if (i + sid > end) return -1;
    i += sid;
    if (i + 2 > end) return -1;                          /* cipher_suites */
    size_t cs = u16(p + i); i += 2;
    if (i + cs > end) return -1;
    i += cs;
    if (i + 1 > end) return -1;                          /* compression_methods */
    size_t cm = p[i]; i += 1;
    if (i + cm > end) return -1;
    i += cm;

    if (i + 2 > end) return -1;                          /* extensions block */
    size_t ext_total = u16(p + i); i += 2;
    size_t ext_end = i + ext_total;
    if (ext_end > end) ext_end = end;                    /* clamp to the body */

    while (i + 4 <= ext_end) {
        size_t etype = u16(p + i);
        size_t elen  = u16(p + i + 2);
        i += 4;
        if (i + elen > ext_end) return -1;
        if (etype == 0x0000) {                           /* server_name */
            size_t j = i, eend = i + elen;
            if (j + 2 > eend) return -1;
            size_t list_end = j + 2 + u16(p + j);
            j += 2;
            if (list_end > eend) list_end = eend;
            while (j + 3 <= list_end) {
                size_t ntype = p[j];
                size_t nlen  = u16(p + j + 1);
                j += 3;
                if (j + nlen > list_end) return -1;
                if (ntype == 0x00) {                     /* host_name */
                    if (nlen == 0 || nlen >= hostcap) return -1;
                    memcpy(host, p + j, nlen);
                    host[nlen] = '\0';
                    return 1;
                }
                j += nlen;
            }
            return -1;                                   /* SNI ext but no host_name */
        }
        i += elen;
    }
    return -1;                                            /* no SNI extension */
}
