/* ============================================================================
 * TLS SNI peek — extract the server_name from a buffered ClientHello WITHOUT
 * decrypting (the ssl_preread technique the relay uses to route :443 by hostname).
 * Parses attacker-controlled bytes, so every step is bounds-checked.
 * ============================================================================ */
#ifndef PORTICO_TUNNEL_SNI_H
#define PORTICO_TUNNEL_SNI_H

#include <stddef.h>
#include <stdint.h>

/* Peek the SNI hostname from the front of a TLS ClientHello in buf[0..len).
 *   1  = found (host filled, NUL-terminated),
 *   0  = need more bytes (the ClientHello isn't fully buffered yet),
 *  -1  = not a ClientHello / no SNI / malformed.
 * Assumes the ClientHello fits in a single TLS record (the overwhelming norm). */
int tunnel_sni_peek(const uint8_t *buf, size_t len, char *host, size_t hostcap);

#endif /* PORTICO_TUNNEL_SNI_H */
