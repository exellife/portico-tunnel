/* SNI peek: parse the hostname out of REAL OpenSSL-generated ClientHellos (the most
 * meaningful test — our parser vs an actual TLS stack), plus incremental feeding and
 * hostile/edge inputs. Pure parser; OpenSSL is only used to mint the test bytes. */
#include "sni.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <openssl/ssl.h>

static int ok = 0, fail = 0;
static void chk(const char *n, int c) {
    printf("  %-5s %s\n", c ? "ok" : "FAIL", n);
    if (c) ok++; else fail++;
}

/* Drive OpenSSL just far enough to emit a ClientHello and capture its bytes. */
static int capture_clienthello(const char *sni, unsigned char *out, size_t cap) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL *ssl = SSL_new(ctx);
    int sp[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
    fcntl(sp[0], F_SETFL, O_NONBLOCK);          /* so SSL_connect returns after the 1st flight */
    SSL_set_fd(ssl, sp[0]);
    if (sni) SSL_set_tlsext_host_name(ssl, sni);
    SSL_connect(ssl);                            /* writes ClientHello, then WANT_READ */
    ssize_t n = read(sp[1], out, cap);
    SSL_free(ssl); SSL_CTX_free(ctx); close(sp[0]); close(sp[1]);
    return (int)n;
}

int main(void) {
    printf("== TLS SNI peek ==\n");

    unsigned char ch[8192];
    char host[256];

    /* ---- real ClientHello WITH SNI ---- */
    int n = capture_clienthello("shop.example.org", ch, sizeof ch);
    chk("captured a real ClientHello", n > 0);
    chk("extracts SNI from a real OpenSSL ClientHello",
        tunnel_sni_peek(ch, (size_t)n, host, sizeof host) == 1 && strcmp(host, "shop.example.org") == 0);

    /* ---- incremental: partial buffers say 'need more', full says 'found' ---- */
    chk("partial ClientHello -> need more (0)", tunnel_sni_peek(ch, 5, host, sizeof host) == 0);
    chk("one byte short -> need more (0)", tunnel_sni_peek(ch, (size_t)n - 1, host, sizeof host) == 0);
    chk("full ClientHello -> found (1)", tunnel_sni_peek(ch, (size_t)n, host, sizeof host) == 1);

    /* ---- real ClientHello WITHOUT SNI ---- */
    int n2 = capture_clienthello(NULL, ch, sizeof ch);
    chk("no-SNI ClientHello -> -1",
        n2 > 0 && tunnel_sni_peek(ch, (size_t)n2, host, sizeof host) == -1);

    /* ---- hostile / malformed inputs are rejected, never over-read ---- */
    unsigned char junk[16] = { 0x16, 0x03, 0x01, 0x00, 0x10, 0x01, 0x00, 0x00, 0x04 };
    junk[0] = 0x17;                              /* not a handshake record */
    chk("non-ClientHello first byte -> -1", tunnel_sni_peek(junk, sizeof junk, host, sizeof host) == -1);
    junk[0] = 0x16; junk[5] = 0x02;              /* handshake type != ClientHello (>=9 bytes present) */
    chk("wrong handshake type -> -1", tunnel_sni_peek(junk, sizeof junk, host, sizeof host) == -1);

    /* truncate the real ClientHello mid-extensions -> must say need-more or reject,
     * but never read past `len` (ASan would catch an over-read) */
    int over = 0;
    for (size_t L = 1; L <= (size_t)n; L++) {
        int r = tunnel_sni_peek(ch, L, host, sizeof host);
        if (r != 0 && r != 1 && r != -1) over = 1;   /* only valid return codes */
    }
    chk("every truncation length is handled safely (ASan watches over-reads)", !over);

    /* a tiny re-tagged record claiming a huge handshake length -> rejected, no read */
    unsigned char big[9] = { 0x16, 0x03, 0x01, 0xff, 0xff, 0x01, 0xff, 0xff, 0xff };
    chk("absurd handshake length -> -1", tunnel_sni_peek(big, sizeof big, host, sizeof host) == -1);

    printf("\n%s  (%d ok, %d failed)\n", fail ? "FAIL" : "PASS", ok, fail);
    return fail ? 1 : 0;
}
