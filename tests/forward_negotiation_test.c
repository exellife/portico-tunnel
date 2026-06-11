/* M7: HELLO/HELLO_OK now negotiate the forward-kind sequence so positional misalignment
 * between the relay's --tcp/--sni order and the agent's --forward order is caught at
 * registration (before a public TLS hostname can be misrouted to e.g. local sshd) instead of
 * silently trusting array index. The relay declares its authoritative forward kinds; a HELLO
 * whose kinds don't match (count or kind) is refused; the relay echoes its kinds in HELLO_OK
 * and the agent re-checks them. Transport-agnostic — tested over a socketpair. */
#include "control.h"
#include "io.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>

static int ok = 0, fail = 0;
static void chk(const char *n, int c) { printf("  %-5s %s\n", c ? "ok" : "FAIL", n); if (c) ok++; else fail++; }

/* relay thread: tunnel_relay_accept with the given authoritative kinds (NULL = legacy). */
struct relay_arg { int fd; const uint8_t *kinds; size_t n; int rc; };
static void *relay_thr(void *p) {
    struct relay_arg *a = p;
    tunnel_io_t io = tunnel_io_fd(a->fd);
    tunnel_decoder_t d; tunnel_decoder_reset(&d);
    tunnel_hello_t h;
    a->rc = tunnel_relay_accept(&io, &d, &h, NULL, a->kinds, a->n, NULL, NULL, NULL, 0);
    return NULL;
}

/* hand-rolled relay that ignores the agent's HELLO and replies HELLO_OK with `echo` kinds —
 * to test the AGENT-side echo check in isolation. */
struct bad_arg { int fd; const char *echo; };
static void *bad_echo_thr(void *p) {
    struct bad_arg *a = p;
    tunnel_io_t io = tunnel_io_fd(a->fd);
    tunnel_decoder_t d; tunnel_decoder_reset(&d);
    tunnel_frame_t f;
    if (tunnel_io_read_frame(&io, &d, &f) == 1 && f.type == TF_HELLO)
        tunnel_io_write_frame(&io, TF_HELLO_OK, 0, a->echo, (uint32_t)strlen(a->echo));
    return NULL;
}

/* Run one agent<->relay registration; returns the agent's register rc, fills relay rc + err. */
static int run_case(const uint8_t *relay_kinds, size_t rn,
                    const uint8_t *agent_kinds, size_t an, int *relay_rc, char *err, size_t errcap) {
    int sv[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    struct relay_arg ra = { .fd = sv[1], .kinds = relay_kinds, .n = rn, .rc = -2 };
    pthread_t th; pthread_create(&th, NULL, relay_thr, &ra);
    tunnel_hello_t ah; memset(&ah, 0, sizeof ah); snprintf(ah.agent_id, sizeof ah.agent_id, "a");
    for (size_t i = 0; i < an; i++) ah.forward_kinds[i] = agent_kinds[i];
    ah.n_forwards = an;
    tunnel_io_t io = tunnel_io_fd(sv[0]); tunnel_decoder_t d; tunnel_decoder_reset(&d);
    int rc = tunnel_agent_register(&io, &d, &ah, err, errcap);
    pthread_join(th, NULL); close(sv[0]); close(sv[1]);
    if (relay_rc) *relay_rc = ra.rc;
    return rc;
}

int main(void) {
    printf("== HELLO/HELLO_OK forward-kind negotiation (M7) ==\n");
    const uint8_t TS[2] = { TUNNEL_FWD_TCP, TUNNEL_FWD_SNI };
    const uint8_t TT[2] = { TUNNEL_FWD_TCP, TUNNEL_FWD_TCP };
    const uint8_t T1[1] = { TUNNEL_FWD_TCP };

    /* ---- codec roundtrip with forward kinds ---- */
    {
        tunnel_hello_t h = {0}; snprintf(h.agent_id, sizeof h.agent_id, "agent-7");
        snprintf(h.hostnames[0], sizeof h.hostnames[0], "a.example.com"); h.n_hosts = 1;
        h.forward_kinds[0] = TUNNEL_FWD_TCP; h.forward_kinds[1] = TUNNEL_FWD_SNI;
        h.forward_kinds[2] = TUNNEL_FWD_TCP; h.n_forwards = 3;
        uint8_t pb[2048]; int pl = tunnel_hello_encode(&h, pb, sizeof pb);
        tunnel_hello_t h2;
        chk("HELLO encodes+parses forward kinds (and keeps hostnames)",
            pl > 0 && tunnel_hello_parse(pb, (uint32_t)pl, &h2) == 0 &&
            h2.n_hosts == 1 && strcmp(h2.hostnames[0], "a.example.com") == 0 &&
            h2.n_forwards == 3 && h2.forward_kinds[0] == TUNNEL_FWD_TCP &&
            h2.forward_kinds[1] == TUNNEL_FWD_SNI && h2.forward_kinds[2] == TUNNEL_FWD_TCP);
    }

    int rrc; char err[160];
    /* ---- matching kinds accept ---- */
    chk("matching forward kinds register OK (agent)", run_case(TS, 2, TS, 2, &rrc, err, sizeof err) == 0);
    chk("matching forward kinds accepted (relay)", rrc == 0);

    /* ---- kind mismatch (tcp,sni vs tcp,tcp) refused ---- */
    int arc = run_case(TS, 2, TT, 2, &rrc, err, sizeof err);
    chk("kind mismatch refused (agent register fails)", arc == -1);
    chk("kind mismatch reason surfaced", strstr(err, "kind mismatch") != NULL);
    chk("kind mismatch refused (relay rejects)", rrc == -1);

    /* ---- count mismatch (2 vs 1) refused ---- */
    arc = run_case(TS, 2, T1, 1, &rrc, err, sizeof err);
    chk("count mismatch refused", arc == -1 && strstr(err, "count mismatch") != NULL);

    /* ---- back-compat: legacy relay (no kinds) doesn't negotiate -> accept ---- */
    chk("legacy relay (NULL kinds) still registers a kind-declaring agent",
        run_case(NULL, 0, TS, 2, &rrc, err, sizeof err) == 0);

    /* ---- back-compat: agent opts out (n_forwards 0) -> relay does not enforce ---- */
    chk("agent that declares no forwards still registers against a kind relay",
        run_case(TS, 2, NULL, 0, &rrc, err, sizeof err) == 0);

    /* ---- agent-side echo check: a relay that echoes WRONG kinds is rejected by the agent ---- */
    {
        int sv[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
        struct bad_arg ba = { .fd = sv[1], .echo = "tt" };   /* claims tcp,tcp */
        pthread_t th; pthread_create(&th, NULL, bad_echo_thr, &ba);
        tunnel_hello_t ah; memset(&ah, 0, sizeof ah); snprintf(ah.agent_id, sizeof ah.agent_id, "a");
        ah.forward_kinds[0] = TUNNEL_FWD_TCP; ah.forward_kinds[1] = TUNNEL_FWD_SNI; ah.n_forwards = 2;
        tunnel_io_t io = tunnel_io_fd(sv[0]); tunnel_decoder_t d; tunnel_decoder_reset(&d);
        int rc = tunnel_agent_register(&io, &d, &ah, err, sizeof err);
        pthread_join(th, NULL); close(sv[0]); close(sv[1]);
        chk("agent rejects a relay whose HELLO_OK kinds disagree", rc == -1 && strstr(err, "kind mismatch") != NULL);
    }

    printf("\n%s  (%d ok, %d failed)\n", fail ? "FAIL" : "PASS", ok, fail);
    return fail ? 1 : 0;
}
