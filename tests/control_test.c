/* Control channel: HELLO codec roundtrip + edge rejects, and the live register/accept
 * handshake over a socketpair — success, hostname refusal, and a PING answered while
 * the agent waits for its verdict. Threaded loopback; no TLS yet (that wraps the same
 * tunnel_io_t in 3b). */
#include "control.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>

static int ok = 0, fail = 0;
static void chk(const char *n, int c) {
    printf("  %-5s %s\n", c ? "ok" : "FAIL", n);
    if (c) ok++; else fail++;
}

/* relay-side allow(): permit exactly the one hostname in `ud`. */
static int allow_one(const char *agent_id, const char *host, void *ud) {
    (void)agent_id;
    return strcmp(host, (const char *)ud) == 0;
}

/* Thread running tunnel_relay_accept against fd, allowing g_allowed. */
struct accept_ctx { int fd; const char *allowed; int rc; tunnel_hello_t hello; };
static void *accept_thread(void *p) {
    struct accept_ctx *c = p;
    tunnel_io_t io = tunnel_io_fd(c->fd);
    tunnel_decoder_t dec; tunnel_decoder_reset(&dec);
    c->rc = tunnel_relay_accept(&io, &dec, &c->hello, NULL, allow_one, (void *)c->allowed, NULL, 0);
    return NULL;
}

/* Thread that hand-rolls a relay: read HELLO, send PING, expect PONG, send HELLO_OK. */
struct ping_ctx { int fd; int saw_hello, saw_pong; };
static void *ping_relay_thread(void *p) {
    struct ping_ctx *c = p;
    tunnel_io_t io = tunnel_io_fd(c->fd);
    tunnel_decoder_t dec; tunnel_decoder_reset(&dec);
    tunnel_frame_t f;
    if (tunnel_io_read_frame(&io, &dec, &f) == 1 && f.type == TF_HELLO) c->saw_hello = 1;
    tunnel_io_write_frame(&io, TF_PING, 0, NULL, 0);
    if (tunnel_io_read_frame(&io, &dec, &f) == 1 && f.type == TF_PONG) c->saw_pong = 1;
    tunnel_io_write_frame(&io, TF_HELLO_OK, 0, NULL, 0);
    return NULL;
}

int main(void) {
    printf("== tunnel control channel ==\n");

    /* ---- HELLO codec ---- */
    tunnel_hello_t h = {0};
    snprintf(h.agent_id, sizeof h.agent_id, "agent-7");
    snprintf(h.hostnames[0], sizeof h.hostnames[0], "a.example.com");
    snprintf(h.hostnames[1], sizeof h.hostnames[1], "www.a.example.com");
    h.n_hosts = 2;
    uint8_t pb[2048];
    int pl = tunnel_hello_encode(&h, pb, sizeof pb);
    tunnel_hello_t h2;
    chk("HELLO encode/parse roundtrip",
        pl > 0 && tunnel_hello_parse(pb, (uint32_t)pl, &h2) == 0 &&
        strcmp(h2.agent_id, "agent-7") == 0 && h2.n_hosts == 2 &&
        strcmp(h2.hostnames[0], "a.example.com") == 0 &&
        strcmp(h2.hostnames[1], "www.a.example.com") == 0);

    uint8_t junk[8] = { 'x','x','x','x','x','x','x','x' };   /* no newline -> just an agent_id, 0 hosts */
    tunnel_hello_t h3;
    chk("HELLO with no hostnames parses to 0 hosts",
        tunnel_hello_parse(junk, sizeof junk, &h3) == 0 && h3.n_hosts == 0);

    /* ---- success: agent registers an allowed hostname ---- */
    {
        int sv[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
        struct accept_ctx ac = { .fd = sv[1], .allowed = "ok.example.com" };
        pthread_t th; pthread_create(&th, NULL, accept_thread, &ac);

        tunnel_hello_t ah = {0};
        snprintf(ah.agent_id, sizeof ah.agent_id, "agent-ok");
        snprintf(ah.hostnames[0], sizeof ah.hostnames[0], "ok.example.com");
        ah.n_hosts = 1;
        tunnel_io_t io = tunnel_io_fd(sv[0]);
        tunnel_decoder_t dec; tunnel_decoder_reset(&dec);
        char err[128];
        int rc = tunnel_agent_register(&io, &dec, &ah, err, sizeof err);
        pthread_join(th, NULL);

        chk("agent registers (HELLO_OK)", rc == 0);
        chk("relay accepted + parsed hostname",
            ac.rc == 0 && ac.hello.n_hosts == 1 && strcmp(ac.hello.hostnames[0], "ok.example.com") == 0);
        close(sv[0]); close(sv[1]);
    }

    /* ---- refusal: agent claims a disallowed hostname ---- */
    {
        int sv[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
        struct accept_ctx ac = { .fd = sv[1], .allowed = "ok.example.com" };
        pthread_t th; pthread_create(&th, NULL, accept_thread, &ac);

        tunnel_hello_t ah = {0};
        snprintf(ah.agent_id, sizeof ah.agent_id, "agent-bad");
        snprintf(ah.hostnames[0], sizeof ah.hostnames[0], "evil.example.com");
        ah.n_hosts = 1;
        tunnel_io_t io = tunnel_io_fd(sv[0]);
        tunnel_decoder_t dec; tunnel_decoder_reset(&dec);
        char err[128];
        int rc = tunnel_agent_register(&io, &dec, &ah, err, sizeof err);
        pthread_join(th, NULL);

        chk("agent registration refused (HELLO_ERR)", rc == -1);
        chk("refusal reason surfaced to agent", strstr(err, "not allowed") != NULL);
        chk("relay rejected", ac.rc == -1);
        close(sv[0]); close(sv[1]);
    }

    /* ---- a PING during registration is answered with PONG ---- */
    {
        int sv[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
        struct ping_ctx pc = { .fd = sv[1] };
        pthread_t th; pthread_create(&th, NULL, ping_relay_thread, &pc);

        tunnel_hello_t ah = {0};
        snprintf(ah.agent_id, sizeof ah.agent_id, "agent-ping");
        snprintf(ah.hostnames[0], sizeof ah.hostnames[0], "p.example.com");
        ah.n_hosts = 1;
        tunnel_io_t io = tunnel_io_fd(sv[0]);
        tunnel_decoder_t dec; tunnel_decoder_reset(&dec);
        int rc = tunnel_agent_register(&io, &dec, &ah, NULL, 0);
        pthread_join(th, NULL);

        chk("agent answered PING with PONG mid-handshake", pc.saw_hello && pc.saw_pong);
        chk("agent still registered after the PING", rc == 0);
        close(sv[0]); close(sv[1]);
    }

    printf("\n%s  (%d ok, %d failed)\n", fail ? "FAIL" : "PASS", ok, fail);
    return fail ? 1 : 0;
}
