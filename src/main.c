/* portico-tunnel CLI — `--relay` (public box) or `--agent` (next to the origin).
 *
 * Forwards are positional: forward_id N is the N-th forward declared, and the relay's
 * --tcp/--sni flags must line up (in order) with the agent's --forward targets.
 *
 *   relay:  portico-tunnel --relay --control-port 7443 \
 *               --cert s.crt --key s.key --client-ca ca.pem \
 *               --tcp 2222            # forward 0: relay :2222  (e.g. SSH)
 *               --sni app.example.com # forward 1: SNI on :443
 *   agent:  portico-tunnel --agent --relay-addr relay.example.com:7443 \
 *               --ca ca.pem --cert c.crt --key c.key --id home \
 *               --forward 127.0.0.1:22    # forward 0 -> local sshd
 *               --forward 127.0.0.1:8080  # forward 1 -> local web
 */
#include "stream.h"
#include "control.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <stdatomic.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MAX_FWD 16

static void on_signal(int s) { (void)s; _exit(0); }   /* stateless proxy: immediate exit */
static int allow_all(const char *a, const char *h, void *u) { (void)a; (void)h; (void)u; return 1; }

static int bind_listen(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_ANY); a.sin_port = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0 || listen(fd, 64) != 0) {
        fprintf(stderr, "portico-tunnel: cannot bind :%d (%s)\n", port, strerror(errno));
        close(fd); return -1;
    }
    return fd;
}

/* L2: parse a numeric CLI value with full validation (no silent atoi truncation). */
static long parse_num(const char *s, long lo, long hi, const char *flag) {
    char *end; errno = 0;
    long v = strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v < lo || v > hi) {
        fprintf(stderr, "portico-tunnel: %s: invalid value '%s' (want %ld..%ld)\n", flag, s, lo, hi);
        exit(2);
    }
    return v;
}
static int parse_port(const char *s, const char *flag) { return (int)parse_num(s, 1, 65535, flag); }
static int parse_secs(const char *s, const char *flag) { return (int)parse_num(s, 0, 86400, flag); }

/* L3: split "host:port" / "[v6]:port" in place. Brackets are required for IPv6 literals;
 * an ambiguous bare multi-colon address, an empty host, or a non-numeric/empty port is an
 * error rather than a silently mis-split or dial-time failure. Returns 0 or -1. */
static int hostport(char *s, char **host, char **port) {
    char *c;
    if (*s == '[') {                                       /* [IPv6]:port */
        char *rb = strchr(s, ']');
        if (!rb || rb[1] != ':') return -1;
        *rb = '\0'; *host = s + 1; c = rb + 1; *port = c + 1;
    } else {
        c = strchr(s, ':');
        if (!c || strchr(c + 1, ':')) return -1;           /* missing, or bare IPv6 -> require brackets */
        *c = '\0'; *host = s; *port = c + 1;
    }
    if (**host == '\0' || **port == '\0') return -1;       /* empty host or port */
    char *end; errno = 0;
    long pv = strtol(*port, &end, 10);
    if (errno != 0 || *end != '\0' || pv < 1 || pv > 65535) return -1;   /* numeric 1..65535 */
    return 0;
}

static const char *opt(int argc, char **argv, int *i, const char *flag) {
    if (*i + 1 >= argc) { fprintf(stderr, "portico-tunnel: %s needs a value\n", flag); exit(2); }
    return argv[++(*i)];
}

static void usage(void) {
    fputs("usage:\n"
          "  portico-tunnel --relay --control-port N --cert F --key F --client-ca F\n"
          "                 [--https-port N] [--tcp RPORT]... [--sni HOST]... [--hb SECS]\n"
          "  portico-tunnel --agent --relay-addr HOST:PORT --ca F --cert F --key F\n"
          "                 [--id NAME] --forward [tcp:|sni:]LOCALHOST:PORT... [--host NAME]... [--hb SECS]\n"
          "  (forward N's [tcp:|sni:] kind must match the relay's N-th --tcp/--sni; checked at registration)\n",
          stderr);
}

static int run_relay(int argc, char **argv) {
    int control_port = 7443, https_port = 443, hb = 0;
    const char *cert = NULL, *key = NULL, *client_ca = NULL;
    static tunnel_listener_t lis[MAX_FWD + 1]; size_t nlis = 0;
    static tunnel_sni_route_t routes[MAX_FWD]; size_t nroutes = 0;
    static uint8_t fwd_kinds[MAX_FWD];          /* M7: kind by forward_id, in declaration order */
    uint32_t next_fwd = 0;
    int sni_fd = -1;

    for (int i = 2; i < argc; i++) {
        if      (!strcmp(argv[i], "--control-port")) control_port = parse_port(opt(argc, argv, &i, "--control-port"), "--control-port");
        else if (!strcmp(argv[i], "--https-port"))   https_port   = parse_port(opt(argc, argv, &i, "--https-port"), "--https-port");
        else if (!strcmp(argv[i], "--cert"))         cert      = opt(argc, argv, &i, "--cert");
        else if (!strcmp(argv[i], "--key"))          key       = opt(argc, argv, &i, "--key");
        else if (!strcmp(argv[i], "--client-ca"))    client_ca = opt(argc, argv, &i, "--client-ca");
        else if (!strcmp(argv[i], "--hb"))           hb = parse_secs(opt(argc, argv, &i, "--hb"), "--hb");
        else if (!strcmp(argv[i], "--tcp")) {
            if (nlis >= MAX_FWD) { fprintf(stderr, "too many forwards\n"); return 2; }
            int rport = parse_port(opt(argc, argv, &i, "--tcp"), "--tcp");
            int fd = bind_listen(rport); if (fd < 0) return 1;
            fwd_kinds[next_fwd] = TUNNEL_FWD_TCP;
            lis[nlis].listen_fd = fd; lis[nlis].sni = 0; lis[nlis].forward_id = next_fwd++; nlis++;
        }
        else if (!strcmp(argv[i], "--sni")) {
            const char *host = opt(argc, argv, &i, "--sni");
            if (sni_fd < 0) {
                sni_fd = bind_listen(https_port); if (sni_fd < 0) return 1;
                lis[nlis].listen_fd = sni_fd; lis[nlis].sni = 1; lis[nlis].forward_id = 0; nlis++;
            }
            if (nroutes >= MAX_FWD) { fprintf(stderr, "too many forwards\n"); return 2; }
            fwd_kinds[next_fwd] = TUNNEL_FWD_SNI;
            routes[nroutes].host = host; routes[nroutes].forward_id = next_fwd++; nroutes++;
        }
        else { fprintf(stderr, "portico-tunnel: unknown relay option %s\n", argv[i]); usage(); return 2; }
    }
    if (!cert || !key || !client_ca || nlis == 0) {
        fprintf(stderr, "portico-tunnel --relay: need --cert --key --client-ca and at least one --tcp/--sni\n");
        return 2;
    }
    int ctrl = bind_listen(control_port);
    if (ctrl < 0) return 1;

    static atomic_int stop; atomic_init(&stop, 0);
    tunnel_relay_run_config_t cfg = {
        .control_fd = ctrl, .cert = cert, .key = key, .client_ca = client_ca,
        .listeners = lis, .n_listeners = nlis, .routes = routes, .n_routes = nroutes,
        .forward_kinds = fwd_kinds, .n_forwards = next_fwd,
        .allow = allow_all, .heartbeat_secs = hb, .stop = &stop,
    };
    fprintf(stderr, "portico-tunnel relay: agents on :%d, %u forward(s)\n", control_port, next_fwd);
    return tunnel_relay_run(&cfg);
}

static int run_agent(int argc, char **argv) {
    char *relay_addr = NULL; const char *ca = NULL, *cert = NULL, *key = NULL, *id = "portico-agent";
    int hb = 0;
    static tunnel_target_t fwd[MAX_FWD]; size_t nfwd = 0;
    static tunnel_hello_t hello; memset(&hello, 0, sizeof hello);

    for (int i = 2; i < argc; i++) {
        if      (!strcmp(argv[i], "--relay-addr")) relay_addr = (char *)opt(argc, argv, &i, "--relay-addr");
        else if (!strcmp(argv[i], "--ca"))   ca   = opt(argc, argv, &i, "--ca");
        else if (!strcmp(argv[i], "--cert")) cert = opt(argc, argv, &i, "--cert");
        else if (!strcmp(argv[i], "--key"))  key  = opt(argc, argv, &i, "--key");
        else if (!strcmp(argv[i], "--id"))   id   = opt(argc, argv, &i, "--id");
        else if (!strcmp(argv[i], "--hb"))   hb   = parse_secs(opt(argc, argv, &i, "--hb"), "--hb");
        else if (!strcmp(argv[i], "--forward")) {
            if (nfwd >= MAX_FWD) { fprintf(stderr, "too many forwards\n"); return 2; }
            char *t = (char *)opt(argc, argv, &i, "--forward"), *h, *p;
            /* M7: an optional "tcp:"/"sni:" prefix declares the forward's kind (default tcp), so
             * the agent's forward sequence is checked against the relay's at registration. */
            uint8_t kind = TUNNEL_FWD_TCP;
            if      (!strncmp(t, "tcp:", 4)) { t += 4; kind = TUNNEL_FWD_TCP; }
            else if (!strncmp(t, "sni:", 4)) { t += 4; kind = TUNNEL_FWD_SNI; }
            if (hostport(t, &h, &p) != 0) { fprintf(stderr, "bad --forward %s (want [tcp:|sni:]host:port)\n", t); return 2; }
            snprintf(fwd[nfwd].host, sizeof fwd[nfwd].host, "%s", h);
            snprintf(fwd[nfwd].port, sizeof fwd[nfwd].port, "%s", p);
            hello.forward_kinds[nfwd] = kind; hello.n_forwards = nfwd + 1;
            nfwd++;
        }
        else if (!strcmp(argv[i], "--host")) {
            if (hello.n_hosts >= TUNNEL_MAX_HOSTS) { fprintf(stderr, "too many --host\n"); return 2; }
            snprintf(hello.hostnames[hello.n_hosts], sizeof hello.hostnames[0], "%s", opt(argc, argv, &i, "--host"));
            hello.n_hosts++;
        }
        else { fprintf(stderr, "portico-tunnel: unknown agent option %s\n", argv[i]); usage(); return 2; }
    }
    char *rh, *rp;
    if (!relay_addr || hostport(relay_addr, &rh, &rp) != 0 || !cert || !key || nfwd == 0) {
        fprintf(stderr, "portico-tunnel --agent: need --relay-addr HOST:PORT --cert --key and >=1 --forward\n");
        return 2;
    }
    snprintf(hello.agent_id, sizeof hello.agent_id, "%s", id);

    static atomic_int stop; atomic_init(&stop, 0);
    tunnel_agent_run_config_t cfg = {
        .relay_host = rh, .relay_port = rp, .ca_file = ca, .client_cert = cert, .client_key = key,
        .hello = &hello, .forwards = fwd, .n_forwards = nfwd, .heartbeat_secs = hb, .stop = &stop,
    };
    fprintf(stderr, "portico-tunnel agent '%s': relay %s:%s, %zu forward(s)\n", id, rh, rp, nfwd);
    return tunnel_agent_run(&cfg);
}

int main(int argc, char **argv) {
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);
    if (argc < 2) { usage(); return 2; }
    if (!strcmp(argv[1], "--relay")) return run_relay(argc, argv);
    if (!strcmp(argv[1], "--agent")) return run_agent(argc, argv);
    usage();
    return 2;
}
