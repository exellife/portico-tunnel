# portico-tunnel

A reverse tunnel for exposing a server behind a **dynamic IP / NAT / CGNAT** to the
public internet — while keeping **end-to-end TLS** (the relay never decrypts) and
letting the origin (e.g. [portico](../portico)) **issue its own certificate** through
the tunnel.

One binary, two modes:
- `portico-tunnel --relay` — runs on a public box; SNI-routes inbound traffic to agents.
- `portico-tunnel --agent` — runs next to the origin; dials out, forwards streams locally.

See **[docs/spec.md](docs/spec.md)** for the full agent + relay specification and the
phased build plan. Status: **working data plane + self-healing agent + a runnable
binary**; built bottom-up and sanitizer-clean (ASan + TSan).

## Build

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
ctest --test-dir build
```

Sanitizer builds: `-DTUNNEL_ASAN=ON` or `-DTUNNEL_TSAN=ON`.

## Run

Forwards are positional — the relay's `--tcp`/`--sni` flags line up (in order) with the
agent's `--forward` targets. Example: expose a home SSH server through a public relay.

```
# on the public box (needs a server cert/key + a CA that signs agent certs):
portico-tunnel --relay --control-port 7443 \
    --cert relay.crt --key relay.key --client-ca ca.crt \
    --tcp 2222                       # forward 0: relay :2222

# next to the origin (dials out; client cert signed by ca.crt):
portico-tunnel --agent --relay-addr relay.example.com:7443 \
    --ca ca.crt --cert agent.crt --key agent.key --id home \
    --forward 127.0.0.1:22           # forward 0 -> local sshd

# then, from anywhere:
ssh -p 2222 user@relay.example.com   # lands on the home sshd
```

`--sni HOST` adds an SNI-routed forward on `--https-port` (default 443) for TLS
services. mTLS (client cert signed by `--client-ca`) is the trust gate. The agent
reconnects automatically with backoff; a dynamic home IP is just a reconnect.
