# portico-tunnel

A reverse tunnel for exposing a server behind a **dynamic IP / NAT / CGNAT** to the
public internet — while keeping **end-to-end TLS** (the relay never decrypts) and
letting the origin (e.g. [portico](../portico)) **issue its own certificate** through
the tunnel.

One binary, two modes:
- `portico-tunnel --relay` — runs on a public box; SNI-routes inbound traffic to agents.
- `portico-tunnel --agent` — runs next to the origin; dials out, forwards streams locally.

See **[docs/spec.md](docs/spec.md)** for the full agent + relay specification and the
phased build plan. Status: **early — building the agent first**, bottom-up and
sanitizer-clean.

## Build

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
ctest --test-dir build
```

Sanitizer builds: `-DTUNNEL_ASAN=ON` or `-DTUNNEL_TSAN=ON`.
