# portico-tunnel — agent & relay specification (v1)

A reverse tunnel that exposes a server behind a **dynamic IP / NAT / CGNAT** to the
public internet, while preserving **end-to-end TLS** (the relay can't decrypt) and
letting the origin (portico) **issue its own certificate** through the tunnel.

This document is the contract. Code follows it; when they disagree, fix one on purpose.

---

## 1. Components

Two programs, one shared core library, plus the unchanged origin server:

```
            PUBLIC (stable IP, e.g. a VM)            HOME (dynamic IP / CGNAT)
          ┌───────────────────────────┐           ┌──────────┐     ┌──────────┐
 client ─►│           RELAY           │◄═ tunnel ═►│  AGENT   │ ──► │ portico  │
   :443   │  :443 ingress (passthru)  │  one TLS   │ dials    │ :443│ (origin) │
   :80    │  :80  ingress (ACME)      │  conn,     │  OUT     │     └──────────┘
          │  :7443 control (agents in)│  multiplexed                local TCP
          └───────────────────────────┘
```

- **RELAY** (`portico-tunnel --relay`) — runs on the public box. SNI-aware L4 router +
  stream multiplexer. Never terminates public TLS.
- **AGENT** (`portico-tunnel --agent`) — runs next to the origin. Dials the relay,
  registers hostnames, forwards inbound streams to a local TCP target (portico).
- **`libtunnel`** — shared core (framing, TLS link, stream engine, the byte pump).
  Both modes link it. (This is the library portico itself could embed later for a
  native agent mode — out of scope for v1.)
- **portico** — unchanged; just the local TCP service the agent forwards to.

## 2. Locked decisions (v1)

| Area | Decision | Rationale |
|---|---|---|
| Packaging | one binary, `--relay` / `--agent`, sharing `libtunnel` | they share all protocol/transport code |
| Tunnel transport | **TLS** (OpenSSL) — one long-lived agent→relay connection | reuse portico's TLS; authenticated, encrypted control + data |
| Multiplexing | **our own length-prefixed framing** with `stream_id` over the one TLS conn | dependency-light (just OpenSSL), fully in our control + testable. nghttp2/QUIC are the future upgrade path, not v1. |
| Flow control (v1) | bounded per-stream buffers; coarse (stop reading the tunnel when any stream's local side is backpressured) | correct and simple for home/small-fleet; refine later |
| Auth | **mTLS** (agent presents a client cert the relay's CA signs) — token is an alt | proven, no hand-rolled crypto |
| Public TLS | **passthrough** — relay routes by SNI, never decrypts; origin terminates | end-to-end secrecy; the reason this beats Cloudflare Tunnel |
| Routing key | TLS **SNI** | one readable field; multi-tenant by hostname |

## 3. Wire protocol (the tunnel)

All frames travel inside the single agent↔relay TLS connection.

**Frame header (9 bytes, big-endian) + payload:**
```
 +0  u8   type
 +1  u32  stream_id      (0 = connection-level / control)
 +5  u32  length         (payload byte count, ≤ MAX_FRAME)
 +9  u8   payload[length]
```

**Frame types:**

| type | name | dir | stream_id | payload |
|------|------|-----|-----------|---------|
| 0x01 | HELLO | A→R | 0 | agent_id, auth, hostnames[] (TLV/JSON) |
| 0x02 | HELLO_OK | R→A | 0 | assigned lease / limits |
| 0x03 | HELLO_ERR | R→A | 0 | reason string |
| 0x04 | PING | both | 0 | — |
| 0x05 | PONG | both | 0 | — |
| 0x10 | OPEN | R→A | new id | hostname, client_ip (the public peer) |
| 0x11 | DATA | both | id | opaque bytes for that stream |
| 0x12 | END | both | id | sender half-closed (no more DATA this dir) |
| 0x13 | RESET | both | id | abort the stream now |

**Stream lifecycle:** relay accepts a public connection → allocates `stream_id` →
sends `OPEN` → both sides exchange `DATA` (the relay feeds raw client bytes incl. the
TLS ClientHello; the agent feeds origin bytes) → `END` per direction on EOF → `RESET`
on abort. `stream_id` is relay-allocated, monotonically increasing, never reused on a
given tunnel.

**Sizes:** `MAX_FRAME` payload = 16 KiB (DATA is chunked to this). Header is fixed 9 B.

## 4. Agent specification

**Config** (file or flags): relay endpoint `host:port`; client cert+key (or token);
CA to verify the relay; local target (default `127.0.0.1:443`); `hostnames[]` to
register; reconnect backoff (min/max); heartbeat interval.

**Lifecycle:**
1. **Connect** — TCP-dial the relay; TLS handshake; **verify the relay's cert** against
   the configured CA (the agent authenticates the relay too); present client cert/token.
2. **Register** — send `HELLO{agent_id, auth, hostnames}`; await `HELLO_OK`
   (fatal-stop on `HELLO_ERR`, e.g. a hostname it's not allowed).
3. **Serve** — event loop over the tunnel:
   - `OPEN{id}` → dial the local target; map `id → local fd`.
   - `DATA{id}` → write payload to that local fd (buffer + backpressure).
   - local fd readable → wrap bytes in `DATA{id}` to the relay.
   - `END`/local-EOF → propagate half-close (`shutdown` / `END`).
   - `RESET`/error → close the local fd, drop the mapping.
4. **Heartbeat** — send `PING` every interval; if no `PONG` within timeout, treat the
   tunnel as dead.
5. **Reconnect** — on any tunnel drop, close all local fds, back off (exponential +
   jitter), redial, re-register. A dynamic-IP change is just a reconnect — transparent.

**Concurrency:** many streams over one tunnel, driven by one event loop (epoll).
**Outbound-only:** the agent never listens; this is what defeats NAT/CGNAT.

## 5. Relay specification

**Listeners:** `:443` public (passthrough), `:80` public (ACME relay), `:7443` control
(agents dial in). Ports configurable.

**Control (:7443):** accept agent TLS connections; require **mTLS** (or token); read
`HELLO`; check the per-agent **hostname allow-list** (an agent may only claim names it's
authorized for — prevents hijacking); on success insert `hostname → tunnel` into the
routing table and reply `HELLO_OK`. Heartbeats; on disconnect, remove the agent's routes.

**Public :443 (the hot path):**
1. Accept TCP; **peek** the TLS ClientHello and parse **SNI** only — no decryption, no
   key (the `ssl_preread` technique).
2. `SNI → tunnel` lookup. No route → close (passthrough can't speak HTTP).
3. Allocate `stream_id`; `OPEN{id, hostname, client_ip}` to the tunnel; feed the buffered
   ClientHello + subsequent bytes as `DATA`; splice both directions until `END`/`RESET`.
   The relay only ever sees ciphertext.

**Public :80:** forward `/.well-known/acme-challenge/*` (or all :80) down the tunnel to
the agent → origin's HTTP-01 responder, so the origin issues its own cert. (Optional:
301 → https for everything else.)

**Hardening:** reuse portico's accept-time IP gating and slowloris reaping (a peer that
connects and never sends a ClientHello is reaped). Per-agent auth + allow-list. Rate
limits on control connects.

**Multi-tenant:** one relay, many agents, many hostnames, all keyed by SNI.

## 6. Security model

- Control channel is mutually authenticated (relay cert verified by agent; agent cert/
  token verified by relay).
- Hostname **allow-list** per agent — no claiming names you don't own.
- Public traffic is **passthrough** — the relay cannot read or alter it; the origin holds
  the only private key.
- Relay is public ingress → same hardening posture as portico's listener.
- **Caveat — ECH:** SNI routing needs a readable SNI. Encrypted Client Hello would blind
  the relay; out of scope for v1 (note it, don't solve it).

## 7. Phased plan (agent-first; each phase independently tested, sanitizer-clean)

1. **splice** — bidirectional byte pump (backpressure + half-close). *No network.* ← first
2. **frame codec** — encode/decode §3 frames; table-driven tests. *No network.*
3. **control channel** — agent TLS-dials a stub relay, mTLS, `HELLO`→`HELLO_OK`, heartbeats.
4. **stream engine** — `OPEN`/`DATA`/`END`/`RESET`; agent forwards a stream to a local
   target (reuses splice + codec). Multiplex many streams over one tunnel.
5. **relay ingress** — `:443` SNI-peek + route + open stream; end-to-end with a real origin.
6. **reconnect + multi-tenant + allow-list.**
7. **ACME-through-tunnel** — `:80` relay so the origin issues its own cert.
8. **harden** — ASan/TSan throughout; an integration test that issues a cert through the
   tunnel and serves a page (mirrors portico's Pebble e2e).

Phases 1–4 are agent/shared core; the relay enters at 5 — so we **build the agent first**.

## 8. Testing discipline

Each piece gets a focused unit/integration test, run under AddressSanitizer and (for
threaded/socket code) ThreadSanitizer, before the next layer leans on it — the same
bottom-up rigor portico's HTTP/ACME stack was built with.
