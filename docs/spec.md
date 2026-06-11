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

- **RELAY** (`portico-tunnel --relay`) — runs on the public box. An L4 router + stream
  multiplexer that routes by **SNI** on :443 and by **listen port** for TCP forwards
  (see §3.1). Never terminates public traffic.
- **AGENT** (`portico-tunnel --agent`) — runs next to the origin. Dials the relay,
  registers a set of **forwards** (each maps public ingress → a local TCP target), and
  pumps inbound streams to the right local target. The target is just TCP, so a forward
  can expose portico's :443, an sshd's :22, a database — anything.
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
| Routing | two modes (§3.1): **SNI** on :443 for TLS services, **TCP port-forward** for everything else | SNI multiplexes many hostnames on one port; non-TLS protocols (SSH, DBs) have no SNI, so they get a dedicated relay port |

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
| 0x01 | HELLO | A→R | 0 | agent_id + a list of **forwards** (§3.1) |
| 0x02 | HELLO_OK | R→A | 0 | accepted forwards (with each forward_id + bound port) |
| 0x03 | HELLO_ERR | R→A | 0 | reason string |
| 0x04 | PING | both | 0 | — |
| 0x05 | PONG | both | 0 | — |
| 0x10 | OPEN | R→A | new id | `forward_id` + client_ip (the public peer) |
| 0x11 | DATA | both | id | opaque bytes for that stream |
| 0x12 | END | both | id | sender half-closed (no more DATA this dir) |
| 0x13 | RESET | both | id | abort the stream now |

**Stream lifecycle:** relay accepts a public connection → picks the **forward** it
belongs to (by SNI or by which port it arrived on) → allocates `stream_id` → sends
`OPEN{forward_id, client_ip}` → the agent dials that forward's local target → both
sides exchange `DATA` (for an SNI forward the relay feeds raw client bytes incl. the
TLS ClientHello; the agent feeds origin bytes) → `END` per direction on EOF → `RESET`
on abort. `stream_id` is relay-allocated, monotonically increasing, never reused on a
given tunnel. `forward_id` tells the agent which local target to dial.

**Sizes:** `MAX_FRAME` payload = 16 KiB (DATA is chunked to this). Header is fixed 9 B.

### 3.1 Forwards & routing modes

A **forward** is the unit an agent registers: it binds some public ingress on the relay
to one local TCP target the agent will dial. Two kinds, differing only in how the relay
decides which forward an incoming connection belongs to:

| kind | relay ingress | routed by | terminates TLS? | for |
|------|---------------|-----------|------------------|-----|
| **sni** | the shared :443 | the TLS **SNI** in the ClientHello | no (passthrough) | HTTPS / any TLS service; many hostnames share :443 |
| **tcp** | a **dedicated relay port** (e.g. :2222) | which port the connection arrived on | no (raw bytes) | SSH, databases, game servers — anything non-TLS, or where a fixed port is wanted |

Both kinds ride the **same** tunnel and stream engine; only the relay's "which forward?"
lookup differs (an SNI→forward map vs a port→forward map). A `tcp` forward is pure byte
passthrough, so it works for any protocol and stays end-to-end encrypted when the
payload is already encrypted (e.g. SSH): the relay only ever moves ciphertext.

**Declaration (HELLO).** The HELLO payload is the agent_id followed by one forward per
line:
```
<agent_id>
sni <hostname>      <local_host:port>     e.g.  sni  app.example.com  127.0.0.1:443
tcp <remote_port>   <local_host:port>     e.g.  tcp  2222             127.0.0.1:22
```

**Authorization (per agent).** The relay validates each forward against that agent's
policy before accepting it:
- `sni` → the hostname must be in the agent's **hostname allow-list** (no claiming a
  name you don't own).
- `tcp` → the requested `remote_port` must be in the agent's **allowed-port set/range**
  (no grabbing :22 of the box, or another tenant's port). The relay also refuses a port
  already bound by another forward.

On acceptance the relay replies `HELLO_OK` listing the accepted forwards with their
`forward_id` (index the agent uses to map `OPEN`→target) and the actually-bound port.

**Example — SSH to the home LAN.** Register `tcp 2222 → 127.0.0.1:22`; then
`ssh -p 2222 admin@<relay>` lands on the home sshd, and `ssh -J admin@<relay>:2222 …`
hops onward to any LAN machine. The relay can additionally gate `:2222` by source IP so
the SSH port isn't open to the whole internet.

## 4. Agent specification

**Config** (file or flags): relay endpoint `host:port`; client cert+key (or token);
CA to verify the relay; the list of **forwards** to register (each `sni <host> <target>`
or `tcp <rport> <target>`, §3.1); reconnect backoff (min/max); heartbeat interval.

**Lifecycle:**
1. **Connect** — TCP-dial the relay; TLS handshake; **verify the relay's cert** against
   the configured CA (the agent authenticates the relay too); present client cert/token.
2. **Register** — send `HELLO{agent_id, forwards}`; await `HELLO_OK` (which echoes the
   accepted `forward_id`s); fatal-stop on `HELLO_ERR` (e.g. a forward it's not allowed).
3. **Serve** — event loop over the tunnel:
   - `OPEN{id, forward_id}` → dial that forward's local target; map `id → local fd`.
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

**Listeners:** `:443` public (SNI passthrough), `:80` public (ACME relay), `:7443`
control (agents dial in), plus **one dynamic listener per accepted `tcp` forward** (its
`remote_port`, bound when the forward is registered, closed when the agent disconnects).
Ports configurable.

**Control (:7443):** accept agent TLS connections; require **mTLS** (or token); read
`HELLO`; authorize each forward against that agent's policy (`sni` → hostname allow-list;
`tcp` → allowed-port set, and the port must be free); on success register the forwards —
insert each into the `SNI → forward` map and/or bind its `tcp` port — and reply
`HELLO_OK` with the assigned `forward_id`s. Heartbeats; on disconnect, drop the agent's
SNI routes and close its bound ports.

**Routing the two ingress kinds (the hot paths):**
- **:443 (SNI)** — accept TCP; **peek** the ClientHello and parse **SNI** only (no
  decryption, no key — the `ssl_preread` technique); `SNI → forward` lookup; no route →
  close. Then open a stream feeding the buffered ClientHello + subsequent bytes.
- **a `tcp` forward port** — accept TCP; the forward is implied by *which port* it
  arrived on; open a stream immediately (no peek). Pure byte passthrough.

In both cases: allocate `stream_id`; send `OPEN{id, forward_id, client_ip}`; splice both
directions as `DATA` until `END`/`RESET`. The relay only ever moves bytes — it never
decrypts (for `sni`, it cannot; for `tcp`, the payload is whatever the protocol is).

**Public :80:** forward `/.well-known/acme-challenge/*` (or all :80) down the tunnel to
the agent → origin's HTTP-01 responder, so the origin issues its own cert. (Optional:
301 → https for everything else.)

**Hardening:** reuse portico's accept-time IP gating and slowloris reaping (a peer that
connects and never sends data is reaped). Per-agent auth + per-forward authorization.
Rate limits on control connects. A `tcp` forward may carry an optional **source-IP
allow-list** so e.g. an SSH port isn't open to the whole internet.

**Multi-tenant:** one relay, many agents; SNI forwards keyed by hostname, `tcp` forwards
keyed by port — no collisions across tenants (enforced at registration).

## 6. Security model

- Control channel is mutually authenticated (relay cert verified by agent; agent cert/
  token verified by relay).
- **Per-forward authorization** per agent: `sni` against a hostname allow-list (no
  claiming names you don't own), `tcp` against an allowed-port set (no grabbing the box's
  :22 or another tenant's port).
- Public traffic is **passthrough** — the relay never decrypts. For `sni` it cannot
  (the origin holds the only key); for `tcp` it just moves bytes (already-encrypted
  protocols like SSH stay end-to-end secret).
- A `tcp` forward may set a **source-IP allow-list** at the relay, so an exposed admin
  port (e.g. SSH) is reachable only from trusted IPs, not the whole internet.
- Relay is public ingress → same hardening posture as portico's listener.
- **Caveat — ECH:** SNI routing needs a readable SNI. Encrypted Client Hello would blind
  the relay's `sni` mode (the `tcp` mode is unaffected); out of scope for v1.

## 7. Phased plan (agent-first; each phase independently tested, sanitizer-clean)

1. **splice** — bidirectional byte pump (backpressure + half-close). *No network.* ← first
2. **frame codec** — encode/decode §3 frames; table-driven tests. *No network.*
3. **control channel** — agent TLS-dials a stub relay, mTLS, `HELLO`→`HELLO_OK`, heartbeats.
4. **stream engine** — `OPEN`/`DATA`/`END`/`RESET`; agent forwards a stream to a local
   target (reuses splice + codec). Multiplex many streams over one tunnel.
5. **relay ingress (tcp forward)** — a dedicated relay port → open stream; the simplest
   routing (no peek), end-to-end with a real local TCP service (e.g. an echo server or
   sshd). Proves the whole path.
6. **relay ingress (sni)** — `:443` SNI-peek + `SNI → forward` route; passthrough to a
   real TLS origin.
7. **reconnect + multi-tenant + per-forward authorization.**
8. **ACME-through-tunnel** — `:80` relay so the origin issues its own cert.
9. **harden** — ASan/TSan throughout; an integration test that issues a cert through the
   tunnel and serves a page (mirrors portico's Pebble e2e), and one that SSHes through a
   `tcp` forward.

Phases 1–4 are agent/shared core; the relay enters at 5 — so we **build the agent first**.
Note the `tcp` forward (no SNI peek) is the *simpler* relay path, so it comes before the
SNI path — and it's what makes SSH-over-tunnel work.

## 8. Testing discipline

Each piece gets a focused unit/integration test, run under AddressSanitizer and (for
threaded/socket code) ThreadSanitizer, before the next layer leans on it — the same
bottom-up rigor portico's HTTP/ACME stack was built with.
