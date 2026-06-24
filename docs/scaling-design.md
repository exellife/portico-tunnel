# portico-tunnel — scaling design (single-thread → multi-core bulk mover)

A transition plan from what portico-tunnel **is** today — a lean, single-threaded,
low-latency tunnel for web/realtime traffic and home-origin exposure — toward a
**multi-core high-throughput bulk-data mover**, *if and when measurement justifies it*.

Unlike [`spec.md`](spec.md) (the v1 contract), this is a **roadmap**, not a contract:
it records the constraints, the staged path, and the decision gates so a future change
doesn't start the architecture conversation from scratch.

---

## Where we are (2026-06)

Single `serve_loop` per agent connection, one thread, **one mTLS tunnel connection**
multiplexing all logical streams via frames. epoll-based (O(ready) wakeups). Validated:
**4000 concurrent streams at ~1.6 ms added RTT on one core**, ~9 MB RSS, ASan/UBSan-clean,
adversarial-review-clean. Single-stream throughput on loopback (no TLS) ~50 MB/s.

Known limits (see `TODO.md`): **single-threaded** (throughput capped at ~1 core);
**coarse global backpressure** (concurrent full-duplex *bulk* streams head-of-line-block
each other); residual O(MAX_STREAMS) per-iteration scans. It is a **latency/concurrency
engine, not a bandwidth firehose.**

---

## 0. The gate: measure before you build

A home-origin tunnel's real ceiling is usually the **WAN/uplink, not relay cores**:
- relay→agent crosses the internet to a *home* box → the home **upload bandwidth** caps everything;
- the relay (e.g. the 954 MB / 2-core Oracle VM) is capped by its **cloud egress**, not just CPU.

**Step 0 is a measurement, not engineering:** load-test the real public path (TLS,
cross-network) and find what actually saturates — uplink, relay NIC/egress, or a relay
core. If a *core* is not the measured bottleneck, **stop here** — multi-threading buys
nothing the network can't carry. Everything below is gated on this result.

---

## Phase 0 results (2026-06-24) — measured, and it changed the plan

Load test against the live public path (`https://portico-test.duckdns.org`, a 256 MB
static asset, concurrent downloaders, relay/agent CPU sampled live):

| concurrent bulk downloads | aggregate throughput |
|---|---|
| **1** | **43 Mbit/s** (flows fine — ≈ the home uplink for a single TCP stream) |
| 2 | 6 Mbit/s — **collapses 7×** |
| 3+ | **~0** |

**Relay CPU stayed at 0% (load 0.00) throughout; agent ~0%, cellar 1–3%.** A healthy
tunnel sharing a link would *hold* aggregate at ~43 Mbit/s as N rises (just split across
streams). Dropping **below single-stream** is impossible for link-sharing — it is the
unmistakable signature of **coarse global backpressure thrashing**: one stream's consumer
falls behind → the relay stops reading the tunnel for *all* streams → stall/resume
oscillation drives aggregate to zero.

**Verdict — the gate fired "STOP" on the multi-core path:**
- **NOT relay-CPU bound** (idle) → **Phases 3/4 (multi-connection + relay threads) are NOT
  justified for this deployment.** More cores/connections fix a bottleneck we don't have.
- **NOT raw-WAN-bandwidth bound** either (a single stream sustains 43 Mbit/s) — the
  concurrent collapse is *software*, not the pipe.
- **The real blocker is the coarse backpressure → Phase 1 (per-stream flow control) is
  reclassified from "valuable" to CRITICAL.** It is very likely the *only* throughput work
  this deployment needs: it lets N concurrent streams share the ~43 Mbit/s uplink instead of
  collapsing to zero. The aggregate ceiling stays the WAN uplink (~43 Mbit/s) — which the
  relay has ample CPU headroom to drive.
- *(Caveat: the load was generated from inside the home LAN, so the client hairpins the home
  up+down link. That can aggravate consumer-rate variance, but the aggregate-below-single-
  stream collapse is diagnostic of backpressure regardless. A true off-LAN client re-test
  would make it airtight; the conclusion already holds.)*

**Net: skip the multi-core rewrite; do Phase 1.** Re-measure after Phase 1 — if a relay core
then becomes the wall (it won't at ~43 Mbit/s), revisit the multi-core path. Phase 0 just
saved the whole Phase 3/4 effort.

---

## The one fundamental constraint

**A single TLS connection is one ordered byte-stream → one core, inherently.** TLS's
AES-GCM record sequence and TCP's in-order delivery cannot be parallelized across cores.
So multi-core throughput **requires multiple parallel tunnel connections** with streams
sharded across them. This single fact shapes the entire roadmap: the data plane's
connection model is the thing that must change.

---

## Staged roadmap

Phases 1, 2, 5 are **incremental** (ship independently, low–moderate risk). Phase 3 is the
**architectural fork**; Phase 4 pairs with it.

### Phase 1 — Per-stream (credit-based) flow control  *(do first, regardless)*
Replace the single global `backpressured` flag with per-stream send windows/credits
(HTTP/2-style). A stalled sink only backpressures **its own** stream, not the whole tunnel.
- **Unlocks:** concurrent bulk streams stop head-of-line-blocking — *even single-threaded*.
  Directly fixes the one concrete limitation the stress probe found.
- **Type:** incremental, no architectural commitment. Moderate complexity.
- *Already tracked in `TODO.md` Backlog.*

### Phase 2 — Eliminate residual O(MAX_STREAMS) scans
Counters (`n_active`/`n_backpressured`/`n_connecting`) for O(1) gates; time-gated reap;
event-driven epoll arming (arm at state-change sites + on global tw-room transitions).
- **Unlocks:** flatter latency at high fan-out; cheaper per-connection so threading scales.
- **Type:** incremental. Moderate. *(`TODO.md` Backlog.)*

### Phase 3 — Multi-connection tunnel bundle  ← **the fork**
The agent opens **N parallel TLS links** to the relay (a "bundle"). Streams are
**sticky-hashed** to a link (a stream lives entirely on one link → ordering is free, no
reordering layer). Each link is served by **its own `serve_loop` on its own thread/core**.
- **Unlocks:** multi-core aggregate throughput ≈ N links × per-link core. A *single* stream
  still caps at one core/link — fine for the **many-concurrent-bulk-transfers** workload.
- **Requires:** connection-pool management, per-link reconnect/backoff, HELLO extended to
  negotiate a bundle (id + link count), stream→link assignment + rebalancing, and the relay
  side becoming multi-threaded (Phase 4).
- **Type:** substantial rewrite of the connection layer. **High risk.**
- **Explicitly NOT in scope:** striping a *single* stream across links (MPTCP-style, needs
  per-byte sequencing + reordering). Only worth it if one transfer must exceed one core —
  usually it isn't, and it's a large complexity jump. Skip unless measured-necessary.

### Phase 4 — Relay worker pool
Today `tunnel_relay_run` accepts and serves **one agent serially**. For N links per agent
(Phase 3) and many agents, the relay needs an accept + worker-thread pool, with the SNI
route table as read-mostly shared state.
- **Type:** significant; pairs with Phase 3.

### Phase 5 — Zero-copy + transport tuning
kTLS + `splice()`/`sendfile()` (kernel-to-kernel, no userspace copy — the big one for raw
throughput once TLS is kernel-offloaded), `SO_REUSEPORT` for multi-thread accept, BBR
congestion control, larger socket buffers.
- **Unlocks:** the last 2–5× of raw throughput.
- **Type:** incremental polish, high payoff once 3/4 exist.

---

## The buy-vs-build fork (decide before Phase 3)

At the point you want true multi-core bulk throughput, hand-rolled N-TCP bundling is **not
obviously the right build**. The principled alternative is **QUIC / HTTP-3**: native,
*independent* multi-streaming over UDP — no TLS-stream head-of-line blocking *by design*,
which is exactly the problem Phase 3 works around. Re-platforming the data plane on QUIC
could be **less** total work than N-TCP bundling + the operational surface it adds, and
it's where the industry went for this exact reason. Mature off-the-shelf tunnels (frp,
rathole) are the other "don't build it" option. **Evaluate QUIC vs. Phase-3-bundle with
real numbers from Phase 0 in hand — do not pre-commit to the hand-rolled bundle.**

---

## Phase 1 — design (per-stream credit-based flow control)

The fix for the Phase 0 collapse. Replaces the single global `backpressured` flag (one
stalled sink halts the whole tunnel) with **per-stream send windows**, so a slow consumer
only pauses *its own* stream.

**Core invariant:** a sender never has more than `WINDOW` unacked bytes in flight for a
stream → the receiver's per-stream buffer can always hold an incoming frame → **the receiver
never has to stop reading the tunnel** → streams are decoupled.

**Wire change:** one new frame, `TF_WINDOW` (0x14), payload = `u32` BE byte-increment. A
receiver emits it as it drains a stream's buffer to the local sink, granting the sender that
many more bytes of credit. (`TF_DATA`/`TF_OPEN`/`TF_END`/`TF_RESET` unchanged.)

**Per-stream state (both sides — every stream is full-duplex, so each side is both):**
- *receiver:* a **ring buffer** `rbuf` of capacity `FLOW_WINDOW` (malloc'd on OPEN, freed on
  close) + `r_drained` (bytes drained since the last grant, for batching).
- *sender:* `send_credit` (bytes the peer will currently accept).
- Initial credit is implicit at OPEN: both sides start a new stream with `send_credit =
  FLOW_WINDOW` and an empty `rbuf` of the same capacity.

**Sender rules (reading a local source for stream X):**
- Read X's fd only while `send_credit > 0`; each `TF_DATA` of `n` bytes does `send_credit -= n`.
- At `send_credit == 0`, **don't arm EPOLLIN for X's fd** (per-stream source gating) — but keep
  serving every other stream.
- On `TF_WINDOW(X, n)`: `send_credit += n`; re-arm X.

**Receiver rules (`TF_DATA` for stream X):**
- Append to X's `rbuf` (room guaranteed by the invariant).
- Drain `rbuf` to X's fd on POLLOUT; accumulate `r_drained`.
- When `r_drained >= FLOW_WINDOW/2`, send `TF_WINDOW(X, r_drained)` and reset (half-window
  batching, HTTP/2-style — avoids a grant per byte).

**Removed:** the global `backpressured` flag, the gate-scan's `backpressured`, the `maybe_bp`
per-frame scan, and the tunnel-in `!backpressured` gate. The receiver **always** drains the
tunnel; the only remaining stop is `tw`-full (the underlying TCP write buffer is full — real
link backpressure, per-connection, which clears as the peer reads, and the peer always reads).

**Window sizing:** `FLOW_WINDOW` covers the bandwidth-delay product to not regress
single-stream throughput — at the measured 43 Mbit/s and a ~10–30 ms tunnel RTT that's
~64–256 KB. Start at **256 KB** (`#define`, tunable). Memory = `FLOW_WINDOW` × *active* streams
(ring malloc'd per active stream, freed on close) — fine at current concurrency; a lazy/adaptive
ring (start small, grow to window only for bulk streams) is a noted follow-up for the
thousands-of-idle-WS case.

**Deadlock freedom:** window grants are ordinary frames; both sides always drain the tunnel
(no coarse stop), so credit always flows back. The only block is `tw`-full, which the peer's
draining relieves.

**Validation:** full suite + ASan/UBSan, a new `concurrency_throughput` test (N concurrent
bulk streams must now sustain ≈ N×single, not collapse), then re-measure the live path (the
Phase 0 sweep should hold instead of collapsing).

---

## Recommended sequence

1. **Phase 0 (measure the real path)** — cheap; may reveal the WAN is the wall → done.
2. **Phase 1 (per-stream flow control)** — biggest bang, fixes the concrete limitation,
   zero architectural commitment. Do this next regardless of the multi-core question.
3. **Then decide Phase 3 vs. QUIC** with measurements — only commit to the connection-model
   rewrite once a relay *core* is proven to be the bottleneck and the network can carry more.

Throughput math to sanity-check against (rough): a single mTLS link on one core is
crypto-bound at ~0.5–2 Gbit/s (AES-NI minus mux/copy overhead); N links ≈ N× that, capped
by min(relay egress, home uplink). On the current 2-core / 954 MB relay that's ~1–4 Gbit/s
*if* the network path allows — which Phase 0 must confirm.
