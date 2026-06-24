# portico-tunnel — TODO / work log

Backlog and resolved work for the relay↔agent tunnel (the mTLS-multiplexed transport
that exposes a home origin publicly via a cloud relay). Security findings (H/M/L items
referenced in code comments) live in [`SECURITY_REVIEW.md`](SECURITY_REVIEW.md); this
file tracks reliability/feature work.

---

## Capacity & sizing (reference, not a task)

`MAX_STREAMS` (currently **4096**, compile-time, heap-allocated) is a self-imposed cap, ~7×
below the real hardware/OS walls. The ceilings, tightest-relevant-first — **which one binds
depends on whether streams are idle or active:**

- **Agent ephemeral ports — ~28K.** The agent dials cellar at a *fixed* `127.0.0.1:8443`, one
  conn per stream, so each needs a unique source port. `ip_local_port_range` (default
  32768–60999 = **28,232**) caps concurrent agent→cellar conns. Tunable: widen the range
  (→ ~64K) or have cellar listen on extra ports/IPs (each adds another ~28K namespace).
- **Relay RAM — workload-dependent.** Per stream the relay holds 1 public socket + a slot in
  the `MAX_STREAMS` array (16 KB `tobuf`, **lazily committed** — untouched until data flows).
  - *Idle-heavy* (open-but-quiet WS, the realistic SPA case): ~a 4 KB metadata page + small
    kernel socket buffers, tobuf untouched → ~8 KB/stream. The **954 MB Oracle relay fits
    ~28K idle** (≈500 MB) → the agent's 28K ports is the wall.
  - *Active/bulk*: tobuf (16 KB) touched + larger socket buffers → ~30–50 KB/stream → the
    **954 MB relay caps ~10–15K** → the Oracle box is the wall.
  So: **the under-provisioned Oracle relay is the box to grow first**; srvlab (agent) at 64 GB
  is fine. RAM tracks *active* concurrency, not the cap (so a big MAX_STREAMS is cheap until used).
- **File descriptors.** `fs.file-max` is effectively unlimited; the catch is the **soft
  `ulimit -n` = 1024** — services need `LimitNOFILE` raised in their systemd unit to exceed
  ~1024 concurrent (the stress probe raises it itself via setrlimit; the deployed cellar/agent/
  relay units do not yet).
- **Single core.** One serve_loop thread caps aggregate throughput, and the residual
  O(MAX_STREAMS) scans (gate/arm/reap) grow with the cap — epoll fixed the *wakeup* to O(ready)
  but not those. Sharding the relay across worker threads is the lever beyond one core.

To actually scale up: bump `MAX_STREAMS`, raise `LimitNOFILE` on the units, widen
`ip_local_port_range`, **grow the relay VM's RAM**, then thread-shard. Measured headroom today
(`tests/stress_test`, MAX_STREAMS=4096): 4000 concurrent streams at ~1.6 ms RTT, single thread.

---

## Backlog

> The multi-core / high-throughput evolution (and the gate-before-you-build reality check) is
> planned in [`docs/scaling-design.md`](docs/scaling-design.md). Phase 1 (per-stream flow
> control), the lazy ring, window auto-tune, and Phase 2 (the one hot residual scan) are all
> shipped — see Resolved.

- [ ] **Residual scans — Stage A/C (parked).** The reap sweep (the only scan that ran every
      wakeup) is now time-gated (Resolved). The remaining gate + arm scans are syscall-free for
      stable/idle streams, so they only bite at tens-of-thousands of streams on one core — below
      our current port/`MAX_STREAMS` walls. Parked under the same gate as the multi-core work:
      revisit only if a single relay core becomes the *measured* throughput wall (re-measure
      first). Stage C (event-driven arming) carries a silent-hang risk — do it fresh + carefully
      with a high-fanout hang test if ever revisited.

## Resolved

- [x] **Per-stream window auto-tunes to the BDP (#48).** A fixed window can't win — too small
      throttles a fat/high-RTT pipe; too big buffers up to that size for every slow-sink stream
      (a memory cliff). Now each stream starts at `WND_INIT` (256 KB) and grows toward `WND_MAX`
      (8 MB): the sender, when window-limited (source has more but credit hit 0), sends a new
      `TF_WNDREQ`; the receiver doubles that stream's window + grants the extra credit, but ONLY
      while its sink keeps up (ring near-empty) — that gate distinguishes window-limited (grow) from
      sink-limited (don't, bound memory). Short/LAN pipes never grow; fat high-RTT pipes climb to
      their BDP; slow sinks stay small. New `tests/window_autotune_test` (delay bridge gives the
      credit loop a real 100 ms RTT): single download hits 22 MB/s vs the 2.5 MB/s fixed-`WND_INIT`
      floor (≈9× — proves growth). Suite 28/28 + ASan/UBSan. **Protocol change → lockstep deploy.**

- [x] **Lazy / adaptive receive ring (#47).** `a2bd3a4`. The ring no longer mallocs the full
      window per stream at OPEN — it starts at `RING_INIT` (16 KB, one frame) and grows toward the
      stream's current window only as backlog demands, so idle/small streams (thousands of quiet
      WebSockets) cost 16 KB, not the window. Decouples "how many streams" from "how big a window."

- [x] **Time-gate the reap sweep (#39 Stage B).** `bf6bef3`. The O(MAX_STREAMS) reap sweep ran on
      every wakeup; now gated to at most once per `REAP_INTERVAL_MS` (100 ms). Every reap check is
      time-based, so the coarser cadence is harmless. The other residual scans (gate/arm) are
      parked (Backlog) — syscall-free for stable streams, only matter far above current scale.

- [x] **Per-stream credit flow control — fix the concurrent-bulk collapse.** `67d005d`
      (+ `5a4261f` ring clamp). Replaced the global `backpressured` flag with per-stream send
      windows + a receive ring + `TF_WINDOW` grants, so one stalled sink only pauses its own
      stream. Live re-measure: the Phase 0 collapse is gone — N concurrent downloads now scale
      (11→47 Mbit/s as N=1→8) instead of collapsing (was 43→6→~0). Suite 27/27 + ASan; new
      `tests/concurrency_test`. Open: full-duplex bulk (conn-level FC) + the two ring items above.

- [x] **serve_loop poll() → epoll (flatten RTT under high fan-out).** `ad03f04`. poll()
      rebuilt + kernel-rescanned an N-entry set every iteration, so per-stream latency grew
      with total connection count even with one active stream. epoll caches each fd's
      interest (`.ep_armed`, epoll_ctl only on change) and returns just the ready fds.
      Measured (32-core, loopback): 4000-stream RTT 6224µs → 1654µs (3.8×); 64→4000 growth
      6.3× → 3.1×. Suite 26/26, ASan/UBSan clean. Residual O(n) scans tracked under Backlog.
- [x] **MAX_STREAMS 64 → 4096 (heap-allocated).** `85d2cb2`. The per-agent concurrent-stream
      cap was 64 — each live WebSocket pins a stream for its whole session, so ~60 concurrent
      realtime users was the wall regardless of CPU/RAM (the relay idles at ~9 MB / <1 core).
      Raised to 4096; moved the per-conn stream array (16 KB/stream) off the stack to the heap
      so it doesn't blow the thread stack. Stress probe (`tests/stress_test`, 32-core box):
      4000 concurrent streams round-trip OK, ~38k opens/s, RTT 1.0ms@64→6.0ms@4000; single
      full-duplex stream ~50 MB/s (loopback, no TLS). Surfaced the coarse-backpressure limit
      now tracked under Backlog.


- [x] **Heartbeat now detects half-open sessions (field-confirmed outage).** `b90f584`.
      The relay↔agent session wedged every few days in production
      (`portico-test.duckdns.org`): the **data path died while the TCP stayed `ESTAB`**,
      so forwards returned `000` but both ends still reported "connected" (`ss` showed the
      socket, `systemctl` showed active). It alternated sides — once the **agent** (no
      ESTAB at all → needed an agent restart), once the **relay** (agent still connected
      but the forward dead → needed a *relay* restart, after which the agent re-homed onto
      the fresh relay). Two bugs in `src/stream.c serve_loop`:
      1. the `missed` heartbeat counter was reset on every successful tunnel **write**
         ("peer is accepting our bytes → alive"). But a write only means the local send
         buffer accepted bytes; a half-open peer (its TCP ACKs, its app is dead) accepts
         writes forever, so `missed` never climbed and the dead path looked live. → reset
         `missed` **only on inbound bytes** (a PONG / any frame) — the sole proof of life.
      2. `missed` incremented per **poll timeout**, but the poll is clamped to ~250ms by
         the idle-sweep / stop-flag wakes, not `heartbeat_secs` — so once detection worked
         it would have torn down healthy idle tunnels in ~750ms. → gate probes + misses by
         **wall clock** to once per `heartbeat_secs` (intended ~3-interval / ~60s tolerance),
         decoupled from the poll cadence.
      Either side detecting death tears the session down; the existing reconnect machinery
      (agent redials, relay re-accepts) recovers cleanly. Regression: `tests/heartbeat_test.c`
      stands up a relay that registers then goes silent (holds the TLS conn open, never
      PONGs); with the bug the agent hangs forever (1 session), fixed it reconnects. Suite
      26/26.
      - *Follow-up:* the two 60s systemd-timer watchdogs (Oracle restarts `portico-relay`
        on a loopback-SNI `/health` `000`; srvlab restarts `portico-agent` when it holds no
        ESTAB to relay `:7443`) now run only as backup — retire them after ~a week with no
        recurrence.
