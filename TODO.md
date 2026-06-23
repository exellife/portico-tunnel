# portico-tunnel — TODO / work log

Backlog and resolved work for the relay↔agent tunnel (the mTLS-multiplexed transport
that exposes a home origin publicly via a cloud relay). Security findings (H/M/L items
referenced in code comments) live in [`SECURITY_REVIEW.md`](SECURITY_REVIEW.md); this
file tracks reliability/feature work.

---

## Backlog

- [ ] **Per-stream (credit-based) flow control — replace coarse global backpressure.**
      Found by `tests/stress_test`: the engine stops reading the tunnel for ALL streams
      whenever ANY one stream's local sink stalls (`backpressured` is a single global flag
      in `serve_loop`). So **K≥2 concurrent full-duplex BULK streams head-of-line-block**
      each other and stall. Fine for small-message / request-response / WS traffic (the
      probe round-trips 4000 concurrent small streams cleanly), but a real ceiling for
      bulk-heavy concurrent workloads. Fix: per-stream send windows / credits so a stalled
      stream only backpressures itself, not the whole tunnel.
- [ ] **Drop the residual O(MAX_STREAMS) per-iteration scans.** After the epoll switch
      (below), the loop still rescans all stream slots three times per iteration: the gate
      computation (`backpressured`/`has_free`/`connecting`), the reap sweep, and the arm
      loop. They're cheap (~µs) but cap how flat the RTT curve can get (epoll cut 64→4000
      growth to 3.1×; these would take it toward ~1×). Fix: maintain counters
      (`n_active`/`n_backpressured`/`n_connecting`) at state transitions for O(1) gates;
      time-gate the reap to run every ~sweep interval; arm interest event-driven (only for
      touched streams + on global tw-room transitions) instead of scanning every iteration.

## Resolved

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
