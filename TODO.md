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
- [ ] **poll() is O(n) — switch the serve_loop to epoll for high fan-out.** With
      MAX_STREAMS=4096 the single thread works but per-stream RTT grows ~1ms→6ms from 64→
      4000 streams because every poll() rescans all fds. epoll (edge/level) would flatten
      that. Also unlocks raising MAX_STREAMS further. (Throughput stays single-thread-bound
      until/unless the relay shards streams across worker threads.)

## Resolved

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
