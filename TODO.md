# portico-tunnel — TODO / work log

Backlog and resolved work for the relay↔agent tunnel (the mTLS-multiplexed transport
that exposes a home origin publicly via a cloud relay). Security findings (H/M/L items
referenced in code comments) live in [`SECURITY_REVIEW.md`](SECURITY_REVIEW.md); this
file tracks reliability/feature work.

---

## Resolved

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
