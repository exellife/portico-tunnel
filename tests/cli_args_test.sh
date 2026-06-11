#!/usr/bin/env bash
# L2/L3: the CLI must reject malformed numeric args and host:port specs up front
# (strtol + range, proper [IPv6]:port parsing) instead of silently truncating with
# atoi() or mis-splitting on the last colon. No certs/network needed — these all
# exit before binding.
set -u
BIN="${1:?usage: cli_args_test.sh <portico-tunnel binary>}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"

ok=0; fail=0
# expect: run BIN with given args, assert exit code is 2 AND stderr matches a regex.
reject() { local desc="$1" want="$2"; shift 2
  local out rc
  out="$("$BIN" "$@" 2>&1)"; rc=$?
  if [ "$rc" -eq 2 ] && grep -qE "$want" <<<"$out"; then echo "  ok    $desc"; ok=$((ok+1))
  else echo "  FAIL  $desc (rc=$rc out='$out')"; fail=$((fail+1)); fi; }
# expect: parse ACCEPTED — fails later for a different reason, never the parse error.
accept_parse() { local desc="$1" notwant="$2"; shift 2
  local out; out="$("$BIN" "$@" 2>&1)"
  if grep -qE "$notwant" <<<"$out"; then echo "  FAIL  $desc (rejected: '$out')"; fail=$((fail+1))
  else echo "  ok    $desc"; ok=$((ok+1)); fi; }

echo "== CLI arg hardening (L2/L3) =="

# L2: numeric args
reject "--control-port out of range (70000)" "invalid value"  --relay --control-port 70000 --cert x --key y --client-ca z --tcp 22
reject "--control-port non-numeric (abc)"    "invalid value"  --relay --control-port abc   --cert x --key y --client-ca z --tcp 22
reject "--tcp trailing junk (22junk)"        "invalid value"  --relay --cert x --key y --client-ca z --tcp 22junk
reject "--tcp zero"                          "invalid value"  --relay --cert x --key y --client-ca z --tcp 0
reject "--hb negative"                       "invalid value"  --agent --hb -5 --relay-addr h:1 --cert x --key y --forward 127.0.0.1:22

# L3: host:port
reject "bare IPv6 --forward (ambiguous)"     "bad --forward"  --agent --relay-addr h:1 --cert x --key y --forward fd00::5
reject "--forward empty port"               "bad --forward"  --agent --relay-addr h:1 --cert x --key y --forward 127.0.0.1:
reject "--forward bracketed port out of range" "bad --forward" --agent --relay-addr h:1 --cert x --key y --forward '[::1]:70000'
# incomplete on purpose: the forward must PARSE (no "bad --forward"); the run then stops at
# the missing-required-args check instead of dialing.
accept_parse "bracketed IPv6 --forward parses" "bad --forward" --agent --forward '[::1]:22'

echo
if [ "$fail" -eq 0 ]; then echo "PASS  ($ok ok, 0 failed)"; else echo "FAIL  ($ok ok, $fail failed)"; fi
[ "$fail" -eq 0 ]
