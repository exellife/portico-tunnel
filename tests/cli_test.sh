#!/usr/bin/env bash
# Integration smoke for the runnable binary: start `portico-tunnel --relay` and
# `--agent` (with openssl-minted mTLS certs), forward a TCP port to a local echo
# server, and push bytes through  client -> relay -> tunnel -> agent -> echo -> back.
# Self-skips if openssl or python3 is missing.
set -u
BIN="${1:?usage: cli_test.sh <portico-tunnel binary>}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"   # absolute (we cd into a tmpdir)

command -v openssl >/dev/null 2>&1 || { echo "cli: SKIPPED (no openssl)"; exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "cli: SKIPPED (no python3)"; exit 0; }

TMP="$(mktemp -d)"
RELAY_PID=""; AGENT_PID=""; ECHO_PID=""
cleanup() { for p in "$AGENT_PID" "$RELAY_PID" "$ECHO_PID"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done; wait 2>/dev/null; rm -rf "$TMP"; }
trap cleanup EXIT

cd "$TMP"
gen() { openssl ecparam -genkey -name prime256v1 -out "$1" 2>/dev/null; }

# CA + server (SAN localhost) + client certs
gen ca.key
openssl req -new -x509 -key ca.key -out ca.crt -days 1 -subj "/CN=tunnelCA" 2>/dev/null
gen s.key
openssl req -new -key s.key -out s.csr -subj "/CN=localhost" 2>/dev/null
openssl x509 -req -in s.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out s.crt -days 1 \
    -extfile <(printf "subjectAltName=DNS:localhost") 2>/dev/null
gen c.key
openssl req -new -key c.key -out c.csr -subj "/CN=agent" 2>/dev/null
openssl x509 -req -in c.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out c.crt -days 1 2>/dev/null

# echo server on an ephemeral port (prints the port on stdout)
cat > echo.py <<'PY'
import socket, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 0)); s.listen(8)
print(s.getsockname()[1], flush=True)
def handle(c):
    while True:
        d = c.recv(4096)
        if not d: break
        c.sendall(d)
    c.close()
while True:
    c, _ = s.accept(); threading.Thread(target=handle, args=(c,), daemon=True).start()
PY
python3 echo.py > echoport.txt & ECHO_PID=$!
for _ in $(seq 1 50); do [ -s echoport.txt ] && break; sleep 0.1; done
EPORT="$(cat echoport.txt)"
[ -n "$EPORT" ] || { echo "FAIL: echo server didn't start"; exit 1; }

CTRL=$(( 20000 + (RANDOM % 20000) ))
FWD=$(( CTRL + 1 ))

"$BIN" --relay --control-port "$CTRL" --cert s.crt --key s.key --client-ca ca.crt \
       --tcp "$FWD" >relay.log 2>&1 & RELAY_PID=$!
sleep 0.4
"$BIN" --agent --relay-addr "localhost:$CTRL" --ca ca.crt --cert c.crt --key c.key \
       --id smoke --forward "127.0.0.1:$EPORT" >agent.log 2>&1 & AGENT_PID=$!

# give the agent time to dial + register
sleep 1.2

# push bytes through the forwarded port
cat > client.py <<'PY'
import socket, sys
p = int(sys.argv[1])
c = socket.create_connection(('127.0.0.1', p), timeout=5)
c.sendall(b'hello-portico-tunnel')
data = b''
while len(data) < 20:
    d = c.recv(4096)
    if not d: break
    data += d
sys.stdout.write(data.decode(errors='replace'))
PY
OUT="$(python3 client.py "$FWD" 2>/dev/null)"

if [ "$OUT" = "hello-portico-tunnel" ]; then
    echo "cli: PASS (client -> relay -> tunnel -> agent -> echo -> back)"
    exit 0
fi
echo "cli: FAIL (got '$OUT')"
echo "--- relay.log ---"; cat relay.log
echo "--- agent.log ---"; cat agent.log
exit 1
