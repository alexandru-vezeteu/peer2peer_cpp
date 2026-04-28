#!/bin/sh
# Generates per-node test files in /testfiles, then execs the p2p daemon.
set -e

NODE_ID="${NODE_ID:-00}"
mkdir -p /testfiles

# ── Small text file ───────────────────────────────────────────────────────────
cat > /testfiles/hello.txt << EOF
Hello from node-${NODE_ID}!

This plaintext file was created at container startup.
Send it to a peer with:  /file <n> /testfiles/hello.txt
EOF

# ── JSON profile ──────────────────────────────────────────────────────────────
cat > /testfiles/profile.json << EOF
{
  "node_id": "${NODE_ID}",
  "listen_port": "90${NODE_ID}",
  "description": "P2P encrypted peer node ${NODE_ID}",
  "capabilities": ["ed25519-auth", "x25519-kex", "chacha20poly1305", "chunked-transfer"],
  "started_at": "$(date +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

# ── Large text file (~40 KB) — forces multi-chunk transfer ────────────────────
{
  printf "=== Node %s log dump ===\n\n" "${NODE_ID}"
  i=1
  while [ $i -le 500 ]; do
    printf "Line %04d | node=%s | msg=The quick brown fox jumps over the lazy dog. Entry %d.\n" \
           "$i" "${NODE_ID}" "$i"
    i=$((i + 1))
  done
} > /testfiles/large.txt

# ── Binary file (100 KB random) — tests binary-safe chunked transfer ──────────
openssl rand -out /testfiles/data.bin 102400

printf "[node-%s] test files ready in /testfiles:\n" "${NODE_ID}"
ls -lh /testfiles/

exec /app/p2p "$@"
