#!/usr/bin/env bash
# Part of proxy-filter localtest — see ./README.md
#
# Stops the localtest mitmdump process. Does NOT touch the WireGuard
# tunnel itself (toggle that off in the WireGuard app).

set -euo pipefail

PID_FILE="/tmp/proxy-filter-localtest.pid"

# Kill any mitmdump in WireGuard mode (covers strays from earlier runs)
pkill -f "mitmdump.*--mode.*wireguard" 2>/dev/null || true

# Kill the cat-pipeline subshell if it's still around
if [[ -f "$PID_FILE" ]]; then
  PID="$(cat "$PID_FILE")"
  if kill -0 "$PID" 2>/dev/null; then
    kill "$PID" 2>/dev/null || true
  fi
  rm -f "$PID_FILE"
fi

# Belt-and-suspenders: kill the cat process feeding our log
pkill -f "cat$" 2>/dev/null || true

echo "Stopped."
echo
echo "Don't forget to toggle the WireGuard tunnel off in the WireGuard app,"
echo "or your Mac will lose internet (the tunnel still tries to route through"
echo "the now-stopped proxy)."
