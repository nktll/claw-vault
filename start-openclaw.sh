#!/usr/bin/env bash
# start-openclaw.sh — Unlock vault, inject credentials, start openclaw, strip on exit.
#
# Usage:
#   ./start-openclaw.sh              # start openclaw agent (default)
#   ./start-openclaw.sh mcp          # start MCP HTTP server instead
#
# Environment variables:
#   OPENCLAW_MCP_DIR   Path to openclaw-mcp project (default: ~/openclaw-mcp)
#   OPENCLAW_CONFIG    Path to openclaw.json (default: ~/.openclaw/openclaw.json)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INJECT="python3 $SCRIPT_DIR/inject_openclaw.py"
OPENCLAW_MCP_DIR="${OPENCLAW_MCP_DIR:-$HOME/openclaw-mcp}"

# ── Ensure vault is unlocked ──────────────────────────────────────────────────
if ! claw-vault status 2>/dev/null | grep -q "UNLOCKED"; then
    echo "🔑  Vault is locked — unlocking first…"
    claw-vault unlock
fi

# ── Inject credentials into openclaw.json ────────────────────────────────────
echo ""
echo "🔓  Injecting credentials into openclaw.json…"
$INJECT inject

# ── Register cleanup trap (strip on exit, Ctrl+C, kill, etc.) ────────────────
cleanup() {
    echo ""
    echo "🔒  Stripping credentials from openclaw.json…"
    $INJECT strip || true
}
trap cleanup EXIT INT TERM HUP

# ── Start the requested process ───────────────────────────────────────────────
MODE="${1:-openclaw}"

echo ""
case "$MODE" in
    mcp)
        echo "🚀  Starting MCP HTTP server…"
        cd "$OPENCLAW_MCP_DIR"
        claw-vault run -- npm run start:http
        ;;
    openclaw)
        echo "🚀  Starting openclaw agent…"
        exec openclaw start
        ;;
    *)
        echo "❌  Unknown mode: $MODE"
        echo "    Usage: $0 [openclaw|mcp]"
        exit 1
        ;;
esac
