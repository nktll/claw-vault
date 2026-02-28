#!/usr/bin/env python3
"""
inject_openclaw.py — Patch / strip sensitive values in openclaw.json via claw-vault.

Usage:
  inject_openclaw.py inject   # read from vault → write real values into openclaw.json
  inject_openclaw.py strip    # remove real values from openclaw.json (back to template)

Default vault key → openclaw.json path mapping:
  GEMINI_API_KEY     → agents.defaults.memorySearch.remote.apiKey
  TELEGRAM_TOKEN     → channels.telegram.botToken
  GATEWAY_AUTH_TOKEN → gateway.auth.token
  NOTION_API_TOKEN   → skills.entries.notion.apiKey

Custom mapping:
  Create ~/.claw-vault/openclaw-map.json to override or extend the defaults:

  {
    "MY_CUSTOM_KEY": ["path", "in", "openclaw", "json"],
    "SLACK_TOKEN":   ["channels", "slack", "botToken"]
  }
"""

from __future__ import annotations

import json
import os
import socket
import sys
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────

OPENCLAW_JSON  = Path(os.environ.get("OPENCLAW_CONFIG", Path.home() / ".openclaw" / "openclaw.json"))
VAULT_MAP_FILE = Path.home() / ".claw-vault" / "openclaw-map.json"
SOCKET_PATH    = Path(f"/tmp/.claw-vault-{os.getuid()}.sock")

# Default vault key → nested JSON path mapping
DEFAULT_VAULT_MAP: dict[str, list[str]] = {
    "GEMINI_API_KEY":     ["agents", "defaults", "memorySearch", "remote", "apiKey"],
    "TELEGRAM_TOKEN":     ["channels", "telegram", "botToken"],
    "GATEWAY_AUTH_TOKEN": ["gateway", "auth", "token"],
    "NOTION_API_TOKEN":   ["skills", "entries", "notion", "apiKey"],
}


def _load_vault_map() -> dict[str, list[str]]:
    """Load mapping from ~/.claw-vault/openclaw-map.json, falling back to defaults."""
    if VAULT_MAP_FILE.exists():
        try:
            custom = json.loads(VAULT_MAP_FILE.read_text())
            merged = {**DEFAULT_VAULT_MAP, **custom}
            return merged
        except Exception as e:
            print(f"⚠️   Could not read {VAULT_MAP_FILE}: {e} — using defaults")
    return DEFAULT_VAULT_MAP


# ── Vault client ──────────────────────────────────────────────────────────────

def _vault_get(key: str) -> str | None:
    """Fetch a single secret from the running claw-vault daemon. Returns None if not found."""
    if not SOCKET_PATH.exists():
        print("❌  claw-vault is locked. Run: claw-vault unlock")
        sys.exit(1)
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect(str(SOCKET_PATH))
        s.sendall(json.dumps({"cmd": "get", "key": key}).encode())
        buf = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        s.close()
        resp = json.loads(buf)
        if not resp.get("ok"):
            return None  # key not in vault — skip silently
        return resp["value"]
    except (ConnectionRefusedError, FileNotFoundError):
        print("❌  claw-vault daemon not responding. Run: claw-vault unlock")
        sys.exit(1)


# ── JSON helpers ──────────────────────────────────────────────────────────────

def _nested_set(obj: dict, path: list[str], value: str) -> None:
    for key in path[:-1]:
        obj = obj.setdefault(key, {})
    obj[path[-1]] = value


def _nested_get(obj: dict, path: list[str]) -> str | None:
    for key in path[:-1]:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key, {})
    return obj.get(path[-1]) if isinstance(obj, dict) else None


# ── Commands ──────────────────────────────────────────────────────────────────

def cmd_inject() -> None:
    """Read values from vault and write them into openclaw.json."""
    if not OPENCLAW_JSON.exists():
        print(f"❌  Not found: {OPENCLAW_JSON}")
        print(f"    Set OPENCLAW_CONFIG env var if your config is elsewhere.")
        sys.exit(1)

    vault_map = _load_vault_map()

    with open(OPENCLAW_JSON) as f:
        config = json.load(f)

    patched = 0
    skipped = 0
    for vault_key, json_path in vault_map.items():
        value = _vault_get(vault_key)
        if value is None:
            skipped += 1
            continue
        _nested_set(config, json_path, value)
        patched += 1
        print(f"   ✓ {vault_key} → {'.'.join(json_path)}")

    if skipped:
        print(f"   ℹ️   Skipped {skipped} key(s) not found in vault")

    tmp = OPENCLAW_JSON.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(config, f, indent=2)
    tmp.replace(OPENCLAW_JSON)
    os.chmod(OPENCLAW_JSON, 0o600)

    print(f"\n✅  Injected {patched} credential(s) into {OPENCLAW_JSON}")


def cmd_strip() -> None:
    """Remove sensitive values from openclaw.json (replace with empty strings)."""
    if not OPENCLAW_JSON.exists():
        print(f"❌  Not found: {OPENCLAW_JSON}")
        sys.exit(1)

    vault_map = _load_vault_map()

    with open(OPENCLAW_JSON) as f:
        config = json.load(f)

    stripped = 0
    for vault_key, json_path in vault_map.items():
        current = _nested_get(config, json_path)
        if current:
            _nested_set(config, json_path, "")
            stripped += 1
            print(f"   ✓ cleared {'.'.join(json_path)}")

    tmp = OPENCLAW_JSON.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(config, f, indent=2)
    tmp.replace(OPENCLAW_JSON)
    os.chmod(OPENCLAW_JSON, 0o600)

    if stripped:
        print(f"\n🔒  Stripped {stripped} credential(s) from {OPENCLAW_JSON}")
    else:
        print("ℹ️   Already stripped — nothing to do.")


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in ("inject", "strip"):
        print(__doc__)
        print("Usage: inject_openclaw.py inject|strip")
        sys.exit(1)

    if sys.argv[1] == "inject":
        cmd_inject()
    else:
        cmd_strip()


if __name__ == "__main__":
    main()
