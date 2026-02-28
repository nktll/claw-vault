#!/usr/bin/env python3
"""
claw-vault — Credential vault for OpenClaw MCP server

Security model:
  • Credentials encrypted with AES-256-GCM using a 256-bit random master key
  • Master key encrypted with Argon2id(password + salt) — never stored in plaintext
  • TOTP (Google Authenticator) required as 2nd factor at every unlock
  • Unlocked master key held only in daemon RAM, never written to disk
  • Daemon accessible via Unix socket at /tmp/.claw-vault-<uid>.sock (mode 0600)
  • Brute-force lockout: 5 failed attempts → 60s lockout

Usage:
  claw-vault init                    Initialize vault & enroll Google Authenticator
  claw-vault add KEY [VALUE]         Add / update a credential
  claw-vault remove KEY              Remove a credential
  claw-vault list                    List stored credential names
  claw-vault unlock                  Unlock vault (password + TOTP → starts daemon)
  claw-vault lock                    Lock vault (wipes master key from RAM)
  claw-vault status                  Show vault lock status
  claw-vault get KEY                 Print a credential value [requires unlocked]
  claw-vault run -- CMD [ARGS]       Run command with all credentials as env vars
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import signal
import socket
import sys
import time
from pathlib import Path
from typing import Dict, Optional

# ── Dependency check ──────────────────────────────────────────────────────────

_MISSING: list[str] = []
try:
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag  # noqa: F401
except ImportError:
    _MISSING.append("cryptography>=42.0")

try:
    import pyotp  # type: ignore
except ImportError:
    _MISSING.append("pyotp>=2.9")

if _MISSING:
    print("❌  Missing dependencies. Install them with:")
    print(f"    pip install {' '.join(_MISSING)}")
    sys.exit(1)

# ── Paths & constants ─────────────────────────────────────────────────────────

_UID = os.getuid() if hasattr(os, "getuid") else 0

VAULT_DIR    = Path.home() / ".claw-vault"
VAULT_FILE   = VAULT_DIR / "vault.json"
SOCKET_PATH  = Path(f"/tmp/.claw-vault-{_UID}.sock")
PID_FILE     = Path(f"/tmp/.claw-vault-{_UID}.pid")
LOCKOUT_FILE = VAULT_DIR / ".lockout"

# Argon2id parameters — OWASP Interactive recommended minimum
_KDF = dict(time_cost=3, memory_cost=65536, parallelism=4, hash_length=32)

MAX_ATTEMPTS    = 5
LOCKOUT_SECONDS = 60

# ── Crypto helpers ────────────────────────────────────────────────────────────

def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from password using Argon2id (64 MB, 3 iterations)."""
    kdf = Argon2id(
        salt=salt,
        length=_KDF["hash_length"],
        iterations=_KDF["time_cost"],
        lanes=_KDF["parallelism"],
        memory_cost=_KDF["memory_cost"],
    )
    return kdf.derive(password.encode("utf-8"))


def _encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """Encrypt with AES-256-GCM. Returns (12-byte nonce, ciphertext+tag)."""
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce, ct


def _decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypt with AES-256-GCM. Raises InvalidTag on wrong key or tampered data."""
    return AESGCM(key).decrypt(nonce, ciphertext, None)


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


# ── Vault file I/O ────────────────────────────────────────────────────────────

def _load_vault() -> dict:
    if not VAULT_FILE.exists():
        print("❌  Vault not initialized. Run: claw-vault init")
        sys.exit(1)
    with open(VAULT_FILE) as f:
        return json.load(f)


def _save_vault(vault: dict) -> None:
    """Atomic write: write to .tmp then rename."""
    VAULT_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = VAULT_FILE.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(vault, f, indent=2)
    tmp.replace(VAULT_FILE)
    os.chmod(VAULT_FILE, 0o600)


# ── Brute-force lockout ───────────────────────────────────────────────────────

def _check_lockout() -> None:
    if not LOCKOUT_FILE.exists():
        return
    try:
        data: dict = json.loads(LOCKOUT_FILE.read_text())
    except Exception:
        LOCKOUT_FILE.unlink(missing_ok=True)
        return
    if data.get("attempts", 0) >= MAX_ATTEMPTS:
        remaining = data.get("lockout_until", 0) - time.time()
        if remaining > 0:
            print(f"🔒  Too many failed attempts. Try again in {int(remaining)}s.")
            sys.exit(1)
        else:
            LOCKOUT_FILE.unlink(missing_ok=True)


def _record_failure() -> None:
    VAULT_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        data: dict = json.loads(LOCKOUT_FILE.read_text()) if LOCKOUT_FILE.exists() else {}
    except Exception:
        data = {}
    attempts = data.get("attempts", 0) + 1
    LOCKOUT_FILE.write_text(json.dumps({
        "attempts": attempts,
        "lockout_until": time.time() + LOCKOUT_SECONDS,
    }))
    remaining = MAX_ATTEMPTS - attempts
    if remaining > 0:
        print(f"   ({remaining} attempt(s) remaining before {LOCKOUT_SECONDS}s lockout)")


def _clear_lockout() -> None:
    LOCKOUT_FILE.unlink(missing_ok=True)


# ── TOTP helpers ──────────────────────────────────────────────────────────────

def _verify_totp(seed: str, code: str) -> bool:
    """Validate a TOTP code with ±1 window tolerance (±30 s clock drift)."""
    return pyotp.TOTP(seed).verify(code.strip(), valid_window=1)


def _provisioning_uri(seed: str) -> str:
    return pyotp.TOTP(seed).provisioning_uri(
        name="openclaw-mcp", issuer_name="claw-vault"
    )


# ── Daemon ────────────────────────────────────────────────────────────────────

class _Daemon:
    """
    Holds the master key in RAM and serves credentials over a Unix socket.

    Protocol: newline-terminated JSON request → JSON response.

    Supported commands:
      {"cmd": "ping"}                     → {"ok": true, "status": "unlocked"}
      {"cmd": "get",  "key": "K"}         → {"ok": true,  "value": "V"}
      {"cmd": "set",  "key": "K", "value": "V"} → {"ok": true}
      {"cmd": "del",  "key": "K"}         → {"ok": true}
      {"cmd": "list"}                     → {"ok": true, "keys": [...]}
      {"cmd": "all"}                      → {"ok": true, "credentials": {...}}
      {"cmd": "lock"}                     → {"ok": true}  (then daemon exits)
    """

    def __init__(self, master_key: bytes, vault: dict) -> None:
        self._key   = master_key
        self._vault = vault   # live in-memory copy (authoritative while unlocked)

    # ── Credential operations ─────────────────────────────────────────────────

    def _names(self) -> list[str]:
        return list(self._vault.get("credentials", {}).keys())

    def _get(self, name: str) -> Optional[str]:
        entry = self._vault.get("credentials", {}).get(name)
        if entry is None:
            return None
        try:
            return _decrypt(self._key, _b64d(entry["nonce"]), _b64d(entry["ciphertext"])).decode("utf-8")
        except Exception:
            return None

    def _set(self, name: str, value: str) -> None:
        nonce, ct = _encrypt(self._key, value.encode("utf-8"))
        self._vault.setdefault("credentials", {})[name] = {
            "nonce": _b64e(nonce),
            "ciphertext": _b64e(ct),
        }
        _save_vault(self._vault)

    def _del(self, name: str) -> bool:
        creds = self._vault.get("credentials", {})
        if name not in creds:
            return False
        del creds[name]
        _save_vault(self._vault)
        return True

    # ── Socket handling ───────────────────────────────────────────────────────

    @staticmethod
    def _recv_all(conn: socket.socket) -> bytes:
        """Read until connection closes (or 1 MB limit)."""
        buf = b""
        conn.settimeout(5.0)
        while True:
            try:
                chunk = conn.recv(8192)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
            if len(buf) > 1_048_576:
                raise ValueError("Request payload too large")
            # Try to parse — stop as soon as we have valid JSON
            try:
                json.loads(buf)
                break
            except json.JSONDecodeError:
                continue
        return buf

    @staticmethod
    def _send(conn: socket.socket, data: dict) -> None:
        conn.sendall(json.dumps(data).encode("utf-8"))

    def _handle(self, conn: socket.socket) -> None:
        try:
            raw = self._recv_all(conn)
            req: dict = json.loads(raw)
            cmd = req.get("cmd", "")

            if cmd == "ping":
                self._send(conn, {"ok": True, "status": "unlocked"})

            elif cmd == "get":
                key = req.get("key", "")
                val = self._get(key)
                if val is None:
                    self._send(conn, {"ok": False, "error": f"Key not found: '{key}'"})
                else:
                    self._send(conn, {"ok": True, "value": val})

            elif cmd == "set":
                key   = req.get("key", "")
                value = req.get("value", "")
                if not key:
                    self._send(conn, {"ok": False, "error": "Missing 'key' field"})
                else:
                    self._set(key, value)
                    self._send(conn, {"ok": True})

            elif cmd == "del":
                key = req.get("key", "")
                if self._del(key):
                    self._send(conn, {"ok": True})
                else:
                    self._send(conn, {"ok": False, "error": f"Key not found: '{key}'"})

            elif cmd == "list":
                self._send(conn, {"ok": True, "keys": self._names()})

            elif cmd == "all":
                creds: Dict[str, str] = {}
                for k in self._names():
                    v = self._get(k)
                    if v is not None:
                        creds[k] = v
                self._send(conn, {"ok": True, "credentials": creds})

            elif cmd == "lock":
                self._send(conn, {"ok": True, "message": "Locking vault"})
                conn.close()
                self._stop()

            else:
                self._send(conn, {"ok": False, "error": f"Unknown command: '{cmd}'"})

        except json.JSONDecodeError:
            try:
                self._send(conn, {"ok": False, "error": "Invalid JSON request"})
            except Exception:
                pass
        except Exception as exc:
            try:
                self._send(conn, {"ok": False, "error": str(exc)})
            except Exception:
                pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def _stop(self) -> None:
        SOCKET_PATH.unlink(missing_ok=True)
        PID_FILE.unlink(missing_ok=True)
        sys.exit(0)

    def run(self) -> None:
        """Start blocking socket server. Runs until lock or signal."""
        SOCKET_PATH.unlink(missing_ok=True)
        PID_FILE.write_text(str(os.getpid()))

        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            srv.bind(str(SOCKET_PATH))
            os.chmod(SOCKET_PATH, 0o600)
            srv.listen(10)
            srv.settimeout(1.0)

            def _sig(sig, frame):
                try:
                    srv.close()
                except Exception:
                    pass
                self._stop()

            signal.signal(signal.SIGTERM, _sig)
            signal.signal(signal.SIGINT,  _sig)
            signal.signal(signal.SIGHUP,  _sig)

            while True:
                try:
                    conn, _ = srv.accept()
                    self._handle(conn)
                except socket.timeout:
                    continue
                except OSError:
                    break
        finally:
            try:
                srv.close()
            except Exception:
                pass
            self._stop()


# ── Client (CLI → daemon) ─────────────────────────────────────────────────────

def _send_cmd(cmd: dict) -> dict:
    """Send a command to the running daemon and return the response."""
    if not SOCKET_PATH.exists():
        print("❌  Vault is locked. Run: claw-vault unlock")
        sys.exit(1)
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(10.0)
        s.connect(str(SOCKET_PATH))
        s.sendall(json.dumps(cmd).encode("utf-8"))
        # Read response
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
        s.close()
        return json.loads(data)
    except (ConnectionRefusedError, FileNotFoundError):
        SOCKET_PATH.unlink(missing_ok=True)
        print("❌  Vault daemon not responding. Run: claw-vault unlock")
        sys.exit(1)
    except json.JSONDecodeError:
        print("❌  Invalid response from daemon.")
        sys.exit(1)


def _is_unlocked() -> bool:
    """Non-fatal check — returns True if daemon is running and healthy."""
    if not SOCKET_PATH.exists():
        return False
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect(str(SOCKET_PATH))
        s.sendall(b'{"cmd":"ping"}')
        buf = b""
        while True:
            chunk = s.recv(256)
            if not chunk:
                break
            buf += chunk
        s.close()
        return json.loads(buf).get("ok", False)
    except Exception:
        return False


# ── Shared unlock logic ───────────────────────────────────────────────────────

def _do_unlock() -> tuple[bytes, dict]:
    """
    Prompt for password + TOTP code, validate both, and return (master_key, vault).
    Enforces lockout on failures. Exits on any auth error.
    """
    _check_lockout()
    vault = _load_vault()

    password = getpass.getpass("🔑  Password: ")
    print("⏳  Deriving key (this takes a moment)…")
    salt       = _b64d(vault["kdf"]["salt"])
    unlock_key = _derive_key(password, salt)

    # Decrypt TOTP seed — this also proves the password is correct
    try:
        blob = vault["totp"]
        totp_seed = _decrypt(
            unlock_key, _b64d(blob["nonce"]), _b64d(blob["ciphertext"])
        ).decode("utf-8")
    except Exception:
        _record_failure()
        print("❌  Wrong password.")
        sys.exit(1)

    # Verify TOTP
    code = input("📱  Google Authenticator code: ").strip()
    if not _verify_totp(totp_seed, code):
        _record_failure()
        print("❌  Invalid TOTP code.")
        sys.exit(1)

    # Decrypt master key
    try:
        blob = vault["master_key"]
        master_key = _decrypt(
            unlock_key, _b64d(blob["nonce"]), _b64d(blob["ciphertext"])
        )
    except Exception:
        _record_failure()
        print("❌  Vault data is corrupted.")
        sys.exit(1)

    _clear_lockout()
    return master_key, vault


# ── CLI commands ──────────────────────────────────────────────────────────────

def _cmd_init(_args: argparse.Namespace) -> None:
    if VAULT_FILE.exists():
        ans = input(
            "⚠️   Vault already exists. Reinitialize?\n"
            "    This will DESTROY all stored credentials. [y/N]: "
        )
        if ans.strip().lower() != "y":
            print("Aborted.")
            return

    print("\n🔐  claw-vault initialization\n" + "─" * 50)

    # Password
    while True:
        pw  = getpass.getpass("Set vault password (strong passphrase recommended): ")
        pw2 = getpass.getpass("Confirm password: ")
        if pw == pw2:
            break
        print("Passwords do not match. Try again.\n")

    print("\n⏳  Generating keys…")
    salt       = os.urandom(32)
    unlock_key = _derive_key(pw, salt)

    # TOTP seed — encrypted with unlock_key
    totp_seed     = pyotp.random_base32()
    t_nonce, t_ct = _encrypt(unlock_key, totp_seed.encode())

    # Master key — 256-bit random, never derived from password
    master_key      = os.urandom(32)
    mk_nonce, mk_ct = _encrypt(unlock_key, master_key)

    vault: dict = {
        "version": 1,
        "kdf": {
            "algorithm": "argon2id",
            "salt": _b64e(salt),
            **_KDF,
        },
        "totp": {
            "nonce":      _b64e(t_nonce),
            "ciphertext": _b64e(t_ct),
        },
        "master_key": {
            "nonce":      _b64e(mk_nonce),
            "ciphertext": _b64e(mk_ct),
        },
        "credentials": {},
    }

    _save_vault(vault)

    # ── Google Authenticator enrollment ──────────────────────────────────────
    uri = _provisioning_uri(totp_seed)
    print("\n" + "─" * 60)
    print("📱  GOOGLE AUTHENTICATOR SETUP")
    print("─" * 60)

    # Try to render a QR code in the terminal
    try:
        import qrcode  # type: ignore
        qr = qrcode.QRCode(border=1)
        qr.add_data(uri)
        qr.make(fit=True)
        qr.print_ascii(invert=True)
        print()
    except ImportError:
        print(f"\nTOTP URI (copy into authenticator app):\n{uri}\n")
        print("Tip: install qrcode[pil] for a terminal QR code.\n")

    print("⚠️   IMPORTANT — Save this manual backup key on paper:")
    print(f"    {totp_seed}")
    print("\n    In Google Authenticator: tap '+' → Enter a setup key")
    print(f"    Account name : openclaw-mcp")
    print(f"    Key          : {totp_seed}")
    print(f"    Type         : Time-based")
    print("─" * 60)

    # Verify enrollment
    input("\nPress Enter after adding the account in Google Authenticator…")
    code = input("Enter the 6-digit code shown to verify: ").strip()
    if not _verify_totp(totp_seed, code):
        print("❌  Code mismatch! The vault has been deleted. Run init again.")
        VAULT_FILE.unlink(missing_ok=True)
        sys.exit(1)

    print("\n✅  Google Authenticator verified!")
    print("\nNext steps:")
    print("  claw-vault add AUTH_TOKEN <value>     # store a credential")
    print("  claw-vault unlock                     # unlock after reboot")
    print("  claw-vault run -- npm run start:http  # start bot with secrets")


def _cmd_add(args: argparse.Namespace) -> None:
    key_name: str = args.key
    value: str    = args.value if args.value else getpass.getpass(f"Value for '{key_name}': ")

    # Prefer daemon path (no re-auth needed)
    if _is_unlocked():
        resp = _send_cmd({"cmd": "set", "key": key_name, "value": value})
        if resp.get("ok"):
            print(f"✅  Credential '{key_name}' saved.")
        else:
            print(f"❌  {resp.get('error')}")
            sys.exit(1)
        return

    # Vault locked — unlock temporarily
    print("🔓  Vault is locked. Unlocking to add credential…")
    master_key, vault = _do_unlock()
    nonce, ct = _encrypt(master_key, value.encode("utf-8"))
    vault.setdefault("credentials", {})[key_name] = {
        "nonce":      _b64e(nonce),
        "ciphertext": _b64e(ct),
    }
    _save_vault(vault)
    print(f"✅  Credential '{key_name}' saved.")


def _cmd_remove(args: argparse.Namespace) -> None:
    key_name: str = args.key
    vault = _load_vault()

    if key_name not in vault.get("credentials", {}):
        print(f"❌  Key '{key_name}' not found.")
        sys.exit(1)

    ans = input(f"Remove '{key_name}'? [y/N]: ")
    if ans.strip().lower() != "y":
        print("Aborted.")
        return

    # Prefer daemon (keeps in-memory state consistent)
    if _is_unlocked():
        resp = _send_cmd({"cmd": "del", "key": key_name})
        if resp.get("ok"):
            print(f"✅  Credential '{key_name}' removed.")
        else:
            print(f"❌  {resp.get('error')}")
            sys.exit(1)
        return

    # Vault locked — we can remove the encrypted blob without the master key
    del vault["credentials"][key_name]
    _save_vault(vault)
    print(f"✅  Credential '{key_name}' removed.")


def _cmd_list(_args: argparse.Namespace) -> None:
    vault = _load_vault()
    keys  = list(vault.get("credentials", {}).keys())
    state = "🔓 UNLOCKED" if _is_unlocked() else "🔒 LOCKED"
    print(f"Vault {state}")
    if keys:
        print(f"\nStored credentials ({len(keys)}):")
        for k in keys:
            print(f"  • {k}")
    else:
        print("\n  (no credentials stored yet)")


def _cmd_unlock(_args: argparse.Namespace) -> None:
    if _is_unlocked():
        print("✅  Vault is already unlocked.")
        return

    master_key, vault = _do_unlock()

    # ── Daemonize ─────────────────────────────────────────────────────────────
    sys.stdout.flush()
    sys.stderr.flush()

    pid = os.fork()

    if pid == 0:
        # ── Child: become daemon ──────────────────────────────────────────────
        os.setsid()

        # Detach stdio
        devnull = os.open(os.devnull, os.O_RDWR)
        for fd in (0, 1, 2):
            try:
                os.close(fd)
            except OSError:
                pass
            os.dup2(devnull, fd)
        if devnull > 2:
            os.close(devnull)

        daemon = _Daemon(master_key, vault)
        daemon.run()
        sys.exit(0)

    else:
        # ── Parent: wait for socket to appear (up to 8 s) ────────────────────
        for _ in range(80):
            time.sleep(0.1)
            if SOCKET_PATH.exists():
                break

        if SOCKET_PATH.exists():
            print(f"✅  Vault unlocked!  Daemon PID: {pid}")
            print(f"\n   Run your bot:  claw-vault run -- npm run start:http")
        else:
            print("❌  Daemon failed to start.")
            sys.exit(1)


def _cmd_lock(_args: argparse.Namespace) -> None:
    if not _is_unlocked():
        print("🔒  Vault is already locked.")
        return
    _send_cmd({"cmd": "lock"})
    time.sleep(0.3)
    print("🔒  Vault locked. Master key wiped from memory.")


def _cmd_status(_args: argparse.Namespace) -> None:
    unlocked = _is_unlocked()
    if unlocked:
        pid  = PID_FILE.read_text().strip() if PID_FILE.exists() else "?"
        keys = list(_load_vault().get("credentials", {}).keys())
        print("🔓  Vault is UNLOCKED")
        print(f"   Daemon PID  : {pid}")
        print(f"   Socket      : {SOCKET_PATH}")
        print(f"   Credentials : {len(keys)}")
    else:
        print("🔒  Vault is LOCKED")
        if VAULT_FILE.exists():
            keys = list(_load_vault().get("credentials", {}).keys())
            print(f"   Stored keys : {len(keys)}")
        else:
            print("   (not initialized — run: claw-vault init)")


def _cmd_get(args: argparse.Namespace) -> None:
    resp = _send_cmd({"cmd": "get", "key": args.key})
    if resp.get("ok"):
        print(resp["value"])
    else:
        print(f"❌  {resp.get('error')}", file=sys.stderr)
        sys.exit(1)


def _cmd_run(args: argparse.Namespace) -> None:
    command: list[str] = args.command

    # Strip the '--' separator that argparse passes through
    if command and command[0] == "--":
        command = command[1:]

    if not command:
        print("❌  No command specified.")
        print("    Example: claw-vault run -- npm run start:http")
        sys.exit(1)

    resp = _send_cmd({"cmd": "all"})
    if not resp.get("ok"):
        print(f"❌  {resp.get('error')}")
        sys.exit(1)

    creds: Dict[str, str] = resp["credentials"]
    env = os.environ.copy()
    env.update(creds)

    print(f"🚀  Injecting {len(creds)} credential(s) → {command[0]}")
    os.execvpe(command[0], command, env)   # replaces current process; no return


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="claw-vault",
        description="🔐  claw-vault — Credential vault for OpenClaw MCP server",
    )
    sub = parser.add_subparsers(dest="cmd", required=True, metavar="COMMAND")

    sub.add_parser("init",   help="Initialize vault & enroll Google Authenticator")

    p_add = sub.add_parser("add", help="Add / update a credential")
    p_add.add_argument("key",           help="Credential name, e.g. AUTH_TOKEN")
    p_add.add_argument("value", nargs="?", help="Value (prompted securely if omitted)")

    p_rm = sub.add_parser("remove", help="Remove a credential")
    p_rm.add_argument("key", help="Credential name")

    sub.add_parser("list",   help="List stored credential names")
    sub.add_parser("unlock", help="Unlock vault (password + TOTP → starts daemon)")
    sub.add_parser("lock",   help="Lock vault and wipe master key from RAM")
    sub.add_parser("status", help="Show vault lock/unlock status")

    p_get = sub.add_parser("get", help="Print a credential value [requires unlocked]")
    p_get.add_argument("key")

    p_run = sub.add_parser(
        "run",
        help="Run a command with credentials injected as environment variables",
    )
    p_run.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Command to run. Separate with --:  claw-vault run -- npm run start:http",
    )

    args = parser.parse_args()

    {
        "init":   _cmd_init,
        "add":    _cmd_add,
        "remove": _cmd_remove,
        "list":   _cmd_list,
        "unlock": _cmd_unlock,
        "lock":   _cmd_lock,
        "status": _cmd_status,
        "get":    _cmd_get,
        "run":    _cmd_run,
    }[args.cmd](args)


if __name__ == "__main__":
    main()
