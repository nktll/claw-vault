# claw-vault

**Encrypted credential vault with TOTP (Google Authenticator) unlock for self-hosted [OpenClaw](https://github.com/openclaw/openclaw) deployments.**

If you run OpenClaw on a VPS, your API keys (Gemini, Telegram, Notion, OpenAI, etc.) are stored in plaintext inside `~/.openclaw/openclaw.json`. Anyone who gains access to your server — through a backup, snapshot, directory traversal, or a compromised process — can steal all of them instantly.

claw-vault solves this.

---

## The problem

OpenClaw stores credentials in plaintext ([issue #7916](https://github.com/openclaw/openclaw/issues/7916), [issue #11829](https://github.com/openclaw/openclaw/issues/11829), [discussion #9676](https://github.com/openclaw/openclaw/discussions/9676)):

```json
{
  "channels": {
    "telegram": { "botToken": "8576904436:AAHz..." }
  },
  "skills": {
    "entries": {
      "notion": { "apiKey": "ntn_26765..." }
    }
  }
}
```

Security researchers found **30,000+ exposed OpenClaw instances** in a 12-day scan (Feb 2026), and **7.1% of ClawHub marketplace skills** leak credentials. The official docs recommend `chmod 600` — necessary, but not sufficient if someone accesses your disk or takes a backup.

---

## How claw-vault works

```
At rest (vault locked):
  ~/.openclaw/openclaw.json  →  all API key fields are empty strings
  ~/.claw-vault/vault.json   →  AES-256-GCM encrypted blob  ← useless without password + phone

After unlock (vault open):
  Password + Google Authenticator code
       │
       ▼
  Argon2id KDF  →  unlock key  →  decrypts master key (in RAM only)
                                       │
                                       ▼
                              inject_openclaw.py patches openclaw.json
                              with real values just-in-time

On exit / lock:
  inject_openclaw.py strips values back out  →  openclaw.json is clean again
```

**What's encrypted:** everything in `~/.claw-vault/vault.json` — your credentials, the master key, and the TOTP seed — using AES-256-GCM with a 256-bit random master key.

**What's in RAM only:** the decrypted master key, held by a background daemon process. Never written to disk.

**TOTP role:** Google Authenticator acts as a gate — you must provide a valid 6-digit code on every unlock. The code is verified cryptographically (TOTP seed is itself encrypted in the vault).

---

## Security model

| Threat | Protected? |
|---|---|
| Attacker steals disk / backup copy | ✅ Encrypted blobs only — useless without password + phone |
| Attacker reads filesystem while vault is **locked** | ✅ Full protection |
| Non-root process on same machine while **unlocked** | ✅ Unix socket is `0600`, root-only |
| Attacker gets **root shell** while unlocked | ⚠️ Can query vault socket or dump RAM — true of all software vaults |

No software-only solution protects against a live root compromise. claw-vault protects your most realistic threat: **at-rest theft of credentials from disk, backups, and snapshots**.

---

## Requirements

- Linux (uses `os.fork`, Unix sockets)
- Python 3.11+
- OpenClaw installed and configured at `~/.openclaw/`

---

## Installation

```bash
# 1. Clone
git clone https://github.com/nktll/claw-vault
cd claw-vault

# 2. Install
pip install -e .

# 3. Verify
claw-vault --help
```

Or install directly without cloning:

```bash
pip install claw-vault
```

---

## Quick start

### Step 1 — Initialize the vault

```bash
claw-vault init
```

This will:
- Ask you to set a strong passphrase
- Generate a TOTP secret and show a QR code — **scan it with Google Authenticator**
- Write the vault to `~/.claw-vault/vault.json` (encrypted, safe to back up)

### Step 2 — Store your credentials

```bash
claw-vault add GEMINI_API_KEY        # prompts for value securely
claw-vault add TELEGRAM_TOKEN
claw-vault add GATEWAY_AUTH_TOKEN
claw-vault add NOTION_API_TOKEN
claw-vault add OPENAI_API_KEY
```

### Step 3 — Strip plaintext from openclaw.json

```bash
python3 inject_openclaw.py strip
```

Your `openclaw.json` now has empty strings for all API key fields. Safe at rest.

### Step 4 — Start OpenClaw via claw-vault

```bash
./start-openclaw.sh
```

This will:
1. Unlock the vault (prompts password + Google Authenticator code)
2. Inject credentials into `openclaw.json` just-in-time
3. Start OpenClaw
4. Strip credentials back out on exit (Ctrl+C, kill, crash)

---

## Daily workflow

After every VPS reboot:

```bash
# Option A — everything in one command:
./start-openclaw.sh

# Option B — manual steps:
claw-vault unlock                    # password + Google Authenticator
python3 inject_openclaw.py inject    # patch openclaw.json
openclaw start                       # start agent
```

The vault daemon runs in the background. OpenClaw can restart freely without re-unlocking — only a full reboot or `claw-vault lock` requires re-authentication.

---

## MCP HTTP server

If you use the OpenClaw MCP HTTP server:

```bash
./start-openclaw.sh mcp
# or
claw-vault unlock
claw-vault run -- npm run start:http   # injects all vault keys as env vars
```

---

## Custom credential mapping

By default, claw-vault maps these vault keys to `openclaw.json` paths:

| Vault key | openclaw.json path |
|---|---|
| `GEMINI_API_KEY` | `agents.defaults.memorySearch.remote.apiKey` |
| `TELEGRAM_TOKEN` | `channels.telegram.botToken` |
| `GATEWAY_AUTH_TOKEN` | `gateway.auth.token` |
| `NOTION_API_TOKEN` | `skills.entries.notion.apiKey` |

To add or override mappings, create `~/.claw-vault/openclaw-map.json`:

```json
{
  "SLACK_TOKEN":    ["channels", "slack", "botToken"],
  "DISCORD_TOKEN":  ["channels", "discord", "botToken"],
  "MY_CUSTOM_KEY":  ["skills", "entries", "myskill", "apiKey"]
}
```

Custom mappings are merged with the defaults.

---

## All CLI commands

```bash
claw-vault init                    # Set up vault, enroll Google Authenticator
claw-vault add KEY [VALUE]         # Add / update a credential
claw-vault remove KEY              # Remove a credential
claw-vault list                    # List stored credential names
claw-vault get KEY                 # Print a credential value (vault must be unlocked)
claw-vault unlock                  # Unlock vault (password + TOTP → starts daemon)
claw-vault lock                    # Lock vault, wipe master key from RAM
claw-vault status                  # Show lock status and stored key count
claw-vault run -- COMMAND          # Run any command with credentials as env vars
```

---

## TypeScript / Node.js client

For Node.js processes that need to fetch secrets at runtime (not just at startup via env vars):

```typescript
import { getSecret, getAllSecrets, isVaultUnlocked } from './vault-client.js';

if (!(await isVaultUnlocked())) {
  console.error('Run: claw-vault unlock');
  process.exit(1);
}

const token = await getSecret('TELEGRAM_TOKEN');
// or inject everything into process.env:
const secrets = await getAllSecrets();
Object.assign(process.env, secrets);
```

---

## Vault file structure

```
~/.claw-vault/
└── vault.json        # Everything encrypted — safe to back up, useless without password + phone
```

```json
{
  "version": 1,
  "kdf": {
    "algorithm": "argon2id",
    "salt": "<32 random bytes, base64>",
    "time_cost": 3,
    "memory_cost": 65536,
    "parallelism": 4
  },
  "totp": {
    "nonce": "...",
    "ciphertext": "..."
  },
  "master_key": {
    "nonce": "...",
    "ciphertext": "..."
  },
  "credentials": {
    "GEMINI_API_KEY": { "nonce": "...", "ciphertext": "..." },
    "TELEGRAM_TOKEN": { "nonce": "...", "ciphertext": "..." }
  }
}
```

---

## Cryptographic details

- **Cipher:** AES-256-GCM (authenticated encryption — detects tampering)
- **KDF:** Argon2id — 64 MB memory, 3 iterations, 4 lanes (OWASP Interactive minimum)
- **Master key:** 256-bit random, never derived from password
- **TOTP:** RFC 6238, ±30 second clock drift tolerance, verified via pyotp
- **Writes:** atomic (write to `.tmp`, then `rename`) — no partial state on disk
- **Brute-force protection:** 5 failed attempts → 60-second lockout

---

## Contributing

Issues and PRs welcome. See [open issues](https://github.com/nktll/claw-vault/issues).

Related upstream OpenClaw issues this project addresses:
- [#7916 — Support for encrypted API keys / secrets management](https://github.com/openclaw/openclaw/issues/7916)
- [#11829 — Security Roadmap: Protecting API Keys from Agent Access](https://github.com/openclaw/openclaw/issues/11829)
- [#9676 — RFC: Agent-Blind Credential Architecture](https://github.com/openclaw/openclaw/discussions/9676)

---

## License

MIT
