# claw-vault

**Keep your OpenClaw API keys off disk. Unlock with a password + Google Authenticator.**

---

## How it works in practice

After setup, this is all you do after a VPS reboot:

```bash
./start-openclaw.sh
```

That's it. It prompts for your password and a 6-digit code from Google Authenticator, then starts OpenClaw with all credentials injected. When you stop it — credentials are wiped from disk again.

**At rest, your `openclaw.json` looks like this:**

```json
{
  "channels": {
    "telegram": { "botToken": "" }
  },
  "skills": {
    "entries": {
      "notion": { "apiKey": "" }
    }
  }
}
```

Empty strings. Anyone who steals your disk, snapshot, or backup gets nothing.

---

## Why this exists

OpenClaw stores API keys in plaintext in `~/.openclaw/openclaw.json`. Security researchers found **30,000+ exposed instances** in a 12-day scan (Feb 2026), and **7.1% of ClawHub skills** leak credentials. The official recommendation is `chmod 600` — but that doesn't help if someone takes a backup or snapshot of your VPS.

This has been [requested](https://github.com/openclaw/openclaw/issues/7916) [multiple](https://github.com/openclaw/openclaw/issues/11829) [times](https://github.com/openclaw/openclaw/discussions/9676) with no built-in solution. claw-vault fills that gap.

---

## Setup (one time)

**1. Install the core vault**

```bash
pip install claw-vault
```

**2. Install the OpenClaw plugin**

```bash
openclaw plugins install openclaw-plugin-claw-vault
```

This registers the plugin so OpenClaw automatically injects credentials at startup and strips them on exit. It also gives the agent a built-in skill to manage the vault (`claw-vault status`, `claw-vault lock`, etc.).

**3. Initialize the vault**

```bash
claw-vault init
```

Sets your passphrase and shows a QR code — scan it with Google Authenticator.

**4. Store your credentials**

```bash
claw-vault add GEMINI_API_KEY        # prompts securely, nothing shown on screen
claw-vault add TELEGRAM_TOKEN
claw-vault add GATEWAY_AUTH_TOKEN
claw-vault add NOTION_API_TOKEN
claw-vault add OPENAI_API_KEY
```

**5. Strip plaintext from openclaw.json**

```bash
python3 inject_openclaw.py strip
```

Done. Your keys are now encrypted in `~/.claw-vault/vault.json` and gone from `openclaw.json`.

> **Without the plugin (manual mode):** skip step 2 and use `./start-openclaw.sh` to start OpenClaw — it handles inject/strip via a wrapper script instead.

---

## Daily use

**With the plugin installed**, just unlock the vault before starting OpenClaw:

```bash
claw-vault unlock      # password + Google Authenticator code
openclaw start         # plugin handles inject/strip automatically
```

**Without the plugin:**

```bash
./start-openclaw.sh          # unlock + inject + start agent
./start-openclaw.sh mcp      # unlock + inject + start MCP HTTP server
```

The vault stays unlocked in the background — OpenClaw can restart freely without re-authenticating. Only a full reboot requires unlocking again.

---

## What's protected

| Scenario | Safe? |
|---|---|
| Someone steals your disk or VPS backup | ✅ Encrypted blobs, useless without password + phone |
| Filesystem access while vault is locked | ✅ Full protection |
| Another process on the same machine | ✅ Vault socket is owner-only (`0600`) |
| Full root access while vault is unlocked | ⚠️ No software vault can protect against this |

---

## Custom mappings

The default mapping covers standard OpenClaw credentials. To add your own, create `~/.claw-vault/openclaw-map.json`:

```json
{
  "SLACK_TOKEN":   ["channels", "slack", "botToken"],
  "DISCORD_TOKEN": ["channels", "discord", "botToken"]
}
```

Custom entries are merged with the defaults.

---

## All commands

```bash
claw-vault init               # first-time setup
claw-vault add KEY [VALUE]    # store a credential
claw-vault remove KEY         # delete a credential
claw-vault list               # show stored key names
claw-vault unlock             # password + TOTP → start daemon
claw-vault lock               # wipe master key from RAM
claw-vault status             # locked / unlocked?
claw-vault get KEY            # print a value (requires unlocked)
claw-vault run -- COMMAND     # run any command with credentials as env vars
```

---

## Node.js / TypeScript client

```typescript
import { getSecret, getAllSecrets } from './vault-client.js';

const token = await getSecret('TELEGRAM_TOKEN');
// or load everything into process.env:
Object.assign(process.env, await getAllSecrets());
```

---

<details>
<summary>Security & cryptographic details</summary>

- **Cipher:** AES-256-GCM — authenticated encryption, detects tampering
- **KDF:** Argon2id — 64 MB memory, 3 iterations, 4 lanes (OWASP Interactive minimum)
- **Master key:** 256-bit random, never derived from password, RAM-only while unlocked
- **TOTP:** RFC 6238, ±30s clock drift tolerance
- **Writes:** atomic (`rename`-based) — no partial state on disk
- **Brute-force:** 5 failures → 60s lockout

The TOTP seed and master key are both encrypted in `~/.claw-vault/vault.json` alongside your credentials. Backing up that file is safe — it's useless without your passphrase and phone.

</details>

---

## Contributing

Issues and PRs welcome. See [open issues](https://github.com/nktll/claw-vault/issues).

---

## License

MIT
