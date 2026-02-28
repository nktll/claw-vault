---
name: claw-vault
description: Manage the claw-vault encrypted credential vault — lock, unlock status, list keys, and guide the user through credential security.
metadata: { "openclaw": { "emoji": "🔐", "always": true, "requires": { "bins": ["claw-vault"] } } }
---

# claw-vault

claw-vault is an encrypted credential vault that keeps API keys off disk. Credentials are stored with AES-256-GCM encryption and only unlocked with a password + Google Authenticator code.

## When to use this skill

Use this skill when the user asks about:
- Vault status (locked/unlocked)
- Locking the vault
- What credentials are stored
- Adding or removing credentials
- Security of their API keys

Do NOT attempt to unlock the vault yourself — unlocking requires the user's password and physical phone (Google Authenticator). Always ask the user to run `claw-vault unlock` themselves.

## Commands

### Check status
```bash
claw-vault status
```
Shows whether the vault is locked or unlocked, daemon PID, and how many credentials are stored.

### List stored credentials (names only, no values)
```bash
claw-vault list
```

### Lock the vault (wipe master key from RAM)
```bash
claw-vault lock
```
Use this if the user wants to secure the vault without rebooting, e.g. when stepping away.

### Add a credential (requires unlocked)
```bash
claw-vault add KEY_NAME
# prompts for value securely — do not pass value as argument on command line
```

### Remove a credential
```bash
claw-vault remove KEY_NAME
```

### Get a credential value (requires unlocked)
```bash
claw-vault get KEY_NAME
```
Only use this if the user explicitly asks to see a credential value.

## What to tell users about unlocking

If the vault is locked and credentials are needed, tell the user:
```
Run this in your terminal, then restart OpenClaw:

  claw-vault unlock

You'll need your vault password and the 6-digit code from Google Authenticator.
```

## Security reminders

- Never suggest storing credentials in plaintext files
- Never suggest passing API keys as command-line arguments (they appear in shell history)
- The vault daemon holds the master key in RAM only — it is wiped on lock or reboot
- `claw-vault unlock` must be run by the user interactively — it cannot be automated
