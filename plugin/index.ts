/**
 * openclaw-plugin-claw-vault
 *
 * Integrates claw-vault into the OpenClaw lifecycle:
 *   - start()  → checks if vault is unlocked, injects credentials into openclaw.json
 *   - stop()   → strips credentials from openclaw.json
 *
 * The agent also gets a bundled skill (./skills/SKILL.md) teaching it how to
 * interact with the vault (lock, status, list, etc.).
 */

import { spawnSync } from "child_process";
import { existsSync } from "fs";
import { homedir } from "os";
import { join, resolve } from "path";

// ── Types (subset of openclaw plugin-sdk) ─────────────────────────────────────

interface PluginConfig {
  autoInject?: boolean;
  autoStrip?:  boolean;
  injectScript?: string;
}

interface ServiceApi {
  registerService(opts: {
    id:    string;
    start: () => Promise<void>;
    stop:  () => Promise<void>;
  }): void;
  log: {
    info:  (msg: string) => void;
    warn:  (msg: string) => void;
    error: (msg: string) => void;
  };
  config: PluginConfig;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const UID = typeof process.getuid === "function" ? process.getuid() : 0;
const VAULT_SOCKET = `/tmp/.claw-vault-${UID}.sock`;

function isVaultUnlocked(): boolean {
  return existsSync(VAULT_SOCKET);
}

/**
 * Find inject_openclaw.py — checks next to this file first,
 * then the plugin install directory, then PATH fallback.
 */
function findInjectScript(configuredPath?: string): string | null {
  if (configuredPath) {
    const p = resolve(configuredPath.replace("~", homedir()));
    return existsSync(p) ? p : null;
  }

  const candidates = [
    join(__dirname, "..", "inject_openclaw.py"),             // dev: repo root
    join(homedir(), ".openclaw/extensions/claw-vault/inject_openclaw.py"), // installed
    join(__dirname, "inject_openclaw.py"),                    // same dir
  ];

  for (const p of candidates) {
    if (existsSync(p)) return p;
  }
  return null;
}

function runInjectScript(scriptPath: string, mode: "inject" | "strip", log: ServiceApi["log"]): void {
  const result = spawnSync("python3", [scriptPath, mode], {
    encoding: "utf8",
    timeout: 10_000,
  });

  if (result.stdout) {
    for (const line of result.stdout.trim().split("\n")) {
      log.info(`[claw-vault] ${line}`);
    }
  }

  if (result.status !== 0) {
    const err = result.stderr?.trim() || "unknown error";
    log.warn(`[claw-vault] ${mode} exited with code ${result.status}: ${err}`);
  }
}

// ── Plugin entry point ────────────────────────────────────────────────────────

export default function register(api: ServiceApi): void {
  const cfg: PluginConfig = api.config ?? {};
  const autoInject = cfg.autoInject !== false;  // default true
  const autoStrip  = cfg.autoStrip  !== false;  // default true

  api.registerService({
    id: "claw-vault",

    async start() {
      if (!autoInject) {
        api.log.info("[claw-vault] autoInject disabled — skipping");
        return;
      }

      if (!isVaultUnlocked()) {
        api.log.warn(
          "[claw-vault] Vault is LOCKED — credentials not injected. " +
          "Run `claw-vault unlock` then restart OpenClaw, or ask the agent to unlock."
        );
        return;
      }

      const scriptPath = findInjectScript(cfg.injectScript);
      if (!scriptPath) {
        api.log.warn(
          "[claw-vault] inject_openclaw.py not found. " +
          "Set plugins.entries.claw-vault.config.injectScript in openclaw.json."
        );
        return;
      }

      api.log.info("[claw-vault] Vault unlocked — injecting credentials into openclaw.json…");
      runInjectScript(scriptPath, "inject", api.log);
    },

    async stop() {
      if (!autoStrip) return;

      const scriptPath = findInjectScript(cfg.injectScript);
      if (!scriptPath) return;

      api.log.info("[claw-vault] Stripping credentials from openclaw.json…");
      runInjectScript(scriptPath, "strip", api.log);
    },
  });
}
