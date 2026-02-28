/**
 * claw-vault TypeScript client
 *
 * Fetches credentials from the running claw-vault daemon via Unix socket.
 * Use this when you need to retrieve individual secrets at runtime from
 * within a Node.js process that was NOT started with `claw-vault run`.
 *
 * @example
 * ```typescript
 * import { getSecret, getAllSecrets, isVaultUnlocked } from './vault/vault-client.js';
 *
 * // Check if vault is available
 * if (!(await isVaultUnlocked())) {
 *   console.error('Vault is locked. Run: claw-vault unlock');
 *   process.exit(1);
 * }
 *
 * // Fetch a single secret
 * const token = await getSecret('AUTH_TOKEN');
 *
 * // Or fetch all secrets at once and merge into env
 * const secrets = await getAllSecrets();
 * Object.assign(process.env, secrets);
 * ```
 */

import * as net from 'net';
import * as os from 'os';

// Socket path must match the Python daemon
const uid = typeof process.getuid === 'function' ? process.getuid() : 0;
const SOCKET_PATH = `/tmp/.claw-vault-${uid}.sock`;
const TIMEOUT_MS  = 5_000;

// ── Low-level transport ───────────────────────────────────────────────────────

function sendCommand(cmd: Record<string, unknown>): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(SOCKET_PATH);
    let raw = '';

    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error('claw-vault: connection timed out'));
    }, TIMEOUT_MS);

    socket.on('connect', () => {
      socket.write(JSON.stringify(cmd));
    });

    socket.on('data', (chunk) => {
      raw += chunk.toString('utf8');
    });

    socket.on('end', () => {
      clearTimeout(timer);
      try {
        resolve(JSON.parse(raw) as Record<string, unknown>);
      } catch {
        reject(new Error(`claw-vault: invalid JSON response: ${raw}`));
      }
    });

    socket.on('error', (err) => {
      clearTimeout(timer);
      reject(new Error(`claw-vault: ${err.message} — is the vault unlocked?`));
    });
  });
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Returns true if the claw-vault daemon is running and responsive.
 * Never throws — safe to use as a guard check.
 */
export async function isVaultUnlocked(): Promise<boolean> {
  try {
    const resp = await sendCommand({ cmd: 'ping' });
    return resp['ok'] === true;
  } catch {
    return false;
  }
}

/**
 * Fetch a single credential by name.
 * @throws if the vault is locked or the key does not exist.
 */
export async function getSecret(key: string): Promise<string> {
  const resp = await sendCommand({ cmd: 'get', key });
  if (!resp['ok']) {
    throw new Error(`claw-vault: ${resp['error'] ?? 'unknown error'}`);
  }
  return resp['value'] as string;
}

/**
 * Fetch all stored credentials as a key→value map.
 * @throws if the vault is locked.
 */
export async function getAllSecrets(): Promise<Record<string, string>> {
  const resp = await sendCommand({ cmd: 'all' });
  if (!resp['ok']) {
    throw new Error(`claw-vault: ${resp['error'] ?? 'unknown error'}`);
  }
  return resp['credentials'] as Record<string, string>;
}

/**
 * Fetch all secrets and merge them into process.env.
 * Call this once at application startup (before reading env vars).
 * @throws if the vault is locked.
 */
export async function injectSecretsIntoEnv(): Promise<void> {
  const secrets = await getAllSecrets();
  Object.assign(process.env, secrets);
}

/**
 * List credential names stored in the vault (no values).
 * @throws if the vault is locked.
 */
export async function listSecrets(): Promise<string[]> {
  const resp = await sendCommand({ cmd: 'list' });
  if (!resp['ok']) {
    throw new Error(`claw-vault: ${resp['error'] ?? 'unknown error'}`);
  }
  return resp['keys'] as string[];
}
