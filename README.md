# Private Vault Sync

[![CI](https://github.com/kuminovvv/private-vault-sync/actions/workflows/ci.yml/badge.svg)](https://github.com/kuminovvv/private-vault-sync/actions/workflows/ci.yml)
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)

A self-hosted synchronization prototype for Obsidian, with a Rust server and a TypeScript plugin. The goal is simple device pairing and resilient transfers over unstable connections, without a separate desktop synchronization app.

> **Experimental (0.4.0).** This is not a production-ready replacement for Obsidian Sync. Use a test vault and keep independent backups. Encrypted mode is implemented but has not been independently audited. Not affiliated with Obsidian.

## Features

- Content-addressed 1 MiB blocks and SHA-256 validation on both ends.
- Missing-block negotiation, retries and a persistent partial-download cache.
- Parallel workers: three on desktop, two on mobile; progress, bytes and average speed.
- Authenticated WebSocket notifications, reconnect with backoff and polling fallback.
- One-time enrollment codes, pairing links and locally generated QR codes.
- Device listing and revocation; server stores token hashes.
- Revision checks, retained history and restoration; conflicting versions are not silently overwritten.
- Optional deletion propagation, disabled by default, with tombstones, history, local trash and explicit approval for batches of more than ten queued deletions.
- Files are enumerated through the vault storage adapter, including extensions not indexed by Obsidian. Hidden folders and configuration are excluded.
- Verified snapshots and offline recovery into a new directory; restored devices must enroll again.

## Install the beta plugin

Download the ZIP from the [Releases page](https://github.com/kuminovvv/private-vault-sync/releases), extract it into your vault's `.obsidian/plugins/private-vault-sync/`, then enable Private Vault Sync under Community plugins. On Android, use a file manager that can display hidden folders. There is no separate sync application. Keep the original vault and a separate backup until you have verified a complete round trip on two devices.

For a new, empty store, the administrator enables the temporary loopback-only setup listener using `deploy/compose.owner-setup.yaml` and an authenticated SSH local forward. Never publish the administrative port or proxy its routes. Configure the first plugin with the public HTTPS origin as `server` and `setupServer`, and the local forwarded origin as `setupUrl`. Open its settings, choose a username and a strong passphrase (at least 16 characters), and select **Create account**. On other devices install the plugin and sign in with the same server, username and passphrase. The QR code pre-fills the address and username but does not carry credentials. The random vault key is automatically wrapped and recovered on the client. After owner setup remove the temporary listener and SSH forward. Existing nonempty legacy stores are not migrated automatically.

Account protocol: scrypt (N=131072, r=8, p=1) with a random 256-bit salt, HKDF-SHA-256 domain separation, AES-256-GCM-SIV key wrapping. The server receives a derived authentication value, not the passphrase, and stores its hash and the encrypted vault-key envelope. A weak passphrase is vulnerable to offline guessing if the database is stolen; use a password manager. There is no password reset or account recovery without the original passphrase and a usable backup. This protocol is experimental, not independently audited. The setup listener is disabled by default; initialization is atomic and is refused once a store is occupied. Only the public status and login routes should be exposed through HTTPS.

## Architecture

Obsidian plugin (TypeScript) ⇄ HTTP API + WebSocket ⇄ Rust / Axum ⇄ SQLite metadata + content-addressed blocks.

The current server binds to loopback by default. The client permits plain HTTP only for loopback tests; remote deployment requires HTTPS and additional hardening.

## Local development

Requirements: Rust stable, Node.js 24, npm, Obsidian for manual UI testing.

1. Build and start the server:

   ```sh
   cd server
   cargo build --locked
   cargo run --locked
   ```

   Default address: `http://127.0.0.1:8877`. Default data directory: `server/data` when launched from the server directory.

2. Generate an initial enrollment code in another terminal in the same directory:

   ```sh
   cargo run --locked -- pair
   ```

   The code expires in ten minutes and can only be redeemed once. Keep it private.

3. Build the plugin from the repository root:

   ```sh
   cd plugin
   npm ci
   npm run build
   ```

4. Copy `plugin/main.js` and `plugin/manifest.json` into `.obsidian/plugins/private-vault-sync/` within a separate test vault. Enable Private Vault Sync in Obsidian's community plugins.
5. In the plugin settings, enter the loopback server address, enrollment code and recovery key. Generate a random recovery key on the first device only and store it in a password manager. Additional devices can use a pairing link or QR code and enter the same key separately.

Never run two sync engines on the same vault at the same time.

## Tests

Run after building the server and plugin, from the repository root:

```sh
# Linux / macOS
node tests/integration.mjs ./server/target/debug/private-sync
node tests/client.mjs ./server/target/debug/private-sync
```

```powershell
# Windows
node tests/integration.mjs .\server\target\debug\private-sync.exe
node tests/client.mjs .\server\target\debug\private-sync.exe
```

The API suite verifies authorization, resume after restart, integrity, revisions, deletion/history and WebSocket events. The client suite runs the compiled plugin against a filesystem-backed Obsidian API test double. It checks interrupted downloads, cache reuse, edits, trash, restore and conflicts.

A local stress test transferred 800 MiB of synthetic attachments in both directions and checked file hashes. This is not a WAN speed benchmark or proof of real mobile compatibility.

## Roadmap

- Independent cryptographic review, improved key management and recovery UX.
- Full settings sync, directory renames and text conflict merging.
- Storage quota validation, garbage collection, tested backup/restore and security review.
- Memory-efficient streaming of large files, especially on mobile.
- Real Obsidian desktop and Android/iOS testing, then hardened self-hosted deployment.

## Current limitations

Single-vault prototype. Files up to 512 MiB; the plugin can allocate whole files in memory. New connections require a random recovery key; the legacy test mode does not encrypt data. Encrypted deployments reveal file sizes, equality within a context, revision metadata, devices and access patterns. They do not defend against server rollback or deletion. The GUI smoke test fixture exists but real GUI integration and mobile testing have not been completed. Do not make the server publicly accessible or use it as the sole copy of important data.

See [SECURITY.md](SECURITY.md). Licensed under [MIT](LICENSE).


## Isolated deployment pilot

The Dockerfile and deploy/compose.test.yaml are intended for synthetic data only. The container has no published ports, runs without root, and uses a separate persistent data directory. The prototype enforces a block storage quota, a concurrent request limit, a body size limit and request timeout. These are not a substitute for a full security audit or a complete disk quota. Restrict pilot access at the reverse proxy, use HTTPS, and never connect the sole copy of a real vault. Set SYNC_PROXY_NETWORK to an existing dedicated proxy network; initialize deploy/data with owner UID/GID 10001. See the existing local tests for validation.

## Backup and recovery

Use Python 3.11+ on the server. A snapshot captures consistent SQLite metadata and copies all referenced immutable blocks, verifying SHA-256 checksums. Run `python3 deploy/backup.py snapshot --data deploy/data --backups backups --keep 7`. Verify a snapshot with `python3 deploy/backup.py verify --snapshot backups/<timestamp>`. Restore with `python3 deploy/backup.py restore --snapshot backups/<timestamp> --target restored-data`. The target must not exist. Never overwrite an active store; stop the server and follow an offline migration procedure. Restored stores require re-enrollment, and the recovery key remains necessary. Keep additional off-host backups.

## Experimental encrypted protocol (v1)

The client uses AES-256-GCM-SIV (RFC 8452) via @noble/ciphers, HKDF-SHA-256 with separate keys for path encryption, content encryption and nonce derivation, and a random 256-bit recovery key. Deterministic keyed nonces allow retransmission of identical encrypted blocks without re-uploading them. Encrypted blocks are bound to the file path, index and count; an encrypted whole-file digest rejects mixed-version blocks. The server receives encrypted names and encrypted content, not the recovery key. It still observes ciphertext sizes, equality within a context, revisions and access patterns. The protocol does not authenticate server history or prevent rollback, deletion or denial of service. Local notes and the plugin's local configuration (including the recovery key) are not encrypted at rest by this plugin.

The encrypted-only pilot requires a fresh compatible data directory, uses SYNC_ENCRYPTED_ONLY=1, rejects legacy clients, and prevents updates/deletion of the key-check marker. This compatibility gate does not prove that arbitrary clients encrypt their payloads. Never migrate an unencrypted database in place or reuse a recovery key for unrelated vaults. Loss of the recovery key means loss of access to encrypted data. There is no server-side reset or recovery. Retain independent backups and do not treat this prototype as audited software.

Run the encrypted integration suite with SYNC_TEST_ENCRYPTED=1 and SYNC_TEST_FILES=12 (environment variables) using tests/client.mjs and the compiled server. CI runs both encrypted and legacy suites.
