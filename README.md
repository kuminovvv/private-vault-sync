# Private Vault Sync

[![CI](https://github.com/kuminovvv/private-vault-sync/actions/workflows/ci.yml/badge.svg)](https://github.com/kuminovvv/private-vault-sync/actions/workflows/ci.yml)
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)

A self-hosted synchronization prototype for Obsidian, with a Rust server and a TypeScript plugin. The goal is simple device pairing and resilient transfers over unstable connections, without a separate desktop synchronization app.

> **Experimental (0.2.0 plugin).** This is not a production-ready replacement for Obsidian Sync. Use a test vault and keep independent backups. No end-to-end encryption yet. Not affiliated with Obsidian.

## Features

- Content-addressed 1 MiB blocks and SHA-256 validation on both ends.
- Missing-block negotiation, retries and a persistent partial-download cache.
- Parallel workers: three on desktop, two on mobile; progress, bytes and average speed.
- Authenticated WebSocket notifications, reconnect with backoff and polling fallback.
- One-time enrollment codes, pairing links and locally generated QR codes.
- Device listing and revocation; server stores token hashes.
- Revision checks, retained history and restoration; conflicting versions are not silently overwritten.
- Optional deletion propagation, disabled by default, with tombstones, history, local trash and explicit approval for batches of more than ten queued deletions.

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
5. In the plugin settings, enter the loopback server address and the enrollment code. Additional devices can use a pairing link or QR code after installing the plugin and opening the intended vault.

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

- End-to-end encryption, with secure key management and recovery.
- Full settings sync, directory renames and text conflict merging.
- Storage quota validation, garbage collection, tested backup/restore and security review.
- Memory-efficient streaming of large files, especially on mobile.
- Real Obsidian desktop and Android/iOS testing, then hardened self-hosted deployment.

## Current limitations

Single-vault prototype. Files up to 512 MiB; the plugin can allocate whole files in memory. No end-to-end encryption: the server can read contents, filenames and metadata. The GUI smoke test fixture exists but real GUI integration and mobile testing have not been completed. Do not make the server publicly accessible or use it as the sole copy of important data.

See [SECURITY.md](SECURITY.md). Licensed under [MIT](LICENSE).


## Isolated deployment pilot

The Dockerfile and deploy/compose.test.yaml are intended for synthetic data only. The container has no published ports, runs without root, and uses a separate persistent data directory. The prototype enforces a block storage quota, a concurrent request limit, a body size limit and request timeout. These are not a substitute for a full security audit or a complete disk quota. Restrict pilot access at the reverse proxy, use HTTPS, and never connect the sole copy of a real vault. Set SYNC_PROXY_NETWORK to an existing dedicated proxy network; initialize deploy/data with owner UID/GID 10001. See the existing local tests for validation.