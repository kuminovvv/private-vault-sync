# Security

Private Vault Sync is an experimental single-vault prototype, not production-ready software.

- Use synthetic data or a separately backed-up test vault.
- Do not expose the current server publicly.
- The current protocol does not provide end-to-end encryption. The server can read file contents and metadata.
- Never publish enrollment codes, device tokens, runtime databases, or real vaults.
- Report suspected vulnerabilities privately to the repository owner. Do not include credentials or personal files in public issues.

Security review, storage quotas, hardened deployment, backup/restore validation and mobile testing are required before production use.
