# Security

Private Vault Sync is an experimental single-vault prototype, not production-ready software.

- Use synthetic data or a separately backed-up test vault.
- Do not expose the current server publicly.
- Experimental E2EE protects file contents and names in encrypted mode; it is not independently audited. Legacy test mode is unencrypted. The server still sees size, timing, revision and device metadata, and can roll back or delete data. Keep the recovery key offline or in a password manager. The local plugin configuration holds the key.
- Never publish enrollment codes, device tokens, runtime databases, or real vaults.
- Report suspected vulnerabilities privately to the repository owner. Do not include credentials or personal files in public issues.

Security review, storage quotas, hardened deployment, backup/restore validation and mobile testing are required before production use.
