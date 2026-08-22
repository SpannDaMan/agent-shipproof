# Privacy

Agent ShipProof is a local, skills-only plugin and dependency-free command-line tool.

## Data handling

- It does not send receipts, commands, files, or validation results over the network.
- It has no telemetry, analytics, advertising, hosted accounts, authentication, or tracking code.
- It does not require API keys or other credentials.
- It reads and writes paths selected by the user on the local machine.

Completion Receipts can intentionally retain command arguments, claims, output excerpts, relative paths, hashes, and local Git metadata. Keep receipts local, inspect and redact them before sharing, and never place credentials or secrets in claims or command arguments.

Host products such as Codex, Claude Code, GitHub, or an operating system have their own terms and telemetry settings. Agent ShipProof does not control or expand them.

For non-sensitive privacy defects, use the repository issue tracker after publication. See [SECURITY.md](SECURITY.md) and [SUPPORT.md](SUPPORT.md).
