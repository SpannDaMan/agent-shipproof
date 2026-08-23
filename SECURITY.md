# Security policy

Completion Receipts can contain claims, command arguments, output excerpts, branch names, paths, hashes, and other sensitive metadata. Keep them private by default and review/redact them before sharing.

`shipproof run` executes the supplied command with the caller's permissions and is not a sandbox. The default combined stdout/stderr ceiling is 10 MB; lower it for untrusted or noisy commands. Best-effort redaction cannot make a receipt safe to publish.

Do not submit live credentials or proprietary content in a public issue. After the repository is public, report vulnerabilities through GitHub's private security reporting channel when available. Until then, do not disclose sensitive details through public channels.

Security-sensitive changes require negative tests and a threat-model update. Receipts are not correctness proof, security proof, identity proof, signature, certification, or attestation.
