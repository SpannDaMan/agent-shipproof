---
name: agent-shipproof
description: Use when an approved local command needs a verifiable receipt. Run only that command, record its exit status, selected file hashes, and observed Git state, or verify later path-level drift; never treat the receipt as proof of correctness, security, identity, authorization, or sandboxing.
---

# Completion Receipt

Use this skill when the user wants a reviewable record of what a coding-agent run actually observed.

## Boundary

The product emits a **Completion Receipt**. Never call the receipt an attestation, certification, signature, correctness proof, security proof, identity proof, or sandbox guarantee. The product name does not widen the artifact's evidence claim.

## Workflow

1. Confirm the exact root, command, claims, and include patterns. Never infer authorization for an external or destructive command.
2. Keep secrets out of arguments, claims, command output, and selected artifacts.
3. Run `shipproof run` only for the explicitly authorized command. It executes with the caller's permissions and is not a sandbox; set a conservative timeout and output ceiling.
4. Report the observed command exit, selected artifact count, local Git fields, and receipt digest.
5. For v0.1.1 receipts, review the `observed_evidence` envelope and its explicit omissions before describing coverage.
6. Use `shipproof verify` later to identify added, removed, or changed paths without exposing contents.
7. Treat any integrity mismatch, missing HMAC key, untrusted selection contract, or tool error as non-passing.
8. Stop before sharing or uploading a receipt unless the user separately authorizes it after sensitivity review.

Optional pilot HMAC authentication uses a shared secret supplied through an environment variable. It is not a public-key signature and does not prove who ran the command.
