# Threat model

## Protected outcome

Create a reviewable record that binds declared claims to observed local command results, selected file hashes, and local Git state, then identify later drift.

## Covered risks

- A receipt body changed after capture.
- A selected file added, removed, or changed.
- Captured Git identity or working-state fields changed.
- A receipt overwritten silently.
- A selected symlink escaping the intended file set.
- A tool or command failure presented as a clean verification.
- Common credential shapes or absolute workstation roots echoed in bounded output excerpts.
- A shared-secret authentication tag accepted under the wrong key.
- A receipt path escaping the declared root.
- Unbounded receipt excerpts or routine command output exhausting temporary storage during the pilot.

## Out of scope

- Correctness, completeness, security, safety, authorship, identity, intent, authorization, or sandboxing.
- Proving that the observed command was itself trustworthy or sufficient.
- Capturing an atomic filesystem snapshot while another process edits the tree.
- Defending against a compromised interpreter, operating system, Git executable, command, scanner, or HMAC key holder.
- Public-key signatures, timestamp authorities, hardware-backed keys, or remote attestation.
- Comprehensive secret detection or safe public disclosure of a receipt.
- File contents outside the explicit include patterns or inside excluded patterns.
- Full stdout/stderr custody; only hashes and bounded redacted excerpts are stored.
- Perfect output-ceiling precision. The process is polled, so operating-system buffering can produce a small captured-byte overshoot before termination.

The default unsigned receipt detects accidental or ordinary tampering only when a trusted copy of the stored payload digest or receipt exists. Anyone able to replace both body and digest can create a self-consistent unsigned receipt. Optional pilot HMAC authentication improves shared-secret tamper detection but does not prove who created the receipt.
