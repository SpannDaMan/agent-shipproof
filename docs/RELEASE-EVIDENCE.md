# Release Evidence Contract

Completion Receipt binds generated release evidence to a non-self-referential product revision.

## Product revision digest

The product file set includes regular candidate files except files under `validation/`, Git metadata, build output, caches, bytecode, virtual environments, distribution output, and packaging residue. Symlinks are forbidden by the release validator.

For each included file, sort by POSIX-style relative path and append this UTF-8 record:

```text
relative_path<TAB>byte_count<TAB>file_sha256<LF>
```

The SHA-256 of the complete record sequence is `product_revision_sha256`. Generated receipts live under `validation/`, so writing a current receipt does not alter the product revision it names.

## Required binding

Eval, package, Codex-plugin, Claude-plugin, OpenAI-submission, cross-platform packaging, and composite receipts must name the exact current `product_revision_sha256`. The final composite validator rejects stale, malformed, private-data-bearing, or mismatched receipts.

This binding identifies product bytes named by a receipt. It does not prove semantic correctness, security, identity, authorization, sandboxing, hosted behavior, adoption, or market demand.
