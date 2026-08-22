# Completion Receipt contract

Schema version `1.0` binds:

- declared claim text labeled `declared_not_semantically_verified`;
- displayed command arguments plus a digest of the exact argv byte sequence;
- shell-free command execution, observed exit code, timeout state, output-ceiling state, and duration;
- hashes and bounded redacted excerpts for stdout and stderr;
- explicit include/exclude patterns;
- the selected artifact manifest with relative path, bytes, and SHA-256;
- local Git HEAD, branch, normalized status digest, and dirty-entry count when Git is available;
- a canonical body SHA-256;
- optional pilot HMAC authentication.

Canonicalization is UTF-8 JSON with sorted keys and compact separators. The `integrity` object is excluded from the canonical body it describes. Pilot HMAC input is domain-separated as `agent-shipproof-pilot-hmac-v1`, then binds the key ID and canonical body. A supplied verification key cannot silently accept an unsigned receipt.

Verification first checks receipt integrity and optional authentication. It never trusts a changed receipt to choose file paths. Only after the receipt itself passes does verification re-evaluate its selection and report file or Git drift.

No hash or authentication tag establishes semantic correctness, authorization, authorship, or safe disclosure.

`shipproof run` executes the caller-supplied argv with the caller's operating-system permissions. It is not a sandbox. Timeout uses observed code `124` on every platform; combined stdout/stderr ceiling termination uses `125`. The default ceiling is 10 MB, while each display excerpt is bounded to 4 KB. A small operating-system buffering overshoot may be captured before termination and is represented in the byte counts and hashes.
