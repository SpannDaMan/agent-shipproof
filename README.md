# Completion Receipt

Record what the agent ran.

Use Completion Receipt when you have an approved local command to run and need a verifiable record of what happened. It runs only that command, records its exit status, hashes selected files, captures observed Git state, and later reports added, removed, or changed paths without file contents. Receipt inputs and metadata still need local sensitivity review because redaction is best effort. It is observed evidence, not proof of correctness, security, identity, authorization, or sandboxing.

## Receipt boundary

A Completion Receipt records observable local evidence under a documented construction. It does **not** prove correctness, security, completeness, identity, authorization, authorship, sandboxing, or that a release is safe to ship.

The optional HMAC is shared-secret tamper authentication. It is not a public-key signature, identity proof, or attestation.

The envelope deliberately omits absolute paths, credentials, environment-variable values, identity, authorization, and unselected runtime behavior. A valid v0.1.0 receipt remains verifiable; new v0.1.2 receipts require the envelope.

## Five-minute demo

```bash
python tools/demo.py
```

The demo creates a toy checkout, runs a validation command, writes a receipt, verifies the unchanged checkout, changes one selected file, and verifies again. Drift output names changed relative paths without revealing file contents.

## Create a receipt

`shipproof run` launches the command you supply with the current user's permissions. It does not sandbox, authorize, or make the command safe. Review the command and working directory before running it.

```bash
shipproof run \
  --root . \
  --receipt completion-receipt.json \
  --claim "Unit tests passed" \
  --include "src/**" \
  --include "tests/**" \
  -- python -m unittest discover -s tests -v
```

The command does not use a shell. It exits `0` when the observed command exits `0`, `1` for command failure, timeout, or output-ceiling termination, and `2` for ShipProof input or environment errors. Timeout is recorded as `124`; output-ceiling termination is `125`.

At least one `--claim` and one explicit `--include` are required. This avoids implying coverage for unselected files.

## Verify and show drift

```bash
shipproof verify completion-receipt.json --root .
```

Verification exits `0` when receipt integrity, optional authentication, selected artifacts, and captured Git fields match. It exits `1` for receipt or checkout drift and `2` when verification cannot be performed reliably. Drift output lists only added, removed, and changed relative paths plus changed Git field names.

## Privacy and custody

Claims, command arguments, output excerpts, Git branch names, selected paths, and hashes can be sensitive. Common credential shapes and the local root are redacted from display excerpts, but arbitrary secrets and proprietary values may remain. Keep receipts local, inspect them before sharing, and never put secrets in claims or command arguments.

Full stdout and stderr are represented by hashes and bounded display excerpts; the full streams are not stored in the receipt. SHA-256 values are not anonymization.

## Install

```bash
python -m pip install .
shipproof --version
python tools/demo.py
```

Python 3.10 or later is required. Runtime behavior uses the Python standard library and local Git when available. It has no network, telemetry, provider credential, hosted service, or MCP server.

## Plugins

Completion Receipt is skills-only with a local CLI. The Codex and Claude package instructions are in [Codex installation](docs/CODEX-INSTALL.md), [Claude installation](docs/CLAUDE-INSTALL.md), and the [OpenAI submission packet](docs/OPENAI-PLUGIN-SUBMISSION.md). Local package validation does not prove hosted installation, provider acceptance, or directory publication.

See [Privacy](PRIVACY.md), [Terms](TERMS.md), [Support](SUPPORT.md), [Security](SECURITY.md), and the [release evidence contract](docs/RELEASE-EVIDENCE.md).

For immediately usable CI packaging, see the [GitHub Actions recipe](docs/GITHUB-ACTIONS.md) and [generic CI recipe](examples/ci/generic-ci.md).

## Status

`v0.1.2` is the current private candidate. Publication requires fresh activation, schema, receipt, CI-example, and frozen-candidate validation evidence.

MIT licensed. Public developer display: Orbral.
