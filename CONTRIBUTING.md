# Contributing

Contributions are welcome after the repository is public. Open a focused issue or pull request that explains the behavioral reason, includes a regression test for behavior changes, and updates revision-bound evidence when the release shape changes.

Preserve these invariants:

- Completion Receipt is the artifact name.
- No correctness, security, authorship, identity, authorization, or sandbox claim.
- No shell-mediated command execution.
- No overwrite of an existing receipt or selected symlink.
- No file contents in drift output.
- No HMAC secret in a receipt or command line.

From a Python 3.10+ checkout, run the targeted local checks:

```bash
python -B -m unittest discover -s tests -v
python -B tools/run_evals.py
python -B tools/demo.py
python -B tools/validate_provider_packages.py --json
```

The frozen release gate is maintained separately. Do not claim that a local package check proves hosted installation, provider acceptance, or public availability.
