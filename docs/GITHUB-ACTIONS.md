# GitHub Actions recipe

This recipe records what a CI agent ran and archives the local Completion Receipt even when the observed command fails. The receipt is evidence of selected observations; it is not a correctness, security, identity, authorization, or supply-chain certification.

```yaml
name: test-with-shipproof

on:
  pull_request:

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m pip install .
      - name: Run tests and create observed evidence
        id: shipproof
        continue-on-error: true
        run: >-
          shipproof run
          --root .
          --receipt completion-receipt.json
          --claim "The selected test command completed with the recorded exit code"
          --include "plugins/**"
          --include "tests/**"
          -- python -m pytest -q
      - name: Verify receipt integrity and selected checkout state
        if: always() && hashFiles('completion-receipt.json') != ''
        run: shipproof verify completion-receipt.json --root .
      - name: Archive receipt
        if: always() && hashFiles('completion-receipt.json') != ''
        uses: actions/upload-artifact@v4
        with:
          name: shipproof-completion-receipt
          path: completion-receipt.json
          if-no-files-found: error
      - name: Preserve observed command failure
        if: steps.shipproof.outcome == 'failure'
        run: exit 1
```

The workflow uses only the checkout, local Python process, local Git metadata, and the CI platform's normal artifact upload. Do not place secrets in claims, command arguments, selected files, or receipt excerpts.
