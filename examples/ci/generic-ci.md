# Generic CI recipe

Install Completion Receipt from the reviewed checkout, run one explicitly approved command, retain the receipt regardless of the command exit, and let the CI platform archive it.

```text
python -m pip install .
shipproof run --root . --receipt completion-receipt.json --claim "Recorded validation command" --include "src/**" --include "tests/**" -- python -m pytest -q
shipproof verify completion-receipt.json --root .
```

Configure the CI runner to archive `completion-receipt.json` in an `always`/post step. Preserve the original `shipproof run` exit code as the job result. The receipt records selected evidence and explicit omissions; it does not authorize the command or certify the build.
