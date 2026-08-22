# Release checklist

- [ ] Unit and adversarial tests pass.
- [ ] Create/verify/tamper demo passes.
- [ ] Receipt integrity, HMAC failure modes, selected-symlink rejection, and content-free drift output remain covered.
- [ ] Transparent master and all five derivatives pass alpha, dimensions, hash, and safe-fill QA.
- [ ] Public-bound text has no private routes, conversation URLs, workstation paths, credentials, or generated residue.
- [ ] Codex and Claude manifests match the skills-only public metadata.
- [ ] OpenAI submission data has five positive and three negative cases.
- [ ] Fresh eval, package, Codex, Claude, submission-data, and cross-platform packaging receipts bind to the frozen revision.
- [ ] One final composite release gate passes on the frozen bytes.
- [ ] Clean standalone export, hosted CI, public install, and provider submissions are completed by the owning release lane.

The final gate and every external action are intentionally outside this local implementation pass.
