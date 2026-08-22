# Install in Codex

Agent ShipProof is a skills-only Codex plugin with a bundled local CLI. It does not install an MCP server, request credentials, or make network calls.

From a local checkout:

```bash
python -m pip install .
shipproof --version
python tools/demo.py
```

After the repository is public, use the marketplace flow supplied by the repository host:

```text
codex plugin marketplace add SpannDaMan/agent-shipproof
codex plugin add agent-shipproof@agent-shipproof
```

Start a new Codex session after installation so the plugin snapshot is loaded. Local validation does not prove hosted installation, provider acceptance, or listing publication.
