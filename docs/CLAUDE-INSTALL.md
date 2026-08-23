# Install in Claude Code

Completion Receipt ships as a skills-only Claude Code plugin. It does not install an MCP server, request credentials, or make network calls.

After the repository is public:

```text
/plugin marketplace add SpannDaMan/agent-shipproof
/plugin install agent-shipproof@agent-shipproof
```

Start a new Claude Code session after installation so the current plugin snapshot is loaded.

## Local validation

From the repository root:

```bash
claude plugin validate .
claude plugin marketplace add .
```

The second command is local testing only. A successful local install does not demonstrate Anthropic acceptance, official marketplace listing, or hosted installation.

The bundled CLI is optional:

```bash
python -m pip install .
shipproof --version
```
