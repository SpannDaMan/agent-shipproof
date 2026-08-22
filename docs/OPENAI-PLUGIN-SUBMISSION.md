# OpenAI Plugin Submission Packet

Agent ShipProof is prepared as a skills-only plugin. It has no MCP server, UI, authentication, credentials, network access, telemetry, or hosted data storage.

## Local package

- Plugin root: `plugins/agent-shipproof`
- OpenAI/Codex manifest: `plugins/agent-shipproof/.codex-plugin/plugin.json`
- Skill: `plugins/agent-shipproof/skills/agent-shipproof/SKILL.md`
- Local CLI: `plugins/agent-shipproof/scripts/shipproof.py`
- Public submission data: `submission/openai-plugin-submission.json`

## Submission prerequisites

Before a root-owned submission:

1. Freeze the candidate and pass the final composite release gate.
2. Publish the reviewed repository under `SpannDaMan/agent-shipproof` through the owning release lane.
3. Confirm public website, support, privacy, and terms URLs resolve.
4. Complete any provider-required publisher verification without changing credentials, scopes, or permissions from this package.
5. Upload the final skills-only archive and inspect its manifest.
6. Run the five positive and three negative cases in `submission/openai-plugin-submission.json`.

OpenAI review and directory publication are external actions. A valid local package is not review approval or public availability.
