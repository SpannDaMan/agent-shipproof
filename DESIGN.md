# Completion Receipt design contract

Status: private candidate visual authority

## Product idea

Completion Receipt turns a run into an inspectable trail. The visual identity is a receipt ribbon passing through two content-addressed nodes—evidence in, evidence out—without seals, medals, signatures, or certification imagery.

## Mark

Use a folded receipt ribbon with a clipped lower edge. Three small square hash nodes sit on the receipt; an electric-cyan evidence path connects the first and last inside a deep-navy and signal-blue structure. The silhouette must remain legible at 32 pixels.

Avoid shields, badges, gavels, wax seals, certificates, checkmark medals, fingerprints, chains, locks, and anything that implies legal proof or identity attestation.

## Tokens

- Deep navy: `#06235D`
- Signal blue: `#0183E0`
- Electric cyan: `#09CEFC`
- Cloud white: `#F8FAFC`
- Slate: `#64748B`
- Primary type: Inter, ui-sans-serif, system-ui, sans-serif
- Mono type: IBM Plex Mono, ui-monospace, monospace
- Card radius: 14px
- Control radius: 9px

## Plugin page

- Icon: receipt ribbon and three nodes; no text.
- Screenshot: left side shows `captured` and the payload digest; right side shows an unchanged pass followed by one changed path. The non-claim remains visible.
- Social preview: mark left, “Receipts for what actually ran.” right, one compact `changed: src/app.py` card.

## Accessibility

Verification state uses words and symbols, not color alone. Body contrast is at least 4.5:1. Digest strings use a mono face and wrap rather than overflow.

## Asset authority

- Canonical source: `plugins/agent-shipproof/assets/Agent ShipProof Agent Smith Palette Master 210826.png`.
- Route and immutable hash: `plugins/agent-shipproof/assets/Logo Generation Manifest 140826.json`.
- Delivery PNGs are deterministic resize or layout derivatives that place the source without local geometry creation.
- The candidate carries no production SVG reconstruction.

## Copy boundary

Always call the artifact a **Completion Receipt**. Never use “attestation,” “certified,” “cryptographic proof,” “signed by the agent,” or “guaranteed correct.”
