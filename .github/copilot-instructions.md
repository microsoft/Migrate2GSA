# Copilot instructions — Migrate2GSA

Start with [`AGENTS.md`](../AGENTS.md) for the repository map, conventions, and verification
steps. This repo already ships detailed instruction files under
[`.github/instructions/`](instructions/) — **read those too** (especially
`powershell.instructions.md` and the `conversion-spec-*` files). This file adds high-level
Copilot guardrails.

## What this repo is
A PowerShell module (`Migrate2GSA/`) that converts third-party SSE/ZTNA exports into Entra
Global Secure Access configuration, plus vendor `Samples/`, design `Specs/`, and a Docusaurus
`website/`.

## Working here
- Put public cmdlets in `Migrate2GSA/functions/`, private helpers in `Migrate2GSA/internal/`.
- Keep `Migrate2GSA.psd1` exports and version in sync with added/removed functions.
- Follow `.github/instructions/powershell.instructions.md` for style; follow the
  `conversion-spec-*` instructions when touching conversion logic.
- Validate with `scripts/verify.ps1` (manifest + import + Pester) before pushing; the
  `.githooks/pre-commit.ps1` hook also runs locally.
- Update `website/docs/` for user-facing changes.

## PR guardrails
- Keep PRs scoped to one converter/area; do not mix module changes with website restructuring.
- Never commit secrets, tokens, or real customer/tenant configs (sanitize samples).
- Apply the PR labels and description footer required by
  [`.github/instructions/telemetry.instructions.md`](instructions/telemetry.instructions.md).
