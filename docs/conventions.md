# Conventions — Migrate2GSA

Observed layout and authoring conventions. Derived from the current structure; update as it
evolves. PowerShell coding style is defined authoritatively in
`.github/instructions/powershell.instructions.md` — this file summarizes structure.

## Layout
- **Module** — `Migrate2GSA/`: `Migrate2GSA.psd1` (manifest), `Migrate2GSA.psm1` (root),
  `functions/` (exported cmdlets), `internal/` (private helpers, including `Test-*` validators).
- **Samples** — `Samples/<Vendor>/` sanitized example inputs.
- **Specs** — `Specs/{Convert,Export,Provision,Tools,Common}/` design docs.
- **Docs site** — `website/` (Docusaurus): author user docs in `website/docs/`.
- **Agent tooling** — `.github/agents/`, `.github/instructions/`, `.agents/skills/`.
- **Automation** — `.github/workflows/` (CI), `.githooks/` (local pre-commit).

## Authoring conventions
- Public function per file in `functions/`; private helpers in `internal/`.
- Keep the module manifest (`.psd1`) function exports and version current.
- Sanitize all `Samples/` — no real tenant IDs, IPs, users, or secrets.
- Update `website/docs/` alongside user-facing changes.

## Validation
Run `pwsh scripts/verify.ps1`: validates the manifest with `Test-ModuleManifest`, imports the
module, and runs Pester tests when present.
