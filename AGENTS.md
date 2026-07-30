# AGENTS.md — Migrate2GSA

PowerShell module and tooling to **migrate third-party SSE/ZTNA configurations to Microsoft
Entra Global Secure Access** (Private Access / Internet Access). This file is the entry point
for humans and coding agents.

## Repository map
| Path | What lives here |
| --- | --- |
| `Migrate2GSA/` | The PowerShell module: `Migrate2GSA.psd1` (manifest), `Migrate2GSA.psm1`, `functions/` (public), `internal/` (private helpers incl. `internal/functions/**/Test-*.ps1`). |
| `Samples/` | Vendor sample configs (Cisco Umbrella, Citrix, PANW, Zscaler ZIA/ZPA, Forcepoint, NSWG, EIA). |
| `Specs/` | Design/spec markdown (Convert, Export, Provision, Tools, Common). |
| `website/` | Docusaurus documentation site (`docs/`, `blog/`, `docusaurus.config.js`). |
| `.github/agents/` | Custom agent definitions (conversion-spec-eia, conversion-spec-epa, documentation-specialist). |
| `.github/instructions/` | Copilot instruction files (powershell, conversion-spec-*, entra-internet-access). |
| `.github/workflows/`, `.githooks/` | CI and local pre-commit hooks. |
| `.agents/skills/` | Repo skill modules. |

## Conventions
See [`docs/conventions.md`](docs/conventions.md). PowerShell-specific guidance already lives in
[`.github/instructions/powershell.instructions.md`](.github/instructions/powershell.instructions.md).

## Verification / Definition of Done
```powershell
pwsh scripts/verify.ps1
```
`verify.ps1` validates the module manifest (`Test-ModuleManifest`), imports the module, and
runs Pester tests if present. A change is done when `verify.ps1` passes, the pre-commit hook
(`.githooks/pre-commit.ps1`) is satisfied, and docs are updated for user-facing changes.

## PR & work-item telemetry — required
Every PR must follow [`.github/instructions/telemetry.instructions.md`](.github/instructions/telemetry.instructions.md)
(labels + description footer), in addition to the existing `.github/instructions/*` guidance.

## Copilot
See [`.github/copilot-instructions.md`](.github/copilot-instructions.md).
