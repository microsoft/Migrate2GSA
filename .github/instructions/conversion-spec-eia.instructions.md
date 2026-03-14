---
applyTo: 'Specs/Convert/*2EIA*'
description: 'Common patterns and rules for writing Entra Internet Access (EIA) conversion specs'
---

# EIA Conversion Spec Guidelines

These guidelines apply to specs that convert third-party web security products to Entra Internet Access (EIA). They do NOT apply to Entra Private Access (EPA) conversions — EPA has a different policy model and separate conventions.

## Spec Structure

Every EIA conversion spec must include these sections in order:

1. **Document Information** — Version, Date, Status, Target Module, Function Name, Author
2. **Overview** — Purpose, Design Alignment
3. **Source Product Model** — Describe the source product's policy hierarchy and config structure
4. **EIA Target Structure** — How source objects map to EIA policies, rules, and security profiles
5. **Policy & Rule Naming Conventions** — Naming table mapping source constructs to EIA `PolicyName` and `RuleName` formats
6. **Input File Structures** — Each input file, its fields, and processing rules
7. **Output Files** — Always 3 outputs: Policies CSV, Security Profiles CSV, Log file
8. **Processing Logic** — Phased: Load → Validate → Process/Transform → Export
9. **Function Interface** — Parameters, types, defaults, validation

## Core Conversion Rules

### Include/Exclude Filtering

Every conversion function MUST support policy name filtering via parameters:
- `IncludePolicyName` (`string[]`, default `$null`) — wildcard patterns (`-like`) to include. Only matching policies are processed.
- `ExcludePolicyName` (`string[]`, default `$null`) — wildcard patterns to exclude. Exclude wins when both match.
- Both are case-insensitive.

### Policies for All Users → Default Security Profile

Source policies that apply to all users (no user/group scoping) must be converted to:
- Web content filtering policies (with `Block` or `Allow` action) containing the appropriate rules
- Linked to a **Default Security Profile** with a high priority number (e.g., 50000) — high number = low precedence
- Assigned to all users via a Conditional Access policy targeting a placeholder group (e.g., `"All Internet Access Users"`)

### Policies for Specific Users/Groups → Override Security Profiles

Source policies scoped to specific users or groups must be converted to:
- Web content filtering policies linked to **Override Security Profiles** with lower priority numbers (e.g., starting at 1000) — lower number = higher precedence = evaluated first
- Policies targeting the **same set of users/groups** must be combined into the **same Security Profile** and assigned via a single CA policy
- Each Override Security Profile gets its own Conditional Access policy targeting the specific Entra users/groups

### Application Mapping

When the source product supports targeting policies to applications (e.g., "Facebook" instead of `facebook.com`):
- Reference an **application mapping CSV** that maps source app IDs/names to GSA FQDN endpoints
- This mapping file is created outside the scope of the conversion spec
- The spec must document: expected columns, how unmatched apps are handled (flag with `ReviewNeeded=Yes`), and the dual-pattern convention (`domain.com;*.domain.com`) if applicable

### Category Mapping

When the source product supports targeting policies to web categories:
- Reference a **category mapping CSV** that maps source categories to GSA web categories
- This mapping file is created outside the scope of the conversion spec
- Unmapped categories must be flagged: set `ReviewNeeded=Yes`, `Provision=No`, and use a placeholder in `RuleDestinations` (e.g., `UNMAPPED:SourceCategoryName`)

## Output CSV Format

### Policies CSV Columns

Required columns: `PolicyName,PolicyType,PolicyAction,RuleType,RuleDestinations,RuleName,Provision`
Optional columns: `Description,ReviewNeeded,ReviewDetails`

- **PolicyType**: `WebContentFiltering` or `TLSInspection`
- **PolicyAction**: For WebContentFiltering: `Block` or `Allow`. For TLSInspection: `Bypass` or `Inspect` (sets the default action). Source actions that don't map cleanly (e.g., `Alert`, `Continue`, `Warn`) should be flagged with `ReviewNeeded=Yes`.
- **RuleType**: For WebContentFiltering: `FQDN`, `URL`, `webCategory`, or `ipAddress`. For TLSInspection: `bypass` or `inspect`.
- **RuleDestinations**: Semicolon-separated. FQDN/URL/IP rules have a 300-character limit per row; split into additional rows with suffix (`-2`, `-3`) when exceeded. webCategory rules are never split.
- **Provision**: `yes` unless `ReviewNeeded=Yes`, then `no`

### Security Profiles CSV Columns

`SecurityProfileName,Priority,SecurityProfileLinks,CADisplayName,EntraUsers,EntraGroups,Provision`

- **SecurityProfileLinks**: Semicolon-separated policy links. Filtering policies use `PolicyName:Priority` format; non-filtering links (TLS inspection, threat intelligence, cloud firewall) use `PolicyName` without priority.
- **EntraUsers / EntraGroups**: Semicolon-separated; use placeholder names when source identities need manual mapping. Values of `_Replace_Me` are ignored by the provisioning script.

## Design Alignment

- All EIA conversion functions follow `Convert-ZIA2EIA.ps1` architectural patterns
- Single function with internal helper functions
- Phased processing (Load → Process → Export)
- Logging via `Write-LogMessage` (INFO, WARN, DEBUG, ERROR)
- Region-based code organization
- CSV export using shared utilities with UTF-8 BOM encoding
