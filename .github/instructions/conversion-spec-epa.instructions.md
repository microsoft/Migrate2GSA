---
applyTo: 'Specs/Convert/*2EPA*'
description: 'Common patterns and rules for writing Entra Private Access (EPA) conversion specs'
---

# EPA Conversion Spec Guidelines

These guidelines apply to specs that convert third-party private access / VPN products to Entra Private Access (EPA). They do NOT apply to Entra Internet Access (EIA) conversions — EIA has a different policy model (web content filtering, security profiles, conditional access) and separate conventions.

## Spec Structure

Every EPA conversion spec must include these sections in order:

1. **Overview** — Purpose, scope, key differences from other solutions
2. **Input File Structures** — Source config formats (JSON, XML, text), fields, and examples
3. **Transformation Logic** — Field mapping, expansion rules, protocol consolidation
4. **Conflict Detection** — Algorithm, data structures, resolution
5. **Output Format** — CSV schema with concrete examples
6. **Function Design** — Signatures, helper functions, parameters
7. **Error Handling & Logging** — Validation, warnings, error levels
8. **Processing Flow** — High-level execution diagram and internal data structures
9. **Next Steps** — Manual review and provisioning instructions

## Core Conversion Rules

### Include/Exclude Filtering

Every conversion function MUST support application name filtering via parameters:
- `AppFilter` or equivalent (`string[]`) — wildcard patterns to include. Only matching apps are processed.
- `ExcludeAppFilter` or equivalent (`string[]`) — wildcard patterns to exclude.
- Filtered rows should still appear in output with a `Notes` value explaining the exclusion reason.

### Conflict Detection

Every EPA conversion spec MUST include conflict detection logic. Reuse the algorithm and helper functions from `Convert-ZPA2EPA.ps1`:

- **IP Range Overlaps**: Convert CIDR to integer range, test `max(start₁, start₂) ≤ min(end₁, end₂)`
- **FQDN Exact Matches**: String equality with same protocol/port
- **Wildcard Matching**: `*.domain.com` conflicts with `app.domain.com`
- **Port Range Overlaps**: `Test-PortRangeOverlap` helper function
- Output fields: `Conflict` (`Yes`/`No`) and `ConflictingEnterpriseApp` (comma-separated SegmentIds)

Required helper functions (from ZPA2EPA):
- `Convert-CIDRToRange`, `Convert-IPToInteger`, `Test-IntervalOverlap`, `Test-PortRangeOverlap`, `Get-DestinationType`, `Clear-Domain`

Required data structures:
```
$ipRangeToProtocolToPorts    # IP → protocols → ports → app info
$hostToProtocolToPorts        # FQDN → protocols → ports → app info
$dnsSuffixes                  # Wildcard domains → protocols → ports
```

### DestinationType Classification

| Input Pattern | DestinationType |
|---|---|
| Dotted decimal, no `/` (e.g., `10.50.100.10`) | `ipAddress` |
| Contains `/` + prefix length (e.g., `10.0.0.0/24`) | `ipRangeCidr` |
| Starts with `*` (e.g., `*.domain.com`) | `fqdn` (wildcard) |
| Letters + dots, no `/` (e.g., `app.domain.com`) | `fqdn` |
| DNS suffix (Quick Access only) | `dnsSuffix` |

### Protocol Consolidation

1. Same protocol, different ports → combine ports: `"80,443"`
2. Different protocols, same port → separate segments per protocol
3. Same destination for TCP + UDP → consolidate: `Protocol="TCP,UDP"`
4. No port specified → default to `"1-65535"` (all ports)

### User/Group Assignment

Source access policies referencing users or groups must be mapped to `EntraGroups` and `EntraUsers` columns:
- Groups and users are aggregated per `EnterpriseAppName` across all referencing policies
- Groups are deduplicated case-insensitively; users are semicolon-separated
- Source group formats vary by product (SCIM IDs, X500 paths, AAA group names) — the spec must document the resolution logic
- Placeholder values like `_Replace_Me` should be used when source identities need manual mapping

### Provision Status

```
Provision = "Yes"  → Valid policy with assigned users/groups, no conflicts
Provision = "No"   → Conflict detected, no policy references, or deny-only conditions
```
The `Notes` field must explain the reason when `Provision = "No"`.

## Output CSV Format

### Enterprise Apps CSV Columns

Required columns (validated by `Start-EntraPrivateAccessProvisioning`):

`EnterpriseAppName,SegmentId,destinationHost,DestinationType,Protocol,Ports,ConnectorGroup,Provision,EntraGroups`

Optional columns:

`Notes,EntraUsers,Conflict,ConflictingEnterpriseApp,isQuickAccess`

- **SegmentId**: Format `{AppName}-Segment-###` (zero-padded 3 digits per app) or `SEG-######` (global sequence). Must be unique across the output.
- **DestinationType**: `ipAddress`, `ipRangeCidr`, `fqdn`, or `dnsSuffix` (Quick Access only)
- **Protocol**: `TCP`, `UDP`, or `TCP,UDP`
- **Ports**: Comma-separated ports or ranges (e.g., `80,443` or `1-65535`)
- **ConnectorGroup**: Name of the connector group; use a placeholder (e.g., `DefaultConnectorGroup`) when not determinable from source
- **isQuickAccess**: `yes` or `no` (optional column; if omitted, all rows treated as `no`). `dnsSuffix` DestinationType requires `isQuickAccess=yes`.
- **EntraGroups**: Semicolon-separated group names
- **Conflict / ConflictingEnterpriseApp**: Populated by conflict detection

### Output Filename Convention

`{Timestamp}_GSA_EnterpriseApps_{Source}.csv` (e.g., `20260225_143022_GSA_EnterpriseApps_CitrixNS.csv`)

## Design Alignment

- All EPA conversion functions follow `Convert-ZPA2EPA.ps1` architectural patterns
- Single function with internal helper functions (conflict helpers reused verbatim)
- Phased processing (Load → Validate → Transform/Expand → Conflict Detection → Export)
- Logging via `Write-LogMessage` (INFO, WARN, DEBUG, ERROR)
- Region-based code organization
- CSV export with UTF-8 BOM encoding
