---
sidebar_position: 10
title: Citrix NetScaler to Entra Private Access (EPA) Configuration Transformer
---

## Overview

The `Convert-CitrixNS2EPA` function converts Citrix NetScaler Gateway configuration to Microsoft Entra Private Access format. It parses AAA groups, authorization policies, VPN intranet applications, and group bindings from a plain-text NetScaler config file and generates a CSV ready for import via `Start-EntraPrivateAccessProvisioning`.

## Prerequisites

### Required Input Files

1. **NetScaler Configuration File** (plain-text, any extension)
   - Exported from Citrix NetScaler Gateway
   - Contains `add aaa group`, `add authorization policy`, `add vpn intranetApplication`, and `bind aaa group` commands

### PowerShell Requirements

- PowerShell 7.0 or higher
- Migrate2GSA module installed

## Installation

```powershell
Import-Module Migrate2GSA

Get-Command Convert-CitrixNS2EPA
```

## Syntax

```powershell
Convert-CitrixNS2EPA
    -ConfigFilePath <string>
    [-OutputBasePath <string>]
    [-GroupFilter <string>]
    [-ExcludeGroupFilter <string>]
    [-EnableDebugLogging]
    [-PassThru]
    [<CommonParameters>]
```

## Parameters

### -ConfigFilePath
Path to the NetScaler configuration file (plain-text).

- **Type**: String
- **Required**: Yes

### -OutputBasePath
Base directory for output files.

- **Type**: String
- **Default**: Current directory
- **Required**: No

### -GroupFilter
Wildcard pattern to include only matching AAA groups.

- **Type**: String
- **Required**: No

### -ExcludeGroupFilter
Wildcard pattern to exclude matching AAA groups.

- **Type**: String
- **Required**: No

### -EnableDebugLogging
Enable verbose debug logging for detailed troubleshooting.

- **Type**: Switch
- **Required**: No

### -PassThru
Return results to the pipeline instead of only saving to file.

- **Type**: Switch
- **Required**: No

## Examples

### Example 1: Basic Conversion

```powershell
Convert-CitrixNS2EPA -ConfigFilePath "C:\Export\netscaler.conf"
```

Converts all AAA groups from the specified config file.

### Example 2: Custom Output Directory

```powershell
Convert-CitrixNS2EPA -ConfigFilePath ".\netscaler.conf" -OutputBasePath "C:\Output"
```

### Example 3: Filter by Group Name

```powershell
Convert-CitrixNS2EPA -ConfigFilePath ".\netscaler.conf" -GroupFilter "vpn-warehouse-*"
```

Processes only AAA groups matching the wildcard pattern.

### Example 4: Exclude Groups

```powershell
Convert-CitrixNS2EPA -ConfigFilePath ".\netscaler.conf" -ExcludeGroupFilter "*-test-*"
```

## Output Files

### Enterprise Apps CSV

File name: `<timestamp>_GSA_EnterpriseApps_CitrixNS.csv`

| Column | Description |
|---|---|
| SegmentId | Unique segment identifier (e.g., `SEG-000001`) |
| OriginalAppName | Source AAA group or policy name |
| EnterpriseAppName | Generated EPA Enterprise Application name (`GSA-<GroupName>`) |
| destinationHost | IP address, CIDR range, or FQDN |
| DestinationType | `ipAddress`, `ipRangeCidr`, or `fqdn` |
| Protocol | `TCP`, `UDP`, or `TCP,UDP` |
| Ports | Port number, range, or `1-65535` |
| EntraGroups | Target Entra ID group (placeholder — remap before provisioning) |
| EntraUsers | Target Entra ID users (empty by default) |
| ConnectorGroup | Private Access connector group (`Placeholder_Replace_Me`) |
| Conflict | `Yes` or `No` |
| ConflictingEnterpriseApp | Details of conflicting segment(s) |
| Provision | `Yes` or `No` |
| isQuickAccess | Always `no` |

### Log File

File name: `<timestamp>_Convert-CitrixNS2EPA.log`

## Processing Logic

### Phase 1: Parse
Reads the NetScaler config file and extracts:
- **AAA groups** (`add aaa group`)
- **Authorization policies** (`add authorization policy`) — DENY policies are skipped
- **VPN intranet applications** (`add vpn intranetApplication`)
- **Group bindings** (`bind aaa group`)

Rule expressions are parsed for `CLIENT.IP.DST.EQ`, `CLIENT.IP.DST.IN_SUBNET`, `CLIENT.TCP.DSTPORT.EQ`, and `CLIENT.UDP.DSTPORT.EQ` clauses.

### Phase 2: Resolve Bindings
Consolidates bindings per group, merging TCP/UDP protocols for the same policy. ICMP bindings are skipped. Unbound ALLOW policies are collected separately under `GSA-UnboundPolicies`.

### Phase 3: Transform
Converts each group's bound policies and intranet applications into EPA segment objects. Each AAA group becomes an Enterprise Application named `GSA-<GroupName>`.

### Phase 4: Conflict Detection
Detects overlapping segments across Enterprise Applications based on IP ranges, FQDNs, wildcard DNS suffixes, protocols, and port ranges. Conflicting segments are flagged with `Provision=No`.

### Phase 5: Export
Writes the CSV output and log file.

## Post-Conversion Steps

1. Review the exported CSV for accuracy
2. Remap **EntraGroups** — replace NetScaler AAA group names with Entra ID security group names
3. Replace **ConnectorGroup** placeholders with actual Private Access connector group names
4. Resolve conflicts flagged in the `ConflictingEnterpriseApp` column
5. Review unbound policies and decide whether to provision or discard
6. Validate segments with port range `1-65535` (all ports) are intentional
7. Import using `Start-EntraPrivateAccessProvisioning`

## Known Limitations

- ICMP bindings are skipped (not supported by EPA)
- DENY authorization policies are excluded
- Unbound policies are exported with `Provision=No` for manual review
- Wildcard DNS suffix overlap detection may produce false positives for nested patterns
