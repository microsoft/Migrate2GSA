# Convert-ZIA2EIA

## Overview

The `Convert-ZIA2EIA` function converts ZScaler Internet Access (ZIA) URL filtering configuration to Microsoft Entra Internet Access (EIA) format. It processes URL filtering policies, custom URL categories, and predefined category mappings to generate CSV files ready for import into EIA.

## Prerequisites

### Required Input Files

1. **URL Filtering Policy** (`url_filtering_policy.json`)
   - Exported from ZIA API endpoint: `/urlFilteringRules`
   - Contains URL filtering rules with actions, users, groups, and category references

2. **URL Categories** (`url_categories.json`)
   - Exported from ZIA API endpoint: `/urlCategories`
   - Contains custom and predefined categories with URL/FQDN/IP lists

3. **Category Mappings** (`ZIA2EIA-CategoryMappings.json`)
   - Manual configuration file mapping ZIA predefined categories to GSA categories
   - Template available in Samples directory

### PowerShell Requirements

- PowerShell 7.0 or higher
- Migrate2GSA module installed

## Installation

```powershell
# Import the module
Import-Module Migrate2GSA

# Verify the function is available
Get-Command Convert-ZIA2EIA
```

## Syntax

```powershell
Convert-ZIA2EIA
    [-UrlFilteringPolicyPath <string>]
    [-UrlCategoriesPath <string>]
    [-CategoryMappingsPath <string>]
    [-OutputBasePath <string>]
    [-EnableDebugLogging]
    [<CommonParameters>]
```

## Parameters

### -UrlFilteringPolicyPath
Path to the ZIA URL Filtering Policy JSON export file.

- **Type**: String
- **Default**: `url_filtering_policy.json` in current directory
- **Required**: No (uses default if not specified)

### -UrlCategoriesPath
Path to the ZIA URL Categories JSON export file.

- **Type**: String
- **Default**: `url_categories.json` in current directory
- **Required**: No (uses default if not specified)

### -CategoryMappingsPath
Path to the ZIA to EIA category mappings JSON file.

- **Type**: String
- **Default**: `ZIA2EIA-CategoryMappings.json` in current directory
- **Required**: No (uses default if not specified)

### -OutputBasePath
Base directory for output CSV files and log file.

- **Type**: String
- **Default**: Current directory
- **Required**: No (uses default if not specified)

### -EnableDebugLogging
Enable verbose debug logging for detailed processing information.

- **Type**: Switch
- **Default**: False
- **Required**: No

## Examples

### Example 1: Basic Conversion
```powershell
Convert-ZIA2EIA
```
Converts ZIA configuration using default file paths in the current directory.

### Example 2: Custom Input Paths
```powershell
Convert-ZIA2EIA `
    -UrlFilteringPolicyPath "C:\ZIA\url_filtering_policy.json" `
    -UrlCategoriesPath "C:\ZIA\url_categories.json" `
    -CategoryMappingsPath "C:\ZIA\mappings.json" `
    -OutputBasePath "C:\Output"
```
Converts ZIA configuration from specified paths and saves output to C:\Output.

### Example 3: Enable Debug Logging
```powershell
Convert-ZIA2EIA -EnableDebugLogging
```
Converts ZIA configuration with detailed debug logging enabled.

### Example 4: Pipeline Usage
```powershell
# Navigate to data directory and run conversion
Set-Location C:\ZIA\Export
Convert-ZIA2EIA -EnableDebugLogging | Out-Null
Get-ChildItem *.csv | Format-Table Name, Length, LastWriteTime
```
Changes to the data directory, runs the conversion, and lists the output files.

## Output Files

All output files are created in the `OutputBasePath` directory with a timestamp prefix (`yyyyMMdd_HHmmss`).

### 1. EIA Policies CSV
**Filename**: `[timestamp]_EIA_Policies.csv`

Contains web content filtering policies for custom URL categories and predefined category references.

**Fields**:
- `PolicyName`: Unique policy identifier
- `PolicyType`: Always "WebContentFiltering"
- `PolicyAction`: "Block" or "Allow"
- `Description`: Policy description
- `RuleType`: "FQDN", "URL", "webCategory", or "ipAddress"
- `RuleDestinations`: Semicolon-separated list of destinations
- `RuleName`: Sub-rule identifier for grouping/splitting
- `ReviewNeeded`: "Yes" or "No" flag for manual review
- `ReviewDetails`: Semicolon-separated list of review reasons

### 2. EIA Security Profiles CSV
**Filename**: `[timestamp]_EIA_SecurityProfiles.csv`

Contains security profile definitions that reference web content filtering policies and assign them to users/groups.

**Fields**:
- `SecurityProfileName`: Security profile name (from rule name)
- `SecurityProfilePriority`: Rule priority (order × 10)
- `EntraGroups`: Semicolon-separated group names
- `EntraUsers`: Semicolon-separated user emails
- `PolicyLinks`: Semicolon-separated policy names
- `Description`: Profile description

### 3. Log File
**Filename**: `[timestamp]_Convert-ZIA2EIA.log`

Comprehensive log file with all processing details, warnings, and statistics.

## Processing Logic

### Phase 1: Data Loading
1. Load and validate all input JSON files
2. Build lookup tables for categories and mappings
3. Initialize statistics tracking

### Phase 2: Custom Category Processing
1. Filter and validate custom categories
2. Deduplicate URL entries
3. Clean destinations (remove schemas, ports, query strings, fragments)
4. Classify destinations (FQDN, URL, IP address)
5. Group destinations by base domain
6. Split by character limit (300 characters for FQDN/URL/IP)
7. Create policy entries

### Phase 3: URL Filtering Rule Processing
1. Filter enabled rules (skip disabled)
2. Extract users and groups
3. Separate custom from predefined categories
4. Create/reference custom category policies (Block or Allow)
5. Create predefined category policies
6. Create security profiles
7. Resolve priority conflicts

### Phase 4: Export and Summary
1. Cleanup unreferenced policies
2. Export Policies CSV
3. Export Security Profiles CSV
4. Display summary statistics

## URL Processing Rules

### Cleaning Operations
The function automatically cleans destination entries:

- **Schemas**: `https://example.com` → `example.com`
- **Ports**: `example.com:8080` → `example.com`
- **Query strings**: `example.com?param=value` → `example.com`
- **Fragments**: `example.com#section` → `example.com`
- **IPv4 with port/path**: `192.168.1.100:8080` → **skipped**

All cleaning operations are logged at WARN level.

### Classification Rules

1. **IP Addresses**: Match IPv4 pattern, validated for valid octets (0-255)
2. **URLs**: Contain "/" or wildcard not at start (e.g., `domain*.com`)
3. **FQDNs**: Start with "`*.`" or no wildcards (e.g., `*.contoso.com`, `example.com`)

### Grouping and Splitting

- **FQDNs and URLs**: Grouped by base domain (last 2 segments)
- **IP Addresses**: Not grouped by domain
- **Character Limit**: 300 characters (excluding field quotes, including semicolons)
- **Web Categories**: No character limit, never split

## Category Mapping

### Predefined Categories
Predefined ZIA categories are mapped to GSA categories using the mappings file:

```json
{
  "ZIACategory": "OTHER_ADULT_MATERIAL",
  "GSACategory": "AdultContent"
}
```

### Unmapped Categories
Categories with no mapping are flagged:
- `GSACategory` is null, blank, or "Unmapped"
- Output uses placeholder format: `[ZIACategoryID]_Unmapped`
- `ReviewNeeded` set to "Yes" in output

## Policy Naming Conventions

### Custom Category Policies
- **Block policies**: `[CategoryName]-Block`
- **Allow policies**: `[CategoryName]-Allow` (created on demand)

### Predefined Category Policies
- Format: `[RuleName]-WebCategories-[Action]`
- Example: `urlRule1-WebCategories-Block`

### Rule Names
- **FQDN/URL rules**: Base domain (e.g., `example.com`, `example.com-2`)
- **IP address rules**: `IPs`, `IPs-2`, `IPs-3`
- **Web category rules**: `WebCategories` (no numeric suffix)

## Action Handling

### BLOCK Action
Uses or creates Block policy for custom categories.

### ALLOW Action
Creates Allow policy by duplicating Block policy entries with PolicyAction changed to "Allow".

### CAUTION Action
Converted to BLOCK action:
- Logged as WARNING
- `ReviewNeeded` set to "Yes"
- `ReviewDetails` includes "Rule action CAUTION converted to Block"

## Priority Conflicts

When multiple rules have the same `order` value:
1. Calculate initial priority: `SecurityProfilePriority = order × 10`
2. Check for conflicts
3. Increment priority until unique: `SecurityProfilePriority + 1`
4. Log conflict resolution at INFO level

## Statistics

The function tracks and logs:
- Total rules loaded/processed/skipped
- Custom categories processed/skipped
- Predefined categories referenced/unmapped
- URLs/FQDNs/IPs classified
- Users/groups processed
- Policies/security profiles created
- Groups split for character limits
- Priority conflicts resolved

## Known Limitations

1. **Character Limits**: 300-character limit is hard-coded (except for webCategory)
2. **Base Domain**: Simple last-2-segments approach (may not handle all TLDs correctly)
3. **IPv6**: Not supported (skipped with warning)
4. **CIDR Ranges**: Not supported for IP addresses
5. **Port Numbers**: Not supported (skipped with warning)
6. **Memory**: All data held in memory (acceptable for expected data sizes)

## Troubleshooting

### File Not Found Errors
Ensure all three input files exist in the specified paths:
```powershell
Test-Path "url_filtering_policy.json"
Test-Path "url_categories.json"
Test-Path "ZIA2EIA-CategoryMappings.json"
```

### Invalid JSON Errors
Validate JSON syntax:
```powershell
Get-Content "url_filtering_policy.json" -Raw | ConvertFrom-Json | Out-Null
```

### Empty Output
Check that:
- At least one rule has `state: "ENABLED"`
- Custom categories contain URL entries
- Rules reference valid category IDs

### Review Flags
Policies/profiles flagged for review require manual attention:
- **Unmapped categories**: Update category mappings file or manually map in EIA
- **CAUTION actions**: Verify Block action is appropriate

### Priority Conflicts
Multiple rules with same priority are automatically resolved by incrementing. Review log file for details.

## Related Functions

- `Export-ZIAConfig`: Exports ZIA configuration files
- `Convert-ZPA2EPA`: Converts ZPA to EPA configuration
- `Start-EntraPrivateAccessProvisioning`: Provisions EPA configuration

## See Also

- [ZScaler Internet Access API Documentation](https://help.zscaler.com/zia/)
- [Microsoft Entra Internet Access Documentation](https://learn.microsoft.com/entra/)
- [Migrate2GSA Module Documentation](../README.md)

## Support

For issues or questions:
1. Check the log file for detailed error messages
2. Enable debug logging with `-EnableDebugLogging`
3. Review sample files in `Samples\ZIA2EIA\` directory
4. Consult the specification document: `Specs\20251013-Convert-ZIA2EIA.md`
