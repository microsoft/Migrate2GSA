---
sidebar_position: 3
title: NSWG to Entra Internet Access (EIA) Configuration Transformer
---

## Overview

`Convert-NSWG2EIA` is a PowerShell function that converts Netskope Secure Web Gateway (NSWG) configuration to Microsoft Entra Internet Access (EIA) format. It transforms Real-time Protection policies, custom categories, and URL lists into Microsoft Global Secure Access (GSA) web content filtering policies and security profiles compatible with `Start-EntraInternetAccessProvisioning`.

The function performs comprehensive processing including URL classification, category mapping, policy aggregation by user/group assignment, and automated conflict resolution.

## Prerequisites

- PowerShell 7.0 or higher
- `Migrate2GSA` PowerShell module installed
- Exported NSWG configuration files from `Export-NetskopeConfig`
- NSWG to EIA category mappings CSV file
- Write access to output directory

## Syntax

```powershell
Convert-NSWG2EIA 
    -RealTimeProtectionPoliciesPath <String>
    -UrlListsPath <String>
    -CustomCategoriesPath <String>
    -CategoryMappingsPath <String>
    [-OutputBasePath <String>]
    [-EnableDebugLogging]
    [<CommonParameters>]
```

## Parameters

### -RealTimeProtectionPoliciesPath

Path to Netskope Real-time Protection Policies JSON export file. This is the output from `Export-NetskopeConfig`.

- **Type**: String
- **Required**: Yes
- **Position**: Named
- **Default value**: None
- **Accept pipeline input**: False
- **Validation**: File must exist

### -UrlListsPath

Path to Netskope URL Lists JSON export file. This is the output from `Export-NetskopeConfig`.

- **Type**: String
- **Required**: Yes
- **Position**: Named
- **Default value**: None
- **Accept pipeline input**: False
- **Validation**: File must exist

### -CustomCategoriesPath

Path to Netskope Custom Categories JSON export file. This is the output from `Export-NetskopeConfig`.

- **Type**: String
- **Required**: Yes
- **Position**: Named
- **Default value**: None
- **Accept pipeline input**: False
- **Validation**: File must exist

### -CategoryMappingsPath

Path to NSWG to EIA category mappings CSV file. This file maps Netskope predefined categories to Microsoft GSA web categories. A sample mapping file is provided in the `Samples/NSWG2EIA/` folder of the repository.

- **Type**: String
- **Required**: Yes
- **Position**: Named
- **Default value**: None
- **Accept pipeline input**: False
- **Validation**: File must exist

### -OutputBasePath

Base directory for output files. The function will create timestamped CSV files and a log file in this location.

- **Type**: String
- **Required**: No
- **Position**: Named
- **Default value**: Current working directory
- **Accept pipeline input**: False
- **Validation**: Directory must exist

### -EnableDebugLogging

Enable verbose debug logging for detailed troubleshooting. Provides additional diagnostic information during processing.

- **Type**: Switch
- **Required**: No
- **Position**: Named
- **Default value**: False
- **Accept pipeline input**: False

## Outputs

**System.Management.Automation.PSCustomObject**

Returns a summary object containing:

- `PoliciesCreated` - Number of web content filtering policies created
- `SecurityProfilesCreated` - Number of security profiles created
- `PoliciesCsvPath` - Full path to exported policies CSV file
- `SecurityProfilesCsvPath` - Full path to exported security profiles CSV file
- `LogFilePath` - Full path to log file

## Examples

### Example 1: Basic Conversion

```powershell
# Import the module
Import-Module Migrate2GSA

# Convert NSWG configuration to EIA format
Convert-NSWG2EIA `
    -RealTimeProtectionPoliciesPath "C:\Export\real_time_protection_policies.json" `
    -UrlListsPath "C:\Export\url_lists.json" `
    -CustomCategoriesPath "C:\Export\custom_categories.json" `
    -CategoryMappingsPath "C:\Mappings\NSWG2EIA-CategoryMappings.csv" `
    -OutputBasePath "C:\Conversion"
```

This example performs a complete conversion with all required files.

### Example 2: Convert with Debug Logging

```powershell
Convert-NSWG2EIA `
    -RealTimeProtectionPoliciesPath ".\real_time_protection_policies.json" `
    -UrlListsPath ".\url_lists.json" `
    -CustomCategoriesPath ".\custom_categories.json" `
    -CategoryMappingsPath ".\NSWG2EIA-CategoryMappings.csv" `
    -EnableDebugLogging
```

This example enables detailed debug logging to troubleshoot conversion issues.

### Example 3: Capture Results for Analysis

```powershell
$results = Convert-NSWG2EIA `
    -RealTimeProtectionPoliciesPath ".\real_time_protection_policies.json" `
    -UrlListsPath ".\url_lists.json" `
    -CustomCategoriesPath ".\custom_categories.json" `
    -CategoryMappingsPath ".\NSWG2EIA-CategoryMappings.csv"

Write-Host "Created $($results.PoliciesCreated) policies"
Write-Host "Created $($results.SecurityProfilesCreated) security profiles"
Write-Host "Policies CSV: $($results.PoliciesCsvPath)"
Write-Host "Security Profiles CSV: $($results.SecurityProfilesCsvPath)"
```

This example captures the output for post-conversion analysis.

### Example 4: Conversion Pipeline

```powershell
# Step 1: Export from Netskope
$token = Read-Host "Enter API Token" -AsSecureString
Export-NetskopeConfig -ApiToken $token -TenantUrl "https://contoso.goskope.com"

# Step 2: Convert to EIA format
$results = Convert-NSWG2EIA `
    -RealTimeProtectionPoliciesPath ".\backup_20251119_120000\real_time_protection_policies.json" `
    -UrlListsPath ".\backup_20251119_120000\url_lists.json" `
    -CustomCategoriesPath ".\backup_20251119_120000\custom_categories.json" `
    -CategoryMappingsPath ".\NSWG2EIA-CategoryMappings.csv"

# Step 3: Provision to Entra (after review)
Start-EntraInternetAccessProvisioning -PoliciesCsvPath $results.PoliciesCsvPath `
                                       -SecurityProfilesCsvPath $results.SecurityProfilesCsvPath
```

This example shows the complete end-to-end workflow.

## Output Structure

The function creates timestamped CSV files and a log file:

```
20251119_143022_EIA_Policies.csv
20251119_143022_EIA_SecurityProfiles.csv
20251119_143022_Convert-NSWG2EIA.log
```

### Policies CSV Format

The policies CSV file contains web content filtering policies:

| Column | Description |
|--------|-------------|
| `PolicyName` | Unique policy name derived from URL list or category |
| `PolicyType` | Always "WebContentFiltering" |
| `PolicyAction` | `Allow` or `Block` |
| `Description` | Description of the policy source |
| `RuleType` | `FQDN`, `URL`, `ipAddress`, or `webCategory` |
| `RuleDestinations` | Semicolon-separated list of destinations or categories |
| `RuleName` | Rule identifier within the policy |
| `ReviewNeeded` | `Yes` or `No` - indicates manual review required |
| `ReviewDetails` | Details about why review is needed |
| `Provision` | `Yes` or `No` - whether to provision this policy |

### Security Profiles CSV Format

The security profiles CSV file contains user/group assignments:

| Column | Description |
|--------|-------------|
| `SecurityProfileName` | Unique security profile name |
| `Priority` | Numeric priority (500, 600, 700...) - lower executes first |
| `CADisplayName` | Display name for Conditional Access |
| `EntraGroups` | Semicolon-separated list of Entra group names |
| `EntraUsers` | Semicolon-separated list of user emails |
| `SecurityProfileLinks` | Semicolon-separated policy names with priorities |
| `Description` | Description of aggregated policies |
| `Provision` | `Yes` or `No` - whether to provision this profile |
| `Notes` | Source RT policy names for reference |

### Example CSV Rows

**Policies CSV:**
```csv
PolicyName,PolicyType,PolicyAction,Description,RuleType,RuleDestinations,RuleName,ReviewNeeded,ReviewDetails,Provision
Finance-URLs-Allow,WebContentFiltering,Allow,URL List: Finance-URLs,FQDN,finance.contoso.com;*.finance.contoso.com,finance.contoso.com,No,,Yes
Social-Media-Block,WebContentFiltering,Block,Social Networking - Predefined categories,webCategory,Social Networking,WebCategories,No,,Yes
```

**Security Profiles CSV:**
```csv
SecurityProfileName,Priority,CADisplayName,EntraGroups,EntraUsers,SecurityProfileLinks,Description,Provision,Notes
SecurityProfile-001,500,SecurityProfile-001,Finance Users,,Finance-URLs-Allow:100;Social-Media-Block:200,Aggregated from 1 real-time protection policies,Yes,Finance Access Policy
SecurityProfile-All-Users,600,SecurityProfile-All-Users,Replace_with_All_IA_Users_Group,,Default-Block:100,Aggregated from 1 real-time protection policies,Yes,Default Internet Access
```

## Conversion Process

The function performs the following phases:

### Phase 1: Data Loading and Validation
- Loads Real-time Protection policies from JSON
- Loads URL lists from JSON
- Loads custom categories from JSON
- Loads category mappings from CSV
- Validates JSON structure and data integrity
- Builds lookup tables for efficient processing

### Phase 2: URL List and Custom Category Processing

#### Phase 2.1: URL List Processing
- Processes each URL list
- Detects regex type lists (flags for review)
- Deduplicates destinations
- Cleans and normalizes URLs/FQDNs
- Classifies destinations (URL, FQDN, IP address)
- Creates BOTH Allow and Block policies for each URL list
- Groups destinations by base domain
- Splits by 300-character limit
- Flags IP addresses for review (not yet supported in EIA)

#### Phase 2.2: Custom Category Processing
- Tracks URL list references (inclusion/exclusion)
- Detects URL lists in both inclusion AND exclusion (flags for review)
- Processes predefined categories
- Maps predefined categories to GSA web categories
- Creates policies for predefined categories
- Stores custom category metadata for Phase 3

### Phase 3: Real-time Protection Policy Processing

#### Phase 3.1: Filter Policies
- Filters enabled web policies only
- Skips disabled policies
- Skips NPA (Private Access) policies
- Skips CASB (app_tags filtered) policies

#### Phase 3.2: Parse and Process Each Policy
- Extracts user assignments (emails)
- Extracts group assignments (X500 paths)
- Defaults to "All users" if no assignments
- Resolves application references:
  - Custom categories → URL list policies + predefined categories
  - Predefined categories → GSA web category policies
  - Application objects → Placeholder for review
- Determines action (Allow/Block) based on RT policy action
- Links to appropriate URL list policies (inclusion/exclusion logic)
- Stores policy info for aggregation

#### Phase 3.3: Aggregate Policies by User/Group Assignment
- Groups policies by identical user/group assignments
- Creates security profiles for specific user/group combinations
- Assigns sequential priorities (500, 600, 700...)
- Creates "All Users" profile last (lowest precedence)
- Deduplicates policy links
- Orders policy links: Allow first, then Block (alphabetically)

#### Phase 3.4: Cleanup Unreferenced Policies
- Collects all policy names referenced in security profiles
- Removes policies not referenced by any security profile
- Reduces output to only necessary policies

### Phase 4: Export and Summary
- Exports policies to CSV with UTF-8 BOM encoding
- Exports security profiles to CSV with priority suffixes
- Generates comprehensive summary statistics
- Logs all processing details

## Understanding NSWG Policy Structure

### Real-time Protection Policy Fields
- `status` - Must be "Enabled"
- `accessMethod` - Must NOT be "Client" (NPA)
- `app_tags` - Must be empty or "Any" (not CASB-filtered)
- `user` - Comma-separated users/groups/All
- `application` - Comma-separated custom categories, predefined categories, or application objects
- `action` - Policy action (Alert/Block/Allow)
- `groupOrder` - Policy priority (converted to Priority × 10)
- `ruleName` - Policy name for tracking

### URL List Fields
- `id` - Unique identifier
- `name` - Display name
- `data.type` - "exact" or "regex"
- `data.urls` - Array of URLs/FQDNs/IPs

### Custom Category Fields
- `id` - Unique identifier
- `name` - Category name
- `data.inclusion` - Array of URL list references
- `data.exclusion` - Array of URL list references
- `data.categories` - Array of predefined category references

### User/Group Parsing
**X500 Group Path Example:**
```
fabrikam.com/Groups/Finance/APP Finance Users
```
- Extracts final segment: `APP Finance Users`
- Maps to Entra group name

**Email Address:**
- Direct email addresses are extracted as-is
- Example: `user@contoso.com`

**"All" Assignment:**
- Maps to placeholder: `Replace_with_All_IA_Users_Group`
- Replace with actual "All Internet Access Users" group

## Category Mapping

### Predefined Category Mapping
The CSV file maps Netskope predefined categories to Microsoft GSA web categories:

```csv
NSWGCategory,GSACategory,Notes
Adult Content,Adult Content,Direct mapping
Gambling,Gambling,Direct mapping
Social Networking,Social Networking,Direct mapping
Shopping,Shopping,Direct mapping
Custom Finance Category,,Unmapped - manual review needed
```

### Mapping States
- **Mapped** - Has valid GSACategory value
- **Unmapped - Missing in file** - Category not in CSV
- **Unmapped - No GSA value** - Category in CSV but GSACategory empty or "Unmapped"

### Unmapped Category Handling
Unmapped categories are:
- Prefixed with `UNMAPPED:`
- Flagged with `ReviewNeeded=Yes`
- Set to `Provision=No`
- Logged with reason and statistics

## URL Classification

The function classifies destinations into types:

### FQDN (Fully Qualified Domain Name)
- Standard domain names: `contoso.com`, `app.contoso.com`
- Wildcard domains: `*.contoso.com`, `*.finance.contoso.com`
- Supports wildcard prefix only

### URL (Full URL Path)
- URLs with paths: `https://contoso.com/app`, `http://api.contoso.com/v1`
- Protocol included in classification
- Grouped by base domain

### IP Address
- IPv4 addresses: `192.168.1.1`
- IPv4 CIDR ranges: `10.0.0.0/24`
- IPv6 addresses are skipped (not yet supported)
- Flagged with `ReviewNeeded=Yes` (IP-based filtering not yet supported in EIA)

### Destination Cleaning
- Removes protocol prefixes: `http://`, `https://`
- Converts `.domain.com` to `*.domain.com`
- Removes port numbers from FQDN classification
- Normalizes whitespace

## Priority Assignment

Security profiles are assigned priorities in sequential order:

### Priority Scheme
- **Start**: 500
- **Increment**: 100
- **Specific profiles**: 500, 600, 700, 800...
- **All-Users profile**: Highest number (lowest precedence)

### Example
- SecurityProfile-001: Priority 500 (highest precedence)
- SecurityProfile-002: Priority 600
- SecurityProfile-003: Priority 700
- SecurityProfile-All-Users: Priority 800 (lowest precedence)

### Priority within Policies
Policy links within each security profile are assigned sub-priorities:
- First policy: 100
- Second policy: 200
- Third policy: 300
- Format: `PolicyName:100`

### No Conflicts
With sequential assignment, priority conflicts are impossible and automatically avoided.

## Policy Aggregation Logic

### Aggregation Rules
1. Group RT policies by identical user/group assignments
2. Combine policy links from all policies in each group
3. Deduplicate policy links
4. Order: Allow policies first (alphabetically), then Block policies (alphabetically)
5. Assign sequential priorities

### Example Aggregation

**Input: 3 RT Policies**
- Finance Policy 1: Users=Finance Group, Apps=Finance-URLs (Allow)
- Finance Policy 2: Users=Finance Group, Apps=Social-Media (Block)
- HR Policy: Users=HR Group, Apps=HR-Apps (Allow)

**Output: 2 Security Profiles**
- SecurityProfile-001 (Finance Group): Finance-URLs-Allow, Social-Media-Block
- SecurityProfile-002 (HR Group): HR-Apps-Allow

### Benefits of Aggregation
- Reduces number of security profiles
- Consolidates identical assignments
- Preserves policy ordering logic
- Stays within EIA limits (256 profiles)

## Review Flags

Policies are flagged for review in the following cases:

### URL List Issues
- **Regex type**: URL list uses regex patterns (not directly supported)
- **IP addresses**: Contains IP addresses (IP-based filtering not yet supported)
- **ReviewDetails**: Specific issue description

### Custom Category Issues
- **Duplicate URL lists**: URL list in both inclusion and exclusion
- **ReviewDetails**: Lists conflicting URL list names

### Predefined Category Issues
- **Unmapped category**: Category not in mapping file or no GSA value
- **ReviewDetails**: Lists unmapped category names with reason

### Application Object Issues
- **Application object**: Netskope application object (not category or URL list)
- **ReviewDetails**: Requires manual mapping to destinations

### Review Resolution
1. Open CSV in Excel or text editor
2. Search for `ReviewNeeded=Yes`
3. Read `ReviewDetails` for specific issue
4. Resolve issue (map category, replace placeholder, etc.)
5. Change `Provision=Yes` when ready
6. Re-import to provisioning function

## Provisioning Status

### Provision = "Yes"
- Policy or profile is ready for provisioning
- No review flags
- All dependencies resolved

### Provision = "No"
- Review needed
- Contains unmapped categories
- Contains IP addresses
- Contains regex patterns
- Contains application objects
- Contains conflicting URL lists


### 5. Provision to Entra
```powershell
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath "20251119_143022_EIA_Policies.csv" `
    -SecurityProfilesCsvPath "20251119_143022_EIA_SecurityProfiles.csv"
```

### Log File Location
```
20251119_143022_Convert-NSWG2EIA.log
```

### Debug Mode
When `-EnableDebugLogging` is specified:
- Logs detailed processing for each policy
- Shows category mapping resolution
- Displays URL classification details
- Traces policy aggregation
- Shows security profile creation

### Key Log Sections
1. **Phase 1**: Data loading and validation
2. **Phase 2.1**: URL list processing
3. **Phase 2.2**: Custom category processing
4. **Phase 3.1**: Policy filtering
5. **Phase 3.2**: Individual policy processing
6. **Phase 3.3**: Policy aggregation
7. **Phase 3.4**: Cleanup
8. **Phase 4**: Export and summary

## Troubleshooting

### No Policies Generated

**Cause**: All policies were filtered out or marked for review

**Solution**:
1. Check log file for filtering reasons
2. Verify RT policies are enabled
3. Ensure policies are web gateway (not NPA)
4. Verify policies don't have app_tags filtering
5. Check category mappings are complete

### All Security Profiles Empty

**Cause**: No valid policy links or all policies flagged for review

**Solution**:
1. Check policies CSV for `ReviewNeeded=Yes`
2. Resolve review items first
3. Verify category mappings
4. Check URL list references are valid

### Unmapped Categories

**Cause**: Netskope predefined categories not in mapping file or no GSA value

**Solution**:
1. Review log for specific unmapped categories
2. Update category mappings CSV with correct GSA categories
3. Use official Microsoft GSA web category names
4. Re-run conversion after updating mappings

### Missing User/Group Assignments

**Cause**: RT policies have no user/group assignments

**Solution**:
1. Check Netskope RT policy configuration
2. Verify policies have user or group assignments
3. Default "All" assignment will be used if none specified
4. Replace `Replace_with_All_IA_Users_Group` placeholder

### URL Classification Issues

**Cause**: URLs not classified correctly or unexpected format

**Solution**:
1. Enable debug logging to see classification details
2. Verify URL format in Netskope configuration
3. Check for special characters or encoding issues
4. Review destination cleaning logic in log

## Integration with Other Functions

### Upstream: Export-NetskopeConfig
```powershell
# Step 1: Export Netskope configuration
$token = Read-Host "Enter API Token" -AsSecureString
Export-NetskopeConfig -ApiToken $token -TenantUrl "https://contoso.goskope.com"

# Step 2: Convert to EIA format
Convert-NSWG2EIA `
    -RealTimeProtectionPoliciesPath ".\backup_20251119_120000\real_time_protection_policies.json" `
    -UrlListsPath ".\backup_20251119_120000\url_lists.json" `
    -CustomCategoriesPath ".\backup_20251119_120000\custom_categories.json" `
    -CategoryMappingsPath ".\NSWG2EIA-CategoryMappings.csv"
```

### Downstream: Start-EntraInternetAccessProvisioning
```powershell
# Step 3: Provision to Entra
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath ".\20251119_143022_EIA_Policies.csv" `
    -SecurityProfilesCsvPath ".\20251119_143022_EIA_SecurityProfiles.csv"
```

## Advanced Scenarios

### Custom Category Mapping Strategy

**Scenario**: Large number of unmapped categories

**Approach**:
1. Run initial conversion
2. Extract unmapped categories from log
3. Create complete category mappings CSV
4. Re-run conversion with updated mappings

```powershell
# Extract unmapped categories from log
Get-Content "20251119_143022_Convert-NSWG2EIA.log" | 
    Where-Object { $_ -like "*not found in mapping file*" -or $_ -like "*GSACategory is empty*" } |
    Out-File "unmapped_categories.txt"
```


## Feedback and Support

For issues, questions, or feedback, please refer to the main repository documentation.
