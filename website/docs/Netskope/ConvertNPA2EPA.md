---
sidebar_position: 2
title: NPA to Entra Private Access (EPA) Configuration Transformer
---

## Overview

`Convert-NPA2EPA` is a PowerShell function that converts Netskope Private Access (NPA) configuration to Microsoft Entra Private Access (EPA) format. It transforms private applications and access policies into Microsoft Global Secure Access (GSA) Enterprise Application format compatible with `Start-EntraPrivateAccessProvisioning`.

The function performs comprehensive analysis including conflict detection for overlapping IP ranges, FQDNs, protocols, and ports, while aggregating policy assignments for proper access control.

## Prerequisites

- PowerShell 7.0 or higher
- `Migrate2GSA` PowerShell module installed
- Exported NPA configuration files from `Export-NetskopeConfig`
- Write access to output directory

## Syntax

```powershell
Convert-NPA2EPA 
    -PrivateAppsPath <String>
    [-PoliciesPath <String>]
    [-OutputBasePath <String>]
    [-TargetAppName <String>]
    [-AppNamePattern <String>]
    [-SkipAppName <String>]
    [-SkipAppNamePattern <String>]
    [-EnableDebugLogging]
    [-PassThru]
    [<CommonParameters>]
```

## Parameters

### -PrivateAppsPath

Path to NPA Private Apps JSON export file. This is the output from `Export-NetskopeConfig`.

- **Type**: String
- **Required**: Yes
- **Position**: Named
- **Default value**: None
- **Accept pipeline input**: False
- **Validation**: File must exist

### -PoliciesPath

Path to NPA Policies JSON export file. This is the output from `Export-NetskopeConfig`. If not provided, apps will have placeholder access assignments and will be marked for manual review.

- **Type**: String
- **Required**: No
- **Position**: Named
- **Default value**: None
- **Accept pipeline input**: False
- **Validation**: File must exist if specified

### -OutputBasePath

Base directory for output files. The function will create a timestamped CSV file in this location.

- **Type**: String
- **Required**: No
- **Position**: Named
- **Default value**: Current working directory
- **Accept pipeline input**: False
- **Validation**: Directory must exist

### -TargetAppName

Specific app name for exact match processing. When specified, only processes this specific application. Useful for testing or selective migrations.

- **Type**: String
- **Required**: No
- **Position**: Named
- **Default value**: None
- **Accept pipeline input**: False

### -AppNamePattern

Wildcard pattern for app name matching. Supports * and ? wildcards. Useful for processing groups of related applications.

- **Type**: String
- **Required**: No
- **Position**: Named
- **Default value**: None
- **Accept pipeline input**: False

### -SkipAppName

Comma-separated list of specific app names to skip (exact match). Use this to exclude specific applications from conversion.

- **Type**: String
- **Required**: No
- **Position**: Named
- **Default value**: None
- **Accept pipeline input**: False

### -SkipAppNamePattern

Comma-separated list of wildcard patterns for app names to skip. Use this to exclude groups of applications from conversion.

- **Type**: String
- **Required**: No
- **Position**: Named
- **Default value**: None
- **Accept pipeline input**: False

### -EnableDebugLogging

Enable verbose debug logging for detailed troubleshooting. Provides additional diagnostic information during processing.

- **Type**: Switch
- **Required**: No
- **Position**: Named
- **Default value**: False
- **Accept pipeline input**: False

### -PassThru

Return results to pipeline instead of just saving to file. When specified, the function returns the processed data objects for further processing in PowerShell.

- **Type**: Switch
- **Required**: No
- **Position**: Named
- **Default value**: False
- **Accept pipeline input**: False

## Outputs

**System.Management.Automation.PSCustomObject[]**

When `-PassThru` is specified, returns an array of transformed GSA Enterprise Application configuration objects. Each object contains:

- `EnterpriseAppName` - GSA Enterprise Application name (with GSA- prefix)
- `SegmentId` - Unique segment identifier
- `destinationHost` - Target host/IP/CIDR
- `DestinationType` - Type of destination (fqdn, ipAddress, ipRangeCidr)
- `Protocol` - Transport protocol (tcp, udp)
- `Ports` - Port numbers or ranges
- `ConnectorGroup` - Connector group assignment (placeholder)
- `Provision` - Whether to provision (Yes/No)
- `Notes` - Additional information or warnings
- `EntraGroups` - Semicolon-separated list of Entra groups
- `EntraUsers` - Semicolon-separated list of Entra users
- `Conflict` - Conflict indicator (Yes/No)
- `ConflictingEnterpriseApp` - Conflicting application segments

## Examples

### Example 1: Basic Conversion

```powershell
# Import the module
Import-Module Migrate2GSA

# Convert NPA configuration to EPA format
Convert-NPA2EPA `
    -PrivateAppsPath "C:\Export\backup_20251112_143022\private_apps.json" `
    -PoliciesPath "C:\Export\backup_20251112_143022\npa_policies.json" `
    -OutputBasePath "C:\Conversion"
```

This example performs a complete conversion with both apps and policies.

### Example 2: Convert Without Policies

```powershell
Convert-NPA2EPA `
    -PrivateAppsPath ".\backup_20251112_143022\private_apps.json" `
    -OutputBasePath ".\Output"
```

This example converts apps without policy information. All apps will be marked `Provision=No` for manual review.

### Example 3: Convert Specific Application

```powershell
Convert-NPA2EPA `
    -PrivateAppsPath ".\private_apps.json" `
    -PoliciesPath ".\npa_policies.json" `
    -TargetAppName "Finance Portal"
```

This example processes only the "Finance Portal" application.

### Example 4: Convert Applications by Pattern

```powershell
Convert-NPA2EPA `
    -PrivateAppsPath ".\private_apps.json" `
    -PoliciesPath ".\npa_policies.json" `
    -AppNamePattern "HR*" `
    -SkipAppName "HR-Test,HR-Development"
```

This example processes all HR applications except test and development.

### Example 5: Convert with PassThru for Further Processing

```powershell
$results = Convert-NPA2EPA `
    -PrivateAppsPath ".\private_apps.json" `
    -PoliciesPath ".\npa_policies.json" `
    -PassThru

# Filter to only apps ready for provisioning
$readyToProvision = $results | Where-Object { $_.Provision -eq "Yes" -and $_.Conflict -eq "No" }
Write-Host "Ready to provision: $($readyToProvision.Count) segments"
```

This example captures the output for analysis before provisioning.

### Example 6: Bulk Skip Test Applications

```powershell
Convert-NPA2EPA `
    -PrivateAppsPath ".\private_apps.json" `
    -PoliciesPath ".\npa_policies.json" `
    -SkipAppNamePattern "*-Test,*-Dev,*-Staging"
```

This example skips all test, development, and staging applications.

### Example 7: Debug Mode for Troubleshooting

```powershell
Convert-NPA2EPA `
    -PrivateAppsPath ".\private_apps.json" `
    -PoliciesPath ".\npa_policies.json" `
    -EnableDebugLogging
```

This example enables detailed debug logging to troubleshoot conversion issues.

## Output Structure

The function creates a timestamped CSV file and log file:

```
20251112_143022_GSA_EnterpriseApps_NPA.csv
20251112_143022_Convert-NPA2EPA.log
```

### CSV Output Format

The CSV file contains the following columns:

| Column | Description |
|--------|-------------|
| `EnterpriseAppName` | GSA Enterprise Application name (with GSA- prefix) |
| `SegmentId` | Unique segment identifier for tracking |
| `destinationHost` | Target FQDN, IP address, or CIDR range |
| `DestinationType` | Type: `fqdn`, `ipAddress`, or `ipRangeCidr` |
| `Protocol` | Transport protocol: `tcp` or `udp` |
| `Ports` | Comma-separated port numbers or ranges |
| `ConnectorGroup` | Connector group (initially "Placeholder_Replace_Me") |
| `Provision` | `Yes` or `No` - whether to provision this segment |
| `Notes` | Additional information or exclusion reasons |
| `EntraGroups` | Semicolon-separated list of Entra group names |
| `EntraUsers` | Semicolon-separated list of user emails |
| `Conflict` | `Yes` or `No` - indicates conflicts with other segments |
| `ConflictingEnterpriseApp` | Names of conflicting segments |

### Example CSV Row

```csv
EnterpriseAppName,SegmentId,destinationHost,DestinationType,Protocol,Ports,ConnectorGroup,Provision,Notes,EntraGroups,EntraUsers,Conflict,ConflictingEnterpriseApp
GSA-Finance Portal,Finance Portal-Segment-001,finance.contoso.com,fqdn,tcp,443,Placeholder_Replace_Me,Yes,,Finance Users;Accounting Team,,No,
```

## Conversion Process

The function performs the following steps:

### 1. Data Loading
- Loads private apps from JSON export
- Loads policies from JSON export (if provided)
- Validates JSON structure and data integrity

### 2. Policy Processing
- Extracts user and group assignments from policies
- Parses X500 AD-style paths to extract group names
- Filters enabled "allow" policies only
- Aggregates assignments across multiple policies per app
- Deduplicates users and groups

### 3. Application Filtering
- Applies skip filters (exact name and pattern)
- Applies target filters (exact name and pattern)
- Validates required fields (hosts, protocols, ports)

### 4. Segment Generation
- Creates segments for each host × protocol combination
- Adds GSA- prefix to enterprise app names
- Groups ports by transport protocol (TCP/UDP)
- Assigns access control from policies

### 5. Conflict Detection
- Checks for overlapping IP ranges (CIDR)
- Checks for duplicate FQDN × protocol × port combinations
- Detects wildcard DNS suffix conflicts
- Marks conflicting segments for review

### 6. Data Export
- Groups segments by key fields
- Consolidates duplicate port definitions
- Exports to timestamped CSV file with UTF-8 BOM encoding
- Generates detailed log file

## Understanding NPA Policy Structure

Netskope Private Access policies are converted based on the following structure:

### Policy Fields Used
- `enabled` - Must be "1" (enabled)
- `rule_data.match_criteria_action.action_name` - Must be "allow"
- `rule_data.privateApps` - Array of application names
- `rule_data.userGroups` - Array of X500 group paths
- `rule_data.users` - Array of user identifiers

### X500 Group Path Parsing
Example: `fabrikam.com/Groups/Finance/APP Finance Users`
- Extracts final segment: `APP Finance Users`
- Maps to Entra group name

### Policy Filtering
The function processes only:
- **Enabled** policies (`enabled = "1"`)
- **Allow** policies (`action_name = "allow"`)
- Policies with **defined applications**

## Conflict Detection

The function detects the following types of conflicts:

### IP Range Conflicts
- Overlapping CIDR ranges on same protocol/port
- IP addresses within existing CIDR ranges
- Example: `10.0.0.0/24` conflicts with `10.0.0.50/32`

### FQDN Conflicts
- Exact FQDN matches on same protocol/port
- Example: Two segments both targeting `app.contoso.com:443:tcp`

### Wildcard DNS Conflicts
- Wildcard domains overlapping with specific FQDNs
- Overlapping wildcard domains
- Example: `*.contoso.com` conflicts with `app.contoso.com`

### Resolution
- Conflicting segments are marked with `Conflict=Yes`
- `ConflictingEnterpriseApp` column lists all conflicts
- `Provision` is set to `No` for conflicting segments
- Manual review and resolution required before provisioning

## Provisioning Status

Applications are assigned provisioning status based on policy analysis:

### Provision = "Yes"
- App is referenced in at least one valid (enabled, allow) policy
- No conflicts detected
- Ready for provisioning

### Provision = "No"
- App is not referenced in any valid policy
- App is referenced only in disabled or deny policies
- Conflicts detected with other segments
- Manual review required

### Notes Field
Provides context for provisioning decisions:
- `"App excluded from provisioning - no policy references found"`
- `"App excluded from provisioning - referenced only in disabled or deny policies"`
- Empty for apps ready to provision

## Post-Conversion Steps

After running the conversion, complete the following steps:

### 1. Review the CSV File
```powershell
# Import and analyze the results
$results = Import-Csv "20251112_143022_GSA_EnterpriseApps_NPA.csv"

# Check provisioning readiness
$readyToProvision = $results | Where-Object { $_.Provision -eq "Yes" -and $_.Conflict -eq "No" }
$needsReview = $results | Where-Object { $_.Provision -eq "No" -or $_.Conflict -eq "Yes" }

Write-Host "Ready to provision: $($readyToProvision.Count)"
Write-Host "Needs review: $($needsReview.Count)"
```

### 2. Replace Connector Group Placeholders
- Open the CSV file in Excel or text editor
- Replace all `Placeholder_Replace_Me` values with actual connector group names
- Ensure connector groups exist in your Entra tenant

### 3. Review Provision=No Segments
- Check the `Notes` column for reasons
- Assign `EntraGroups` or `EntraUsers` if needed
- Change `Provision` to `Yes` when ready

### 4. Resolve Conflicts
- Review `ConflictingEnterpriseApp` column
- Decide which segments to keep
- Consider combining or separating applications
- Update `Provision` status accordingly

### 5. Validate Access Assignments
- Verify `EntraGroups` are correct Entra group names
- Verify `EntraUsers` are valid user principal names
- Add missing assignments as needed

### 6. Import to Entra
```powershell
Start-EntraPrivateAccessProvisioning -CsvPath "20251112_143022_GSA_EnterpriseApps_NPA.csv"
```

## Logging

The function creates a detailed log file with the following levels:

- **INFO**: General information and progress updates
- **SUCCESS**: Successful operations
- **WARN**: Warnings for skipped apps or potential issues
- **ERROR**: Error conditions
- **DEBUG**: Detailed debugging information (with `-EnableDebugLogging`)
- **SUMMARY**: Summary statistics and results

### Log File Location
The log file is created in the output directory with timestamp:
```
20251112_143022_Convert-NPA2EPA.log
```

### Debug Mode
When `-EnableDebugLogging` is specified:
- Logs detailed processing for each app and policy
- Shows X500 group path parsing
- Displays conflict detection details
- Traces segment generation

## Conversion Statistics

The function provides comprehensive statistics:

### Application Processing
- Total private apps loaded
- Apps processed
- Apps skipped (no protocols/hosts)
- Total segments generated
- Grouped result records

### Policy Integration
- Total policies loaded
- Valid policies processed
- Policies skipped (disabled/deny/invalid)
- Apps with policy assignments
- Apps with group-based access
- Apps with user-based access
- Total unique users

### Conflicts
- Total conflicts detected
- Conflicting segments by type

## Troubleshooting

### No Apps Generated

**Cause**: All apps were filtered out or have missing required fields

**Solution**:
1. Check log file for skip reasons
2. Verify private apps JSON has valid structure
3. Remove overly restrictive filters
4. Ensure apps have `host` and `protocols` defined

### All Apps Have Provision=No

**Cause**: No policies file provided or no apps referenced in valid policies

**Solution**:
1. Provide `-PoliciesPath` parameter with valid policies
2. Verify policies are enabled (`enabled = "1"`)
3. Verify policies have action "allow"
4. Check policy references correct app names

### Group Names Not Resolved

**Cause**: X500 path parsing issues or empty group paths

**Solution**:
1. Check log file for parsing warnings
2. Verify policy `userGroups` field format
3. Use `-EnableDebugLogging` to trace group parsing

### Unexpected Conflicts

**Cause**: Overlapping network definitions or wildcard domains

**Solution**:
1. Review `ConflictingEnterpriseApp` column
2. Check if IP ranges actually overlap
3. Consider using more specific network definitions
4. Split applications into separate segments

### Invalid CIDR Format

**Cause**: Malformed CIDR notation in host field

**Solution**:
1. Verify CIDR format: `192.168.1.0/24`
2. Check prefix length is between 0-32
3. Ensure IP octets are 0-255
4. Review log for specific validation errors

## Performance Considerations

### Large Deployments
- Processing time increases with number of apps and policies
- Conflict detection is O(n²) for overlapping checks
- Consider filtering to process in batches

### Memory Usage
- All apps and policies loaded into memory
- Large policies files may require significant RAM
- Use filtering parameters to reduce scope

### Optimization Tips
1. Use `-TargetAppName` or `-AppNamePattern` for selective processing
2. Skip test/dev apps with `-SkipAppNamePattern`
3. Process production apps separately from non-production
4. Split large conversions into multiple runs

## Best Practices

### Before Conversion
1. Export complete Netskope configuration using `Export-NetskopeConfig`
2. Review exported JSON files for completeness
3. Document any custom naming conventions or requirements
4. Plan connector group mapping

### During Conversion
1. Start with a test app using `-TargetAppName`
2. Review output CSV format and content
3. Verify conflict detection is working correctly
4. Use `-EnableDebugLogging` for first conversion

### After Conversion
1. Always review the CSV before provisioning
2. Validate all placeholder values are replaced
3. Test with a small batch first
4. Monitor provisioning results

### Iterative Approach
1. Convert test applications first
2. Provision and validate in test environment
3. Refine conversion parameters based on results
4. Document lessons learned
5. Proceed with production conversion

## Integration with Other Functions

### Upstream: Export-NetskopeConfig
```powershell
# Step 1: Export Netskope configuration
$token = Read-Host "Enter API Token" -AsSecureString
Export-NetskopeConfig -ApiToken $token -TenantUrl "https://contoso.goskope.com"

# Step 2: Convert to EPA format
Convert-NPA2EPA `
    -PrivateAppsPath ".\backup_20251112_143022\private_apps.json" `
    -PoliciesPath ".\backup_20251112_143022\npa_policies.json"
```

### Downstream: Start-EntraPrivateAccessProvisioning
```powershell
# Step 3: Provision to Entra
Start-EntraPrivateAccessProvisioning `
    -CsvPath ".\20251112_143022_GSA_EnterpriseApps_NPA.csv"
```

## Feedback and Support

For issues, questions, or feedback, please refer to the main repository documentation.
