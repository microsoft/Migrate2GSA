# ZScaler2GSA

This is experimental code, use it at your own risk.

## Table of Contents

1. [ZPA Configuration Export Tool](#export-zpaconfigps1---zpa-configuration-export-tool)
2. [ZPA to Entra Private Access (EPA) Configuration Transformer](#zpa-to-entra-private-access-epa-configuration-transformer)

## ZPA Configuration Export Tool

### Overview

This PowerShell script (Export-ZPAConfig.ps1) provides a comprehensive backup solution for your Zscaler Private Access (ZPA) environment. It connects to the ZPA management API and exports all critical configuration elements to JSON files, ensuring you have a complete snapshot of your ZPA setup for backup, auditing, or migration purposes.

### What It Does

The script automatically exports the following ZPA configurations:

- **Application Segments** - Your published applications and services
- **Segment Groups** - Logical groupings of application segments
- **Server Groups** - Collections of application servers
- **App Connectors** - Connector instances and their configurations
- **Connector Groups** - Groupings of app connectors
- **Access Policies** - Security policies controlling user access
- **Client Forwarding Policy** - Client forwarding configuration rules
- **Service Edges** - Cloud-based access points
- **Service Edge Groups** - Groupings of service edges
- **Identity Provider Controllers** - IdP integrations and settings
- **SCIM Groups** - User group mappings from all configured identity providers
- **Machine Groups** - Device-based access groupings

### Security Features

- **SecureString Protection**: Client secrets are encrypted in memory and never visible in command history
- **Read-Only Operations**: Script only reads configuration data, never modifies ZPA settings

### Requirements

- PowerShell 5.1 or later
- ZPA API credentials (Client ID, Client Secret, Customer ID)
- Network access to ZPA management APIs
- Write permissions to the backup directory

### Usage

#### Interactive Usage

```powershell
# First, securely enter your client secret
$secureSecret = Read-Host "Enter Client Secret" -AsSecureString

# Run the backup
.\Scripts\Export-ZPAConfig.ps1 -CustomerId "your-customer-id" -ClientId "your-client-id" -ClientSecret $secureSecret
```

#### Advanced Usage with Custom Settings

```powershell
# For beta environment with custom output location
$secureSecret = Read-Host "Enter Client Secret" -AsSecureString
.\Scripts\Export-ZPAConfig.ps1 -CustomerId "12345" -ClientId "api-client" -ClientSecret $secureSecret -BaseUrl "https://config.zpabeta.net" -OutputDirectory "C:\ZPA-Backups"
```

### Output

The script creates a timestamped directory containing:

- Individual JSON files for each configuration type.
- A complete consolidated backup file (`zpa_complete_backup.json`)
- Detailed console output showing backup progress, statistics, and results

The backup is stored in a timestamped folder format: `backup_YYYYMMDD_HHMMSS/` within your specified output directory.

## ZPA to Entra Private Access (EPA) Configuration Transformer

### Overview

This PowerShell script (`Transform-ZPA2EPA.ps1`) transforms exported Zscaler Private Access (ZPA) application segment configurations into a format suitable for Microsoft Entra Private Access (EPA). It processes JSON export files from ZPA and generates CSV files containing Enterprise Application configurations that can be imported into Microsoft's Global Secure Access (GSA) solution.

> **⚠️ Important Notice**: This is experimental code. Use it at your own risk and thoroughly test in a non-production environment before deploying to production systems.

## What It Does

The script performs the following key functions:

1. **Loads ZPA Configuration**: Reads JSON export files containing ZPA application segments, segment groups, access policies, and SCIM groups
2. **Processes Access Policies**: Automatically maps ZPA access policies to SCIM groups and populates Entra ID group assignments
3. **Transforms Data**: Converts ZPA application segments into EPA-compatible Enterprise Application configurations
4. **Detects Conflicts**: Identifies potential configuration conflicts using GSA-style interval-based detection
5. **Generates Output**: Creates CSV files with all necessary configurations for EPA deployment
6. **Provides Guidance**: Offers detailed logging and next-step recommendations

## Key Features

### Access Policy Integration
- **Automatic Group Mapping**: Processes ZPA access policies to automatically populate Entra ID group assignments
- **APP_GROUP Expansion**: Automatically expands application segment groups to individual applications
- **SCIM Group Resolution**: Resolves SCIM group IDs to group names from identity provider
- **Policy Filtering**: Intelligently filters and processes only valid access policies
- **Smart Placeholders**: Uses different placeholder values based on whether access policies are found

### Advanced Filtering
- **Exact Name Matching**: Process specific application segments by name
- **Wildcard Pattern Matching**: Use patterns like `*web*` to match multiple segments
- **Skip Filters**: Exclude specific segments or patterns from processing
- **Combination Filtering**: Apply multiple filters simultaneously

### Intelligent Conflict Detection
- **IP Range Overlaps**: Detects conflicts between IP addresses and CIDR ranges
- **Port Range Conflicts**: Identifies overlapping port ranges across protocols
- **FQDN Conflicts**: Catches duplicate hostnames with conflicting configurations
- **Wildcard Domain Handling**: Manages conflicts with wildcard DNS patterns (*.domain.com)

### Comprehensive Validation
- **CIDR Validation**: Ensures proper subnet notation and valid IP ranges
- **Port Range Validation**: Validates TCP/UDP port ranges (1-65535)
- **IP Address Validation**: Checks IP address format and octet values
- **Data Integrity**: Handles malformed or incomplete configurations gracefully

### Comprehensive Output
- **Structured Logging**: Color-coded console output with file logging
- **Progress Tracking**: Real-time progress indicators for large datasets
- **CSV Export**: Clean, Excel-compatible CSV output
- **Conflict Reporting**: Detailed conflict analysis and resolution guidance

## Prerequisites

### System Requirements
- **PowerShell**: Version 5.1 or later (PowerShell 7+ recommended)
- **Operating System**: Windows 10/11 or Windows Server 2016+
- **Memory**: Minimum 4GB RAM (8GB+ recommended for large configurations)
- **Storage**: Sufficient disk space for input JSON files and output CSV files

### Required Files
- **Required**: ZPA Application Segments JSON export file (typically named `application_segments.json`)
- **Optional**: ZPA Segment Groups JSON export file (`segment_groups.json`) - for deduplication and APP_GROUP expansion
- **Optional**: ZPA Access Policies JSON export file (`access_policies.json`) - for automatic group mapping
- **Optional**: SCIM Groups JSON export file (`scim_groups.json`) - for SCIM group name resolution
- All files generated by the companion [`Export-ZPAConfig.ps1`](Export-ZPAConfig.ps1) script

## Parameters

### Input/Output Parameters
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `AppSegmentPath` | String | No | Path to the ZPA Application Segments JSON file (default: `application_segments.json` in script directory) |
| `OutputBasePath` | String | No | Base directory for output files (default: script directory) |

### Access Policy Parameters (Optional)
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `SegmentGroupPath` | String | No | Path to ZPA Segment Groups JSON file (used for deduplication and APP_GROUP expansion) |
| `AccessPolicyPath` | String | No | Path to ZPA Access Policies JSON file (default: `access_policies.json` in script directory) |
| `ScimGroupPath` | String | No | Path to SCIM Groups JSON file (default: `scim_groups.json` in script directory) |

### Filtering Parameters
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `TargetAppSegmentName` | String | No | Process only the segment with this exact name |
| `AppSegmentNamePattern` | String | No | Wildcard pattern for segment names (e.g., `*web*`, `prod-*`) |
| `SkipAppSegmentName` | String | No | Comma-separated list of exact segment names to skip |
| `SkipAppSegmentNamePattern` | String | No | Comma-separated list of wildcard patterns to skip |

### Debug Parameter
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `EnableDebugLogging` | Switch | No | Enable verbose debug logging for troubleshooting |

## Usage Examples

### Basic Usage
Transform all application segments using default settings:
```powershell
.\Transform-ZPA2EPA.ps1
```

### Specify Custom Paths
Use custom input and output paths:
```powershell
.\Transform-ZPA2EPA.ps1 -AppSegmentPath "C:\ZPA\exports\App_Segments.json" -OutputBasePath "C:\EPA\output"
```

### Process Specific Segment
Transform only a specific application segment:
```powershell
.\Transform-ZPA2EPA.ps1 -TargetAppSegmentName "Web-Application-Prod"
```

### Pattern-Based Filtering
Process all production web applications:
```powershell
.\Transform-ZPA2EPA.ps1 -AppSegmentNamePattern "*web*prod*"
```

### Skip Specific Segments
Process all segments except test environments:
```powershell
.\Transform-ZPA2EPA.ps1 -SkipAppSegmentNamePattern "*test*,*dev*"
```

### Debug Mode
Enable detailed logging for troubleshooting:
```powershell
.\Transform-ZPA2EPA.ps1 -EnableDebugLogging
```

### With Access Policy Integration
Automatically populate Entra ID group assignments from ZPA access policies:
```powershell
.\Transform-ZPA2EPA.ps1 `
    -AppSegmentPath "C:\ZPA\application_segments.json" `
    -SegmentGroupPath "C:\ZPA\segment_groups.json" `
    -AccessPolicyPath "C:\ZPA\access_policies.json" `
    -ScimGroupPath "C:\ZPA\scim_groups.json" `
    -OutputBasePath "C:\EPA\output"
```

### Complex Filtering Example
Process production segments while skipping legacy applications:
```powershell
.\Transform-ZPA2EPA.ps1 `
    -AppSegmentNamePattern "*prod*" `
    -SkipAppSegmentName "Legacy-App-1,Legacy-App-2" `
    -SkipAppSegmentNamePattern "*deprecated*" `
    -AccessPolicyPath ".\access_policies.json" `
    -ScimGroupPath ".\scim_groups.json" `
    -EnableDebugLogging
```

## Input File Format

The script expects a JSON file containing an array of ZPA application segments. Each segment should have the following structure:

```json
[
  {
    "name": "Web-Application-Prod",
    "domainNames": ["webapp.company.com", "*.api.company.com"],
    "tcpPortRange": [
      {"from": 80, "to": 80},
      {"from": 443, "to": 443}
    ],
    "udpPortRange": [
      {"from": 53, "to": 53}
    ],
    "segmentGroupName": "Production Apps",
    "serverGroups": [
      {"name": "Web-Servers-Group"}
    ]
  }
]
```

### Required Fields
- `name`: Application segment name
- `domainNames`: Array of domains (IP addresses, CIDR ranges, or FQDNs)

### Optional Fields
- `tcpPortRange`: Array of TCP port ranges
- `udpPortRange`: Array of UDP port ranges
- `segmentGroupName`: Segment group name
- `serverGroups`: Array of server group objects

## Output

### Generated Files

1. **CSV Export**: `YYYYMMDD_HHMMSS_GSA_EnterpriseApps_All.csv`
   - Timestamped filename for easy identification
   - Contains all transformed Enterprise Application configurations
   - Ready for EPA import or manual configuration

2. **Log File**: `script.log`
   - Detailed execution log with timestamps
   - Error tracking and debugging information
   - Color-coded console output mirrored to file

### CSV Output Structure

| Column | Description |
|--------|-------------|
| `SegmentId` | Unique segment identifier (SEG-XXXXXX format) |
| `OriginalAppName` | Original ZPA application segment name |
| `EnterpriseAppName` | Generated EPA Enterprise Application name (prefixed with "GSA-") |
| `destinationHost` | Target host (IP, CIDR, or FQDN) |
| `DestinationType` | Type of destination (ipAddress, ipRangeCidr, or FQDN) |
| `Protocol` | Network protocol (TCP or UDP) |
| `Ports` | Port range (single port or range like "80-443") |
| `SegmentGroup` | Original ZPA segment group |
| `ServerGroups` | Associated server groups |
| `EntraGroup` | **Auto-populated from access policies** or placeholder (see EntraGroup Values below) |
| `ConnectorGroup` | Placeholder for connector group (replace with actual values) |
| `Conflict` | "Yes" if conflicts detected, "No" otherwise |
| `ConflictingEnterpriseApp` | Names of conflicting applications |
| `Provision` | "Yes" if ready to provision, "No" if conflicts need resolution |

#### EntraGroup Values

The `EntraGroup` column is automatically populated based on access policy configuration:

- **`Group1; Group2; Group3`**: Semicolon-separated SCIM group names when access policies are found
- **`No_Access_Policy_Found_Replace_Me`**: Access policy files provided but no policy found for this application
- **`Placeholder_Replace_Me`**: Access policy files not provided (backward compatible mode)

## Access Policy Integration

The script can automatically process ZPA access policies to populate Entra ID group assignments, eliminating manual placeholder replacement for the `EntraGroup` column.

### How It Works

1. **Load Access Policies**: Reads ZPA access policies from JSON export
2. **Load SCIM Groups**: Reads SCIM group mappings from identity provider
3. **Filter Policies**: Processes only valid ALLOW policies with simple AND logic
4. **Extract Targets**: Identifies which applications and application groups are targeted
5. **Expand APP_GROUPs**: Uses segment group membership to expand groups to individual apps
6. **Resolve Groups**: Converts SCIM group IDs to group names
7. **Build Lookup**: Creates mapping of Application ID → SCIM group names
8. **Populate CSV**: Automatically fills EntraGroup column with semicolon-separated group names

### Policy Filtering Criteria

The script processes policies that meet **all** of these criteria:

- ✅ Policy Type = "1" (Access Policy)
- ✅ Action = "ALLOW"
- ✅ Root Operator = "AND"
- ✅ Contains APP or APP_GROUP targets
- ✅ Contains SCIM_GROUP conditions
- ✅ No negated conditions

Policies that don't meet these criteria are skipped with logged reasons.


## Conflict Detection

The script implements sophisticated conflict detection to prevent configuration issues:

### IP Range Conflicts
- Detects overlapping IP addresses (ipAddress) and CIDR ranges (ipRangeCidr)
- Handles subnet containment and intersection scenarios
- Validates CIDR notation and IP address formats

### Port Range Conflicts
- Identifies overlapping port ranges within the same protocol
- Handles single ports and port ranges
- Separates TCP and UDP conflict detection

### Domain Conflicts
- Catches duplicate FQDN configurations
- Manages wildcard domain conflicts (*.domain.com)
- Validates domain name formats

### Conflict Resolution
When conflicts are detected:
1. The conflicting configuration is marked with `Conflict: Yes`
2. The `ConflictingEnterpriseApp` column lists all conflicting applications
3. The `Provision` column is set to "No" to prevent automatic deployment
4. Detailed conflict information is logged for manual review

## Post-Processing Steps

After running the script, follow these steps:

### 1. Review Output
- Open the generated CSV file in Excel or a text editor
- Review the summary statistics in the console output
- Check the log file for any errors or warnings

### 2. Review and Update Values
The CSV may contain values that need review or replacement:

- **EntraGroup**: 
  - **Auto-populated**: If access policies were provided, review the automatically assigned groups for accuracy
  - **`No_Access_Policy_Found_Replace_Me`**: Replace with appropriate Entra ID group names for applications without policies
  - **`Placeholder_Replace_Me`**: Replace with appropriate Entra ID group names if access policies weren't provided
- **ConnectorGroup**: Replace `Placeholder_Replace_Me` with appropriate connector group names

### 3. Resolve Conflicts
For records marked with `Conflict: Yes`:
- Review the `ConflictingEnterpriseApp` column for details
- Determine if conflicts are legitimate or can be consolidated
- Modify configurations as needed to resolve conflicts
- Update the `Provision` column to "Yes" after resolution

### 4. Validate Configurations
- Confirm port ranges are correct for each application
- Ensure Entra ID groups and connector groups exist
- Test a small subset before bulk deployment

### 5. Import to Entra Private Access
Use the completed CSV to configure Enterprise Applications in Microsoft Entra Private Access.

## Support and Contributing

This script is provided as-is for experimental use. When encountering issues:

1. **Enable Debug Logging**: Use `-EnableDebugLogging` for detailed information
2. **Check Log Files**: Review `script.log` for error details
3. **Validate Input Data**: Ensure ZPA export files are complete and valid
4. **Test Incrementally**: Use filtering to isolate problematic segments

For improvements or bug fixes, consider contributing to the repository.

## Related Tools

- [`Export-ZPAConfig.ps1`](Export-ZPAConfig.ps1): Companion script for exporting ZPA configurations
- Microsoft Entra Private Access Documentation
- Microsoft Global Secure Access Documentation

---

