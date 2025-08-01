# ZScaler2GSA

This is experimental code, use it at your own risk.

## Export-ZPAConfig.ps1 - ZPA Configuration Export Tool

### Overview

This PowerShell script provides a comprehensive backup solution for your Zscaler Private Access (ZPA) environment. It connects to the ZPA management API and exports all critical configuration elements to JSON files, ensuring you have a complete snapshot of your ZPA setup for backup, auditing, or migration purposes.

### What It Does

The script automatically exports the following ZPA configurations:

- **Application Segments** - Your published applications and services
- **Segment Groups** - Logical groupings of application segments
- **Server Groups** - Collections of application servers
- **App Connectors** - Connector instances and their configurations
- **Connector Groups** - Groupings of app connectors
- **Access Policies** - Security policies controlling user access
- **Policy Sets** - Collections of related policies
- **Service Edges** - Cloud-based access points
- **Service Edge Groups** - Groupings of service edges
- **Identity Provider Controllers** - IdP integrations and settings
- **SCIM Groups** - User group mappings from identity providers
- **SAML Attributes** - SAML assertion configurations
- **Machine Groups** - Device-based access groupings
- **Posture Profiles** - Device compliance policies
- **Trusted Networks** - Network location definitions

### Key Features

- **Complete Configuration Export**: Captures all major ZPA configuration elements in a single run
- **Timestamped Backups**: Each backup is organized with date/time stamps for easy version tracking
- **Multiple Output Formats**: Creates both individual configuration files and a complete consolidated backup
- **Secure Authentication**: Uses OAuth2 client credentials with SecureString for enhanced security
- **Error Handling**: Robust error handling with detailed logging
- **Flexible Output**: Configurable backup directory location

### Security Features

- **SecureString Protection**: Client secrets are encrypted in memory and never visible in command history
- **Read-Only Operations**: Script only reads configuration data, never modifies ZPA settings

### Requirements

- PowerShell 5.1 or later
- ZPA API credentials (Client ID, Client Secret, Customer ID)
- Network access to ZPA management APIs
- Write permissions to the backup directory

### Usage

#### Interactive Usage (Recommended for Security)

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

- Individual JSON files for each configuration type (e.g., `application_segments.json`)
- A complete consolidated backup file (`zpa_complete_backup.json`)
- Detailed console output showing backup progress and results


# ZPA to Entra Private Access (EPA) Configuration Transformer

## Overview

This PowerShell script (`Transform-ZPA2EPA.ps1`) transforms exported Zscaler Private Access (ZPA) application segment configurations into a format suitable for Microsoft Entra Private Access (EPA). It processes JSON export files from ZPA and generates CSV files containing Enterprise Application configurations that can be imported into Microsoft's Global Secure Access (GSA) solution.

> **⚠️ Important Notice**: This is experimental code. Use it at your own risk and thoroughly test in a non-production environment before deploying to production systems.

## What It Does

The script performs the following key functions:

1. **Loads ZPA Configuration**: Reads JSON export files containing ZPA application segments
2. **Transforms Data**: Converts ZPA application segments into EPA-compatible Enterprise Application configurations
3. **Detects Conflicts**: Identifies potential configuration conflicts using GSA-style interval-based detection
4. **Generates Output**: Creates CSV files with all necessary configurations for EPA deployment
5. **Provides Guidance**: Offers detailed logging and next-step recommendations

## Key Features

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

### Professional Output
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
- ZPA Application Segments JSON export file (typically named `App_Segments.json`)
- Generated by the companion [`Export-ZPAConfig.ps1`](Export-ZPAConfig.ps1) script

## Parameters

### Input/Output Parameters
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `AppSegmentPath` | String | No | Path to the ZPA Application Segments JSON file (default: `App_Segments.json` in script directory) |
| `OutputBasePath` | String | No | Base directory for output files (default: script directory) |

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

### Complex Filtering Example
Process production segments while skipping legacy applications:
```powershell
.\Transform-ZPA2EPA.ps1 `
    -AppSegmentNamePattern "*prod*" `
    -SkipAppSegmentName "Legacy-App-1,Legacy-App-2" `
    -SkipAppSegmentNamePattern "*deprecated*" `
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
| `OriginalAppName` | Original ZPA application segment name |
| `EnterpriseAppName` | Generated EPA Enterprise Application name (prefixed with "GSA-") |
| `destinationHost` | Target host (IP, CIDR, or FQDN) |
| `DestinationType` | Type of destination (IP, Subnet, or FQDN) |
| `Protocol` | Network protocol (TCP or UDP) |
| `Ports` | Port range (single port or range like "80-443") |
| `SegmentGroup` | Original ZPA segment group |
| `ServerGroups` | Associated server groups |
| `ConditionalAccessPolicy` | Placeholder for CA policy (replace with actual values) |
| `EntraGroup` | Placeholder for Entra ID group (replace with actual values) |
| `ConnectorGroup` | Placeholder for connector group (replace with actual values) |
| `Conflict` | "Yes" if conflicts detected, "No" otherwise |
| `ConflictingEnterpriseApp` | Names of conflicting applications |
| `Provision` | "Yes" if ready to provision, "No" if conflicts need resolution |

## Conflict Detection

The script implements sophisticated conflict detection to prevent configuration issues:

### IP Range Conflicts
- Detects overlapping IP addresses and CIDR ranges
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

### 2. Replace Placeholders
The CSV contains placeholder values that must be replaced:

- **ConditionalAccessPolicy**: Replace with appropriate Conditional Access policy names
- **EntraGroup**: Replace with relevant Entra ID group names  
- **ConnectorGroup**: Replace with appropriate connector group names

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

*Last Updated: July 18, 2025*
*Script Version: 1.0*