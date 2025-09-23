# Entra Private Access (EPA) Provisioning

This directory contains the `Provision-EntraPrivateAccessConfig.ps1` script for automatically provisioning Microsoft Entra Private Access applications from CSV configuration data.

## Overview

The EPA provisioning script automates the creation of Private Access applications and their network segments in Microsoft Entra. It reads CSV configuration files containing application details and provisions them with comprehensive logging, error handling, and retry capabilities.

## Prerequisites

### PowerShell Requirements

- **PowerShell 7.0 or later** (required)
- Download from: [PowerShell Releases](https://github.com/PowerShell/PowerShell/releases)

### Required PowerShell Modules

The script will validate these modules are installed:

- `Microsoft.Entra.Beta.Groups`
- `Microsoft.Entra.Beta.Authentication`
- `Microsoft.Entra.Beta.NetworkAccess`

Install all required modules with:

```powershell
Install-Module -Name Microsoft.Entra.Beta -Force -AllowClobber
```

### Entra Authentication

You must authenticate with sufficient permissions before running the script:

```powershell
Connect-Entra -Scopes 'NetworkAccessPolicy.ReadWrite.All', 'Application.ReadWrite.All', 'NetworkAccess.ReadWrite.All' -ContextScope Process
```

## CSV Configuration Format

The script expects a CSV file with the following required columns:

| Column | Description | Example |
|--------|-------------|---------|
| `SegmentId` | Segment identifier, can be a number or a string, only for reporting/logging. | `DomainController1`
| `EnterpriseAppName` | Name of the Private Access application | `GSA-WebApp-Production` |
| `destinationHost` | Target host/IP address/range | `webapp.internal.com`, `10.1.2.3`, or `192.168.1.0/24` |
| `DestinationType` | Type of destination (`fqdn`, `ipAddress`, `ipRangeCidr`, `ipRange`) | `fqdn` |
| `Protocol` | Network protocol (`tcp` or `udp`) | `tcp` |
| `Ports` | Port specification (single, range, or comma-separated) | `443`, `8080-8090`, `80,443,8080` |
| `ConnectorGroup` | Name of the Application Proxy connector group | `Production-Connectors` |
| `Provision` | Whether to provision this entry (`Yes` or `No`) | `Yes` |
| `EntraGroup` | Entra ID group to assign to the application (optional, ignored if blank). Only support single groups. | `WebApp-Users` |

### DestinationType Values

The `DestinationType` field supports the following values:

| Value | Description | destinationHost Example |
|-------|-------------|-------------------------|
| `fqdn` | Fully qualified domain name | `webapp.internal.com` |
| `ipAddress` | Single IPv4 address | `10.1.2.100` |
| `ipRangeCidr` | IP range in CIDR notation | `192.168.1.0/24` |
| `ipRange` | IP range from start to end | `192.168.1.1..192.168.1.50` |

### Sample CSV Content

Check sample provided, Sample-EntraPrivateAccessConfig.rename_to_csv.

## Usage Examples

### Basic Usage

```powershell
.\Provision-EntraPrivateAccessConfig.ps1 -ProvisioningConfigPath ".\config.csv"
```

### Preview Changes (WhatIf Mode)

```powershell
.\Provision-EntraPrivateAccessConfig.ps1 -ProvisioningConfigPath ".\config.csv" -WhatIf
```

### Filter by Application Name Prefix

```powershell
.\Provision-EntraPrivateAccessConfig.ps1 -ProvisioningConfigPath ".\config.csv" -AppNamePrefix "GSA-Production"
```

### Filter by Connector Group

```powershell
.\Provision-EntraPrivateAccessConfig.ps1 -ProvisioningConfigPath ".\config.csv" -ConnectorGroupFilter "Production-Connectors"
```

### Automated Execution (Skip Confirmations)

```powershell
.\Provision-EntraPrivateAccessConfig.ps1 -ProvisioningConfigPath ".\config.csv" -Force
```

### Custom Log File Location

```powershell
.\Provision-EntraPrivateAccessConfig.ps1 -ProvisioningConfigPath ".\config.csv" -LogPath "C:\Logs\EPA-Provisioning.log"
```

## Script Parameters

| Parameter | Required | Description | Default |
|-----------|----------|-------------|---------|
| `ProvisioningConfigPath` | ✅ | Path to the CSV configuration file | - |
| `AppNamePrefix` | ❌ | Filter applications by name prefix | Empty (no filter) |
| `ConnectorGroupFilter` | ❌ | Filter by connector group name | Empty (no filter) |
| `LogPath` | ❌ | Path for the log file | `.\Provision-EntraPrivateAccessConfig.log` |
| `WhatIf` | ❌ | Enable dry-run mode (preview only) | `$false` |
| `Force` | ❌ | Skip confirmation prompts | `$false` |

## How It Works

### 1. Pre-Flight Validation

- Validates PowerShell version (7.0+ required)
- Checks required PowerShell modules
- Validates Entra authentication and permissions
- Imports and validates CSV configuration

### 2. Dependency Resolution

- Resolves connector group names to IDs
- Resolves Entra group names to IDs
- Validates all dependencies exist in the tenant

### 3. Application Provisioning

- Groups segments by application name
- Creates Private Access applications (or uses existing ones)
- Assigns Entra groups to applications
- Creates network segments for each application

### 4. Results and Logging

- Comprehensive logging to console and file
- Progress tracking with ETA calculations
- Exports results CSV for retry scenarios
- Detailed execution summary

## Output Files

### Log File

- **Default Location**: `.\Provision-EntraPrivateAccessConfig.log`
- **Content**: Detailed execution log with timestamps and component tracking
- **Levels**: INFO, WARN, ERROR, SUCCESS, DEBUG, SUMMARY

### Results CSV

- **Location**: Same directory as input CSV with timestamp prefix
- **Naming**: `YYYYMMDD_HHMMSS_[original-filename]_provisioned.csv`
- **Purpose**: Track provisioning status and enable retry scenarios
- **Status Values**:
  - `Provisioned`: Successfully created new application and segments
  - `AddedToExisting`: Added segments to existing application
  - `Filtered: [reason]`: Skipped due to filters or settings
  - `Skipped: [reason]`: Skipped due to dependency issues
  - `Error: [details]`: Failed with specific error

### Reusing Output CSV for Additional Runs

The generated results CSV can be used as input for subsequent script executions. This is particularly useful for:

- **Fixing Configuration Issues**: After resolving dependency problems or correcting CSV values
- **Retry Failed Operations**: Re-attempting segments that failed due to transient issues
- **Incremental Provisioning**: Adding new segments to your existing configuration

#### CSV Reuse Mechanism

1. **Successfully Provisioned Segments**: The script automatically sets `Provision = No` for segments that were successfully created. This prevents duplicate provisioning on subsequent runs.

2. **Failed/Skipped Segments**: These retain `Provision = Yes`, allowing them to be retried without affecting successful segments.

3. **Configuration Updates**: You can modify any values (connector groups, Entra groups, etc.) in the output CSV before reusing it.

#### Example Workflow

```powershell
# Initial run - some segments fail due to missing connector group
.\Provision-EntraPrivateAccessConfig.ps1 -ProvisioningConfigPath ".\initial-config.csv"

# Output generated: 20250804_143022_initial-config_provisioned.csv
# - 5 segments: Provision = No (successfully created)
# - 3 segments: Provision = Yes (failed due to missing connector group)

# Fix connector group names in the output CSV, then rerun
.\Provision-EntraPrivateAccessConfig.ps1 -ProvisioningConfigPath ".\20250804_143022_initial-config_provisioned.csv"

# Only the 3 failed segments will be processed (Provision = Yes)
# The 5 successful segments will be skipped (Provision = No)
```

#### Best Practices for Reuse

- **Always Review**: Check the `ProvisioningResult` column to understand what happened
- **Fix Root Causes**: Address dependency issues before rerunning
- **Backup Original**: Keep a copy of your original CSV for reference
- **Validate Changes**: Use `-WhatIf` to preview what will be processed

## Error Handling and Retry

### Common Issues and Solutions

#### Missing Connector Groups

```text
❌ Skipping application 'MyApp': Unresolved connector groups found
   - 'NonExistent-Connectors' (not found in tenant)
```

**Solution**: Verify connector group names in your CSV match those in your Entra tenant.

#### Placeholder Values

```text
❌ Skipping application 'MyApp': Unresolved connector groups found
   - 'Placeholder_Replace_Me' (placeholder - replace with actual connector group name)
```

**Solution**: Replace placeholder values with actual connector group and Entra group names.

#### Authentication Issues

```text
❌ Entra PowerShell connection required
```

**Solution**: Authenticate with required scopes:

```powershell
Connect-Entra -Scopes 'NetworkAccessPolicy.ReadWrite.All', 'Application.ReadWrite.All', 'NetworkAccess.ReadWrite.All' -ContextScope Process
```

### Retry Failed Operations

1. Check the generated results CSV file
2. Fix any configuration issues
3. Set failed entries' `Provision` column back to `Yes`
4. Re-run the script with the updated CSV

## Best Practices

### Before Running

1. **Test with WhatIf**: Always run with `-WhatIf` first to preview changes
2. **Verify Dependencies**: Ensure all connector groups and Entra groups exist
3. **Backup Configuration**: Keep a backup of your original CSV file
4. **Check Permissions**: Verify you have the required Entra permissions

### During Execution

1. **Monitor Logs**: Watch the console output for warnings and errors
2. **Don't Interrupt**: Allow the script to complete to avoid partial configurations
3. **Review Progress**: Use the progress bar to estimate completion time

### After Execution

1. **Review Summary**: Check the execution summary for any failures
2. **Validate Results**: Test a few applications to ensure they work correctly
3. **Save Logs**: Keep log files for troubleshooting and audit purposes
4. **Update Documentation**: Document any customizations or lessons learned

## Troubleshooting

### Script Won't Start

- Verify PowerShell 7+ is installed and being used
- Check that required modules are installed
- Ensure you're authenticated to Entra

### Applications Not Created

- Verify connector groups exist in your tenant
- Check that CSV column names match exactly
- Review logs for specific error messages

### Segments Not Added

- Check port formatting in CSV (no spaces, correct delimiters)
- Verify destination hosts are reachable from connectors
- Review protocol specifications (tcp/udp)

### Group Assignments Failed

- Ensure Entra groups exist and are accessible
- Verify group names match exactly (case-sensitive)
- Check that groups are security groups, not distribution lists


---

**Author**: Andres Canello  
**Version**: 1.0  
**Last Updated**: August 2025
