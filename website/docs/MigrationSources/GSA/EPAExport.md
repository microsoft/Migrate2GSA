---
sidebar_position: 1
title: Entra Private Access Export
---

# Export Entra Private Access Configuration

## Overview

The `Export-EntraPrivateAccessConfig` function exports your complete Microsoft Entra Private Access (EPA) configuration to CSV format. Unlike migration from third-party platforms, this exports directly from your existing Global Secure Access tenant, making it ideal for backup, disaster recovery, tenant-to-tenant migrations, or replicating configurations across environments.

**What Gets Exported:**
- All EPA applications and their display names
- Application segments (destination hosts, protocols, ports)
- Connector group assignments
- Entra group and user assignments
- Quick Access application indicators
- Segment metadata (IDs, destination types)

**Output Format:** CSV file compatible with [Start-EntraPrivateAccessProvisioning](../../Provision/EntraPrivateAccessProvisioning.md), enabling seamless restoration or migration.

## Use Cases

### 🔄 Tenant-to-Tenant Migration
Migrate your EPA configuration when:
- Moving between production and test environments
- Consolidating or splitting Entra tenants
- Setting up parallel environments for disaster recovery
- Replicating configurations across geographic regions

### 💾 Backup and Restore
Create point-in-time backups:
- Before major configuration changes
- As part of regular backup procedures
- Prior to testing new policies or segments
- For compliance and audit requirements

### 🛡️ Disaster Recovery
Maintain recovery snapshots:
- Quick restoration after accidental deletion
- Recovery from misconfiguration
- Rollback to known-good configurations
- Business continuity planning

### 🔁 Configuration Replication
Duplicate successful configurations:
- Promote tested configurations from dev to prod
- Standardize settings across multiple tenants
- Template configurations for new deployments
- Share baseline configurations across teams

## Prerequisites

### PowerShell Requirements
- **PowerShell Version:** 7.0 or later ([Installation Guide](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell))
- **Module:** Migrate2GSA module loaded

### Microsoft Graph Requirements
- **Authentication:** Active Microsoft Graph connection ([Connect-MgGraph](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.authentication/connect-mggraph) or `Connect-Entra`)
- **Required Module:** Microsoft.Graph.Authentication

### Permission Scopes (Read-Only)
The following **read-only** scopes are required:

| Scope | Purpose |
|-------|---------|
| `Application.Read.All` | Read EPA applications, segments, and service principals |
| `Directory.Read.All` | Read connector groups, Entra groups, and users |
| `NetworkAccess.Read.All` | Read Global Secure Access tenant status and network access resources |

:::tip
These are read-only scopes. The function only exports data and makes no modifications to your tenant.
:::

### Tenant Prerequisites
- Global Secure Access tenant must be onboarded (status: `onboarded`)
- Private Access feature must be enabled
- At least one connector group configured (recommended)

## Parameters

### `-OutputPath`
**Type:** String  
**Required:** No  
**Default:** Current directory (`$PWD`)

Directory where the timestamped backup folder will be created.

```powershell
Export-EntraPrivateAccessConfig -OutputPath "C:\GSA-Backups"
```

The function creates this structure:
```
C:\GSA-Backups\
└── GSA-backup_20260220_143022\
    └── PrivateAccess\
        ├── 20260220_143022_EPA_Config.csv
        └── 20260220_143022_Export-EPA.log
```

### `-LogPath`
**Type:** String  
**Required:** No  
**Default:** Auto-generated in backup folder

Custom location for the log file. By default, the log is placed in the timestamped backup folder.

```powershell
Export-EntraPrivateAccessConfig -LogPath "C:\Logs\EPA-Export.log"
```

## Output Structure

### Folder and File Naming

The function creates a timestamped backup folder with consistent naming:

```
GSA-backup_yyyyMMdd_HHmmss/
└── PrivateAccess/
    ├── yyyyMMdd_HHmmss_EPA_Config.csv
    └── yyyyMMdd_HHmmss_Export-EPA.log
```

**Example:**
```
GSA-backup_20260220_143022/
└── PrivateAccess/
    ├── 20260220_143022_EPA_Config.csv
    └── 20260220_143022_Export-EPA.log
```

**Timestamp Format:** `yyyyMMdd_HHmmss` (Year-Month-Day_Hour-Minute-Second)

### CSV File Format

The exported CSV contains the following columns:

| Column | Description | Example Values |
|--------|-------------|----------------|
| `EnterpriseAppName` | Display name of the EPA application | `Corporate Intranet`, `HR Portal` |
| `SegmentId` | Graph ID of the segment (reference only) | `a1b2c3d4-e5f6-7890-abcd-ef1234567890` |
| `isQuickAccess` | Quick Access indicator (`yes` or `no`) | `yes`, `no` |
| `destinationHost` | FQDN, IP address, IP range, or CIDR | `intranet.contoso.com`, `10.0.1.0/24` |
| `DestinationType` | Type of destination | `FQDN`, `ipAddress`, `ipRange`, `ipRangeCidr`, `dnsSuffix` |
| `Protocol` | Network protocol | `tcp`, `udp`, `tcp,udp` |
| `Ports` | Port numbers (comma-separated) | `443`, `80,443`, `8080-8090` |
| `ConnectorGroup` | Connector group name | `US-East Connectors`, `EMEA Connectors` |
| `Provision` | Provisioning flag (always `no` for exports) | `no` |
| `EntraGroups` | Assigned Entra groups (semicolon-separated) | `Sales;Marketing;HR` |
| `EntraUsers` | Assigned users by UPN (semicolon-separated) | `john@contoso.com;jane@contoso.com` |

:::info Multi-Segment Applications
Applications with multiple segments generate multiple CSV rows—one row per segment. Application-level properties (name, connector group, assignments) are duplicated across all rows for that application.
:::

### Log File

The log file contains detailed execution information:
- Tenant validation results
- Applications and segments processed
- Connector group resolutions
- User and group assignment lookups
- Warnings (missing connectors, no assignments, etc.)
- Errors encountered
- Performance metrics (API calls, cached lookups, duration)
- Summary statistics

## Usage Examples

### Basic Export
Export to current directory with default settings:

```powershell
Export-EntraPrivateAccessConfig
```

**Output:**
```
.\GSA-backup_20260220_143022\PrivateAccess\
```

### Specify Output Directory
Export to a dedicated backup location:

```powershell
Export-EntraPrivateAccessConfig -OutputPath "C:\GSA-Backups"
```

### Custom Log Location
Place log file outside the backup folder:

```powershell
Export-EntraPrivateAccessConfig `
    -OutputPath "C:\Backups" `
    -LogPath "C:\Logs\EPA-Export-$(Get-Date -Format 'yyyyMMdd').log"
```

### Scheduled Backup Script
Create a scheduled task for automated backups:

```powershell
# Monthly backup script
$backupPath = "\\fileserver\GSA-Backups\$(Get-Date -Format 'yyyy-MM')"
New-Item -Path $backupPath -ItemType Directory -Force | Out-Null

# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Application.Read.All", "Directory.Read.All", "NetworkAccess.Read.All"

# Export EPA configuration
Export-EntraPrivateAccessConfig -OutputPath $backupPath

# Disconnect
Disconnect-MgGraph
```

### Backup Before Changes
Take a snapshot before making configuration changes:

```powershell
# Create pre-change backup
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupNote = "PreChange_AddNewSegments"
$outputPath = "C:\EPA-Backups\$backupNote`_$timestamp"

Export-EntraPrivateAccessConfig -OutputPath $outputPath

Write-Host "Backup completed. Safe to proceed with changes." -ForegroundColor Green
Write-Host "Restore point: $outputPath" -ForegroundColor Cyan
```

## Restoration Process

Restoring an exported configuration uses the same provisioning function as migrations from other platforms.

### 1. Review the Exported CSV

Before restoring, review and edit the CSV file:

```powershell
# Open in Excel or your preferred CSV editor
$csvPath = "C:\GSA-Backups\GSA-backup_20260220_143022\PrivateAccess\20260220_143022_EPA_Config.csv"
Invoke-Item $csvPath
```

**Edit the `Provision` column:**
- Change `no` to `yes` for rows you want to restore
- Leave as `no` for rows to skip

### 2. Connect to Target Tenant

```powershell
# Connect with write permissions
Connect-MgGraph -Scopes @(
    "Application.ReadWrite.All",
    "Directory.ReadWrite.All", 
    "NetworkAccess.ReadWrite.All"
)
```

### 3. Run the Provisioning Function

```powershell
# Restore from exported CSV
Start-EntraPrivateAccessProvisioning `
    -InputCSVPath "C:\GSA-Backups\GSA-backup_20260220_143022\PrivateAccess\20260220_143022_EPA_Config.csv" `
    -OutputPath "C:\EPA-Restore-Results"
```

:::tip Selective Restoration
You can restore specific applications by editing the CSV:
- Set `Provision=yes` only for applications you want to restore
- Delete rows you don't need
- Modify settings before restoration (change connector groups, update assignments, etc.)
:::

For complete provisioning documentation, see [Entra Private Access Provisioning](../../Provision/EntraPrivateAccessProvisioning.md).

## What Gets Exported

### ✅ Included in Export
- **Applications:** All EPA application names and IDs
- **Segments:** Complete segment definitions (hosts, types, protocols, ports)
- **Connector Groups:** Group names assigned to applications
- **Assignments:** Entra groups and users assigned to applications
- **Quick Access:** Quick Access application indicators
- **Metadata:** Segment IDs and destination types

### ❌ Not Automatically Exported
- **Connector configurations:** Physical connector deployments
- **Network topology:** On-premises network configurations
- **Certificate configurations:** TLS/SSL certificates
- **Conditional Access policies:** CA policies (separately managed in Entra)
- **Connector health status:** Runtime connector state

:::warning Post-Restoration Steps
After restoring to a new tenant:
1. Deploy and configure connectors in the target environment
2. Assign connector groups to applications
3. Verify network connectivity from connectors to destination hosts
4. Test application access from client devices
5. Review and update Conditional Access policies
:::

## Validation and Error Handling

The export function performs comprehensive validation:

### Tenant Validation
- ✓ Global Secure Access onboarding status
- ✓ Private Access feature enabled
- ✓ Connector groups availability

### Data Validation
- ✓ Destination host format (FQDN, IP, CIDR matching destination type)
- ✓ Protocol values (`tcp`, `udp`)
- ✓ Port ranges (1-65535)
- ✓ Connector group resolution
- ✓ User and group name lookups

### Warnings Logged
- Applications with no segments
- Applications with no connector group
- Applications with no user/group assignments
- Deleted connector groups (exported as `[DELETED]_<ID>`)
- Suspicious destinations (localhost, 127.0.0.1, 0.0.0.0)
- Mismatched destination types and hosts

### Error Handling
The export continues even when errors occur:
- Missing data is left blank (not populated with placeholders)
- Errors are logged with details
- Summary report shows total warnings and errors
- Partial exports are still saved and usable

## Performance and Optimization

### API Call Optimization
The function uses intelligent caching to minimize Graph API calls:

- **Connector Group Cache:** Group IDs are resolved once and cached
- **Entra Group Cache:** Group names are cached after first lookup
- **User Cache:** User UPNs are cached to avoid repeated queries

**Example Performance Metrics:**
```
Graph API calls made: 147
Cached lookups used: 823
Total duration: 12.3 seconds
```

### Large Configuration Handling
For tenants with many applications:
- Progress indicators show real-time status
- Applications processed sequentially to avoid throttling
- Caching reduces API calls by ~85% on average
- Output files compressed automatically by PowerShell CSV export

## Troubleshooting

### Common Issues

#### "Tenant not onboarded"
```
Global Secure Access has not been activated on this tenant.
```

**Solution:** Complete GSA tenant onboarding in the Microsoft Entra admin center before exporting.

#### "Private Access not enabled"
```
Private Access is not enabled on this tenant.
```

**Solution:** Enable the Private Access feature in Global Secure Access settings.

#### Insufficient Permissions
```
Insufficient privileges to complete the operation.
```

**Solution:** Reconnect with required scopes:
```powershell
Connect-MgGraph -Scopes "Application.Read.All", "Directory.Read.All", "NetworkAccess.Read.All"
```

#### Empty CSV Generated
```
No Private Access applications found in tenant.
```

**Reason:** The tenant has no EPA applications, or the user lacks permissions to view them.

**Solution:** Verify applications exist in the Entra admin center and confirm Graph connection has proper scopes.

#### Missing Connector Groups
```
Apps with no connector group: 5
```

**Reason:** Applications exist but don't have connector groups assigned yet.

**Impact:** Export succeeds, but `ConnectorGroup` column will be empty. Assign connector groups before or after restoration.

#### Deleted Connector Groups
```
Deleted connector groups detected: 2
```

**Reason:** Applications reference connector groups that were deleted.

**Result:** Exported as `[DELETED]_<GroupID>` in the CSV. Update these before restoration.

### Debug Mode

For detailed troubleshooting, review the log file:

```powershell
# Export and immediately view the log
Export-EntraPrivateAccessConfig -OutputPath "C:\Backups"

# Find and open the log file
$latestBackup = Get-ChildItem "C:\Backups\GSA-backup_*" | Sort-Object Name -Descending | Select-Object -First 1
$logFile = Get-ChildItem "$latestBackup\PrivateAccess\*_Export-EPA.log"
Get-Content $logFile -Tail 50
```

## Export Summary Report

After completion, the function displays a detailed summary:

```
=== EXPORT SUMMARY ===
Export completed successfully!

Backup folder: C:\GSA-Backups\GSA-backup_20260220_143022

Entra Private Access (EPA):
  Exported: 24 Applications
  Exported: 156 Segments

  Connector Groups:
    Unique connector groups referenced: 4
    Apps with no connector group: 0
    Deleted connector groups detected: 0

  Assignments:
    Apps with no user/group assignments: 2
    Total unique groups assigned: 18
    Total unique users assigned: 5

  Segment Statistics:
    Average segments per app: 6.5
    App with most segments: Corporate Intranet (47 segments)
    Apps with no segments: 0

  Performance:
    Graph API calls made: 147
    Cached lookups used: 823
    Total duration: 12.3 seconds

  Warnings: 2 (see log file for details)
  Errors: 0

Files created in PrivateAccess\:
  - 20260220_143022_EPA_Config.csv (45.2 KB)
  - 20260220_143022_Export-EPA.log (12.7 KB)
```

## Next Steps

After exporting your EPA configuration:

1. **Review the CSV**: Open the exported CSV and verify all applications and segments were captured correctly

2. **Store Securely**: Save backups to a secure location with appropriate access controls (exported data includes your network topology)

3. **Document Context**: Add notes about the export:
   - Purpose (backup, migration, etc.)
   - Tenant/environment details
   - Any known issues or pending changes

4. **Test Restoration**: Periodically test restoration to a non-production tenant to validate your backup process

5. **Automate**: Consider scheduling regular exports for disaster recovery

6. **Next Export Type**: Export Internet Access configuration (coming soon)

## Related Documentation

- [Entra Private Access Provisioning](../../Provision/EntraPrivateAccessProvisioning.md) - Restore/provision EPA configurations
- [Migration Workflow](../../migration-workflow.md) - Overall migration process
- [ZPA to EPA Migration](../ZScaler/ZPA2EPA.md) - Alternative: Migrate from Zscaler Private Access
- [GreenField EPA Deployment](../../GreenField/EntraPrivateAccess.md) - Deploy EPA from scratch

## Additional Resources

- [Microsoft Entra Private Access Documentation](https://learn.microsoft.com/en-us/entra/global-secure-access/concept-private-access)
- [Global Secure Access Overview](https://learn.microsoft.com/en-us/entra/global-secure-access/overview-what-is-global-secure-access)
- [Microsoft Graph API Reference](https://learn.microsoft.com/en-us/graph/api/resources/networkaccess-networkaccessroot)
