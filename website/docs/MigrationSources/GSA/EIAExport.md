---
sidebar_position: 2
title: Entra Internet Access Export
---

# Export Entra Internet Access Configuration

:::tip Available Now
The `Export-EntraInternetAccessConfig` function is now available. Use it to export your complete EIA configuration for backup, disaster recovery, and tenant-to-tenant migrations.
:::

## Overview

The `Export-EntraInternetAccessConfig` function exports your complete Microsoft Entra Internet Access (EIA) configuration to CSV format, enabling backup, disaster recovery, tenant-to-tenant migrations, and configuration replication scenarios.

Similar to the [EPA Export](./EPAExport.md) functionality, this exports directly from your existing Global Secure Access tenant, creating CSV files compatible with the provisioning function for seamless restoration.

## Export Scope

### What Is Exported

**Web Content Filtering Policies:**
- FQDN-based rules
- URL path rules
- Web category rules
- IP address rules
- Rule priorities and actions

**TLS Inspection Policies:**
- Bypass rules
- Inspection rules
- Certificate configurations

**Security Profiles:**
- Profile names and descriptions
- Policy associations
- Priority ordering
- Conditional Access policy links (optional)

**Conditional Access Assignments** (optional):
- User assignments
- Group assignments
- Conditional Access policy display names

### Output Structure

The function generates two CSV files in a timestamped backup folder:

```
GSA-backup_yyyyMMdd_HHmmss/
└── InternetAccess/
    ├── yyyyMMdd_HHmmss_EIA_Policies.csv
    ├── yyyyMMdd_HHmmss_EIA_SecurityProfiles.csv
    └── yyyyMMdd_HHmmss_Export-EIA.log
```

:::note Empty CSVs
If no policies or security profiles exist, the function creates CSV files with headers only, ensuring consistent file structure for automation scenarios.
:::

## Use Cases

### 🔄 Tenant-to-Tenant Migration
- Move between production and test environments
- Consolidate or split Entra tenants
- Set up parallel environments for disaster recovery
- Replicate configurations across geographic regions

### 💾 Backup and Restore
- Point-in-time backups before configuration changes
- Regular backup procedures
- Compliance and audit snapshots
- Pre-deployment safety nets

### 🛡️ Disaster Recovery
- Quick restoration after accidental deletion
- Recovery from misconfiguration
- Rollback to known-good configurations
- Business continuity planning

### 🔁 Configuration Replication
- Promote tested configurations from dev to prod
- Standardize policies across multiple tenants
- Template configurations for new deployments

## Parameters

### `-OutputPath`
**Type:** String  
**Required:** No  
**Default:** Current directory (`$PWD`)

Directory where the timestamped backup folder will be created. The function automatically creates a subfolder structure: `GSA-backup_[timestamp]/InternetAccess/`

### `-IncludeConditionalAccessPolicies`
**Type:** Switch  
**Required:** No

When specified:
- Exports Conditional Access policy assignments linked to security profiles
- Includes user UPNs and group display names
- Requires additional Graph API permissions (see Prerequisites below)
- Forces Security Profiles CSV creation even if no profiles exist

:::note User/Group Resolution
The function resolves Azure AD user IDs to UPNs and group IDs to display names. Uses internal caching to minimize Graph API calls. Guest/external user assignments are logged but not exported to CSV.
:::

### `-LogPath`
**Type:** String  
**Required:** No  
**Default:** Created in backup folder as `[timestamp]_Export-EIA.log`

Custom path for the export log file. Useful when centralizing logs or integrating with monitoring systems.

## Restoration Process

Once exported, restoration uses the existing provisioning function:

```powershell
# Edit the CSV files to set Provision=yes for desired policies

# Restore Internet Access configuration
Start-EntraInternetAccessProvisioning `
    -PoliciesCSVPath "path\to\EIA_Policies.csv" `
    -SecurityProfilesCSVPath "path\to\EIA_SecurityProfiles.csv" `
    -OutputPath "C:\EIA-Restore-Results"
```

For complete provisioning details, see [Entra Internet Access Provisioning](../../Provision/EntraInternetAccessProvisioning.md).

## Prerequisites

### PowerShell Requirements
- **PowerShell 7.0 or later** (required)
- **Migrate2GSA module** installed and imported
- **Microsoft.Graph.Authentication module** installed

### Microsoft Graph Connection
You must be connected to Microsoft Graph before running this function:

```powershell
# Basic connection for policies and profiles only
Connect-MgGraph -Scopes "NetworkAccessPolicy.Read.All"

# Connection including Conditional Access policy export
Connect-MgGraph -Scopes "NetworkAccessPolicy.Read.All","Policy.Read.All","User.Read.All","Directory.Read.All"
```

The function validates your Graph connection and required scopes before proceeding.

### Required Permission Scopes

| Scope | Required For | Permission Level |
|-------|--------------|------------------|
| `NetworkAccessPolicy.Read.All` | EIA policies and security profiles | **Always required** |
| `Policy.Read.All` | Conditional Access policies | Only if `-IncludeConditionalAccessPolicies` specified |
| `User.Read.All` | Resolve user IDs to UPNs | Only if `-IncludeConditionalAccessPolicies` specified |
| `Directory.Read.All` | Resolve group IDs to names | Only if `-IncludeConditionalAccessPolicies` specified |

:::tip Read-Only Operations
All operations are read-only. The function does not modify your tenant configuration.
:::

### Global Secure Access Tenant Status
Your tenant must be onboarded to Global Secure Access. The function validates tenant status before export and will fail if GSA is not activated.

## Features

✅ **Complete Configuration Export**
- Web Content Filtering policies with FQDN, URL, and web category rules
- TLS Inspection policies with bypass/inspect rules and priorities
- Security Profiles with policy links and priority ordering

✅ **Conditional Access Integration**
- Optional export of CA policy assignments
- User and group resolution with internal caching
- Minimal Graph API calls through intelligent caching

✅ **Production-Ready Output**
- Timestamped backup folders for organization
- CSV format compatible with provisioning functions
- Comprehensive logging with component-level tracing
- Progress indicators for long-running operations
- Creates consistent output structure even when no policies exist

✅ **Performance Optimized**
- User and group caching minimizes API calls
- Progress reporting for large configurations
- Detailed summary report with performance metrics

## Examples

### Example 1: Basic Export to Current Directory
```powershell
Export-EntraInternetAccessConfig
```
Creates `.\GSA-backup_[timestamp]\InternetAccess\` with policies and security profiles.

### Example 2: Export to Specific Location
```powershell
Export-EntraInternetAccessConfig -OutputPath "C:\GSA-Backups"
```
Creates `C:\GSA-Backups\GSA-backup_[timestamp]\InternetAccess\`

### Example 3: Include Conditional Access Policies
```powershell
# Ensure you're connected with required scopes
Connect-MgGraph -Scopes "NetworkAccessPolicy.Read.All","Policy.Read.All","User.Read.All","Directory.Read.All"

Export-EntraInternetAccessConfig -IncludeConditionalAccessPolicies
```
Exports policies, profiles, and CA policy assignments with user/group resolution.

### Example 4: Custom Output and Log Paths
```powershell
Export-EntraInternetAccessConfig `
    -OutputPath "C:\Backups\GSA" `
    -LogPath "C:\Logs\EIA-Export_$(Get-Date -Format 'yyyyMMdd').log"
```
Separate backup and log locations for enterprise backup procedures.

### Example 5: Scheduled Backup via Task
```powershell
# Daily backup script
$timestamp = Get-Date -Format "yyyyMMdd"
$backupPath = "\\fileserver\GSA-Backups\$timestamp"

# Connect with app-based authentication
Connect-MgGraph -ClientId $appId -TenantId $tenantId -CertificateThumbprint $certThumb

Export-EntraInternetAccessConfig -OutputPath $backupPath -IncludeConditionalAccessPolicies
```
Automated backup with service principal authentication.

## Related Documentation

- ✅ **[EPA Export](./EPAExport.md)** - Export Private Access configurations
- **[Entra Internet Access Provisioning](../../Provision/EntraInternetAccessProvisioning.md)** - Restore/provision EIA configurations from CSV
- **[Working with CSVs](../../WorkingWithCSVs/eia-csv-configuration.md)** - CSV format reference and validation
- **[Migration Workflow](../../migration-workflow.md)** - Overall 4-phase migration process
- **[ZIA to EIA Migration](../ZScaler/ZIA2EIA.md)** - Migrate from Zscaler Internet Access

---

**Last Updated:** February 27, 2026  
**Status:** ✅ Available — Production ready  
**Version:** 1.0
