---
sidebar_position: 2
title: Entra Internet Access Export
---

# Export Entra Internet Access Configuration

:::info Coming Soon
The `Export-EntraInternetAccessConfig` function is currently under development. This page provides a preview of the planned functionality.
:::

## Overview

The `Export-EntraInternetAccessConfig` function will export your complete Microsoft Entra Internet Access (EIA) configuration to CSV format, enabling backup, disaster recovery, tenant-to-tenant migrations, and configuration replication scenarios.

Similar to the [EPA Export](./EPAExport.md) functionality, this will export directly from your existing Global Secure Access tenant, creating CSV files compatible with the provisioning function for seamless restoration.

## Planned Export Scope

### What Will Be Exported

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

The function will generate two CSV files in a timestamped backup folder:

```
GSA-backup_yyyyMMdd_HHmmss/
└── InternetAccess/
    ├── yyyyMMdd_HHmmss_EIA_Policies.csv
    ├── yyyyMMdd_HHmmss_EIA_SecurityProfiles.csv
    └── yyyyMMdd_HHmmss_Export-EIA.log
```

## Planned Use Cases

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

## Planned Parameters

### `-OutputPath`
Directory where the timestamped backup folder will be created.

### `-IncludeConditionalAccessPolicies`
Include Conditional Access policy assignments in the Security Profiles export (requires additional permissions).

### `-LogPath`
Custom location for the log file (defaults to backup folder).

## Restoration Process

Once exported, restoration will use the existing provisioning function:

```powershell
# Edit the CSV files to set Provision=yes for desired policies

# Restore Internet Access configuration
Start-EntraInternetAccessProvisioning `
    -PoliciesCSVPath "path\to\EIA_Policies.csv" `
    -SecurityProfilesCSVPath "path\to\EIA_SecurityProfiles.csv" `
    -OutputPath "C:\EIA-Restore-Results"
```

For complete provisioning details, see [Entra Internet Access Provisioning](../../Provision/EntraInternetAccessProvisioning.md).

## Prerequisites (Planned)

### PowerShell Requirements
- PowerShell 7.0 or later
- Migrate2GSA module

### Microsoft Graph Requirements
- Active Microsoft Graph connection
- Microsoft.Graph.Authentication module

### Permission Scopes (Read-Only)
- `NetworkAccessPolicy.Read.All` - Read EIA policies and security profiles
- `Policy.Read.All` - Read Conditional Access policies (if `-IncludeConditionalAccessPolicies` specified)
- `User.Read.All` and `Directory.Read.All` - Read user/group assignments (if including CA policies)

## Current Status

This function is planned for implementation following the same architecture and patterns as `Export-EntraPrivateAccessConfig`:

- ✅ **Technical specification completed** - See [Specs/Export/20260212-Export-EntraInternetAccessConfig.md](/Specs/Export/20260212-Export-EntraInternetAccessConfig.md)
- ✅ **CSV format defined** - Output compatible with existing provisioning function
- ⏳ **Implementation in progress** - Function development underway
- ⏳ **Testing planned** - Validation with production tenant configurations

## Example Usage (Preview)

Once available, the function will work similarly to EPA export:

```powershell
# Basic export
Export-EntraInternetAccessConfig

# Export to specific location
Export-EntraInternetAccessConfig -OutputPath "C:\GSA-Backups"

# Include Conditional Access policy assignments
Export-EntraInternetAccessConfig -IncludeConditionalAccessPolicies

# Custom output and log paths
Export-EntraInternetAccessConfig `
    -OutputPath "C:\Backups" `
    -LogPath "C:\Logs\EIA-Export.log"
```

## Related Documentation

- ✅ **[EPA Export](./EPAExport.md)** - Available now for Private Access configurations
- [Entra Internet Access Provisioning](../../Provision/EntraInternetAccessProvisioning.md) - Restore/provision EIA configurations
- [Migration Workflow](../../migration-workflow.md) - Overall migration process
- [ZIA to EIA Migration](../ZScaler/ZIA2EIA.md) - Alternative: Migrate from Zscaler Internet Access

## Need This Feature Now?

If you have an immediate need for EIA export functionality:

1. **Contact the team:** migrate2gsateam@microsoft.com
2. **Share your use case:** Help us prioritize development based on real-world scenarios
3. **Manual export alternative:** For now, you can manually document your EIA policies and convert to CSV format matching the [provisioning function schema](../../Provision/EntraInternetAccessProvisioning.md)

## Updates

Check back for updates on this feature, or watch the [GitHub repository](https://github.com/microsoft/Migrate2GSA) for implementation progress.

---

**Last Updated:** February 20, 2026  
**Status:** Specification complete, implementation in progress
