---
sidebar_position: 3
title: Entra Private Access App Discovery
description: Export Entra Private Access App Discovery data to CSV for application onboarding and provisioning.
keywords: [Entra Private Access, EPA, app discovery, application onboarding, Global Secure Access]
---

# Export Entra Private Access App Discovery

## Overview

The `Export-EntraPrivateAccessAppDiscovery` function exports App Discovery data from Microsoft Entra Private Access to a CSV file compatible with `Start-EntraPrivateAccessProvisioning`.

App Discovery captures network traffic flowing through the Global Secure Access client, revealing destination hosts and ports that users are actively accessing. This is especially useful for identifying traffic flowing through the Quick Access application (catch-all) that should be converted into dedicated named Enterprise applications for better governance and access control.

For each discovered segment, the function also resolves the list of users who accessed it, populating the `EntraUsers` column with their UPNs.

## Output Structure

```
GSA-backup_yyyyMMdd_HHmmss/
└── PrivateAccess/
    ├── yyyyMMdd_HHmmss_EPA_AppDiscovery.csv
    └── yyyyMMdd_HHmmss_Export-EPA-Discovery.log
```

### CSV Columns

| Column | Description |
|--------|-------------|
| `SegmentId` | Auto-generated ID (`SEG-D-000001`) |
| `OriginalAppName` | Generated name based on the destination host |
| `EnterpriseAppName` | Placeholder — set this to group segments into apps |
| `destinationHost` | FQDN or IP address |
| `DestinationType` | `FQDN` or `ipAddress` |
| `Protocol` | Transport protocol (TCP, UDP) |
| `Ports` | Port number |
| `EntraGroups` | Entra groups to assign (blank — fill in before provisioning) |
| `EntraUsers` | Pre-populated UPNs from discovery data |
| `ConnectorGroup` | Placeholder — set to your connector group name |
| `Provision` | `No` by default — set to `Yes` for rows to provision |
| `isQuickAccess` | Always `no` (segments are provisioned into Enterprise apps) |
| `DiscoveryAccessType` | Original access type from the API (`quickAccess` or `appAccess`) |
| `FirstAccessDateTime` | First observed access |
| `LastAccessDateTime` | Last observed access |
| `TransactionCount` | Number of transactions |
| `UserCount` | Number of unique users |
| `DeviceCount` | Number of unique devices |
| `TotalBytesSent` / `TotalBytesReceived` | Traffic volume |
| `DiscoveredApplicationSegmentId` | API segment identifier |

## Prerequisites

- **PowerShell 7+** with the Migrate2GSA module loaded
- **Microsoft.Graph.Authentication** module
- Active Graph connection with scopes: `NetworkAccess.Read.All`, `NetworkAccessPolicy.Read.All`
- Global Secure Access tenant onboarded with Private Access enabled

## Parameters

### `-OutputPath`
**Type:** String | **Default:** Current directory

Directory where the timestamped backup folder will be created.

### `-DaysBack`
**Type:** Int | **Default:** `30` | **Range:** 1–180

Number of days back from today for the discovery window.

### `-AccessTypeFilter`
**Type:** String | **Default:** `quickAccess` | **Values:** `quickAccess`, `appAccess`, `all`

Filter discovered segments by access type.

### `-Top`
**Type:** Int | **Default:** `500` | **Range:** 1–5000

Maximum number of records to return (ordered by user count descending).

### `-LogPath`
**Type:** String | **Default:** Auto-generated in backup folder

Custom path for the log file.

## Examples

```powershell
# Export quickAccess segments from the last 30 days (defaults)
Export-EntraPrivateAccessAppDiscovery

# Export all access types
Export-EntraPrivateAccessAppDiscovery -AccessTypeFilter all

# Last 90 days to a custom location
Export-EntraPrivateAccessAppDiscovery -DaysBack 90 -OutputPath "C:\GSA-Backups"

# Retrieve up to 2000 segments
Export-EntraPrivateAccessAppDiscovery -Top 2000 -AccessTypeFilter all
```

## Workflow: Discovery to Provisioning

1. **Export** discovery data:
   ```powershell
   Export-EntraPrivateAccessAppDiscovery -DaysBack 30
   ```
2. **Review** the CSV and edit:
   - Set `EnterpriseAppName` to group segments into logical applications
   - Set `ConnectorGroup` to your connector group name
   - Optionally add `EntraGroups` for access assignment
   - Set `Provision=Yes` for rows to provision
3. **Provision** the applications:
   ```powershell
   Start-EntraPrivateAccessProvisioning -ProvisioningConfigPath ".\GSA-backup_...\PrivateAccess\..._EPA_AppDiscovery.csv"
   ```
