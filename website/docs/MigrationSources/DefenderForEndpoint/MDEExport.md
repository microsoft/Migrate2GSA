---
sidebar_position: 1
title: Export MDE Web Filtering Config
---

## Overview

`Export-MDEWebFilteringConfig` extracts Microsoft Defender for Endpoint (MDE) web filtering configuration from an **HTTP Archive (HAR) file** captured while browsing the `security.microsoft.com` portal. Like the Cisco Umbrella export, this function parses a local HAR file to reconstruct the configuration — no live API access or credentials are required.

**Why HAR-based?** The MDE portal uses internal proxy API endpoints (`/apiproxy/mtp/`) that route to backend microservices. These endpoints are session-authenticated via the portal and are not part of the official public MDE API surface. Capturing a HAR file while browsing the relevant dashboard pages is the most reliable way to obtain the complete configuration data.

The function extracts **4 configuration object types**:

| # | Object Type | Output File |
|---|------------|-------------|
| 1 | Web Content Filtering Policies | `wcf_policies.json` |
| 2 | Custom Indicators — IP | `ip_indicators.json` |
| 3 | Custom Indicators — URL/Domain | `url_indicators.json` |
| 4 | Device Groups (Machine Groups) | `device_groups.json` |

## Prerequisites

- PowerShell 7.0 or higher
- `Migrate2GSA` PowerShell module installed
- Microsoft Edge (or Google Chrome)
- Access to the [Microsoft Defender portal](https://security.microsoft.com) with sufficient permissions to view web filtering settings and indicators
- No network access or API credentials are required at export time — only the HAR file

---

## Step 1: Capture the HAR File

A HAR (HTTP Archive) file records all browser network requests and responses. You need to capture one while browsing through the relevant configuration sections of the Defender portal so that the API responses for all objects are included.

### 1.1 Log In and Open Developer Tools

1. Open **Microsoft Edge** (or Chrome)
2. Navigate to [https://security.microsoft.com](https://security.microsoft.com) and **log in**
3. Once logged in and on the portal home page, press **F12** to open Developer Tools (or right-click anywhere and select **Inspect**)
4. Click the **Network** tab in the Developer Tools panel
5. Ensure the following settings are configured:
   - **Preserve log** is checked (this prevents the log from clearing when pages navigate)
   - The red recording dot is active (recording is ON)

:::tip Why start after login?
Opening Developer Tools **after** logging in ensures that your login credentials are not captured in the HAR file. The HAR only needs the API responses from browsing configuration pages — not the authentication flow.
:::

### 1.2 Browse All Configuration Sections

After opening Developer Tools with the Network tab active, visit each of the following sections. Wait for each page to fully load before moving to the next.

---

#### Web Content Filtering Policies

1. In the left navigation, go to **Settings** > **Endpoints** > **Web content filtering**
   - Direct URL: `https://security.microsoft.com/securitysettings/endpoints/web_content_filtering`
2. The policy list loads automatically — this captures all WCF policies with their blocked/audited category assignments and device group scoping

---

#### Custom Indicators — URLs/Domains

1. Navigate to **Settings** > **Endpoints** > **Indicators** > **URLs/Domains** tab
   - Direct URL: `https://security.microsoft.com/securitysettings/endpoints/custom_ti_indicators/url`
2. The indicator list loads automatically
3. If you have more than one page of indicators, **scroll down** or navigate to subsequent pages to ensure all paginated responses are captured

---

#### Custom Indicators — IP Addresses

1. Navigate to **Settings** > **Endpoints** > **Indicators** > **IP addresses** tab
   - Direct URL: `https://security.microsoft.com/securitysettings/endpoints/custom_ti_indicators/ip`
2. The indicator list loads automatically
3. If you have more than one page of indicators, scroll through all pages

---

#### Device Groups

1. Navigate to **Settings** > **Endpoints** > **Device groups**
   - Direct URL: `https://security.microsoft.com/securitysettings/endpoints/rbac/machine_groups`
2. The device group list loads automatically — this captures all machine groups with their membership rules and Entra ID group assignments

---

### 1.3 Export the HAR File

Once you have browsed through **all** sections above:

1. Return to the **Network** tab in Developer Tools
2. Right-click anywhere in the request list
3. Select **Save all as HAR with content** (in Edge) or **Save all as HAR** (in Chrome)
4. Save the file with a `.har` extension (e.g., `mde_portal.har`)
5. Close Developer Tools

:::tip File Size
HAR files are typically **50–200 MB** because they include all response bodies (HTML, CSS, JS, images). This is expected — the export function filters to only the relevant API responses.
:::

---

## Step 2: Run the Export

### Syntax

```powershell
Export-MDEWebFilteringConfig
    -HARFilePath <String>
    [-OutputDirectory <String>]
    [-ExportCleanHAR]
    [<CommonParameters>]
```

### Parameters

#### -HARFilePath

Path to the `.har` file captured from the MDE portal.

- **Type**: String
- **Required**: Yes
- **Validation**: File must exist and have a `.har` extension

#### -OutputDirectory

Directory where the timestamped backup folder will be created.

- **Type**: String
- **Required**: No
- **Default value**: Current directory

#### -ExportCleanHAR

When specified, produces **only** a sanitized copy of the HAR file (sensitive headers removed, non-API entries stripped) and skips configuration extraction. This is useful for sharing the HAR with support teams.

- **Type**: Switch
- **Required**: No
- **Default value**: `$false`

### Examples

#### Basic Export

```powershell
Import-Module Migrate2GSA

Export-MDEWebFilteringConfig -HARFilePath "C:\captures\mde_portal.har"
```

Creates a backup folder in the current directory with all extracted configuration files.

#### Export to Custom Directory

```powershell
Export-MDEWebFilteringConfig `
    -HARFilePath "C:\captures\mde_portal.har" `
    -OutputDirectory "C:\Backups\MDE"
```

#### Export a Sanitized HAR for Sharing

```powershell
Export-MDEWebFilteringConfig `
    -HARFilePath "C:\captures\mde_portal.har" `
    -ExportCleanHAR
```

Produces **only** `mde_clean.har` — no JSON extraction is performed. The clean HAR has:
- All non-API entries removed (HTML, CSS, JS, images, analytics)
- `Authorization`, `Cookie`, `Set-Cookie`, `x-xsrf-token`, and `X-Auth*` headers stripped
- Cookie arrays cleared

:::tip Sharing HAR files
Always use `-ExportCleanHAR` before sharing a HAR file. The original HAR contains **session tokens and cookies** that could be used to access your account.
:::

---

## Output Structure

### Full Export (default)

```
MDE-backup_{timestamp}/
├── wcf_policies.json
├── ip_indicators.json
├── url_indicators.json
├── device_groups.json
├── export_metadata.json
└── {timestamp}_Export-MDEWebFilteringConfig.log
```

### Clean HAR Export (`-ExportCleanHAR`)

```
MDE-backup_{timestamp}/
├── mde_clean.har
└── {timestamp}_Export-MDEWebFilteringConfig.log
```

### Export Metadata

The `export_metadata.json` file records provenance and summary counts:

```json
{
    "timestamp": "20260226_143022",
    "sourceFile": "C:\\captures\\mde_portal.har",
    "sourceFileSizeBytes": 52428800,
    "tenantId": "322950bf-0bad-4bfa-990e-3f7e1747b5a6",
    "exportFunction": "Export-MDEWebFilteringConfig",
    "exportModuleVersion": "0.x.x",
    "objectCounts": {
        "wcfPolicies": 2,
        "ipIndicators": 1,
        "urlIndicators": 1,
        "deviceGroups": 2
    },
    "warnings": []
}
```

---

## Configuration Objects Exported

| Object Type | Description |
|------------|-------------|
| **WCF Policies** | Web content filtering policies with category IDs resolved to human-readable names. Blocked and audited categories are listed separately. Device group scoping is resolved to group names. |
| **IP Indicators** | Custom IP address indicators with action (Block, Allow, Warn, AlertOnly), severity, and device group scoping resolved. Paginated responses are merged automatically. |
| **URL/Domain Indicators** | Custom URL and domain indicators with the same enrichment as IP indicators. Both URL and DomainURL types are included. |
| **Device Groups** | Machine groups with automation level and group rule enums resolved to strings. Includes Entra ID group assignments when available. |

---

## Troubleshooting

### "No MDE API requests found in the HAR file"

**Cause**: The HAR file doesn't contain any requests to `security.microsoft.com/apiproxy/mtp/`.

**Solution**:
- Verify you captured the HAR while browsing the **Microsoft Defender portal** (not another Microsoft portal)
- Ensure **Preserve log** was checked before navigating
- Make sure the capture was running while you were logged in and browsing the configuration pages listed in [Step 1.2](#12-browse-all-configuration-sections)

### Missing object types (empty JSON arrays)

**Cause**: You didn't browse the corresponding portal section during the HAR capture.

**Solution**: Recapture the HAR, making sure to visit **all** sections listed in Step 1.2. The log file will indicate which object types were not found.

### "The file is not a valid HAR/JSON file"

**Cause**: The file is corrupted or not a valid HAR export.

**Solution**:
- Re-export the HAR from the browser
- Ensure you selected **Save all as HAR with content** (not just headers)
- Check the file opens in a text editor and starts with `{ "log":`

### "Could not detect tenant ID from HAR entries"

**Cause**: The HAR entries don't contain the `x-tid` or `tenant-id` request headers.

**Solution**: Ensure the HAR was captured while browsing the MDE portal after logging in. The tenant ID header is attached to every API call made by the portal.

---

## Logging

All output is logged to `{timestamp}_Export-MDEWebFilteringConfig.log` in the backup folder. The function uses the following log levels:

| Level | Description |
|-------|-------------|
| **INFO** | General progress and statistics |
| **SUCCESS** | Successful extractions with item names and counts |
| **WARN** | Missing data, unknown category/group IDs |
| **ERROR** | Failures that prevent extraction |
| **SUMMARY** | Section headers and configuration summaries |
| **DEBUG** | Detailed diagnostic information (requires `-Debug`) |

---

## Feedback and Support

For issues, questions, or feedback, please refer to the main repository documentation.
