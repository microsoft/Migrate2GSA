---
sidebar_position: 1
title: Export Cisco Umbrella Config
---

## Overview

`Export-CiscoUmbrellaConfig` extracts Cisco Umbrella configuration from an **HTTP Archive (HAR) file** captured while browsing the Umbrella dashboard. Unlike the other Export functions in this module (which call vendor APIs directly), this function parses a local HAR file to reconstruct the full configuration — no live API access or credentials are required.

**Why HAR-based?** The Cisco Umbrella dashboard uses internal APIs (`api.opendns.com` and `api.umbrella.com`) that are not part of Cisco's public API surface. Capturing a HAR file while browsing the dashboard is the most reliable way to obtain the complete configuration data.

The function extracts **8 configuration object types**:

| # | Object Type | Output File |
|---|------------|-------------|
| 1 | DNS Policies | `dns_policies.json` |
| 2 | Firewall Rules | `firewall_rules.json` |
| 3 | Web Policies | `web_policies.json` |
| 4 | Destination Lists | `destination_lists.json` |
| 5 | Category Settings | `category_settings.json` |
| 6 | Application Settings | `application_settings.json` |
| 7 | Security Settings | `security_settings.json` |
| 8 | Selective Decryption Lists | `selective_decryption_lists.json` |

## Prerequisites

- PowerShell 7.0 or higher
- `Migrate2GSA` PowerShell module installed
- Microsoft Edge (or Google Chrome — the steps are the same)
- Cisco Umbrella dashboard access with sufficient permissions to view all policy sections
- No network access or API credentials are required at export time — only the HAR file

---

## Step 1: Capture the HAR File

A HAR (HTTP Archive) file records all browser network requests and responses. You need to capture one while browsing through **every configuration section** of the Umbrella dashboard so that the API responses for all objects are included.

### 1.1 Log In and Open Developer Tools

1. Open **Microsoft Edge** (or Chrome)
2. Navigate to the Cisco Umbrella dashboard and **log in**
3. Once logged in and on the dashboard home page, press **F12** to open Developer Tools (or right-click anywhere and select **Inspect**)
4. Click the **Network** tab in the Developer Tools panel

<!-- TODO: Screenshot — Edge DevTools with Network tab selected -->

5. Ensure the following settings are configured:
   - **Preserve log** is checked (this prevents the log from clearing when pages navigate)
   - The red recording dot is active (recording is ON)

<!-- TODO: Screenshot — Network tab with Preserve log checkbox highlighted -->

:::tip Why start after login?
Opening Developer Tools **after** logging in ensures that your login credentials are not captured in the HAR file. The HAR only needs the API responses from browsing configuration pages — not the authentication flow.
:::

### 1.2 Browse All Configuration Sections

After logging in, you need to visit each section of the dashboard **and expand/click into individual items** so that the browser fetches their full detail data. The dashboard loads summary data on list pages but fetches expanded details only when you click into each item.

:::warning Important
Simply visiting the list pages is not enough. You must **click into each individual item** (policy, setting, list) to trigger the detail API calls. The detail responses contain additional fields (category arrays, application lists, rule settings) that are not present in the summary views.
:::

Follow this sequence, clicking through every item in each section:

---

#### DNS Policies

1. Navigate to **Policies** > **DNS Policies**
2. The list view loads automatically — this captures the policy list with embedded settings
3. **Click on each DNS policy** to open its detail view
4. Wait for the page to fully load before moving to the next policy

<!-- TODO: Screenshot — DNS Policies list page -->
<!-- TODO: Screenshot — DNS Policy detail view -->

---

#### Firewall Policy

1. Navigate to **Policies** > **Firewall Policy**
2. The firewall ruleset loads automatically in a single view
3. If there are more than 25 rules, **scroll down** or navigate to subsequent pages to load all rules

<!-- TODO: Screenshot — Firewall Policy page -->

---

#### Web Policy

1. Navigate to **Policies** > **Web Policy**
2. The list view loads the web policy bundles
3. **Click on each web policy** to open its detail view — this triggers the proxy ruleset and ruleset settings API calls
4. Wait for the page to fully load before moving to the next policy

<!-- TODO: Screenshot — Web Policy list page -->
<!-- TODO: Screenshot — Web Policy detail view -->

---

#### Destination Lists

1. Navigate to **Policies** > **Policy Components** > **Destination Lists**
2. The list view loads automatically
3. **Click on each destination list** to view its entries — this triggers the destinations detail API calls
4. If a list has many entries, **scroll through** or page through all entries to ensure they are captured

<!-- TODO: Screenshot — Destination Lists page -->
<!-- TODO: Screenshot — Destination List detail with entries -->

---

#### Content Categories (Category Settings)

1. Navigate to **Policies** > **Policy Components** > **Content Categories**
2. The list view loads the category settings summaries
3. **Click on each category setting** to expand it

<!-- TODO: Screenshot — Content Categories list -->
<!-- TODO: Screenshot — Content Category detail view -->

---

#### Application Settings

1. Navigate to **Policies** > **Policy Components** > **Application Settings**
2. The list view loads application setting summaries
3. **Click on each application setting** to expand it

<!-- TODO: Screenshot — Application Settings list -->
<!-- TODO: Screenshot — Application Setting detail view -->

---

#### Security Settings

1. Navigate to **Policies** > **Policy Components** > **Security Settings**
2. **Click on each security setting** to open its detail view — detail responses use datetime strings instead of epoch timestamps

<!-- TODO: Screenshot — Security Settings list -->
<!-- TODO: Screenshot — Security Setting detail view -->

---

#### Selective Decryption Lists

1. Navigate to **Policies** > **Policy Components** > **Selective Decryption**
2. The list view loads the selective decryption list settings
3. **Click on each list** to view its detail if any are present

<!-- TODO: Screenshot — Selective Decryption Lists page -->

---

### 1.3 Export the HAR File

Once you have browsed through **all** sections above:

1. Return to the **Network** tab in Developer Tools
2. Right-click anywhere in the request list
3. Select **Save all as HAR with content** (in Edge) or **Save all as HAR** (in Chrome)

<!-- TODO: Screenshot — Right-click menu with "Save all as HAR with content" highlighted -->

4. Save the file with a `.har` extension (e.g., `umbrella_dashboard.har`)
5. Close Developer Tools

:::tip File Size
HAR files are typically **50–200 MB** because they include all response bodies (HTML, CSS, JS, images). This is expected — the export function filters to only the relevant API responses (~2–5 MB of actual configuration data).
:::

---

## Step 2: Run the Export

### Syntax

```powershell
Export-CiscoUmbrellaConfig
    -HARFilePath <String>
    [-OutputDirectory <String>]
    [-ExportCleanHAR]
    [<CommonParameters>]
```

### Parameters

#### -HARFilePath

Path to the `.har` file captured from the Umbrella dashboard.

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

Export-CiscoUmbrellaConfig -HARFilePath "C:\captures\umbrella_dashboard.har"
```

Creates a backup folder in the current directory with all extracted configuration files.

#### Export to Custom Directory

```powershell
Export-CiscoUmbrellaConfig `
    -HARFilePath "C:\captures\umbrella_dashboard.har" `
    -OutputDirectory "C:\Backups\Umbrella"
```

#### Export a Sanitized HAR for Sharing

```powershell
Export-CiscoUmbrellaConfig `
    -HARFilePath "C:\captures\umbrella_dashboard.har" `
    -ExportCleanHAR
```

Produces **only** `umbrella_clean.har` — no JSON extraction is performed. The clean HAR has:
- All non-API entries removed (HTML, CSS, JS, images, analytics)
- `Authorization`, `Cookie`, `Set-Cookie`, `X-CSRF-Token`, and `X-Auth*` headers stripped
- Cookie arrays cleared

:::tip Sharing HAR files
Always use `-ExportCleanHAR` before sharing a HAR file. The original HAR contains **session tokens and cookies** that could be used to access your Umbrella account.
:::

#### Debug Mode

```powershell
Export-CiscoUmbrellaConfig `
    -HARFilePath "C:\captures\umbrella_dashboard.har" `
    -Debug
```

---

## Output Structure

### Full Export (default)

```
CiscoUmbrella-backup_{timestamp}/
├── dns_policies.json
├── firewall_rules.json
├── web_policies.json
├── destination_lists.json
├── category_settings.json
├── application_settings.json
├── security_settings.json
├── selective_decryption_lists.json
├── export_metadata.json
└── {timestamp}_Export-CiscoUmbrella.log
```

### Clean HAR Export (`-ExportCleanHAR`)

```
CiscoUmbrella-backup_{timestamp}/
├── umbrella_clean.har
└── {timestamp}_Export-CiscoUmbrella.log
```

### Export Metadata

The `export_metadata.json` file records provenance and summary counts:

```json
{
    "timestamp": "20260220_143022",
    "sourceHARFile": "umbrella_dashboard.har",
    "organizationId": "8144773",
    "exportType": "CiscoUmbrella_HAR_Extract",
    "objectCounts": {
        "dnsPolicies": 3,
        "firewallRules": 2,
        "webPolicies": 1,
        "destinationLists": 5,
        "categorySettings": 5,
        "applicationSettings": 3,
        "securitySettings": 4,
        "selectiveDecryptionLists": 1
    },
    "warnings": []
}
```

---

## Configuration Objects Exported

| Object Type | Description |
|------------|-------------|
| **DNS Policies** | DNS filtering policy bundles with embedded category, security, and policy settings. Enriched with individual policy setting details when available. |
| **Firewall Rules** | Firewall ruleset with all rules. Includes hit count interval reference data when present. |
| **Web Policies** | Web filtering policy bundles with proxy rulesets and ruleset settings attached. |
| **Destination Lists** | Custom allow/block lists with their destination entries (domains, IPs, URLs). |
| **Category Settings** | Web content category configurations with full `categories[]` and `warnCategories[]` arrays. |
| **Application Settings** | Application control settings with `applications[]` and `applicationsCategories[]` arrays. Includes system-inherited settings. |
| **Security Settings** | Security threat protection settings with category details. MSP-inherited records are tagged with `_isInherited: true`. |
| **Selective Decryption Lists** | SSL/TLS inspection bypass settings with linked exception domain lists. |

---

## Troubleshooting

### "No Cisco Umbrella API requests found in the HAR file"

**Cause**: The HAR file doesn't contain any requests to `api.opendns.com` or `api.umbrella.com`.

**Solution**:
- Verify you captured the HAR while browsing the **Umbrella dashboard** (not another Cisco product)
- Ensure **Preserve log** was checked before navigating
- Make sure the capture was running while you were logged in and browsing configuration pages

### Missing object types (empty JSON arrays)

**Cause**: You didn't browse the corresponding dashboard section during the HAR capture.

**Solution**:
- Recapture the HAR, making sure to visit **all** sections listed in [Step 1.2](#12-browse-all-configuration-sections)
- Remember to **click into each individual item** — list pages alone don't trigger detail API calls

### "The file is not a valid HAR/JSON file"

**Cause**: The file is corrupted or not a valid HAR export.

**Solution**:
- Re-export the HAR from the browser
- Ensure you selected **Save all as HAR with content** (not just headers)
- Check the file opens in a text editor and starts with `{ "log":`

### Objects exported with list-level data only (warnings about missing details)

**Cause**: You visited the list page but didn't click into individual items.

**Solution**: Recapture the HAR and click on each item in the section to trigger the detail API calls. The log file will indicate which items fell back to list-level data.

---

## Logging

All output is logged to `{timestamp}_Export-CiscoUmbrella.log` in the backup folder. The function uses the following log levels:

| Level | Description |
|-------|-------------|
| **INFO** | General progress and statistics |
| **SUCCESS** | Successful extractions with item names and counts |
| **WARN** | Missing data, fallback to list-level data |
| **ERROR** | Failures that prevent extraction of a specific type |
| **SUMMARY** | Section headers and configuration summaries |
| **DEBUG** | Detailed diagnostic information (requires `-Debug`) |

---

## Feedback and Support

For issues, questions, or feedback, please refer to the main repository documentation.
