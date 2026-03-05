# Export Microsoft Defender for Endpoint Web Filtering Configuration from HAR File — Technical Specification

**Version:** 1.0  
**Date:** February 26, 2026  
**Status:** Draft  
**Target Module:** Migrate2GSA  
**Function Name:** Export-MDEWebFilteringConfig  
**Function Location:** `Migrate2GSA/functions/DefenderEndpoint/Export-MDEWebFilteringConfig.ps1`  
**Author:** Andres Canello

---

## Overview

This specification defines a PowerShell function that **extracts Microsoft Defender for Endpoint (MDE) web filtering configuration from an HTTP Archive (HAR) file** captured while browsing the `security.microsoft.com` portal. This function parses a local HAR file to reconstruct the configuration without requiring live API access or credentials.

**Why HAR-based?** The MDE portal uses internal proxy API endpoints (`/apiproxy/mtp/`) that route to backend microservices. These endpoints are session-authenticated via the portal and are not part of the official public MDE API surface. Capturing a HAR file while browsing the relevant dashboard pages is the most reliable way to obtain the complete configuration data.

**Reference:** All API endpoints, request/response structures, and extraction logic are documented in [MDE_API_Analysis.md](MDE_API_Analysis.md).

---

## 1. Function Definition

### 1.1 Function Name

```powershell
Export-MDEWebFilteringConfig
```

### 1.2 Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-HARFilePath` | String | Yes | — | Absolute or relative path to the `.har` file captured from the MDE portal |
| `-OutputDirectory` | String | No | Current directory | Directory where the timestamped backup folder will be created |
| `-ExportCleanHAR` | Switch | No | `$false` | When specified, **only** produces a sanitized copy of the HAR file (sensitive headers removed, non-API entries stripped) and skips configuration extraction |

### 1.3 Parameter Validation Rules

**HARFilePath:**
- Must exist on disk (`ValidateScript` with `Test-Path`)
- Must have `.har` extension
- File must be readable

**OutputDirectory:**
- If not specified, use current directory (`(Get-Location).Path`)
- Must have write permissions to create subfolder
- Created if it does not exist

**ExportCleanHAR:**
- Switch parameter; defaults to `$false`
- When present, **only** produces a sanitized HAR copy — no JSON extraction is performed
- This is an alternative operating mode, not an addition to the normal export

### 1.4 Prerequisites

- PowerShell 7.0 or higher (required by the Migrate2GSA module)
- No external modules required — all processing is local file I/O and JSON parsing
- No network access required

---

## 2. Configuration Objects to Extract

The function extracts **4 object types** from the HAR file, matching the core configuration sections relevant for web filtering migration.

| # | Object Type | API Path Pattern | Output File |
|---|------------|-----------------|-------------|
| 1 | Web Content Filtering Policies | `/apiproxy/mtp/userRequests/webcategory/policies` | `wcf_policies.json` |
| 2 | Custom Indicators — IP | `/apiproxy/mtp/papin/api/cloud/public/internal/indicators/getQuery?type=ip` | `ip_indicators.json` |
| 3 | Custom Indicators — URL/Domain | `/apiproxy/mtp/papin/api/cloud/public/internal/indicators/getQuery?type=url` | `url_indicators.json` |
| 4 | Device Groups (Machine Groups) | `/apiproxy/mtp/rbacManagementApi/rbac/machine_groups` | `device_groups.json` |

**Not extracted** (UI metadata only, not needed for migration): indicator counts, indicator filter values, machine counts per RBAC group, user exposed RBAC groups.

---

## 3. Output Structure

### 3.1 Folder Structure

**Normal mode (default):**
```
MDE-backup_{timestamp}/
├── wcf_policies.json
├── ip_indicators.json
├── url_indicators.json
├── device_groups.json
├── export_metadata.json
└── {timestamp}_Export-MDEWebFilteringConfig.log
```

**Sanitize mode (`-ExportCleanHAR`):**
```
MDE-backup_{timestamp}/
├── mde_clean.har
└── {timestamp}_Export-MDEWebFilteringConfig.log
```

### 3.2 Timestamp Format

- Format: `yyyyMMdd_HHmmss` (e.g., `20260226_143022`)
- Generated once at function start
- Used consistently for folder name, log file name, and metadata

### 3.3 Export Metadata File

`export_metadata.json` captures provenance information:

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

### 3.4 Individual JSON File Format

Each output file contains the extracted data as a JSON array. Enum values are resolved to human-readable strings. Category IDs in WCF policies are replaced with category names.

Example `wcf_policies.json`:
```json
[
    {
        "PolicyName": "MDE-Policy1",
        "BlockedCategories": ["Gambling"],
        "AuditCategories": ["Child Abuse Images", "Criminal activity", "Hacking"],
        "RbacGroupNames": ["All device groups"],
        "CreatedBy": "admin@contoso.com",
        "LastUpdateTime": "2026-02-25T10:58:14.5302747"
    }
]
```

---

## 4. HAR Parsing Strategy

### 4.1 HAR File Format

A HAR file is a JSON object with structure:
```json
{
    "log": {
        "version": "1.2",
        "creator": { "name": "...", "version": "..." },
        "entries": [
            {
                "request": { "method": "GET", "url": "...", "headers": [...] },
                "response": { "status": 200, "content": { "text": "..." }, "headers": [...] }
            }
        ]
    }
}
```

### 4.2 Relevant Host and Path

Only entries matching **both** criteria contain configuration data:

- **Host:** `security.microsoft.com`
- **Path:** starts with `/apiproxy/mtp/`

All other entries (dashboard HTML, CSS, JS, images, telemetry, CDN) are irrelevant and must be ignored.

### 4.3 Large File Handling — Filter-First Approach

HAR files can be large because they capture all response bodies including dashboard assets.

**Reading:** Use `[System.IO.File]::ReadAllText()` — significantly faster than `Get-Content -Raw` for large files.

**Parsing:** `ConvertFrom-Json` in PowerShell 7 uses `System.Text.Json` internally and handles large files efficiently.

**Memory optimization:**
1. Parse the full HAR into a `$har` object
2. Immediately filter `$har.log.entries` to only entries matching the host and path criteria
3. Store the filtered entries in `$relevantEntries`
4. Set `$har = $null` to release the full HAR object from memory

```powershell
# Step 1: Read and parse
$rawJson = [System.IO.File]::ReadAllText($HARFilePath)
$har = $rawJson | ConvertFrom-Json
$rawJson = $null  # free the string immediately

# Step 2: Filter to relevant API entries
$relevantEntries = $har.log.entries | Where-Object {
    $uri = [System.Uri]::new($_.request.url)
    $uri.Host -eq 'security.microsoft.com' -and $uri.AbsolutePath -like '/apiproxy/mtp/*'
}

# Step 3: Release full HAR
$har = $null
[System.GC]::Collect()
```

> **Note:** If `-ExportCleanHAR` is specified, the function sanitizes and writes the clean HAR, then returns early — the filter-first extraction steps below are not executed.

### 4.4 Tenant ID Auto-Detection

The tenant ID is present as a request header (`x-tid` or `tenant-id`) on every API call. The function auto-detects it from the first relevant entry:

```powershell
$tenantId = $relevantEntries | ForEach-Object {
    $tidHeader = $_.request.headers | Where-Object { $_.name -eq 'x-tid' }
    if ($tidHeader) { $tidHeader.value }
} | Select-Object -First 1

if (-not $tenantId) {
    # Fall back to tenant-id header
    $tenantId = $relevantEntries | ForEach-Object {
        $tidHeader = $_.request.headers | Where-Object { $_.name -eq 'tenant-id' }
        if ($tidHeader) { $tidHeader.value }
    } | Select-Object -First 1
}

if (-not $tenantId) {
    Write-LogMessage "Could not detect tenant ID from HAR entries" -Level "ERROR"
    throw "No MDE API requests with tenant ID header found in the HAR file. Ensure the HAR was captured while browsing the MDE portal."
}

Write-LogMessage "Detected tenant ID: $tenantId" -Level "INFO"
```

### 4.5 Response Extraction Helper

A reusable helper function matches HAR entries by URL pattern and extracts the parsed response body:

```powershell
function Get-HARResponseByUrl {
    param(
        [object[]]$Entries,
        [string]$UrlPattern,
        [string]$QueryFilter,
        [switch]$All
    )

    $matched = $Entries | Where-Object {
        $_.request.method -eq 'GET' -and
        $_.response.status -eq 200 -and
        $_.response.content.text -and
        $_.request.url -match $UrlPattern -and
        (-not $QueryFilter -or $_.request.url -match $QueryFilter)
    }

    if (-not $All) {
        # Use the last successful response (handles browser retries/polling)
        $matched = $matched | Select-Object -Last 1
    }

    $matched | ForEach-Object {
        try {
            $_.response.content.text | ConvertFrom-Json
        } catch {
            Write-LogMessage "Could not parse response for $($_.request.url) — skipping" -Level "WARN"
            $null
        }
    } | Where-Object { $_ -ne $null }
}
```

---

## 5. Extraction Logic per Object Type

### 5.0 Extraction Order

**Device groups must be extracted first** because WCF policies and indicators contain `RbacGroupIds` that must be resolved to device group names. The extraction order is:

1. Device Groups (builds the lookup table)
2. WCF Policies (uses the lookup table)
3. IP Indicators (uses the lookup table)
4. URL/Domain Indicators (uses the lookup table)

### 5.1 Device Groups (Machine Groups)

**Source endpoint in HAR:**
- `GET /apiproxy/mtp/rbacManagementApi/rbac/machine_groups`

**URL pattern:** `/apiproxy/mtp/rbacManagementApi/rbac/machine_groups`

**Extraction:**
1. Find matching responses — if multiple exist, **prefer** the variant with `addAadGroupNames=true` in the query string (contains Entra ID group display names)
2. Extract the `items` array from the response object (response is wrapped in `{ items, containsAadGroupNames, containsMachineGroupCount }`)
3. **Resolve enums to human-readable strings:**
   - `AutoRemediationLevel`: `0` → `"NoAutomatedResponse"`, `1` → `"SemiRequireApprovalAll"`, `2` → `"SemiRequireApprovalNonTemp"`, `3` → `"FullAutomated"`
   - `GroupRules[].Property`: `0` → `"MachineName"`, `1` → `"Domain"`, `2` → `"Tag"`, `3` → `"OS"`, `4` → `"Other"`
4. Preserve `MachineGroupAssignments` with Entra ID group names as-is
5. **Build device group lookup:** Create a hashtable mapping `MachineGroupId` → `Name` for use by subsequent extractions

**Output:** `device_groups.json` — array of device group objects with resolved enum values.

**Device group lookup table:**
```powershell
$deviceGroupLookup = @{}
foreach ($group in $deviceGroups) {
    $name = if ($group.IsUnassignedMachineGroup) { "Ungrouped devices" }
            elseif ([string]::IsNullOrEmpty($group.Name)) { "Unnamed ($($group.MachineGroupId))" }
            else { $group.Name }
    $deviceGroupLookup[$group.MachineGroupId] = $name
}
```

### 5.2 Web Content Filtering Policies

**Source endpoint in HAR:**
- `GET /apiproxy/mtp/userRequests/webcategory/policies`

**URL pattern:** `/apiproxy/mtp/userRequests/webcategory/policies`

**Extraction:**
1. Find the response matching the URL pattern
2. Parse the response body — it is a JSON array of policy objects at the top level (no `data` wrapper)
3. **Resolve category IDs to names:** Replace `BlockedCategoryIds` with `BlockedCategories` (array of category name strings) and `AuditCategoryIds` with `AuditCategories` (array of category name strings) using the built-in web category lookup table
4. **Resolve device group scoping:** Replace `RbacGroupIds` with `RbacGroupNames` by looking up each ID in the device group lookup table. Empty array → `["All device groups"]`
5. **Remove internal fields:** Drop `IndicatorValueIdMappings` (internal portal tracking, not needed for migration)

**Output schema per policy:**
```json
{
    "PolicyName": "MDE-Policy1",
    "BlockedCategories": ["Gambling"],
    "AuditCategories": ["Child Abuse Images", "Criminal activity", "Hacking", "Hate & intolerance", "Illegal drug"],
    "RbacGroupNames": ["All device groups"],
    "CreatedBy": "admin@contoso.com",
    "LastUpdateTime": "2026-02-25T10:58:14.5302747"
}
```

**Built-in web category lookup table:**

The function includes a hardcoded `$WebCategoryMap` hashtable mapping MDE's 28 web category IDs to names:

```powershell
$WebCategoryMap = @{
    7  = "Chat"
    12 = "Criminal activity"
    14 = "Download Sites"
    18 = "Gambling"
    19 = "Games"
    21 = "Hate & intolerance"
    23 = "Illegal drug"
    26 = "Streaming media & downloads"
    29 = "Nudity"
    33 = "Pornography/Sexually explicit"
    39 = "Social networking"
    46 = "Violence"
    47 = "Weapons"
    48 = "Web-based email"
    51 = "Parked Domains"
    52 = "Newly registered domains"
    62 = "Cults"
    65 = "Hacking"
    67 = "Illegal software"
    68 = "Image sharing"
    70 = "Instant messaging"
    73 = "Peer-to-peer"
    75 = "School cheating"
    76 = "Sex education"
    77 = "Tasteless"
    78 = "Child Abuse Images"
    84 = "Self-harm"
    92 = "Professional networking"
}
```

Any unrecognized category ID is output as `"Unknown ({id})"` with a warning logged.

**Output:** `wcf_policies.json` — array of policy objects with resolved category names and device group names.

### 5.3 Custom Indicators — IP

**Source endpoint in HAR:**
- `GET /apiproxy/mtp/papin/api/cloud/public/internal/indicators/getQuery?type=ip&pageIndex={n}&pageSize=1000&ordering=-creationTime`

**URL pattern:** `/apiproxy/mtp/papin/api/cloud/public/internal/indicators/getQuery`  
**Query filter:** `type=ip`

**Extraction:**
1. Find **all** matching responses (may have multiple pages: `pageIndex=0`, `pageIndex=1`, etc.)
2. Each response is a JSON array of indicator objects at the top level (no wrapper)
3. **Merge** all page arrays into a single consolidated array
4. **Resolve enums to human-readable strings:**
   - `action`: `0` → `"AlertOnly"`, `1` → `"Allow"`, `2` → `"Block"`, `4` → `"Warn"`
   - `severity`: `0` → `"Informational"`, `1` → `"Low"`, `2` → `"Medium"`, `3` → `"High"`
   - `indicatorType`: `3` → `"IP"`
5. **Resolve device group scoping:** Replace `rbacGroupIds` with `rbacGroupNames` using the device group lookup. Empty array → `["All device groups"]`

**Output:** `ip_indicators.json` — array of indicator objects with resolved enum values and device group names.

### 5.4 Custom Indicators — URL/Domain

**Source endpoint in HAR:**
- `GET /apiproxy/mtp/papin/api/cloud/public/internal/indicators/getQuery?type=url&pageIndex={n}&pageSize=1000&ordering=-creationTime`

**URL pattern:** `/apiproxy/mtp/papin/api/cloud/public/internal/indicators/getQuery`  
**Query filter:** `type=url`

**Extraction:** Same procedure as IP indicators (Section 5.3), with:
- `indicatorType` resolution: `4` → `"URL"`, `5` → `"DomainURL"`
- Merge pages, resolve all enums, resolve device group scoping

**Output:** `url_indicators.json` — array of indicator objects with resolved enum values and device group names.

---

## 6. URL Matching Strategy

Each object type requires matching HAR entries by URL pattern.

### 6.1 URL Pattern Table

| Object | URL Regex Pattern | Additional Query Filter |
|--------|------------------|------------------------|
| Device Groups | `/apiproxy/mtp/rbacManagementApi/rbac/machine_groups` | Prefer entries with `addAadGroupNames=true` |
| WCF Policies | `/apiproxy/mtp/userRequests/webcategory/policies` | — |
| IP Indicators | `/apiproxy/mtp/papin/api/cloud/public/internal/indicators/getQuery` | Query contains `type=ip` |
| URL Indicators | `/apiproxy/mtp/papin/api/cloud/public/internal/indicators/getQuery` | Query contains `type=url` |

### 6.2 Distinguishing IP vs URL Indicator Requests

Both indicator types use the same `/indicators/getQuery` endpoint, differentiated by the `type` query parameter:

- IP: URL query string contains `type=ip`
- URL/Domain: URL query string contains `type=url`

**Approach:** Check the URL query string for the `type` parameter value. No URL decoding needed — the parameter is a simple key=value pair.

---

## 7. Error Handling

### 7.1 HAR File Errors

| Condition | Action |
|-----------|--------|
| File not found | Terminating error before processing |
| File is not valid JSON | Terminating error: "The file is not a valid HAR/JSON file" |
| JSON parses but has no `log.entries` | Terminating error: "The file does not appear to be a HAR file (missing log.entries)" |
| No relevant API entries found | Terminating error: "No MDE API requests found in the HAR file. Ensure the HAR was captured while browsing the MDE portal at security.microsoft.com" |
| Tenant ID cannot be detected | Terminating error: "Could not detect tenant ID from HAR entries" |

### 7.2 Per-Object Extraction Errors

| Condition | Action |
|-----------|--------|
| Endpoint not found in HAR | Warning: "No {objectType} response found in HAR — skipping"; continue |
| Response body is empty or unparseable | Warning: "Could not parse response for {url} — skipping"; continue |
| Response status is not 200 | Warning: "Non-200 response ({status}) for {url} — skipping"; continue |
| Unknown category ID in WCF policy | Warning: "Unknown web category ID {id} — exported as 'Unknown ({id})'"; continue |
| RbacGroupId not found in device group lookup | Warning: "Unknown device group ID {id} — exported as 'Unknown ({id})'"; continue |

### 7.3 Logging

- Use the internal `Write-LogMessage` function for all output
- Log file: `{timestamp}_Export-MDEWebFilteringConfig.log` in the output folder
- Log levels: `INFO`, `WARN`, `ERROR`, `SUCCESS`
- Log: HAR file size, entry count, relevant entry count, tenant ID detected, per-object extraction counts, warnings for missing data

---

## 8. ExportCleanHAR Feature

When `-ExportCleanHAR` is specified, the function produces a sanitized copy of the HAR file suitable for sharing (e.g., with support teams or for inclusion in migration documentation).

### 8.1 Sanitization Steps

**Step 1 — Filter entries to relevant host and path only:**
- Keep only entries where host is `security.microsoft.com` and path starts with `/apiproxy/mtp/`
- Remove all other entries (dashboard HTML, CDN, analytics, images, telemetry, etc.)

**Step 2 — Strip sensitive headers from ALL remaining entries:**

Remove these headers from `request.headers[]` and `response.headers[]`:

| Header | Reason |
|--------|--------|
| `Authorization` | Bearer tokens |
| `Cookie` | Session cookies |
| `Set-Cookie` | Response session cookies |
| `x-xsrf-token` | Anti-CSRF token |
| Any header starting with `X-Auth` | Auth-related headers |

**Note:** The `x-tid` and `tenant-id` headers are **not** stripped — they contain only the tenant ID (which is already visible in the exported data) and are needed for the clean HAR to be useful for analysis.

Implementation: filter the `headers` array to exclude entries with matching names (case-insensitive).

**Step 3 — Strip cookies arrays:**
- Set `request.cookies` to `[]`
- Set `response.cookies` to `[]`

**Step 4 — Write the sanitized HAR:**
- Preserve the original HAR `log.version`, `log.creator`, `log.browser`, `log.pages` metadata
- Replace `log.entries` with the filtered and redacted entries
- Serialize to JSON with `ConvertTo-Json -Depth 20`
- Write to `mde_clean.har` in the output folder

### 8.2 Processing Flow

When `-ExportCleanHAR` is specified, the function operates in a **separate mode** — it sanitizes the HAR and exits without performing JSON extraction:

1. Read and parse HAR file
2. Sanitize: filter entries to relevant host/path, strip sensitive headers/cookies
3. Write `mde_clean.har` to output folder
4. Release HAR object from memory
5. Display summary and **return** — no JSON extraction steps are executed

### 8.3 Output

File: `mde_clean.har` in the backup folder.

The clean HAR file will be significantly smaller than the original since non-API entries and their response bodies (HTML, JS, CSS, images) are removed.

---

## 9. Implementation Structure

### 9.1 Internal Helper Functions

These functions should be defined within the script or as private helpers in the module's internal functions:

#### `Read-HARFile`

Reads and validates the HAR file, returning the parsed object:
- Uses `[System.IO.File]::ReadAllText()` for performance
- Validates HAR structure (`log`, `log.entries` exist)
- Returns parsed HAR object

#### `Get-HARApiEntries`

Filters HAR entries to relevant API host and path:
- Accepts the full entries array
- Returns only entries matching host `security.microsoft.com` and path `/apiproxy/mtp/*`
- Only keeps `GET` requests with HTTP 200 responses and non-empty `response.content.text`

#### `Get-HARResponseByUrl`

Extracts parsed response data from HAR entries matching a URL pattern:
- Accepts entries array, regex pattern, optional query filter, and optional `-All` switch
- Parses `response.content.text` as JSON
- Returns single response (last match) or array (when `-All`)

#### `Get-HARTenantId`

Auto-detects the tenant ID from the `x-tid` request header (falls back to `tenant-id` header).

#### `Export-CleanHAR`

Sanitizes and writes the clean HAR file:
- Filters entries to relevant host/path
- Strips sensitive headers and cookies
- Writes output file

### 9.2 Main Function Flow

```
1. Validate parameters
2. Generate timestamp
3. Create output folder: MDE-backup_{timestamp}/
4. Initialize logging ($script:LogPath)
5. Read HAR file (Read-HARFile)
6. Log HAR stats (file size, total entries)
7. If -ExportCleanHAR:
    a. Sanitize and write clean HAR (Export-CleanHAR)
    b. Log completion
    c. Display summary and RETURN (skip steps 8–17)
8. Filter to relevant API entries (Get-HARApiEntries)
9. Release full HAR object from memory
10. Auto-detect tenant ID (Get-HARTenantId)
11. Extract Device Groups → device_groups.json
12. Build device group lookup: MachineGroupId → Name
13. Extract WCF Policies → wcf_policies.json (resolve category IDs → names, RbacGroupIds → names)
14. Extract IP Indicators → ip_indicators.json (resolve enums, merge pages, resolve RbacGroupIds)
15. Extract URL/Domain Indicators → url_indicators.json (resolve enums, merge pages, resolve RbacGroupIds)
16. Write export_metadata.json
17. Display summary report
```

### 9.3 Using Export-DataToFile

Each extracted object array is saved using the existing internal `Export-DataToFile` function:

```powershell
Export-DataToFile -Data $wcfPolicies -FilePath "$outputFolder\wcf_policies.json" -Format "JSON"
```

---

## 10. Console Output and Summary

### 10.1 Progress Output

Use `Write-LogMessage` for each phase:

```
[INFO] Reading HAR file: C:\captures\mde_portal.har (52 MB, 943 entries)
[INFO] Filtered to 12 relevant API entries (security.microsoft.com/apiproxy/mtp/)
[INFO] Detected tenant ID: 322950bf-0bad-4bfa-990e-3f7e1747b5a6
[INFO] Extracting Device Groups...
[SUCCESS] Extracted 2 device groups:
         - MDE-DeviceGroup1
         - Ungrouped devices (unassigned)
[INFO] Extracting Web Content Filtering Policies...
[SUCCESS] Extracted 2 WCF policies:
         - MDE-Policy1 (1 blocked, 27 audited categories)
         - MDE-Policy2 (5 blocked, 23 audited categories)
[INFO] Extracting IP Indicators...
[SUCCESS] Extracted 1 IP indicator:
         - 20.20.20.20 (AlertOnly)
[INFO] Extracting URL/Domain Indicators...
[SUCCESS] Extracted 1 URL/Domain indicator:
         - facebook.com (Warn)
```

### 10.2 Completion Summary

```
Export completed successfully!

Backup folder: C:\Output\MDE-backup_20260226_143022\

MDE Web Filtering Configuration (from HAR):
  Tenant ID:          322950bf-0bad-4bfa-990e-3f7e1747b5a6
  WCF Policies:       2
  IP Indicators:      1
  URL Indicators:     1
  Device Groups:      2
  Warnings:           0

Files created:
  - wcf_policies.json
  - ip_indicators.json
  - url_indicators.json
  - device_groups.json
  - export_metadata.json
  - 20260226_143022_Export-MDEWebFilteringConfig.log
```

---

## 11. Usage Examples

### 11.1 Basic Usage

```powershell
Export-MDEWebFilteringConfig -HARFilePath "C:\captures\mde_portal.har"
```

Creates backup in current directory: `.\MDE-backup_20260226_143022\`

### 11.2 Custom Output Directory

```powershell
Export-MDEWebFilteringConfig `
    -HARFilePath "C:\captures\mde_portal.har" `
    -OutputDirectory "C:\Backups\MDE"
```

### 11.3 Sanitized HAR for Sharing

```powershell
Export-MDEWebFilteringConfig `
    -HARFilePath "C:\captures\mde_portal.har" `
    -OutputDirectory "C:\Backups\MDE" `
    -ExportCleanHAR
```

Produces **only** `mde_clean.har` — no JSON extraction is performed.

### 11.4 Verbose Output

```powershell
Export-MDEWebFilteringConfig `
    -HARFilePath "C:\captures\mde_portal.har" `
    -Verbose
```

### 11.5 Pipeline from File Selection

```powershell
Get-Item "C:\captures\*.har" | Select-Object -First 1 -ExpandProperty FullName |
    ForEach-Object { Export-MDEWebFilteringConfig -HARFilePath $_ -ExportCleanHAR }
```

---

## 12. Enum / Constant Reference

### 12.1 Indicator Action

| Value | String | Description |
|-------|--------|-------------|
| `0` | `AlertOnly` | Monitor and generate alert |
| `1` | `Allow` | Explicitly allow |
| `2` | `Block` | Block access |
| `4` | `Warn` | Show warning page, allow bypass |

### 12.2 Indicator Severity

| Value | String |
|-------|--------|
| `0` | `Informational` |
| `1` | `Low` |
| `2` | `Medium` |
| `3` | `High` |

### 12.3 Indicator Type

| Value | String | Query `type` param |
|-------|--------|--------------------|
| `3` | `IP` | `ip` |
| `4` | `URL` | `url` |
| `5` | `DomainURL` | `url` (grouped with URL) |

### 12.4 Auto-Remediation Level

| Value | String |
|-------|--------|
| `0` | `NoAutomatedResponse` |
| `1` | `SemiRequireApprovalAll` |
| `2` | `SemiRequireApprovalNonTemp` |
| `3` | `FullAutomated` |

### 12.5 GroupRules Property

| Value | String |
|-------|--------|
| `0` | `MachineName` |
| `1` | `Domain` |
| `2` | `Tag` |
| `3` | `OS` |
| `4` | `Other` |

---

## 13. Edge Cases and Known Quirks

### 13.1 MDE Portal Quirks

| Quirk | Handling |
|-------|----------|
| WCF policies response is a bare JSON array (no wrapper) | Parse directly as array, no `.data` unwrapping needed |
| Device groups response wraps `items` array in metadata object | Extract `.items` from the response |
| Indicators response is a bare JSON array (no wrapper) | Parse directly as array |
| Two device groups requests in HAR (with/without AAD names) | Prefer the variant with `addAadGroupNames=true` |
| IP and URL indicators share the same `/getQuery` endpoint | Differentiate by `type=ip` vs `type=url` in query string |
| Empty `RbacGroupIds` means "all device groups" | Resolve to `["All device groups"]` |
| Unassigned device group has Priority = 2147483647 | Export with `IsUnassignedMachineGroup: true` |
| `IndicatorValueIdMappings` in WCF policies is internal tracking | Remove from exported output |

### 13.2 HAR Capture Edge Cases

| Case | Handling |
|------|----------|
| User didn't browse all portal pages (missing object types) | Export what's available; log warnings for missing types |
| Multiple HAR captures combined into one file | Process all entries — deduplicate by URL+response |
| Duplicate responses for the same URL (browser retry, polling) | Use the last successful (HTTP 200) response for each unique URL pattern |
| Indicator pagination (multiple `pageIndex` values in HAR) | Merge all page arrays into a single consolidated array per type |
| Compressed response body (`content.encoding: "base64"`) | Detect `content.encoding` and decode if base64; log warning for unsupported encodings |
| Unknown web category ID not in the 28-category lookup | Export as `"Unknown ({id})"` and log warning |

---

## 14. Success Criteria

- [ ] Accept HAR file path and validate the file exists and is valid HAR/JSON
- [ ] Filter HAR entries to `security.microsoft.com` host with `/apiproxy/mtp/` path prefix
- [ ] Auto-detect tenant ID from `x-tid` request header
- [ ] Extract all 4 object types from HAR responses
- [ ] Resolve web category IDs to human-readable names in WCF policies
- [ ] Resolve `RbacGroupIds` to device group names in WCF policies and indicators
- [ ] Resolve enum values (action, severity, indicatorType, AutoRemediationLevel, GroupRules Property) to strings
- [ ] Merge paginated indicator responses into single arrays
- [ ] Prefer device groups response with `addAadGroupNames=true`
- [ ] Generate `export_metadata.json` with provenance information
- [ ] Support `-ExportCleanHAR` mode with header/cookie sanitization
- [ ] Log all operations via `Write-LogMessage`
- [ ] Handle missing object types gracefully (warning, not error)
