# Export Cisco Umbrella Configuration from HAR File — Technical Specification

**Version:** 1.0  
**Date:** February 20, 2026  
**Status:** Draft  
**Target Module:** Migrate2GSA  
**Function Name:** Export-CiscoUmbrellaConfig  
**Function Location:** `Migrate2GSA/functions/CiscoUmbrella/Export-CiscoUmbrellaConfig.ps1`  
**Author:** Andres Canello

---

## Overview

This specification defines a PowerShell function that **extracts Cisco Umbrella configuration from an HTTP Archive (HAR) file** captured while browsing the Umbrella dashboard. Unlike the other Export functions in this module (which call vendor APIs directly), this function parses a local HAR file to reconstruct the configuration without requiring live API access or credentials.

**Why HAR-based?** The Cisco Umbrella dashboard uses internal APIs (`api.opendns.com/v3/` and `api.umbrella.com/v1/`) that are not part of Cisco's public API surface. Capturing a HAR file while browsing the dashboard is the most reliable way to obtain the full configuration data, including embedded sub-objects that the dashboard populates eagerly.

**Reference:** All API endpoints, request/response structures, and extraction logic are documented in [umbrella_har_api_reference.md](umbrella_har_api_reference.md).

---

## 1. Function Definition

### 1.1 Function Name

```powershell
Export-CiscoUmbrellaConfig
```

### 1.2 Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-HARFilePath` | String | Yes | — | Absolute or relative path to the `.har` file captured from the Umbrella dashboard |
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

**ExportCleanHAR:**implem
- Switch parameter; defaults to `$false`
- When present, **only** produces a sanitized HAR copy — no JSON extraction is performed
- This is an alternative operating mode, not an addition to the normal export

### 1.4 Prerequisites

- PowerShell 7.0 or higher (required by the Migrate2GSA module)
- No external modules required — all processing is local file I/O and JSON parsing
- No network access required

---

## 2. Configuration Objects to Extract

The function extracts **8 object types** from the HAR file, matching the sections documented in the HAR API reference.

| # | Object Type | HAR API Hosts | List Endpoint Pattern | Detail Endpoint Pattern | Output File |
|---|------------|---------------|----------------------|------------------------|-------------|
| 1 | DNS Policies | `api.opendns.com` | `/v3/organizations/{orgId}/bundles` (bundleTypeId=1) | `/v3/organizations/{orgId}/policysettings/{id}` | `dns_policies.json` |
| 2 | Firewall Rules | `api.umbrella.com` | `/v1/organizations/{orgId}/rulesets/firewall` | — (single call returns all) | `firewall_rules.json` |
| 3 | Web Policies | `api.opendns.com` + `api.umbrella.com` | `/v3/organizations/{orgId}/bundles` (bundleTypeId=2) | `/v1/organizations/{orgId}/rulesets/bundle/{id}` + `/v1/organizations/{orgId}/rulesets/{id}/settings` | `web_policies.json` |
| 4 | Destination Lists | `api.opendns.com` | `/v3/organizations/{orgId}/destinationlists` | `/v3/organizations/{orgId}/destinationlists/{id}/destinations` | `destination_lists.json` |
| 5 | Category Settings | `api.opendns.com` | `/v3/organizations/{orgId}/categorysettings` | `/v3/organizations/{orgId}/categorysettings/{id}` | `category_settings.json` |
| 6 | Application Settings | `api.opendns.com` | `/v3/organizations/{orgId}/applicationsettings` | `/v3/organizations/{orgId}/applicationsettings/{id}` | `application_settings.json` |
| 7 | Security Settings | `api.opendns.com` | `/v3/organizations/{orgId}/securitysettings` | `/v3/organizations/{orgId}/securitysettings/{id}` | `security_settings.json` |
| 8 | Selective Decryption Lists | `api.opendns.com` | `/v3/organizations/{orgId}/bypassinspectiongroupsettings` | `/v3/organizations/{orgId}/bypassinspectiongroupsettings/{id}` | `selective_decryption_lists.json` |

---

## 3. Output Structure

### 3.1 Folder Structure

**Normal mode (default):**
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

**Sanitize mode (`-ExportCleanHAR`):**
```
CiscoUmbrella-backup_{timestamp}/
├── umbrella_clean.har
└── {timestamp}_Export-CiscoUmbrella.log
```

### 3.2 Timestamp Format

- Format: `yyyyMMdd_HHmmss` (e.g., `20260220_143022`)
- Generated once at function start
- Used consistently for folder name, log file name, and metadata

### 3.3 Export Metadata File

`export_metadata.json` captures provenance information:

```json
{
    "timestamp": "20260220_143022",
    "sourceHARFile": "umbrella_capture.har",
    "organizationId": "8144773",
    "exportType": "CiscoUmbrella_HAR_Extract",
    "objectCounts": {
        "dnsPolicies": 3,
        "firewallRules": 2,
        "webPolicies": 1,
        "destinationLists": 5,
        "categorySettings": 5,
        "applicationSettings": 2,
        "securitySettings": 4,
        "selectiveDecryptionLists": 1
    },
    "warnings": [
        "No individual detail responses found for applicationSettings — exported list-level data only"
    ]
}
```

### 3.4 Individual JSON File Format

Each file contains the **`data` array** extracted from the API response (unwrapped from the `{ status, meta, data }` envelope). For objects that have both list and detail endpoints, the detail-level data is preferred because it includes additional fields (e.g., `categories[]`, `applications[]`).

Example `category_settings.json`:
```json
[
    {
        "id": 15202345,
        "organizationId": 8144773,
        "name": "Default Settings",
        "bundleTypeId": 1,
        "isDefault": true,
        "categories": [
            { "categoryId": 28, "name": "Weapons" },
            { "categoryId": 359, "name": "Nature and Conservation" }
        ],
        "warnCategories": [],
        "createdAt": "2023-05-04 17:10:38",
        "modifiedAt": "2026-02-19 09:57:58"
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
        "entries": [
            {
                "request": {
                    "method": "GET",
                    "url": "https://api.opendns.com/v3/organizations/8144773/bundles?...",
                    "headers": [...]
                },
                "response": {
                    "status": 200,
                    "content": {
                        "mimeType": "application/json",
                        "text": "{ ... JSON response body ... }"
                    }
                }
            }
        ]
    }
}
```

### 4.2 Relevant Hosts

Only entries with requests to these hosts contain configuration data:

- `api.opendns.com`
- `api.umbrella.com`

All other entries (dashboard HTML, CSS, JS, images, analytics, CDN) are irrelevant and must be ignored.

### 4.3 Large File Handling

HAR files routinely exceed 100MB because they capture all response bodies (including large JSON payloads, CSS, JS, images encoded as base64 text).

**Reading:** Use `[System.IO.File]::ReadAllText()` — significantly faster than `Get-Content -Raw` for large files.

**Parsing:** `ConvertFrom-Json` in PowerShell 7 uses `System.Text.Json` internally and handles large files efficiently. No special configuration needed.

**Memory optimization — filter-first approach:**
1. Parse the full HAR into a `$har` object
2. Immediately filter `$har.log.entries` to only entries whose `request.url` matches `api.opendns.com` or `api.umbrella.com`
3. Store the filtered entries in `$relevantEntries`
4. Set `$har = $null` to release the full HAR object from memory
5. A 100MB+ HAR typically reduces to 2–5MB of relevant API responses

```powershell
# Step 1: Read and parse
$rawJson = [System.IO.File]::ReadAllText($HARFilePath)
$har = $rawJson | ConvertFrom-Json
$rawJson = $null  # free the string immediately

# Step 2: Filter to relevant API hosts
$relevantHosts = @('api.opendns.com', 'api.umbrella.com')
$relevantEntries = $har.log.entries | Where-Object {
    $uri = [System.Uri]::new($_.request.url)
    $uri.Host -in $relevantHosts
}

# Step 3: Release full HAR
$harVersion = $har.log.version  # preserve if needed for ExportCleanHAR
$har = $null
[System.GC]::Collect()
```

> **Note:** If `-ExportCleanHAR` is specified, the function sanitizes and writes the clean HAR, then returns early — the filter-first extraction steps below are not executed.

### 4.4 Organization ID Auto-Detection

The `organizationId` is embedded in every API URL path. The function auto-detects it from the first relevant entry:

```powershell
# Match orgId from URL path: /v3/organizations/{orgId}/ or /v1/organizations/{orgId}/
$orgIdPattern = '/organizations/(\d+)/'
$firstMatch = $relevantEntries | ForEach-Object {
    if ($_.request.url -match $orgIdPattern) { $Matches[1] }
} | Select-Object -First 1

if (-not $firstMatch) {
    Write-LogMessage "Could not detect organizationId from HAR entries" -Level "ERROR"
    throw "No Cisco Umbrella API requests found in the HAR file. Ensure the HAR was captured while browsing the Umbrella dashboard."
}

$organizationId = $firstMatch
Write-LogMessage "Detected Umbrella organizationId: $organizationId" -Level "INFO"
```

### 4.5 Response Extraction Helper

A reusable helper function matches HAR entries by URL pattern and extracts the parsed response body:

```powershell
function Get-HARResponseData {
    param(
        [object[]]$Entries,
        [string]$UrlPattern,
        [switch]$All
    )

    $matches = $Entries | Where-Object {
        $_.request.method -eq 'GET' -and
        $_.request.url -match $UrlPattern -and
        $_.response.status -eq 200 -and
        $_.response.content.text
    }

    if ($All) {
        return $matches | ForEach-Object {
            ($_.response.content.text | ConvertFrom-Json)
        }
    }
    else {
        $first = $matches | Select-Object -First 1
        if ($first) {
            return ($first.response.content.text | ConvertFrom-Json)
        }
        return $null
    }
}
```

---

## 5. Extraction Logic per Object Type

### 5.1 DNS Policies

**Source endpoints in HAR:**
- List: `GET /v3/organizations/{orgId}/bundles` with query param `bundleTypeId` = `1`
- Detail (policy settings): `GET /v3/organizations/{orgId}/policysettings/{id}`

**Extraction:**
1. Find the bundles list response filtered to `bundleTypeId=1` (check URL query string for `"bundleTypeId":1` or `"bundleTypeId": 1`)
2. Extract `data[]` array — these are the DNS policy bundle objects
3. The list call with `optionalFields` already embeds `categorySetting`, `securitySetting`, `policySetting`, `fileInspectionSetting`, `domainlists` inline — so the list response alone is usually sufficient
4. Optionally, for each policy's `policySettingGroupId`, look for individual `policysettings/{id}` response to get extended detail fields (`categoryIds`, `categoryNames`)
5. If individual detail responses are found, merge them into the bundle objects as a `policySettingDetail` property

**Output:** `dns_policies.json` — array of bundle objects with embedded settings.

### 5.2 Firewall Rules

**Source endpoints in HAR:**
- List: `GET /v1/organizations/{orgId}/rulesets/firewall`
- Reference data: `GET /v3/organizations/{orgId}/firewallhitcountintervals`

**Extraction:**
1. Find the firewall ruleset response — the entire ruleset (including all rules) comes in a single response
2. Extract the full response object (not just `data` — the firewall endpoint returns the ruleset at the top level with `rules[]` array directly)
3. Optionally, find the hit count intervals reference data and include as a `hitCountIntervals` property

**Output:** `firewall_rules.json` — the ruleset object with `rules[]` array and metadata.

**Pagination note:** If the HAR contains multiple paginated requests (`offset=0`, `offset=25`, etc.), merge all `rules[]` arrays into a single consolidated response.

### 5.3 Web Policies

**Source endpoints in HAR:**
- List: `GET /v3/organizations/{orgId}/bundles` with query param `bundleTypeId` = `2`
- Proxy ruleset: `GET /v1/organizations/{orgId}/rulesets/bundle/{bundleId}`
- Ruleset settings: `GET /v1/organizations/{orgId}/rulesets/{rulesetId}/settings`

**Extraction:**
1. Find the bundles list response filtered to `bundleTypeId=2`
2. Extract `data[]` array — these are the web policy bundle objects (with embedded `categorySetting`, `securitySetting`, `policySetting`, `fileInspectionSetting`, `domainlists`, `settingGroupBypassInspectionGroup`, `restriction`)
3. For each bundle, look for the proxy ruleset response (`/rulesets/bundle/{bundleId}`) and attach as a `proxyRuleset` property
4. For each proxy ruleset, look for its settings response (`/rulesets/{rulesetId}/settings`) and attach as `proxyRuleset.rulesetSettings`

**Output:** `web_policies.json` — array of bundle objects enriched with proxy ruleset and settings.

### 5.4 Destination Lists

**Source endpoints in HAR:**
- List: `GET /v3/organizations/{orgId}/destinationlists`
- Entries: `GET /v3/organizations/{orgId}/destinationlists/{listId}/destinations`

**Extraction:**
1. Find the destination lists response and extract `data[]`
2. For each list, look for entry responses (`/destinationlists/{listId}/destinations`)
3. If entry responses exist, merge all paginated pages and attach as a `destinations` property on the list object
4. Handle multiple pages: the dashboard may fetch entries with different `type` filters (domain, ipv, url) as separate requests — merge all entry arrays for the same list

**Output:** `destination_lists.json` — array of list objects, each with an optional `destinations[]` property containing the list entries.

### 5.5 Category Settings

**Source endpoints in HAR:**
- List: `GET /v3/organizations/{orgId}/categorysettings`
- Detail: `GET /v3/organizations/{orgId}/categorysettings/{id}`

**Extraction:**
1. Find the category settings list response and extract `data[]` (summary with bitmasks only)
2. For each item, look for the individual detail response (`/categorysettings/{id}`)
3. Detail responses include `categories[]` and `warnCategories[]` arrays — **prefer detail data over list data**
4. If a detail response exists for an item, use it as the exported record; otherwise fall back to the list-level record and log a warning

**Output:** `category_settings.json` — array of category setting objects with full `categories[]` and `warnCategories[]` arrays where available.

### 5.6 Application Settings

**Source endpoints in HAR:**
- List: `GET /v3/organizations/{orgId}/applicationsettings`
- Detail: `GET /v3/organizations/{orgId}/applicationsettings/{id}`

**Extraction:**
1. Find the application settings list response and extract `data[]`
2. For each item, look for the individual detail response (`/applicationsettings/{id}`)
3. Detail responses include `applications[]` and `applicationsCategories[]` arrays not present in the list
4. **Prefer detail data**; fall back to list-level with warning
5. **Special case:** System-inherited settings (e.g., `organizationId=1`, name "None") only appear in individual fetches — scan for any `applicationsettings/{id}` responses that are NOT in the list and include them

**Output:** `application_settings.json` — array of application setting objects with full `applications[]` and `applicationsCategories[]` arrays where available.

### 5.7 Security Settings

**Source endpoints in HAR:**
- List: `GET /v3/organizations/{orgId}/securitysettings` (with `optionalFields=["categories"]`)
- Detail: `GET /v3/organizations/{orgId}/securitysettings/{id}`

**Extraction:**
1. Find the security settings list response and extract `data[]`
2. The list endpoint with `optionalFields=["categories"]` already returns `categories[]` inline — **no individual fetch needed** for most cases
3. If individual detail responses also exist, prefer them (they have datetime strings instead of epoch timestamps for `createdAt`/`modifiedAt`)
4. Identify MSP-inherited records (`organizationId != detected orgId`) and tag them with a `_isInherited: true` property for downstream awareness

**Output:** `security_settings.json` — array of security setting objects with `categories[]` included.

### 5.8 Selective Decryption Lists

**Source endpoints in HAR:**
- List: `GET /v3/organizations/{orgId}/bypassinspectiongroupsettings`
- Detail: `GET /v3/organizations/{orgId}/bypassinspectiongroupsettings/{id}`

**Extraction:**
1. Find the list response and extract `data[]`
2. **Important:** `meta.total` is unreliable for this endpoint (may be `0` even when records exist) — always use `data.Count`
3. Detail responses return the same fields but as a single object — use if available, otherwise use list data
4. For each item with a non-null `exceptiondomainlistId`, note that the linked destination list entries can be found in the destination lists export (Section 5.4)

**Output:** `selective_decryption_lists.json` — array of selective decryption list objects.

---

## 6. URL Matching Strategy

Each object type requires matching HAR entries by URL pattern. The patterns must account for:
- URL-encoded query parameters (e.g., `%7B` for `{`, `%22` for `"`)
- Optional query parameter ordering
- Different query string variants for the same endpoint

### 6.1 URL Pattern Table

| Object | URL Pattern (regex) | Additional Filter |
|--------|--------------------|--------------------|
| DNS Policies (list) | `/v3/organizations/\d+/bundles\?` | URL contains `bundleTypeId` + `1` (URL-decoded) |
| DNS Policy Settings (detail) | `/v3/organizations/\d+/policysettings/\d+` | — |
| Firewall Rules | `/v1/organizations/\d+/rulesets/firewall` | — |
| Firewall Hit Count Intervals | `/v3/organizations/\d+/firewallhitcountintervals` | — |
| Web Policies (list) | `/v3/organizations/\d+/bundles\?` | URL contains `bundleTypeId` + `2` (URL-decoded) |
| Web Proxy Ruleset (detail) | `/v1/organizations/\d+/rulesets/bundle/\d+` | — |
| Web Ruleset Settings (detail) | `/v1/organizations/\d+/rulesets/\d+/settings` | Not matching `/rulesets/firewall` |
| Destination Lists (list) | `/v3/organizations/\d+/destinationlists\?` or `/v3/organizations/\d+/destinationlists$` | Exclude URLs containing `/destinations` |
| Destination List Entries (detail) | `/v3/organizations/\d+/destinationlists/\d+/destinations` | — |
| Category Settings (list) | `/v3/organizations/\d+/categorysettings\?` or `/v3/organizations/\d+/categorysettings$` | Exclude URLs with a trailing `/{id}` |
| Category Settings (detail) | `/v3/organizations/\d+/categorysettings/\d+\?` or `/v3/organizations/\d+/categorysettings/\d+$` | — |
| Application Settings (list) | `/v3/organizations/\d+/applicationsettings\?` or `/v3/organizations/\d+/applicationsettings$` | Exclude URLs with trailing `/{id}` |
| Application Settings (detail) | `/v3/organizations/\d+/applicationsettings/\d+` | — |
| Security Settings (list) | `/v3/organizations/\d+/securitysettings\?` or `/v3/organizations/\d+/securitysettings$` | Exclude URLs with trailing `/{id}` |
| Security Settings (detail) | `/v3/organizations/\d+/securitysettings/\d+` | — |
| Selective Decryption (list) | `/v3/organizations/\d+/bypassinspectiongroupsettings\?` or `/v3/organizations/\d+/bypassinspectiongroupsettings$` | Exclude URLs with trailing `/{id}` |
| Selective Decryption (detail) | `/v3/organizations/\d+/bypassinspectiongroupsettings/\d+` | — |

### 6.2 Distinguishing DNS vs Web Bundle Requests

Both DNS and Web policies use the same `/bundles` endpoint. The `bundleTypeId` filter is embedded in the URL query string as URL-encoded JSON:

- DNS: URL contains `bundleTypeId` and `1` (e.g., `filters=%7B%22bundleTypeId%22%3A1%7D`)
- Web: URL contains `bundleTypeId` and `2` (e.g., `filters=%7B%22bundleTypeId%22%3A2%7D`)

**Approach:** URL-decode the query string before matching, then check for `"bundleTypeId":1` vs `"bundleTypeId":2`.

---

## 7. Error Handling

### 7.1 HAR File Errors

| Condition | Action |
|-----------|--------|
| File not found | Terminating error before processing |
| File is not valid JSON | Terminating error: "The file is not a valid HAR/JSON file" |
| JSON parses but has no `log.entries` | Terminating error: "The file does not appear to be a HAR file (missing log.entries)" |
| No relevant API entries found | Terminating error: "No Cisco Umbrella API requests found in the HAR file" |
| orgId cannot be detected | Terminating error: "Could not detect organizationId from HAR entries" |

### 7.2 Per-Object Extraction Errors

| Condition | Action |
|-----------|--------|
| List endpoint not found in HAR | Warning: "No {objectType} list response found in HAR — skipping"; continue |
| Detail endpoint not found for an item | Warning: "No detail response for {objectType} id={id} — using list data"; continue |
| Response body is empty or unparseable | Warning: "Could not parse response for {url} — skipping"; continue |
| Response status is not 200 | Warning: "Non-200 response ({status}) for {url} — skipping"; continue |

### 7.3 Logging

- Use the internal `Write-LogMessage` function for all output
- Log file: `{timestamp}_Export-CiscoUmbrella.log` in the output folder
- Log levels: `INFO`, `WARN`, `ERROR`, `SUCCESS`
- Log: HAR file size, entry count, relevant entry count, orgId detected, per-object extraction counts, warnings for missing data

---

## 8. ExportCleanHAR Feature

When `-ExportCleanHAR` is specified, the function produces a sanitized copy of the HAR file suitable for sharing (e.g., with support teams or for inclusion in migration documentation).

### 8.1 Sanitization Steps

**Step 1 — Filter entries to relevant hosts only:**
- Keep only entries where `request.url` host is `api.opendns.com` or `api.umbrella.com`
- Remove all other entries (dashboard HTML, CDN, analytics, images, etc.)

**Step 2 — Strip sensitive headers from ALL remaining entries:**

Remove these headers from `request.headers[]`:
- `Authorization` (bearer tokens)
- `Cookie` (session cookies)
- `Set-Cookie` (in response headers)
- `X-CSRF-Token`
- Any header whose name starts with `X-Auth`

Implementation: filter the `headers` array to exclude entries with matching names (case-insensitive).

**Step 3 — Strip cookies arrays:**
- Set `request.cookies` to `[]`
- Set `response.cookies` to `[]`

**Step 4 — Write the sanitized HAR:**
- Preserve the original HAR `log.version`, `log.creator`, `log.browser`, `log.pages` metadata
- Replace `log.entries` with the filtered and redacted entries
- Serialize to JSON with `ConvertTo-Json -Depth 20`
- Write to `umbrella_clean.har` in the output folder

### 8.2 Processing Flow

When `-ExportCleanHAR` is specified, the function operates in a **separate mode** — it sanitizes the HAR and exits without performing JSON extraction:

1. Read and parse HAR file
2. Sanitize: filter entries to relevant hosts, strip sensitive headers/cookies
3. Write `umbrella_clean.har` to output folder
4. Release HAR object from memory
5. Display summary and **return** — no JSON extraction steps are executed

### 8.3 Output

File: `umbrella_clean.har` in the backup folder.

The clean HAR file will be significantly smaller than the original (typically 2–10% of original size) since non-API entries and their response bodies are removed.

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

Filters HAR entries to relevant API hosts:
- Accepts the full entries array
- Returns only entries matching `api.opendns.com` or `api.umbrella.com`
- Only keeps `GET` requests with HTTP 200 responses and non-empty `response.content.text`

#### `Get-HARResponseByUrl`

Extracts parsed response data from HAR entries matching a URL pattern:
- Accepts entries array, regex pattern, and optional `-All` switch
- URL-decodes query strings before matching
- Parses `response.content.text` as JSON
- Returns single response or array (when `-All`)

#### `Get-HAROrganizationId`

Auto-detects the organizationId from the first matching URL path.

#### `Export-CleanHAR`

Sanitizes and writes the clean HAR file:
- Filters entries to relevant hosts
- Strips sensitive headers and cookies
- Writes output file

### 9.2 Main Function Flow

```
1. Validate parameters
2. Generate timestamp
3. Create output folder: CiscoUmbrella-backup_{timestamp}/
4. Initialize logging ($script:LogPath)
5. Read HAR file (Read-HARFile)
6. Log HAR stats (file size, total entries)
7. If -ExportCleanHAR:
    a. Sanitize and write clean HAR (Export-CleanHAR)
    b. Release HAR object from memory
    c. Display summary and RETURN (skip steps 8–13)
8. Filter to relevant API entries (Get-HARApiEntries)
9. Release full HAR object from memory
10. Auto-detect organizationId (Get-HAROrganizationId)
11. Extract each object type:
    a. DNS Policies → dns_policies.json
    b. Firewall Rules → firewall_rules.json
    c. Web Policies → web_policies.json
    d. Destination Lists → destination_lists.json
    e. Category Settings → category_settings.json
    f. Application Settings → application_settings.json
    g. Security Settings → security_settings.json
    h. Selective Decryption Lists → selective_decryption_lists.json
12. Write export_metadata.json
13. Display summary report
```

### 9.3 Using Export-DataToFile

Each extracted object array is saved using the existing internal `Export-DataToFile` function:

```powershell
Export-DataToFile -Data $dnsPolicies -FilePath "$outputFolder\dns_policies.json" -Format "JSON"
```

---

## 10. Console Output and Summary

### 10.1 Progress Output

Use `Write-LogMessage` for each phase:

```
[INFO] Reading HAR file: C:\captures\umbrella.har (142 MB, 1,847 entries)
[INFO] Detected Umbrella organizationId: 7293841
[INFO] Filtered to 47 relevant API entries (api.opendns.com, api.umbrella.com)
[INFO] Extracting DNS Policies...
[SUCCESS] Extracted 3 DNS policies:
         - Branch Office Policy
         - Remote Workers Policy
         - Default Policy
[INFO] Extracting Firewall Rules...
[SUCCESS] Extracted 2 firewall rules (1 ruleset):
         - Allow VPN Traffic
         - Default Internet
[INFO] Extracting Web Policies...
[SUCCESS] Extracted 1 web policy with proxy ruleset:
         - Corporate Web Policy
[INFO] Extracting Destination Lists...
[SUCCESS] Extracted 4 destination lists (2 with entries):
         - Approved SaaS Domains (12 entries)
         - Blocked Gambling Sites (8 entries)
         - Global Allow List (0 entries)
         - Global Block List (0 entries)
[INFO] Extracting Category Settings...
[SUCCESS] Extracted 3 category settings:
         - Strict Content Filter
         - Default Web Settings
         - Moderate Content Filter
[INFO] Extracting Application Settings...
[SUCCESS] Extracted 2 application settings:
         - Block Social Media
         - Default Settings
[INFO] Extracting Security Settings...
[SUCCESS] Extracted 3 security settings:
         - High Security Profile (inherited)
         - Default Settings
         - Default Web Settings
[INFO] Extracting Selective Decryption Lists...
[SUCCESS] Extracted 1 selective decryption list:
         - Default Web Selective Decryption List
```

### 10.2 Completion Summary

```
Export completed successfully!

Backup folder: C:\Output\CiscoUmbrella-backup_20260220_143022\

Cisco Umbrella Configuration (from HAR):
  Organization ID: 8144773
  DNS Policies:              3
  Firewall Rules:            2
  Web Policies:              1
  Destination Lists:         5 (1 with entries)
  Category Settings:         5 (4 with full category details)
  Application Settings:      2 (2 with full app details)
  Security Settings:         4 (1 MSP-inherited)
  Selective Decryption Lists: 1
  Warnings: 2 (see log file for details)

Files created:
  - dns_policies.json
  - firewall_rules.json
  - web_policies.json
  - destination_lists.json
  - category_settings.json
  - application_settings.json
  - security_settings.json
  - selective_decryption_lists.json
  - export_metadata.json
  - 20260220_143022_Export-CiscoUmbrella.log
```

---

## 11. Usage Examples

### 11.1 Basic Usage

```powershell
Export-CiscoUmbrellaConfig -HARFilePath "C:\captures\umbrella_dashboard.har"
```

Creates backup in current directory: `.\CiscoUmbrella-backup_20260220_143022\`

### 11.2 Custom Output Directory

```powershell
Export-CiscoUmbrellaConfig `
    -HARFilePath "C:\captures\umbrella_dashboard.har" `
    -OutputDirectory "C:\Backups\Umbrella"
```

### 11.3 With Sanitized HAR for Sharing

```powershell
Export-CiscoUmbrellaConfig `
    -HARFilePath "C:\captures\umbrella_dashboard.har" `
    -OutputDirectory "C:\Backups\Umbrella" `
    -ExportCleanHAR
```

Produces **only** `umbrella_clean.har` — no JSON extraction is performed.

### 11.4 Verbose Output

```powershell
Export-CiscoUmbrellaConfig `
    -HARFilePath "C:\captures\umbrella_dashboard.har" `
    -Verbose
```

### 11.5 Pipeline from File Selection

```powershell
Get-Item "C:\captures\*.har" | Select-Object -First 1 -ExpandProperty FullName |
    ForEach-Object { Export-CiscoUmbrellaConfig -HARFilePath $_ -ExportCleanHAR }
```

---

## 12. Edge Cases and Known Quirks

### 12.1 Umbrella API Quirks (from HAR Reference)

| Quirk | Handling |
|-------|----------|
| `meta.total=0` on selective decryption lists despite data existing | Always use `data.Count`, never `meta.total` for this endpoint |
| System-inherited application settings (`organizationId=1`) not in list | Scan all individual `applicationsettings/{id}` responses for records not present in the list |
| MSP-inherited records (`organizationId != orgId`) in lists | Export these records but tag with `_isInherited: true` |
| `createdAt`/`modifiedAt` format differs between list (epoch) and detail (datetime string) | Prefer detail format; do not attempt to convert between formats |
| DNS and Web bundles share the same `/bundles` endpoint | Differentiate by `bundleTypeId` in the query string filter |
| Security settings list with `optionalFields=["categories"]` returns full data inline | If this variant is present, no need for individual fetches |

### 12.2 HAR Capture Edge Cases

| Case | Handling |
|------|----------|
| User didn't browse all dashboard pages (missing object types) | Export what's available; log warnings for missing types |
| Multiple HAR captures combined into one file | Process all entries — deduplication by URL+response |
| HAR captured from a different Umbrella console version | Rely on URL path patterns, not on exact query parameter format |
| Duplicate responses for the same URL (browser retry, polling) | Use the last successful (HTTP 200) response for each unique URL |
| Compressed response body (`content.encoding: "base64"`) | Detect `content.encoding` and decode if base64; log warning for unsupported encodings |

---

## 13. Success Criteria

### 13.1 Functional Requirements

- [ ] Accept HAR file path and validate the file exists and is valid HAR/JSON
- [ ] Auto-detect organizationId from HAR entry URLs
- [ ] Extract all 8 object types from HAR responses
- [ ] Prefer detail-level responses over list-level where both exist
- [ ] Handle missing object types gracefully (warn and continue)
- [ ] Save each object type as an individual JSON file
- [ ] Generate export_metadata.json with provenance and counts
- [ ] Support `-ExportCleanHAR` to produce a sanitized HAR copy
- [ ] Strip Authorization, Cookie, Set-Cookie, X-CSRF-Token, X-Auth* headers in clean HAR
- [ ] Remove non-API entries from clean HAR
- [ ] Handle HAR files over 100MB without running out of memory
- [ ] Create timestamped backup folder
- [ ] Generate comprehensive log file
- [ ] Use Write-LogMessage and Export-DataToFile internal functions

### 13.2 Quality Requirements

- [ ] Exported JSON files accurately represent the Umbrella configuration
- [ ] No sensitive data (tokens, cookies) in output JSON files or clean HAR
- [ ] Clear, actionable error messages for common failure modes
- [ ] Memory-efficient processing for large HAR files
- [ ] Follows PowerShell 7 idioms and module conventions

---

## 14. Testing Scenarios

### 14.1 Positive Tests

1. Complete HAR with all 8 object types → all JSON files created with correct data
2. HAR with only some object types → available types exported, warnings for missing
3. Large HAR (>100MB) → completes without memory issues
4. `-ExportCleanHAR` → clean HAR contains only API entries with no sensitive headers
5. Custom output directory → folder created and files written correctly

### 14.2 Negative Tests

1. File not found → clear error message
2. Invalid JSON file → clear error message
3. Valid JSON but not a HAR file → clear error message
4. HAR with no Umbrella API entries → clear error message
5. HAR with API errors (non-200 responses) → warnings, continues with available data
6. Output directory not writable → clear error before processing

### 14.3 Edge Case Tests

1. HAR with duplicate responses for same URL → uses last successful response
2. HAR with only list endpoints (no detail fetches) → exports list-level data with warnings
3. MSP-inherited records → exported with `_isInherited` flag
4. System-inherited application setting → detected from individual fetch responses
5. Paginated firewall rules → merged into single response

---

## 15. Dependencies

- PowerShell 7.0 or higher
- Internal module functions:
  - `Write-LogMessage` — For consistent logging and output
  - `Export-DataToFile` — For writing JSON output files
- No external modules or network access required

---

## 16. Future Enhancements

1. Support for additional Umbrella object types as dashboard API evolves
2. Diff/comparison between two HAR exports (detect config changes over time)
3. Direct conversion from Umbrella export to Entra Internet Access provisioning CSV
4. Support for HAR files captured from Umbrella Reporting/Activity pages
5. Batch processing of multiple HAR files from different time periods

---

## References

- [Umbrella HAR API Reference](umbrella_har_api_reference.md) — Complete endpoint and response structure documentation
- [HAR 1.2 Specification](http://www.softwareishard.com/blog/har-12-spec/)
- [Export-NetskopeConfig Specification](20251015-ExportNetskopeConfig.md)
- [Export-EntraInternetAccessConfig Specification](20260212-Export-EntraInternetAccessConfig.md)
