# Cisco Umbrella Dashboard – API Reference (from HAR)

This document is derived from a HAR capture of the Cisco Umbrella dashboard (`dashboard.umbrella.com`).
Each entry identifies the exact HTTP request the dashboard makes to the backend API, including the method, URI, query parameters, request body (if any), and a sample of the response structure.

Use this as the reference for building a PowerShell export script.

**Base URL (dashboard internal API):** `https://api.opendns.com`  
**Authentication:** Session cookie / bearer token obtained via the dashboard login flow.

> **Note:** The dashboard uses `https://api.opendns.com/v3/` — not the public `api.umbrella.com/v2/` — for all policy and configuration data. The organization is referenced by a numeric `organizationId` in the path (e.g. `8888888`).

---

## Section 8 — Selective Decryption Lists (Bypass Inspection Group Settings)

Selective Decryption Lists define what traffic is **exempted from SSL inspection** in Web (SWG) policies. They are referenced by Web policy bundles via the `settingGroupBypassInspectionGroup` embedded object. Internally the API calls these `bypassinspectiongroupsettings`.

Each record links to a **destination list** (`exceptiondomainlistId`) with `access="none"` (the SSL bypass destination list type documented in Section 4) and optionally an application exception list.

---

### Endpoint 8a — List All Selective Decryption Lists

```
GET https://api.opendns.com/v3/organizations/{orgId}/bypassinspectiongroupsettings
    ?sort={"name":"asc","createdAt":"desc"}
    &outputFormat=jsonHttpStatusOverride
```

The `sort` parameter is optional — requests without it return the same data.

**Response envelope:**

```json
{
  "status": { "code": 200, "text": "OK" },
  "meta": { "page": 1, "limit": 25, "total": 0 },
  "data": [ ... ]
}
```

> **Important:** `meta.total` is `0` even though `data` contains one record. This appears to be a dashboard API quirk — **do not use `meta.total` to determine whether records exist; always check `data.length`.**

**Each item in `data`:**

| Field | Type | Notes |
|-------|------|-------|
| `id` | integer | Selective decryption list ID |
| `organizationId` | integer | Owning org |
| `name` | string | Display name |
| `isDefault` | boolean | `true` = default list for the org |
| `bundleTypeId` | integer | Always `2` (Web/SWG only — SSL decryption is a SWG feature) |
| `decryptExceptionCategories` | array | URL categories exempted from decryption — each has `categoryId` and `name` |
| `exceptiondomainlistId` | integer\|null | ID of the linked destination list (`access="none"`) containing exempted domains/IPs/URLs |
| `exceptionapplicationlistId` | integer\|null | ID of a linked application exception list (not used in this org) |
| `totalDomains` | integer | Count of domain entries in the linked destination list |
| `totalApplications` | integer | Count of application entries |
| `totalIps` | integer | Count of IP entries |
| `createdAt` | string | Datetime `"YYYY-MM-DD HH:MM:SS"` |
| `modifiedAt` | string | Datetime `"YYYY-MM-DD HH:MM:SS"` |

**The single record for this org:**

| id | name | isDefault | exceptiondomainlistId | totalDomains | totalIps | totalApplications |
|----|------|-----------|-----------------------|-------------|---------|-------------------|
| `6459767` | Default Web Selective Decryption List | `true` | `17211278` | `0` | `0` | `0` |

---

### Endpoint 8b — Get Individual Selective Decryption List

```
GET https://api.opendns.com/v3/organizations/{orgId}/bypassinspectiongroupsettings/{id}
    ?outputFormat=jsonHttpStatusOverride
```

Returns the same fields as the list but with `data` as a single object (not an array). The `meta` object is still present (with `total: 0`).

**Full response for `id=6459767`:**

```json
{
  "status": { "code": 200, "text": "OK" },
  "meta": { "page": 1, "limit": 25, "total": 0 },
  "data": {
    "id": 6459767,
    "organizationId": 8888888,
    "isDefault": true,
    "name": "Default Web Selective Decryption List",
    "bundleTypeId": 2,
    "decryptExceptionCategories": [],
    "exceptiondomainlistId": 17211278,
    "exceptionapplicationlistId": null,
    "totalDomains": 0,
    "totalIps": 0,
    "totalApplications": 0,
    "createdAt": "2023-05-04 17:10:38",
    "modifiedAt": "2023-05-10 15:10:48"
  }
}
```

---

### Key Observations

- **`meta.total=0` is a known quirk** — the count field is unreliable for this endpoint. Always iterate `data[]` directly.
- Only `bundleTypeId=2` (Web/SWG) records exist — SSL decryption bypass is a SWG-only concept; DNS policies never have bypass inspection groups.
- `exceptiondomainlistId` (`17211278`) references a destination list with `access="none"` — this is the actual list of exempted destinations. To get its entries, use Endpoint 4b (`/destinationlists/17211278/destinations`). In this org it is currently empty (`totalDomains=0`).
- `decryptExceptionCategories` holds category-level bypass rules (entire URL categories exempted from inspection). Empty in this org.
- `exceptionapplicationlistId` is `null` here — when populated it would reference a Cisco-managed application list used for SSL bypass.

### PowerShell Usage Note

```powershell
# List all selective decryption lists
$bypassLists = (Invoke-RestMethod "$base/v3/organizations/$orgId/bypassinspectiongroupsettings?outputFormat=jsonHttpStatusOverride" -Headers $h).data
# Note: do NOT use meta.total — check $bypassLists.Count directly

foreach ($bl in $bypassLists) {
    # Fetch entries from the linked destination list if non-empty
    if ($bl.totalDomains -gt 0 -or $bl.totalIps -gt 0) {
        $entries = (Invoke-RestMethod "$base/v3/organizations/$orgId/destinationlists/$($bl.exceptiondomainlistId)/destinations?outputFormat=jsonHttpStatusOverride" -Headers $h).data
    }
    # $bl.decryptExceptionCategories — category-level bypasses (inline, no extra fetch needed)
}
```

---


Security settings control which threat/security categories are blocked, as well as toggles for advanced inspection features (botnet, malware, phishing, file inspection, AMP, etc.). They are referenced by DNS and Web policies via the `securitySetting` embedded object.

**Key difference from category/application settings:** the list endpoint supports `optionalFields=["categories"]`, so `categories[]` can be retrieved in a single list call — no individual fetch required unless you also need `categoryPrefs`.

---

### Endpoint 7a — List All Security Settings

Two variants observed in the HAR — the dashboard makes both calls on different pages:

**Variant 1 — with `optionalFields=["categories"]` (returns full category arrays inline):**

```
GET https://api.opendns.com/v3/organizations/{orgId}/securitysettings
    ?sort={"name":"asc","createdAt":"desc"}
    &optionalFields=["categories"]
    &outputFormat=jsonHttpStatusOverride
```

**Variant 2 — with `optionalFields=["categoryPrefs"]` (returns bitmask fields, no category arrays):**

```
GET https://api.opendns.com/v3/organizations/{orgId}/securitysettings
    ?sort={"name":"asc","createdAt":"desc"}
    &optionalFields=["categoryPrefs"]
    &outputFormat=jsonHttpStatusOverride
```

> For export purposes, **Variant 1** is preferred — it returns the full `categories[]` array inline and avoids a second round of individual fetches.

**Response envelope:**

```json
{
  "status": { "code": 200, "text": "OK" },
  "meta": { "page": 1, "limit": 25, "total": 4 },
  "data": [ ... ]
}
```

**Each item in `data`:**

| Field | Type | Notes |
|-------|------|-------|
| `id` | integer | Security setting ID |
| `organizationId` | integer | Owning org — may differ if MSP-inherited |
| `name` | string | Display name |
| `isDefault` | boolean | `true` = default for this org |
| `bundleTypeId` | integer | `1` = DNS, `2` = Web |
| `isSwgDefault` | boolean\|null | `true` = SWG default security setting |
| `botnetProtection` | boolean | Block botnet callbacks |
| `malwareProtection` | boolean | Block malware domains |
| `superBotnet` | boolean | Extended botnet protection |
| `superMalware` | boolean | Extended malware protection |
| `phishingProtection` | boolean | Block phishing sites |
| `suspiciousResponseFiltering` | boolean | Filter suspicious DNS responses |
| `malwareUrlProxy` | boolean | Proxy malware URLs |
| `urlProxyHttps` | boolean | Proxy HTTPS URLs |
| `ipFiltering` | boolean | Enable IP-layer filtering |
| `fileInspection` | boolean | Enable file inspection (SWG) |
| `ampScan` | boolean | Enable AMP (Advanced Malware Protection) scanning |
| `categoryBits` | string | Hex bitmask of blocked security categories |
| `categories` | array | Present when `optionalFields=["categories"]` — each has `categoryId` (int) and `name` (string) |
| `categoryPrefs` | string | Present when `optionalFields=["categoryPrefs"]` — low bits bitmask |
| `categoryPrefsHigh` | string | Present when `optionalFields=["categoryPrefs"]` — high bits bitmask |
| `createdAt` | integer | Unix timestamp in list |
| `modifiedAt` | integer | Unix timestamp in list |
| `markedForDeletion` | boolean | |

**All 4 records for this org (from list with `optionalFields=["categories"]`):**

| id | name | bundleTypeId | isDefault | isSwgDefault | organizationId | fileInspection |
|----|------|-------------|-----------|--------------|----------------|----------------|
| `8378733` | Centralized Default Settings | 1 | `true` | `null` | `7777777` (MSP) | `false` |
| `14493272` | Default Settings | 1 | `true` | `null` | `8888888` | `false` |
| `14493273` | Default Web Settings | 2 | `false` | `true` | `8888888` | `true` |
| `15040488` | test | 1 | `false` | `null` | `8888888` | `false` |

> `id=8378733` belongs to `organizationId=7777777` (MSP parent) — read-only inherited record.

---

### Endpoint 7b — Get Individual Security Setting

```
GET https://api.opendns.com/v3/organizations/{orgId}/securitysettings/{securitySettingId}
    ?outputFormat=jsonHttpStatusOverride
```

Returns the same fields as the list but with `categories[]` always included and `createdAt`/`modifiedAt` as datetime strings.

**Example — `id=14493272` ("Default Settings", DNS default):**

```json
{
  "id": 14493272,
  "organizationId": 8888888,
  "isDefault": true,
  "name": "Default Settings",
  "bundleTypeId": 1,
  "isSwgDefault": null,
  "botnetProtection": true,
  "malwareProtection": true,
  "superBotnet": true,
  "superMalware": true,
  "phishingProtection": true,
  "suspiciousResponseFiltering": false,
  "malwareUrlProxy": false,
  "urlProxyHttps": false,
  "ipFiltering": false,
  "fileInspection": false,
  "ampScan": false,
  "categoryBits": "d000000000000000",
  "createdAt": "2023-05-04 17:10:38",
  "modifiedAt": "2023-05-04 17:10:38",
  "markedForDeletion": false,
  "categories": [
    { "categoryId": 83, "name": "Drive-by Downloads/Exploits" },
    { "categoryId": 87, "name": "Mobile Threats" },
    { "categoryId": 89, "name": "High Risk Sites and Locations" }
  ]
}
```

**Example — `id=14493273` ("Default Web Settings", SWG default, `fileInspection=true`, no extra categories):**

```json
{
  "id": 14493273,
  "organizationId": 8888888,
  "isDefault": null,
  "name": "Default Web Settings",
  "bundleTypeId": 2,
  "isSwgDefault": true,
  "botnetProtection": true,
  "malwareProtection": true,
  "superBotnet": true,
  "superMalware": true,
  "phishingProtection": true,
  "suspiciousResponseFiltering": false,
  "malwareUrlProxy": false,
  "urlProxyHttps": false,
  "ipFiltering": false,
  "fileInspection": true,
  "ampScan": false,
  "categoryBits": "0",
  "createdAt": "2023-05-04 17:10:38",
  "modifiedAt": "2023-05-04 17:10:38",
  "markedForDeletion": false,
  "categories": []
}
```

**Example — `id=15040488` ("test", custom security categories):**

```json
{
  "id": 15040488,
  "organizationId": 8888888,
  "isDefault": null,
  "name": "test",
  "bundleTypeId": 1,
  "isSwgDefault": null,
  "botnetProtection": true,
  "malwareProtection": true,
  "superBotnet": true,
  "superMalware": true,
  "phishingProtection": true,
  "suspiciousResponseFiltering": false,
  "malwareUrlProxy": false,
  "urlProxyHttps": false,
  "ipFiltering": false,
  "fileInspection": false,
  "ampScan": false,
  "categoryBits": "40000000006000000000000000000000000000",
  "createdAt": "2025-04-26 09:32:12",
  "modifiedAt": "2025-04-26 09:32:12",
  "markedForDeletion": false,
  "categories": [
    { "categoryId": 174, "name": "Potentially Harmful" },
    { "categoryId": 176, "name": "DNS Tunneling VPN" },
    { "categoryId": 403, "name": "Cryptomining" }
  ]
}
```

---

### Key Observations

- `meta.total=4` — the list **includes** the MSP-inherited record (`id=8378733`, `organizationId=7777777`), unlike application settings where the inherited record was absent from the list. Identify inherited records by `organizationId != {your orgId}`.
- `optionalFields=["categories"]` on the list call returns `categories[]` inline — **no individual fetch needed** to get the full category list. This is more efficient than category settings or application settings.
- `fileInspection=true` only on the Web/SWG default (`bundleTypeId=2`, `isSwgDefault=true`) — file inspection is a SWG-only feature.
- All boolean flags (`botnetProtection`, `malwareProtection`, etc.) default to `true` except `suspiciousResponseFiltering`, `malwareUrlProxy`, `urlProxyHttps`, `ipFiltering`, `fileInspection`, `ampScan` which default to `false`.
- `categoryBits="0"` on "Default Web Settings" with empty `categories[]` — no extra security categories blocked beyond the boolean toggles.

### PowerShell Usage Note

```powershell
# Single call — list returns full categories[] inline
$secSettings = (Invoke-RestMethod (
    "$base/v3/organizations/$orgId/securitysettings" +
    "?sort=%7B%22name%22%3A%22asc%22%7D&optionalFields=%5B%22categories%22%5D&outputFormat=jsonHttpStatusOverride"
) -Headers $h).data

# Identify org-owned vs inherited
$orgOwned  = $secSettings | Where-Object { $_.organizationId -eq $orgId }
$inherited = $secSettings | Where-Object { $_.organizationId -ne $orgId }
```

---


Application settings define which cloud applications and application categories are blocked or allowed. They are referenced by DNS and Web policies via the `applicationSetting` embedded object. Like category settings, the dashboard lists all application settings, then fetches each individually to get the full `applications[]` and `applicationsCategories[]` arrays.

---

### Endpoint 6a — List All Application Settings

```
GET https://api.opendns.com/v3/organizations/{orgId}/applicationsettings
    ?outputFormat=jsonHttpStatusOverride
```

No `optionalFields` required for the list — blocked/allowed/warned counts are included by default (though they may be `null` for the default setting in the list response).

**Response envelope:**

```json
{
  "status": { "code": 200, "text": "OK" },
  "meta": { "page": 1, "limit": 25, "total": 2 },
  "data": [ ... ]
}
```

> **Note:** `meta.total` is `2` — only org-owned records. The third record ("None", `organizationId=1`) is a system-level inherited setting fetched individually when referenced by a policy; it does **not** appear in this list.

**Each item in `data`:**

| Field | Type | Notes |
|-------|------|-------|
| `id` | integer | Application setting ID |
| `organizationId` | integer | Owning org — may differ if system/MSP-inherited |
| `name` | string | Display name |
| `isDefault` | boolean | `true` = default application setting for this org |
| `type` | string | Always `"application"` |
| `bundleTypeId` | integer | `1` = DNS, `2` = Web |
| `isSwgDefault` | boolean\|null | |
| `blockedCount` | integer\|null | Count of explicitly blocked apps+categories; `null` in list for default |
| `allowedCount` | integer\|null | Count of explicitly allowed apps+categories; `null` in list for default |
| `warnedCount` | integer\|null | Count of warned apps+categories; `null` in list for default |
| `createdAt` | integer | Unix timestamp (epoch seconds) in list |
| `modifiedAt` | integer | Unix timestamp (epoch seconds) in list |
| `markedForDeletion` | boolean | |

**Sample list (this org — 2 org-owned records):**

| id | name | isDefault | bundleTypeId |
|----|------|-----------|-------------|
| `15218787` | Default Settings | `true` | `1` |
| `16304687` | test | `false` | `1` |

---

### Endpoint 6b — Get Individual Application Setting (with full app/category lists)

```
GET https://api.opendns.com/v3/organizations/{orgId}/applicationsettings/{applicationSettingId}
    ?outputFormat=jsonHttpStatusOverride
```

The individual fetch adds `applications[]` and `applicationsCategories[]` arrays not present in the list.

**`data` object — additional fields over list:**

| Field | Type | Notes |
|-------|------|-------|
| `applications` | array | Individual apps with explicit actions — each has `applicationId`, `action`, `selectedAction{name,displayName,actionId}`, `name` |
| `applicationsCategories` | array | App categories with explicit actions — each has `applicationCategoryId`, `action`, `selectedAction{...}`, `name` |
| `createdAt` | string | ISO-like datetime `"YYYY-MM-DD HH:MM:SS"` on individual fetch |
| `modifiedAt` | string | ISO-like datetime on individual fetch |

**Example — `id=15218787` ("Default Settings", isDefault=true, empty rules):**

```json
{
  "id": 15218787,
  "organizationId": 8888888,
  "isDefault": true,
  "name": "Default Settings",
  "type": "application",
  "bundleTypeId": 1,
  "isSwgDefault": null,
  "blockedCount": 0,
  "allowedCount": 0,
  "warnedCount": 0,
  "createdAt": "2023-05-10 09:08:20",
  "modifiedAt": "2023-05-10 15:10:46",
  "markedForDeletion": false,
  "applications": [],
  "applicationsCategories": []
}
```

**Example — `id=16304687` ("test", with blocked app categories):**

```json
{
  "id": 16304687,
  "organizationId": 8888888,
  "isDefault": null,
  "name": "test",
  "type": "application",
  "bundleTypeId": 1,
  "isSwgDefault": null,
  "blockedCount": 0,
  "allowedCount": 0,
  "warnedCount": 0,
  "createdAt": "2025-04-26 09:34:09",
  "modifiedAt": "2026-02-19 09:58:58",
  "markedForDeletion": false,
  "applications": [],
  "applicationsCategories": [
    { "applicationCategoryId": 4,  "action": "block", "selectedAction": { "name": "block", "displayName": "Block", "actionId": 0 }, "name": "Business Intelligence" },
    { "applicationCategoryId": 45, "action": "block", "selectedAction": { "name": "block", "displayName": "Block", "actionId": 0 }, "name": "Cloud Carrier" },
    { "applicationCategoryId": 48, "action": "block", "selectedAction": { "name": "block", "displayName": "Block", "actionId": 0 }, "name": "Games" },
    { "applicationCategoryId": 50, "action": "block", "selectedAction": { "name": "block", "displayName": "Block", "actionId": 0 }, "name": "Travel" },
    { "applicationCategoryId": 51, "action": "block", "selectedAction": { "name": "block", "displayName": "Block", "actionId": 0 }, "name": "Anonymizer" },
    { "applicationCategoryId": 52, "action": "block", "selectedAction": { "name": "block", "displayName": "Block", "actionId": 0 }, "name": "P2P" }
  ]
}
```

**Example — `id=1139310` ("None", system-inherited, `organizationId=1`):**

```json
{
  "id": 1139310,
  "organizationId": 1,
  "isDefault": null,
  "name": "None",
  "type": "application",
  "bundleTypeId": 1,
  "isSwgDefault": null,
  "blockedCount": 0,
  "allowedCount": 0,
  "warnedCount": 0,
  "createdAt": "2018-02-26 21:02:58",
  "modifiedAt": "2018-02-26 21:02:58",
  "markedForDeletion": false,
  "applications": [],
  "applicationsCategories": []
}
```

---

### Key Observations

- The list returns `total: 2` (org-owned only). The third record (`id=1139310`, `"None"`, `organizationId=1`) is a **system-level inherited** setting — it only appears when fetched individually (e.g. when a policy references it). Do not expect it in the list.
- `applications[]` holds individual app overrides; `applicationsCategories[]` holds whole-category actions. Both are only populated on the individual fetch.
- `action` values observed: `"block"`, `"allow"`. Both fields on `selectedAction` (`name`, `displayName`, `actionId`) are redundant — `action` string is sufficient for export.
- All observed records have `bundleTypeId=1` (DNS). No Web-specific application settings were observed in this HAR — but the field exists.
- `blockedCount`/`allowedCount`/`warnedCount` are `null` in the list for the default setting, but `0` after individual fetch — use individual fetch values for accuracy.

### PowerShell Usage Note

```powershell
# Step 1: List all application settings (org-owned)
$appSettings = (Invoke-RestMethod "$base/v3/organizations/$orgId/applicationsettings?outputFormat=jsonHttpStatusOverride" -Headers $h).data

# Step 2: Fetch each individually to get applications[] and applicationsCategories[]
foreach ($as in $appSettings) {
    $detail = (Invoke-RestMethod "$base/v3/organizations/$orgId/applicationsettings/$($as.id)?outputFormat=jsonHttpStatusOverride" -Headers $h).data
    # $detail.applications        — individual app overrides
    # $detail.applicationsCategories — whole-category actions
}
```

---


Category settings define which URL content categories are blocked or warned against. They are referenced by DNS and Web policies via the `categorySetting` embedded object. The dashboard lists all category settings for the org, then fetches each individual one to get the full category list.

---

### Endpoint 5a — List All Category Settings

```
GET https://api.opendns.com/v3/organizations/{orgId}/categorysettings
    ?sort={"name":"asc","createdAt":"desc"}
    &optionalFields=["categoryPrefs"]
    &outputFormat=jsonHttpStatusOverride
```

| Parameter | Value | Notes |
|-----------|-------|-------|
| `sort` | `{"name":"asc","createdAt":"desc"}` | URL-encoded in actual request |
| `optionalFields` | `["categoryPrefs"]` | Adds `categoryPrefs` and `categoryPrefsHigh` hex bitmask fields to each record |
| `outputFormat` | `jsonHttpStatusOverride` | Standard dashboard envelope |

**Response envelope:**

```json
{
  "status": { "code": 200, "text": "OK" },
  "meta": { "page": 1, "limit": 25, "total": 5 },
  "data": [ ... ]
}
```

**Each item in `data`:**

| Field | Type | Notes |
|-------|------|-------|
| `id` | integer | Category setting ID |
| `organizationId` | integer | Org that owns this setting — may differ from query org if MSP-inherited |
| `name` | string | Display name |
| `isDefault` | boolean\|null | `true` = default setting for the org; `null` in list (populated on individual fetch) |
| `bundleTypeId` | integer | `1` = DNS, `2` = Web |
| `isSwgDefault` | boolean\|null | `true` = this is the SWG (Secure Web Gateway) default content setting |
| `categoryBits` | string | Hex bitmask of blocked categories (opaque — reconstruct from `categories[]` on individual fetch) |
| `warnCategoryBits` | string | Hex bitmask of warn categories |
| `categoryPrefs` | string | Hex bitmask (returned when `optionalFields=["categoryPrefs"]`) — low bits |
| `categoryPrefsHigh` | string | Hex bitmask — high bits |
| `createdAt` | integer | Unix timestamp (epoch seconds) in list response |
| `modifiedAt` | integer | Unix timestamp (epoch seconds) in list response |
| `markedForDeletion` | boolean | |

**Sample list response (this org — 5 records):**

| id | name | bundleTypeId | isDefault | isSwgDefault | organizationId |
|----|------|-------------|-----------|--------------|----------------|
| `9999999` | Centralized Default Settings | 1 | `true` | `null` | `7777777` (MSP parent) |
| `15202345` | Default Settings | 1 | `true` | `null` | `8888888` |
| `15202346` | Default Web Settings | 2 | `false` | `true` | `8888888` |
| `16304686` | test | 1 | `false` | `null` | `8888888` |
| `16306039` | Test 2 | 2 | `false` | `null` | `8888888` |

> **Note:** `id=9999999` belongs to `organizationId=7777777` (MSP parent org), not `8888888`. This is an MSP-inherited default setting — treat as read-only.

---

### Endpoint 5b — Get Individual Category Setting (with full category list)

```
GET https://api.opendns.com/v3/organizations/{orgId}/categorysettings/{categorySettingId}
    ?outputFormat=jsonHttpStatusOverride
```

No additional `optionalFields` needed — the individual fetch always returns the full `categories[]` and `warnCategories[]` arrays.

**Response envelope:**

```json
{
  "status": { "code": 200, "text": "OK" },
  "data": { ... }
}
```

**`data` object fields (superset of list fields):**

| Field | Type | Notes |
|-------|------|-------|
| `id` | integer | |
| `organizationId` | integer | |
| `name` | string | |
| `isDefault` | boolean\|null | |
| `bundleTypeId` | integer | `1`=DNS, `2`=Web |
| `isSwgDefault` | boolean\|null | |
| `type` | string | Always `"mixed"` in observed data |
| `categoryBits` | string | Hex bitmask (opaque) |
| `warnCategoryBits` | string | Hex bitmask for warn categories |
| `categories` | array | Full list of blocked categories — each has `categoryId` (int) and `name` (string) |
| `warnCategories` | array | Full list of warn categories — same shape as `categories` |
| `createdAt` | string | ISO-like datetime string `"YYYY-MM-DD HH:MM:SS"` on individual fetch |
| `modifiedAt` | string | ISO-like datetime string on individual fetch |
| `markedForDeletion` | boolean | |

**Example — `id=15202346` ("Default Web Settings", bundleTypeId=2, isSwgDefault=true):**

```json
{
  "id": 15202346,
  "organizationId": 8888888,
  "isDefault": null,
  "name": "Default Web Settings",
  "bundleTypeId": 2,
  "isSwgDefault": true,
  "type": "mixed",
  "categoryBits": "80020000000000000000000000040000000",
  "warnCategoryBits": "0",
  "createdAt": "2023-05-04 17:10:38",
  "modifiedAt": "2026-02-19 09:58:15",
  "markedForDeletion": false,
  "categories": [
    { "categoryId": 28, "name": "Weapons" },
    { "categoryId": 355, "name": "Lotteries" },
    { "categoryId": 383, "name": "Web Hosting" }
  ],
  "warnCategories": []
}
```

**Example — `id=15202345` ("Default Settings", bundleTypeId=1, isDefault=true):**

```json
{
  "id": 15202345,
  "organizationId": 8888888,
  "isDefault": true,
  "name": "Default Settings",
  "bundleTypeId": 1,
  "isSwgDefault": null,
  "type": "mixed",
  "categoryBits": "20000000200000000000080000000000000000000000040000000",
  "warnCategoryBits": "0",
  "createdAt": "2023-05-04 17:10:38",
  "modifiedAt": "2026-02-19 09:57:58",
  "markedForDeletion": false,
  "categories": [
    { "categoryId": 28, "name": "Weapons" },
    { "categoryId": 359, "name": "Nature and Conservation" },
    { "categoryId": 431, "name": "Job Search" },
    { "categoryId": 463, "name": "Regional Restricted Sites (Great Britain)" }
  ],
  "warnCategories": []
}
```

**Example — `id=9999999` ("Centralized Default Settings", MSP-inherited, empty):**

```json
{
  "id": 9999999,
  "organizationId": 7777777,
  "isDefault": true,
  "name": "Centralized Default Settings",
  "bundleTypeId": 1,
  "isSwgDefault": null,
  "categoryBits": "0",
  "warnCategoryBits": "0",
  "categories": [],
  "warnCategories": []
}
```

---

### Key Observations

- The list endpoint returns **5 records** total for this org, but only **4 belong to org `8888888`** — one (`id=9999999`) is MSP-inherited from parent org `7777777`.
- `bundleTypeId=1` = DNS category settings; `bundleTypeId=2` = Web (SWG) category settings.
- `isSwgDefault=true` marks the default content setting used by Web policies unless overridden.
- `isDefault=true` marks the default DNS category setting.
- The `categoryBits` hex bitmask is opaque — for reconstruction use the `categories[]` array from the individual fetch.
- `warnCategories` was empty in all observed records for this org — but the field exists and should be captured.
- `createdAt`/`modifiedAt` are **epoch integers** in the list but **datetime strings** in individual fetches.

### PowerShell Usage Note

```powershell
# Step 1: List all category settings
$catSettings = (Invoke-RestMethod "$base/v3/organizations/$orgId/categorysettings?sort=%7B%22name%22%3A%22asc%22%7D&optionalFields=%5B%22categoryPrefs%22%5D&outputFormat=jsonHttpStatusOverride" -Headers $h).data

# Step 2: For each, fetch the individual record to get full categories[] array
foreach ($cs in $catSettings) {
    $detail = (Invoke-RestMethod "$base/v3/organizations/$orgId/categorysettings/$($cs.id)?outputFormat=jsonHttpStatusOverride" -Headers $h).data
    # $detail.categories contains the full blocked category list
    # $detail.warnCategories contains the warn category list
}
```

---


| # | Object | Method | Endpoint |
|---|--------|--------|----------|
| 1 | DNS Policies – list all (with full settings) | `GET` | `/v3/organizations/{orgId}/bundles` |
| 1b | DNS Policy – get individual policy settings | `GET` | `/v3/organizations/{orgId}/policysettings/{policySettingId}` |
| 2 | Firewall Rules – list all (with full rule conditions) | `GET` | `/v1/organizations/{orgId}/rulesets/firewall` |
| 2b | Firewall Hit Count Intervals (reference data) | `GET` | `/v3/organizations/{orgId}/firewallhitcountintervals` |
| 3 | Web Policies – list all (with full embedded settings) | `GET` | `/v3/organizations/{orgId}/bundles` |
| 3b | Web Policy – get proxy ruleset (rule-level conditions) | `GET` | `/v1/organizations/{orgId}/rulesets/bundle/{bundleId}` |
| 3c | Web Policy – get proxy ruleset settings | `GET` | `/v1/organizations/{orgId}/rulesets/{rulesetId}/settings` |
| 4 | Destination Lists – list all | `GET` | `/v3/organizations/{orgId}/destinationlists` |
| 4b | Destination List – get entries (destinations) | `GET` | `/v3/organizations/{orgId}/destinationlists/{listId}/destinations` |

---

---

## 1. DNS Policies – List All (with full embedded settings)

### Request

| Field | Value |
|-------|-------|
| **Method** | `GET` |
| **Base URL** | `https://api.opendns.com` |
| **Path** | `/v3/organizations/{orgId}/bundles` |
| **Full observed URL** | `https://api.opendns.com/v3/organizations/8888888/bundles` |

#### Query Parameters

| Parameter | Value (observed) | Description |
|-----------|-----------------|-------------|
| `filters` | `{"bundleTypeId":1}` | Filter to DNS policies only. `bundleTypeId=1` = DNS, `bundleTypeId=2` = Web. |
| `sort` | `{"isDefault":"asc","priority":"asc"}` | Sort order: default policy last, then by priority ascending. |
| `optionalFields` | `["categorySetting","fileInspectionSetting","policySetting","securitySetting","identityCount","domainlists","settingGroupBypassInspectionGroup"]` | Embed all sub-settings inline. Without these, related objects are returned as IDs only. |
| `outputFormat` | `jsonHttpStatusOverride` | Dashboard-specific param; causes the API to always return HTTP 200 with the real status in the response body. |

> Both `filters` and `sort` and `optionalFields` must be JSON-encoded in the query string (URL-encoded).

### Response Structure

```json
{
  "status": { "code": 200, "text": "OK" },
  "meta": {
    "page": 1,
    "limit": 25,
    "total": 3
  },
  "data": [ /* array of bundle objects, one per DNS policy */ ]
}
```

#### `data[]` — Bundle Object Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | integer | Bundle (policy container) ID. Used to reference the policy. |
| `organizationId` | integer | Org ID. |
| `name` | string | Human-readable policy name (e.g. `"New Policy"`, `"Default Policy"`). |
| `isDefault` | boolean | Whether this is the catch-all default policy. |
| `bundleTypeId` | integer | `1` = DNS policy, `2` = Web policy. |
| `priority` | integer | Evaluation order (lower = evaluated first). |
| `policySettingGroupId` | integer | ID of the linked `policySetting` sub-object (proxy/SWG settings). |
| `securitySettingGroupId` | integer | ID of the linked `securitySetting` sub-object (botnet/malware toggles). |
| `fileInspectionSettingGroupId` | integer | ID of the file inspection settings sub-object. |
| `aupSettingGroupId` | integer | Acceptable Use Policy setting group ID. |
| `applicationAupSettingGroupId` | integer | Application-level AUP setting group ID. |
| `identityCount` | integer | Number of identities (users/groups/devices) assigned to this policy. |
| `reporting` | string | `"enabled"` or `"disabled"`. |
| `disableReporting` | integer | `0` = reporting on. |
| `disableLogging` | integer | `0` = logging on. |
| `originTagIds` | array\|null | Tag IDs if identity filtering by tag is used. |
| `createdAt` | unix timestamp | Creation time. |
| `modifiedAt` | unix timestamp | Last modified time. |

#### Embedded: `categorySetting`

Content category block/allow configuration for this policy.

| Field | Type | Description |
|-------|------|-------------|
| `id` | integer | Category setting group ID. |
| `name` | string | Setting profile name (e.g. `"High"`). |
| `categoryPrefs` | hex string | Bitmask of enabled content categories (base tier). |
| `categoryPrefsHigh` | hex string | Bitmask of "high" severity category overrides. |
| `categoryBits` | hex string | Combined resolved bitmask. |
| `warnCategoryBits` | hex string | Bitmask for categories set to "warn" instead of block. |
| `type` | string | `"mixed"` = combination of block/warn/allow. |
| `bundleTypeId` | integer | `1` = DNS. |

#### Embedded: `policySetting`

Proxy and SWG behaviour settings.

| Field | Type | Description |
|-------|------|-------------|
| `id` | integer | Policy setting group ID (same as `policySettingGroupId`). |
| `intelligentProxy` | boolean | Enables intelligent proxy (HTTP inspection for grey-listed sites). |
| `intelligentProxyHttps` | boolean | Enables HTTPS inspection via intelligent proxy. |
| `upIntelligentProxy` | boolean | Upstream intelligent proxy enabled. |
| `safeSearch` | boolean | Enforces safe search on supported search engines. |
| `ipFiltering` | boolean | IP-layer filtering enabled. |
| `saml` | integer | `0` = SAML auth disabled. |
| `decryptExceptionCategories` | string | Hex bitmask of categories exempt from SSL decryption. |
| `exceptiondomainlistId` | integer | ID of domain list used for SSL decryption exceptions (`0` = none). |
| `swgDisplayBlockPage` | integer | `0` = use default block page. |
| `aiSupplyChainCategories` | string | Hex bitmask for AI supply chain category filtering. |
| `mcpSemanticInspection` | boolean | Machine-learning content inspection enabled. |
| `httpHeaderConstraints` | boolean | HTTP header size constraints enabled. |

#### Embedded: `securitySetting`

Threat/security category toggles.

| Field | Type | Description |
|-------|------|-------------|
| `id` | integer | Security setting group ID. |
| `name` | string | Setting profile name. |
| `botnetProtection` | boolean | Block botnet C2 traffic. |
| `malwareProtection` | boolean | Block malware domains. |
| `superBotnet` | boolean | Extended botnet protection. |
| `superMalware` | boolean | Extended malware protection. |
| `phishingProtection` | boolean | Block phishing domains. |
| `suspiciousResponseFiltering` | boolean | Block suspicious DNS responses. |
| `malwareUrlProxy` | boolean | Proxy malware URLs. |
| `urlProxyHttps` | boolean | Proxy HTTPS URLs for malware scanning. |
| `fileInspection` | boolean | File inspection enabled. |
| `ampScan` | boolean | Cisco AMP file scanning. |
| `categoryPrefs` | hex string | Security category bitmask. |
| `categoryBits` | hex string | Combined security category bitmask. |

#### Embedded: `fileInspectionSetting`

| Field | Type | Description |
|-------|------|-------------|
| `id` | integer | File inspection setting group ID. |
| `fileEngines` | boolean | AV engine scanning enabled. |
| `tgSandbox` | boolean | Threat Grid sandboxing enabled. |
| `fileTypeControlStatus` | boolean | File type blocking rules active. |
| `fileTypeBlockedForDownload` | array | File type IDs blocked on download. |
| `fileTypeBlockedForUpload` | array | File type IDs blocked on upload. |

#### Embedded: `domainlists`

Array of destination lists attached to this policy.

| Field | Type | Description |
|-------|------|-------------|
| `id` | integer | Destination list ID. |
| `name` | string | List name (e.g. `"Global Allow List"`). |
| `access` | string | `"allow"` or `"block"`. |
| `isGlobal` | boolean | `true` = applies to all policies org-wide. |
| `bundleTypeId` | integer | `1` = DNS list. |

### Observed Policies (from HAR)

| Bundle ID | Policy Setting ID | Name | Is Default | Priority |
|-----------|------------------|------|------------|----------|
| `15042903` | `15075987` | New Policy | false | 0 |
| `14766672` | `14804325` | test DNS Policy | false | 1 |
| `14001040` | `14010109` | Default Policy | false | 2 |

---

## 1b. DNS Policy – Get Individual Policy Settings

Used by the dashboard when opening a specific policy to view/edit its proxy/SWG settings in detail.

### Request

| Field | Value |
|-------|-------|
| **Method** | `GET` |
| **Path** | `/v3/organizations/{orgId}/policysettings/{policySettingId}` |
| **Full observed URLs** | `https://api.opendns.com/v3/organizations/8888888/policysettings/15075987` (New Policy) |
| | `https://api.opendns.com/v3/organizations/8888888/policysettings/14804325` (test DNS Policy) |
| | `https://api.opendns.com/v3/organizations/8888888/policysettings/14010109` (Default Policy) |

#### Query Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| `outputFormat` | `jsonHttpStatusOverride` | Always return HTTP 200; embed real status in response body. |

> The `policySettingId` to use is the `policySettingGroupId` value from the bundle object returned by endpoint **1** above.

### Response Structure

```json
{
  "status": { "code": 200, "text": "OK" },
  "data": {
    "id": 15075987,
    "organizationId": 8888888,
    "name": "New Policy",
    "intelligentProxy": true,
    "intelligentProxyHttps": false,
    "upIntelligentProxy": false,
    "upIntelligentProxyHttps": false,
    "ipFiltering": false,
    "fileInspectionId": null,
    "reporting": "enabled",
    "whitelistOnly": false,
    "safeSearch": false,
    "decryptExceptionCategories": "0",
    "exceptiondomainlistId": 0,
    "saml": 0,
    "swgDisplayBlockPage": 0,
    "aiSupplyChainCategories": "0",
    "mcpSemanticInspection": false,
    "httpHeaderConstraints": false,
    "httpHeaderContentLength": 0,
    "categoryIds": [],
    "categoryNames": [],
    "createdAt": "2026-02-17 19:06:17",
    "modifiedAt": "2026-02-17 19:06:17",
    "markedForDeletion": false
  }
}
```

> **Note:** The `categoryIds` / `categoryNames` arrays here are for **application-level** category overrides within the policy setting — distinct from the content category bitmask in `categorySetting`. These were empty in all three observed policies.

### PowerShell Usage Note

For a bulk export, endpoint **1** (the bundles list with `optionalFields`) is sufficient — it returns the full `policySetting` sub-object inline for all policies in a single call. Endpoint **1b** is only needed if you need to fetch a specific policy's settings in isolation (e.g. by known `policySettingId`).

---

## 2. Firewall Rules – List All

A single call retrieves the entire firewall ruleset including all rules, their conditions, actions, and settings. Unlike DNS policies, firewall rules are not paginated by policy — they all live in one flat ruleset per organisation.

### Request

| Field | Value |
|-------|-------|
| **Method** | `GET` |
| **Base URL** | `https://api.umbrella.com` |
| **Path** | `/v1/organizations/{orgId}/rulesets/firewall` |
| **Full observed URL** | `https://api.umbrella.com/v1/organizations/8888888/rulesets/firewall` |

> **Note:** This endpoint uses `https://api.umbrella.com/v1/` — a different base URL and API version than the DNS/bundle endpoints which use `https://api.opendns.com/v3/`.

#### Query Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| `limit` | `25` | Max rules to return per page. |
| `offset` | `0` | Pagination offset (0-based). |

### Response Structure

```json
{
  "organizationId": 8888888,
  "rulesetId": 164673,
  "bundleId": null,
  "rulesetPriority": 1,
  "rulesetIsDefault": false,
  "isFirewall": true,
  "rulesetType": "firewall",
  "rulesetName": "Firewall Ruleset",
  "rulesetDescription": "Firewall Ruleset",
  "rulesetCreatedAt": "2023-05-04T17:10:39+00:00",
  "rulesetModifiedAt": "2025-04-29T12:50:30+00:00",
  "rules": [ /* array of rule objects */ ],
  "globalSettings": [],
  "meta": {
    "totalRules": 2,
    "totalRulesFiltered": 0,
    "limit": 25,
    "offset": 0
  }
}
```

#### Ruleset-level Fields

| Field | Type | Description |
|-------|------|-------------|
| `rulesetId` | integer | ID of the firewall ruleset container. |
| `bundleId` | null | Always `null` for firewall rulesets (used for proxy rulesets). |
| `rulesetType` | string | `"firewall"` for this endpoint. |
| `isFirewall` | boolean | `true`. |
| `rulesetPriority` | integer | Evaluation order among rulesets. |
| `globalSettings` | array | Org-wide ruleset settings (empty in observed data). |
| `meta.totalRules` | integer | Total number of rules in the ruleset (use for pagination). |

#### `rules[]` — Rule Object Fields

| Field | Type | Description |
|-------|------|-------------|
| `ruleId` | integer | Unique rule ID. |
| `ruleName` | string | Human-readable rule name. |
| `rulePriority` | integer | Evaluation order within the ruleset (lower = first). |
| `ruleAction` | string | `"allow"` or `"block"`. |
| `ruleIsEnabled` | boolean | Whether the rule is active. |
| `ruleIsDefault` | boolean | Whether this is the catch-all default rule. |
| `ruleDescription` | string | Optional description text. |
| `createdAt` | ISO 8601 timestamp | Creation time. |
| `modifiedAt` | ISO 8601 timestamp | Last modified time. |
| `ruleConditions` | array | List of match conditions (see below). |
| `ruleSettings` | array | Per-rule settings such as log level (see below). |
| `ruleMetadata.hitCountIntervalId` | integer | Reference to a hit count reporting interval (see endpoint **2b**). |
| `ruleMetadata.hitCountResetAt` | null\|timestamp | When the hit counter was last reset. |

#### `ruleConditions[]` — Condition Object

Each condition is a three-field predicate: `attributeName`, `attributeOperator`, `attributeValue`.

| `attributeName` | Operator | Value type | Description |
|-----------------|----------|-----------|-------------|
| `umbrella.firewall.traffic_type` | `=` | string | `"PUBLIC_INTERNET"` — matches traffic destined for the internet. |
| `umbrella.destination.network_protocol` | `=` | string | `"ANY"`, `"TCP"`, `"UDP"`, `"ICMP"`, etc. |
| `umbrella.source.ip_address` | `IN` | array of CIDR strings | Source IP ranges to match. |
| `umbrella.source.port` | `IN` | array of port range strings | Source port ranges (e.g. `"0-65535"`). |
| `umbrella.destination.port` | `IN` | array of port range strings | Destination port ranges. |
| `umbrella.destination.all` | `=` | boolean | `true` = match all destinations (used in default rule). |
| `umbrella.source.all` | `=` | boolean | `true` = match all sources (used in default rule). |
| `current_time` | `>=` | unix timestamp | Rule activation time (when rule was created/enabled). |
| `config.schedule.time_range` | `BETWEEN` | array of `"(HH:MM,HH:MM)"` strings | Time-of-day schedule. |
| `config.schedule.days_range` | `INTERSECT` | array of day name strings | Days-of-week schedule. |
| `config.schedule.timezone` | `=` | string | Timezone for schedule evaluation (e.g. `"UTC"`). |

#### `ruleSettings[]` — Setting Object

| `settingName` | `settingValue` | Description |
|---------------|---------------|-------------|
| `umbrella.logLevel` | `"LOG_ALL"` / `"LOG_NONE"` | Logging verbosity for this rule. |
| `umbrella.default.traffic` | `"PUBLIC_INTERNET"` | On the default rule: traffic type it covers. |

### Observed Rules (from HAR)

| Rule ID | Name | Priority | Action | Enabled | Is Default |
|---------|------|----------|--------|---------|------------|
| `1016848` | Test Firewall Rule | 1 | allow | false | false |
| `696446` | Default Internet | 2 | allow | true | true |

**Test Firewall Rule — key conditions:**
- Traffic type: `PUBLIC_INTERNET`
- Protocol: `ANY`
- Source IP: `192.168.189.0/24`
- Source ports: `0-65535`, Destination ports: `0-65535`
- Schedule: Mon–Sun, 00:00–23:59 UTC
- Logging: `LOG_ALL`

**Default Internet — key conditions:**
- Matches all sources (`umbrella.source.all = true`)
- Matches all destinations (`umbrella.destination.all = true`)
- Traffic type setting: `PUBLIC_INTERNET`
- Logging: `LOG_ALL`

### PowerShell Usage Note

One call returns all firewall rules. If the organisation has more than `limit` rules, paginate using `offset`. Check `meta.totalRules` against `limit + offset` to determine if additional pages exist.

```powershell
# Example pagination check
$offset = 0; $limit = 25
do {
    $response = Invoke-RestMethod "$baseUrl/v1/organizations/$orgId/rulesets/firewall?limit=$limit&offset=$offset" -Headers $headers
    # process $response.rules ...
    $offset += $limit
} while (($offset) -lt $response.meta.totalRules)
```

---

## 2b. Firewall Hit Count Intervals (Reference Data)

Reference list used by the dashboard to label hit count statistics per rule. Not needed for config export but useful for interpreting `ruleMetadata.hitCountIntervalId`.

### Request

| Field | Value |
|-------|-------|
| **Method** | `GET` |
| **Base URL** | `https://api.opendns.com` |
| **Path** | `/v3/organizations/{orgId}/firewallhitcountintervals` |
| **Query params** | `outputFormat=jsonHttpStatusOverride` |

### Response

```json
{
  "status": { "code": 200, "text": "OK" },
  "data": [
    { "id": 1, "value": "5min",      "label": "Last 5 Minutes" },
    { "id": 2, "value": "1hr",       "label": "Last Hour" },
    { "id": 3, "value": "24hr",      "label": "Last 24 Hours" },
    { "id": 4, "value": "yesterday", "label": "Yesterday" },
    { "id": 5, "value": "30day",     "label": "Last 30 Days" }
  ]
}
```

The observed rules both use `hitCountIntervalId: 3` → **Last 24 Hours**.

---

## 3. Web Policies – List All (with full embedded settings)

The same `/bundles` endpoint as DNS policies but with `bundleTypeId=2`. Returns the full web policy including an additional embedded object — `settingGroupBypassInspectionGroup` — which holds the SSL decryption bypass/selective decryption configuration.

### Request

| Field | Value |
|-------|-------|
| **Method** | `GET` |
| **Base URL** | `https://api.opendns.com` |
| **Path** | `/v3/organizations/{orgId}/bundles` |
| **Full observed URL** | `https://api.opendns.com/v3/organizations/8888888/bundles` |

#### Query Parameters

| Parameter | Value (observed) | Description |
|-----------|-----------------|-------------|
| `filters` | `{"bundleTypeId":2}` | Filter to web policies only. |
| `sort` | `{"isDefault":"asc","priority":"asc"}` | Default policy last, then by priority ascending. |
| `optionalFields` | `["categorySetting","domainlists","fileInspectionSetting","identityCount","policySetting","securitySetting","settingGroupBypassInspectionGroup"]` | Same as DNS but note `settingGroupBypassInspectionGroup` is included — this is the SSL decryption bypass list, specific to web policies. |
| `outputFormat` | `jsonHttpStatusOverride` | Always return HTTP 200 with real status in body. |

> **Difference from DNS:** The `optionalFields` list has the same entries but the order differs slightly, and `settingGroupBypassInspectionGroup` is meaningful (populated) for web policies. Also note web bundle objects include a `restriction` field for Tenant Controls.

### Response Structure

Same envelope as DNS (`status`, `meta`, `data[]`). Key differences in the `data[]` bundle object:

| Field | Type | Description |
|-------|------|-------------|
| `bundleTypeId` | integer | `2` = web policy. |
| `isSwgDefault` | boolean | `true` = this is the default SWG (web) policy. |
| `settingGroupBypassInspectionGroupId` | integer | ID of the SSL decryption bypass group (populated for web, typically `null` for DNS). |
| `restriction` | object | Tenant controls configuration (see below). |

#### Embedded: `settingGroupBypassInspectionGroup` (Web-specific)

Controls which destinations bypass HTTPS/SSL inspection.

| Field | Type | Description |
|-------|------|-------------|
| `id` | integer | Bypass inspection group ID. |
| `name` | string | Profile name (e.g. `"Default Web Selective Decryption List"`). |
| `isDefault` | boolean | Whether this is the org default bypass list. |
| `decryptExceptionCategories` | array | Category IDs exempt from SSL decryption. |
| `exceptiondomainlistId` | integer | ID of the domain list used for decryption bypass. |
| `exceptionapplicationlistId` | integer\|null | ID of application list exempt from decryption (`null` if not set). |
| `bundleTypeId` | integer | `2` = web. |
| `totalDomains` | integer | Count of domains in the exception domain list. |
| `totalIps` | integer | Count of IPs in the exception list. |
| `totalApplications` | integer | Count of applications in the exception list. |

#### Embedded: `restriction` (Tenant Controls — Web-specific)

| Field | Type | Description |
|-------|------|-------------|
| `id` | integer | Tenant controls configuration ID. |
| `name` | string | Profile name (e.g. `"Global Tenant Controls"`). |
| `domains` | array | List of domains subject to tenant restrictions. |
| `restrictions` | array | Tenant restriction rules (e.g. allowed tenants per domain). |

#### Embedded: `policySetting` (Web — notable differences from DNS)

| Field | Observed value | Note |
|-------|---------------|------|
| `intelligentProxy` | `true` | Enabled (same as DNS). |
| `intelligentProxyHttps` | `true` | **HTTPS inspection enabled** — this is the key web-only toggle, was `false` in all DNS policies. |
| `fileInspectionId` | `null` | File inspection tied via `fileInspectionSettingGroupId` instead. |

#### Embedded: `fileInspectionSetting` (Web — notable differences from DNS)

| Field | Observed value | Note |
|-------|---------------|------|
| `fileTypeControlStatus` | `true` | **Active** — file type blocking rules are enforced. Was `false` in DNS policies. |
| `fileTypeBlockedForDownload` | `[36,43,48,53,55,57,58,60,61,63,67,71,72,73,74,75,76,77,104,121,122,124,125,126,127]` | Array of blocked file type IDs. Needs cross-reference to file type catalog. |
| `fileTypeBlockedForUpload` | `[]` | No upload restrictions configured. |

#### Embedded: `securitySetting` (Web — notable differences from DNS)

| Field | Observed value | Note |
|-------|---------------|------|
| `fileInspection` | `true` | **Enabled** for web policy. Was `false` in DNS policies. |
| `bundleTypeId` | `2` | Confirms this security setting belongs to a web policy. |
| `isSwgDefault` | `true` | This is the default SWG security setting. |

### Observed Policy (from HAR)

| Bundle ID | Policy Setting ID | Ruleset ID | Name | Is SWG Default | Priority |
|-----------|------------------|------------|------|---------------|----------|
| `14001041` | `14010110` | `273764` | Default Web Policy | true | 2 |

---

## 3b. Web Policy – Get Proxy Ruleset (Rule-Level Conditions)

The web policy bundle object (`/bundles?bundleTypeId=2`) contains the global content/security/category settings for the policy, but the **per-rule conditions** (which identity groups get which treatment, application category overrides, etc.) live in a separate proxy ruleset. The dashboard fetches this by `bundleId`.

### Request

| Field | Value |
|-------|-------|
| **Method** | `GET` |
| **Base URL** | `https://api.umbrella.com` |
| **Path** | `/v1/organizations/{orgId}/rulesets/bundle/{bundleId}` |
| **Full observed URL** | `https://api.umbrella.com/v1/organizations/8888888/rulesets/bundle/14001041` |

#### Query Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| `extendIdentities` | `true` | Resolves identity type IDs to human-readable labels in an `extradata` block. |

> The `bundleId` (`14001041`) is the `id` field from the bundle object returned by endpoint **3** above.

### Response Structure

```json
{
  "organizationId": 8888888,
  "rulesetId": 273764,
  "bundleId": 14001041,
  "rulesetPriority": 2,
  "rulesetIsDefault": false,
  "isFirewall": false,
  "rulesetType": "proxy",
  "rulesetName": "",
  "rulesetDescription": "",
  "rulesetCreatedAt": "2025-04-29T13:06:13+00:00",
  "rulesetModifiedAt": "2025-04-29T13:06:13+00:00",
  "rules": [ /* array of proxy rule objects */ ],
  "extradata": {
    "identities": [],
    "identityTypes": [ { "id": 3, "label": "AD Groups" } ],
    "categories": [],
    "destinationLists": [],
    "applications": [],
    "applicationLists": []
  }
}
```

#### Ruleset-level Fields

| Field | Type | Description |
|-------|------|-------------|
| `rulesetId` | integer | ID of the proxy ruleset. Used to fetch settings via endpoint **3c**. |
| `bundleId` | integer | The web policy bundle ID this ruleset belongs to. |
| `rulesetType` | string | `"proxy"` for web policy rule sets. |
| `isFirewall` | boolean | `false`. |
| `extradata` | object | Resolved reference data for IDs used in rule conditions (see below). |

#### `rules[]` — Proxy Rule Object Fields

| Field | Type | Description |
|-------|------|-------------|
| `ruleId` | integer | Unique rule ID. |
| `ruleName` | string | Rule name. |
| `rulePriority` | integer | Evaluation order (lower = first). |
| `ruleAction` | string | `"allow"`, `"block"`, or `"warn"`. |
| `ruleIsEnabled` | boolean | Whether the rule is active. |
| `ruleIsDefault` | boolean | Whether this is the catch-all default rule. |
| `ruleConditions` | array | Match conditions (see below). |
| `ruleSettings` | array | Per-rule settings. |
| `ruleMetadata` | object | Additional metadata (empty `{}` for proxy rules). |

#### Proxy `ruleConditions[]` — Observed Attribute Names

| `attributeName` | Operator | Value type | Description |
|-----------------|----------|-----------|-------------|
| `umbrella.bundle_id` | `=` | integer | Scopes the rule to this specific web policy bundle. Always present. |
| `umbrella.source.identity_type_ids` | `INTERSECT` | array of integers | Identity type IDs (e.g. `3` = AD Groups). Cross-reference with `extradata.identityTypes`. |
| `umbrella.destination.application_category_ids` | `INTERSECT` | array of integers | Application category IDs to match (e.g. `50`). Cross-reference with `extradata.categories`. |

#### `extradata` — Resolved Reference Block

Populated when `extendIdentities=true`. Contains human-readable lookups for IDs used in rule conditions.

| Field | Description |
|-------|-------------|
| `identities` | Resolved individual identity objects referenced in rules. |
| `identityTypes` | Identity type labels (e.g. `{ "id": 3, "label": "AD Groups" }`). |
| `categories` | Application category labels referenced in conditions. |
| `destinationLists` | Destination list names referenced in conditions. |
| `applications` | Individual application names referenced in conditions. |
| `applicationLists` | Application list names referenced in conditions. |

### Observed Rule (from HAR)

| Rule ID | Name | Priority | Action | Enabled | Conditions |
|---------|------|----------|--------|---------|------------|
| `1016855` | Test Rule | 1 | warn | false | bundle=`14001041`, identity type=AD Groups (`3`), app category=`50` |

---

## 3c. Web Policy – Get Proxy Ruleset Settings

Fetches org-level settings applied to the entire proxy ruleset (as opposed to per-rule settings). Observed to return an empty array — no custom ruleset-level settings configured.

### Request

| Field | Value |
|-------|-------|
| **Method** | `GET` |
| **Base URL** | `https://api.umbrella.com` |
| **Path** | `/v1/organizations/{orgId}/rulesets/{rulesetId}/settings` |
| **Full observed URL** | `https://api.umbrella.com/v1/organizations/8888888/rulesets/273764/settings` |

> The `rulesetId` (`273764`) comes from the `rulesetId` field in the proxy ruleset response (endpoint **3b**).

### Response

```json
[]
```

An empty array indicates no custom ruleset-level overrides are configured. When populated, entries follow the same `settingName` / `settingValue` structure as `ruleSettings[]` within individual rules.

### PowerShell Usage Note

A complete web policy export requires **three calls**:
1. **Endpoint 3** — `/bundles?filters={"bundleTypeId":2}&optionalFields=[...]` — global policy settings (categories, security, file inspection, SSL bypass, tenant controls, domain lists).
2. **Endpoint 3b** — `/rulesets/bundle/{bundleId}?extendIdentities=true` — per-rule conditions and identity/category assignments.
3. **Endpoint 3c** — `/rulesets/{rulesetId}/settings` — ruleset-level overrides (likely empty but should be checked).

The `bundleId` links call 1 → call 2. The `rulesetId` from call 2 links to call 3.

---

## 4. Destination Lists – List All

A single call returns all destination lists in the organisation with per-list entry counts. The dashboard then fetches entries for each list individually via endpoint **4b**.

### Request

| Field | Value |
|-------|-------|
| **Method** | `GET` |
| **Base URL** | `https://api.opendns.com` |
| **Path** | `/v3/organizations/{orgId}/destinationlists` |
| **Full observed URL** | `https://api.opendns.com/v3/organizations/8888888/destinationlists` |

#### Query Parameters

| Parameter | Value (observed) | Description |
|-----------|-----------------|-------------|
| `page` | `1` | Page number (1-based). |
| `offset` | `0` | Record offset (0-based, alternative to `page`). |
| `limit` | `25` (default) / `100` | Max records per page. Use `100` for bulk export. |
| `sort` | `{"name":"asc","createdAt":"desc"}` | Optional sort order. |
| `optionalFields` | `{"meta":"meta"}` | Request per-list entry counts in a `meta` sub-object. |
| `filters` | `{"isGlobal":true}` | Optional filter to only return global (org-wide) lists. |
| `where[filterAccess][equal]` | `no_decrypt` | Optional filter used by SSL bypass view — returns all lists eligible for decryption bypass. |
| `where[id]` | `18299858` | Optional filter to fetch a single list by ID. |
| `outputFormat` | `jsonHttpStatusOverride` | Always return HTTP 200 with real status in body. |

> For a **full export**, use `page=1&offset=0&limit=100` with `optionalFields={"meta":"meta"}` to get all lists and their entry counts in one call. Then iterate over each list to fetch its entries via endpoint **4b**.

### Response Structure

```json
{
  "status": { "code": 200, "text": "OK" },
  "meta": {
    "page": 1,
    "limit": 25,
    "total": 5
  },
  "data": [ /* array of destination list objects */ ]
}
```

#### `data[]` — Destination List Object Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | integer | Destination list ID. Used in endpoint **4b** to fetch entries. |
| `organizationId` | integer | Org that owns this list. May differ from your org ID for MSP-managed lists (see `isMspDefault`). |
| `name` | string | Human-readable list name. |
| `access` | string | `"allow"` = allowlist, `"block"` = blocklist, `"none"` = SSL decryption bypass list (web policy only). |
| `isGlobal` | boolean | `true` = applies to all policies org-wide. `false` = policy-specific. |
| `bundleTypeId` | integer | `1` = DNS list, `2` = web/proxy list. |
| `isMspDefault` | boolean | `true` = list is inherited from the MSP/parent org and cannot be edited. |
| `markedForDeletion` | boolean | Soft-delete flag. |
| `thirdpartyCategoryId` | integer\|null | Non-null if the list is backed by a third-party threat feed category. |
| `createdAt` | unix timestamp | Creation time. |
| `modifiedAt` | unix timestamp | Last modified time. |
| `meta.domainCount` | integer | Number of FQDN entries in this list. |
| `meta.urlCount` | integer | Number of URL entries (web lists only). |
| `meta.ipv4Count` | integer | Number of IPv4 address entries. |
| `meta.applicationCount` | integer | Number of application entries. |
| `meta.destinationCount` | integer | Total entries across all types. |

### Observed Destination Lists (from HAR)

| ID | Name | Access | Scope | Type | Owner | Entry Count |
|----|------|--------|-------|------|-------|-------------|
| `9881408` | Centralized Default Allow List | allow | policy-specific | DNS (`1`) | MSP (`7777777`) | 0 |
| `9881409` | Centralized Default Block List | block | policy-specific | DNS (`1`) | MSP (`7777777`) | 0 |
| `17187333` | Global Allow List | allow | global | DNS (`1`) | Org | 0 |
| `17187334` | Global Block List | block | global | DNS (`1`) | Org | 0 |
| `18299858` | Test Destination List | none (bypass) | policy-specific | Web (`2`) | Org | 3 (1 domain, 1 URL, 1 IPv4) |

> **Note:** `access: "none"` on the Test Destination List means it is a **selective SSL decryption bypass** list, not a standard allow/block list. It is linked to the web policy via `settingGroupBypassInspectionGroup.exceptiondomainlistId`.

> **Note on MSP lists:** `Centralized Default Allow List` and `Centralized Default Block List` have `organizationId: 7777777` (the parent/MSP org) and `isMspDefault: true`. They appear in the org's list but are read-only. Your PowerShell script should handle this gracefully.

---

## 4b. Destination List – Get Entries (Destinations)

Fetches the individual entries (domains, URLs, IPs) within a specific destination list. Called once per list after retrieving the list index from endpoint **4**.

### Request

| Field | Value |
|-------|-------|
| **Method** | `GET` |
| **Base URL** | `https://api.opendns.com` |
| **Path** | `/v3/organizations/{orgId}/destinationlists/{listId}/destinations` |
| **Full observed URL** | `https://api.opendns.com/v3/organizations/8888888/destinationlists/18299858/destinations` |

#### Query Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| `page` | `1` | Page number (1-based). |
| `limit` | `100` | Max entries per page. |
| `type` | `domain` / `ipv` / `url` | Optional filter by entry type. The SSL bypass view fetches `type=domain` and `type=ipv` as separate calls. Omit for all types combined. |
| `outputFormat` | `jsonHttpStatusOverride` | Standard dashboard param. |

> **Pagination:** Check `meta.total` against `limit`. If `total > limit`, loop with incrementing `page` until all entries are fetched.

### Response Structure

```json
{
  "status": { "code": 200, "text": "OK" },
  "meta": {
    "page": 1,
    "limit": 100,
    "total": 3
  },
  "data": [ /* array of destination entry objects */ ]
}
```

#### `data[]` — Destination Entry Object Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Entry ID (string, not integer). |
| `destination` | string | The actual value: FQDN, URL path, or IP address. |
| `type` | string | `"domain"`, `"url"`, or `"ipv4"`. |
| `comment` | string\|null | Optional human-readable note on why this entry was added. |
| `createdAt` | datetime string | Creation timestamp (`"YYYY-MM-DD HH:MM:SS"`). |

### Observed Entries for Test Destination List (`18299858`)

| ID | Destination | Type | Comment |
|----|-------------|------|---------|
| `193` | `www.google.com` | domain | "Too little privacy" |
| `28551029` | `8.8.8.8` | ipv4 | _(none)_ |
| `47594148` | `yahoo.com/sports` | url | _(none)_ |

### PowerShell Usage Note

A complete destination list export requires two steps:
1. **Endpoint 4** — fetch all lists with entry counts (`meta.destinationCount`).
2. **Endpoint 4b** — for each list where `meta.destinationCount > 0`, paginate through all entries.

Skip the entries call for empty lists (all counts = 0) and for MSP-inherited lists (`isMspDefault: true`) if read-only lists are not required.

```powershell
# Example: export all lists and their entries
$lists = (Invoke-RestMethod "$base/v3/organizations/$orgId/destinationlists?page=1&offset=0&limit=100&optionalFields={`"meta`":`"meta`"}" -Headers $h).data
foreach ($list in $lists) {
    if ($list.meta.destinationCount -gt 0) {
        $page = 1
        do {
            $resp = Invoke-RestMethod "$base/v3/organizations/$orgId/destinationlists/$($list.id)/destinations?page=$page&limit=100" -Headers $h
            # process $resp.data ...
            $page++
        } while (($page - 1) * 100 -lt $resp.meta.total)
    }
}
```

---
