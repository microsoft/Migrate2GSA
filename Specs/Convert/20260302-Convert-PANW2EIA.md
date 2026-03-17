# Convert-PANW2EIA.ps1 Specification

## Document Information
- **Specification Version:** 1.2
- **Date:** 2026-03-16
- **Status:** Draft
- **Target Module:** Migrate2GSA
- **Function Name:** Convert-PANW2EIA
- **Author:** Wendy Badilla
---

## Overview

This PowerShell function converts Palo Alto Networks (PANW) Next-Generation Firewall configuration exported as XML from Panorama to Microsoft Entra Internet Access (EIA) format. The function processes security rules, URL filtering profiles, custom URL categories, and predefined PAN-DB category actions to generate CSV files ready for import into EIA via `Start-EntraInternetAccessProvisioning`.

### Purpose
- Parse Panorama XML export containing shared and device-group configurations
- Transform PANW URL filtering profiles to EIA web content filtering policies
- Convert PANW custom URL categories to EIA web content filtering policies (FQDN/URL rules)
- Map PAN-DB predefined web categories to GSA (Global Secure Access) web categories
- Convert PANW security rules (with URL filtering profile references) to EIA security profiles
- Flag application-based rules for manual review (no direct EIA equivalent)
- Generate import-ready CSV files for EIA configuration

### Design Alignment
This function follows the same architectural patterns as `Convert-ZIA2EIA.ps1`:
- Single function with internal helper functions
- Phased processing approach (Load → Process → Export)
- Comprehensive logging using `Write-LogMessage`
- Region-based code organization
- CSV export using shared utilities

---

## Palo Alto Panorama XML Structure

### Configuration Hierarchy 

Panorama XML exports use a **shared + device-group** model:

```
config
├── shared                              # Objects available to all device-groups
│   ├── profiles
│   │   ├── url-filtering               # URL filtering profiles
│   │   │   └── entry[@name]            # Individual profile
│   │   ├── custom-url-category         # Custom URL categories (under profiles)
│   │   │   └── entry[@name]            # Individual category
│   │   └── ...
│   ├── profile-group                   # Profile groups (reference profiles)
│   │   └── entry[@name]
│   └── ...
├── devices
│   └── entry[@name='localhost.localdomain']
│       └── device-group
│           └── entry[@name='DG-Name']  # Each device-group
│               ├── profiles
│               │   ├── url-filtering   # Device-group-local profiles
│               │   └── custom-url-category
│               ├── pre-rulebase        # Rules processed BEFORE local FW rules
│               │   └── security
│               │       └── rules
│               │           └── entry[@name]
│               ├── post-rulebase       # Rules processed AFTER local FW rules
│               │   └── security
│               │       └── rules
│               │           └── entry[@name]
│               └── ...
```

**Note:** The exact XPath structure has been validated against a real Panorama XML export (PAN-OS 10.x). Custom URL categories are located under `profiles/custom-url-category` in both shared and device-group scopes. The implementation includes fallback checks for both paths to handle PAN-OS version variations.

### Object Resolution Order
1. Look up objects in the device-group first (local scope)
2. Fall back to shared section if not found locally
3. Log a warning if an object is referenced but not found in either scope

---

## Policy and Rule Naming Conventions

This section describes the structure and naming conventions used when converting PANW configurations to EIA policies and rules.

### PANW Structure

**Security Rules:**
- Security rules define traffic matching criteria and an overall action (allow, deny, drop, reset)
- Rules with action `allow` can reference a URL filtering profile via `<profile-setting>`
- Rules contain source-user assignments for user/group-based filtering
- Rules exist in `pre-rulebase` and `post-rulebase` within each device-group
- Each rule has a `disabled` attribute (`yes`/`no`)

**URL Filtering Profiles:**
- URL filtering profiles categorise web traffic and apply per-category actions
- Actions per category: `allow`, `block`, `alert`, `continue`, `override`
- Profiles reference both PAN-DB predefined categories and custom URL categories
- Categories are listed under action-specific child elements (`<allow>`, `<block>`, `<alert>`, `<continue>`, `<override>`)

**Custom URL Categories:**
- Custom URL categories contain a list of URL/FQDN/IP entries
- The `<type>` element is either `URL List` or `Category Match`
  - **URL List:** Contains a `<list>` of URL/FQDN/IP members
  - **Category Match:** Groups predefined categories (out of scope for this conversion — these are handled as predefined category references within the URL filtering profile)
- Each member is a destination entry (FQDN, URL, or IP address — IP addresses are logged and skipped since EIA does not support them)

**Profile Groups:**
- Profile groups bundle multiple security profiles (URL filtering, antivirus, etc.)
- Security rules can reference a profile group instead of individual profiles
- The URL filtering profile within a profile group is what we extract

**PAN-DB Categories:**
- Palo Alto provides ~80 predefined web categories (e.g., `adult`, `malware`, `hacking`)
- These categories use lowercase-hyphenated naming (e.g., `financial-services`, `social-networking`)
- Must be mapped to GSA web categories using a mapping file

### EIA Structure

**EIA Web Content Filtering Policies:**
- Each EIA web content filtering policy contains one or more rules
- Each rule has a destination type: `FQDN`, `URL`, or `webCategory`
- Policies have a single action: `Allow` or `Block`

**Conversion produces three types of policies:**
1. **Custom URL Category Policies** — Created from PANW custom URL categories with URL List type, containing FQDN/URL rules (IP addresses are logged and skipped — EIA does not support IP address destinations)
2. **Web Category Policies** — Created from URL filtering profile category actions, containing webCategory rules with mapped GSA categories
3. **Application Policies** — Created from security rules with application references, containing FQDN rules from App-ID to GSA endpoint mappings

**Security Profiles:**
- Security rules sharing the same user/group assignment are **aggregated** into a single security profile
- Rules assigned to `any` (all users) → aggregated into `SecurityProfile-All-Users` (Default, priority 50000)
- Rules assigned to specific users/groups → aggregated by unique user/group combination into `SecurityProfile-001`, `SecurityProfile-002`, etc. (Override, priority 1000+)
- Each aggregated profile links to all policies from its constituent rules (deduplicated, Allow-first ordering)
- This follows the same aggregation pattern as `Convert-NSWG2EIA`

### Conversion Logic

**Custom URL Category Conversion:**
- Each custom URL category (URL List type) creates a Block policy by default: `[CategoryName]-Block`
- If a URL filtering profile references the category with `allow` action, an Allow version is also created: `[CategoryName]-Allow`
- Unreferenced policies are cleaned up after security profile aggregation

**URL Filtering Profile Conversion:**
- Each URL filtering profile creates one policy per action type:
  - `[ProfileName]-WebCategories-Block` for blocked categories
  - `[ProfileName]-WebCategories-Allow` for allowed categories
  - `[ProfileName]-WebCategories-Alert`, `-Continue`, `-Override` for review actions
- Only mapped GSA categories are included in `RuleDestinations`; partial/unmapped categories are excluded from `RuleDestinations` but listed in `ReviewDetails` for manual review

**Application Conversion:**
- Security rules with application references (non-`any`) are looked up in the App Mappings CSV
- For each matched app: if `GSAEndpoints` are available, create a policy with FQDN rules from the endpoints
- Unmapped apps (empty `GSAAppName`) are flagged for review
- Application policies are named: `[AppName]-[Action]` (e.g., `office365-Allow`)

**Security Profile Aggregation:**
- Multiple security rules assigned to the same users/groups are aggregated into a single security profile
- Policy links are deduplicated — duplicate policy references across rules are merged
- Policy link ordering: Allow policies first (alphabetically), then Block policies (alphabetically)
- Priority: Override profiles (specific user/group) start at 1000, incrementing by 100; Default profile (All-Users) gets priority 50000 (lowest precedence)

### Mapping Summary

| PANW Element | Converts To | EIA Element | Notes |
|---|---|---|---|
| Custom URL Category (URL List) | → | Web Content Filtering Policy | FQDN/URL/IP rules, one policy per custom category per action |
| URL Filtering Profile (block categories) | → | Web Content Filtering Policy | webCategory rules, one policy per profile per action |
| URL Filtering Profile (alert/continue/override categories) | → | Web Content Filtering Policy | webCategory rules, flagged for review |
| URL Filtering Profile (allow categories) | → | Web Content Filtering Policy | webCategory rules with Allow action |
| Security Rule (with applications + mapping) | → | Web Content Filtering Policy | FQDN rules from GSAEndpoints in app mapping |
| Security Rule (with unmapped applications) | → | Web Content Filtering Policy | Flagged for review, apps listed in ReviewDetails |
| Multiple Security Rules (same users/groups) | → | Single Security Profile | Aggregated with deduplicated policy links |
| PAN-DB predefined category | → | GSA web category | Via category mapping file |
| App-ID application | → | FQDN destinations | Via app mapping file |
| Profile Group (containing URL filtering) | → | Resolved to URL filtering profile | Transparent to output |

### Policy Naming Conventions

**Custom Category Policies:**
- Format: `[CustomCategoryName]-[Action]`
- Block action: `[CustomCategoryName]-Block`
- Allow action: `[CustomCategoryName]-Allow`
- Example: `Malicious-URLs-Block`, `Internal-Sites-Allow`

**Web Category Policies (from URL filtering profiles):**
- Format: `[ProfileName]-WebCategories-[Action]`
- Example: `Corporate-URL-Filter-WebCategories-Block`
- Example: `Corporate-URL-Filter-WebCategories-Allow`
- Actions alert/continue/override each get their own policy: `[ProfileName]-WebCategories-Alert`, etc.

**Application Policies:**
- Format: `[GSAAppName]-[Action]` (using the mapped GSA app name)
- Example: `Box-Block`, `Slack-Allow`
- Unmapped apps: `[PANWAppName]-Application-[Action]` with `ReviewNeeded=Yes`
- Example: `custom-internal-app-Application-Block`

**Rule Naming (within policies):**
- FQDN rules: Base domain name (e.g., `example.com`, `example.com-2`)
- URL rules: Base domain name (e.g., `contoso.com/path`, `contoso.com-2`)
- Web category rules: `WebCategories` (never split)

**Security Profile Naming Conventions:**
- All users: `SecurityProfile-All-Users`
- Specific user/group sets: `SecurityProfile-001`, `SecurityProfile-002`, etc.

---

## Input Files

### 1. Panorama XML Export
**Source:** Panorama console export (`Panorama > Setup > Operations > Export named configuration snapshot` or `scp export`)
**Required:** Yes
**Default Path:** None (must be specified)

#### Description
Full configuration XML export from Palo Alto Panorama containing shared objects, device-group configurations, security rules, URL filtering profiles, and custom URL categories.

#### Key XML Elements to Process

**Custom URL Categories:**

XPath (shared): `/config/shared/profiles/custom-url-category/entry`
XPath (device-group): `/config/devices/entry/device-group/entry[@name='{DG}']/profiles/custom-url-category/entry`

| Element/Attribute | Type | Description | Processing Notes |
|---|---|---|---|
| `@name` | attribute | Category name | Maps to PolicyName base |
| `<description>` | element | Category description | Maps to Policy Description |
| `<type>` | element | `URL List` or `Category Match` | Only process `URL List` |
| `<list><member>` | elements | URL/FQDN/IP entries | Each `<member>` is one destination |

**URL Filtering Profiles:**

XPath (shared): `/config/shared/profiles/url-filtering/entry`
XPath (device-group): `/config/devices/entry/device-group/entry[@name='{DG}']/profiles/url-filtering/entry`

| Element/Attribute | Type | Description | Processing Notes |
|---|---|---|---|
| `@name` | attribute | Profile name | Used in policy naming |
| `<description>` | element | Profile description | Maps to Policy Description |
| `<allow><member>` | elements | Categories with allow action | Create Allow policy |
| `<block><member>` | elements | Categories with block action | Create Block policy |
| `<alert><member>` | elements | Categories with alert action | Flag for review |
| `<continue><member>` | elements | Categories with continue action | Flag for review |
| `<override><member>` | elements | Categories with override action | Flag for review |

**Profile Groups:**

XPath (shared): `/config/shared/profile-group/entry`
XPath (device-group): `/config/devices/entry/device-group/entry[@name='{DG}']/profile-group/entry`

| Element/Attribute | Type | Description | Processing Notes |
|---|---|---|---|
| `@name` | attribute | Profile group name | Referenced by security rules |
| `<url-filtering><member>` | element | URL filtering profile name | Resolve to URL filtering profile |

**Security Rules:**

XPath (pre-rules): `/config/devices/entry/device-group/entry[@name='{DG}']/pre-rulebase/security/rules/entry`
XPath (post-rules): `/config/devices/entry/device-group/entry[@name='{DG}']/post-rulebase/security/rules/entry`

| Element/Attribute | Type | Description | Processing Notes |
|---|---|---|---|
| `@name` | attribute | Rule name | Maps to SecurityProfileName |
| `<action>` | element | allow, deny, drop, reset-* | Only process `allow` with profile |
| `<disabled>` | element | `yes` or `no` | Only process if `no` or absent |
| `<source-user><member>` | elements | User/group assignments | `any` → placeholder group |
| `<application><member>` | elements | App-ID references | Flag for review if not `any` |
| `<description>` | element | Rule description | Maps to Description |
| `<profile-setting>` | element | Profile reference | Extract URL filtering profile |

**Profile Setting Resolution:**
The `<profile-setting>` element can reference profiles in two ways:
```xml
<!-- Via profile group -->
<profile-setting>
  <group><member>profile-group-name</member></group>
</profile-setting>

<!-- Via individual profiles -->
<profile-setting>
  <profiles>
    <url-filtering><member>url-filter-profile-name</member></url-filtering>
  </profiles>
</profile-setting>
```

Processing:
1. If `<group>` is used: look up the profile group → extract URL filtering profile name
2. If `<profiles><url-filtering>` is used: extract the profile name directly
3. If no URL filtering profile is found: skip the rule for URL filtering purposes (log at DEBUG level)

#### Processing Rules
1. **Scope:** Process all device-groups found in the XML, merge with shared objects
2. **Disabled Rules:** Skip entries where `<disabled>` = `yes`; log count at INFO level, names at DEBUG
3. **Rule Actions:** Only process security rules with `<action>` = `allow` that have a URL filtering profile attached. Rules with deny/drop/reset actions inherently block traffic at the firewall level and don't need URL filtering migration.
4. **Application References:** If `<application>` contains members other than `any`, flag the security profile for review and list the applications in ReviewDetails

### 2. PANW2EIA-CategoryMappings.csv
**Source:** Manual configuration file (maintained by user)
**Required:** Yes
**Default Path:** `PANW2EIA-CategoryMappings.csv` (in script root directory)

#### Description
Provides mapping between PAN-DB predefined web categories and Microsoft GSA (Global Secure Access) web categories.

#### Schema

| Column | Type | Required | Description |
|---|---|---|---|
| PANWCategory | string | Yes | PAN-DB category name (lowercase-hyphenated, e.g., `adult`, `malware`) |
| GSACategory | string | Yes | Target GSA category name (e.g., `AdultContent`, `Malware`) |
| MappingNotes | string | No | Mapping rationale |

#### Sample Data
```csv
PANWCategory,GSACategory,MappingNotes
adult,PornographyAndSexuallyExplicit,Exact match
abused-drugs,IllegalDrug,Exact match
alcohol-and-tobacco,AlcoholAndTobacco,Exact match
copyright-infringement,IllegalSoftware,Partial - copyright infringement relates to illegal software
gambling,Gambling,Exact match
hacking,Hacking,Exact match
malware,CriminalActivity,Partial - malware hosting is criminal activity
phishing,CriminalActivity,Partial - phishing is criminal activity
social-networking,SocialNetworking,Exact match
weapons,Weapons,Exact match
unknown,Uncategorized,Partial - unknown maps to uncategorized
```

#### Processing Rules
1. **Lookup:** For each PAN-DB category name, find matching `PANWCategory` (case-insensitive)
2. **Unmapped Categories:**
   - If `GSACategory` is null, blank, or `Unmapped`: add `UNMAPPED:PANWCategoryName` placeholder to `RuleDestinations`
   - Set `ReviewNeeded` = `Yes` in output
   - Set `Provision` = `No`
   - Add the unmapped category name to `ReviewDetails`: `Unmapped categories: [list]`
3. **Category Not Found in Mapping File:**
   - If a PAN-DB category referenced in a URL filtering profile is not present in the mapping file
   - Treat same as unmapped: add `UNMAPPED:PANWCategoryName` to `RuleDestinations`, add to `ReviewDetails`
   - Log at WARN level
4. **Partial Mappings (MappingNotes contains 'Partial'):**
   - If the mapping has a valid `GSACategory` but `MappingNotes` indicates `Partial`: **leave the GSA category blank/excluded from `RuleDestinations`**
   - Add to `ReviewDetails`: `Partial mappings require review: [PANWCategory] -> [GSACategory]`
   - Set `ReviewNeeded` = `Yes`
   - This ensures the user explicitly reviews and approves partial matches before provisioning
5. **Exact Mappings:**
   - Use the `GSACategory` value directly in `RuleDestinations`
   - Set `ReviewNeeded` = `No` in output (unless overridden by action review)

### 3. PANW2EIA-AppMappings.csv
**Source:** Provided mapping file (maintained by project)
**Required:** No (optional — if not provided, application references are only flagged for review)
**Default Path:** `PANW2EIA-AppMappings.csv` (in script root directory)

#### Description
Provides mapping between Palo Alto App-ID application names and Microsoft GSA (Global Secure Access) application names with associated FQDN endpoints. When a security rule references applications, this file is used to convert App-ID references into FQDN-based web content filtering policies.

#### Schema

| Column | Type | Required | Description |
|---|---|---|---|
| PANWAppName | string | Yes | Palo Alto App-ID name (lowercase-hyphenated, e.g., `office365-base`, `slack-base`) |
| GSAAppName | string | No | Target GSA application name (e.g., `Box`, `Slack`). Empty if no mapping. |
| MatchType | string | No | `exact` or `approximate`. Empty if no mapping. |
| GSAEndpoints | string | No | Semicolon-separated FQDN endpoints (e.g., `box.com;boxcloud.com`). Empty if no mapping. Each endpoint is expanded using the dual FQDN pattern (`domain.com;*.domain.com`). |

#### Sample Data
```csv
PANWAppName,GSAAppName,MatchType,GSAEndpoints
office365-base,Office 365,exact,
slack-base,Slack,approximate,slack.com;api.slack.com;files.slack.com
boxnet,Box,approximate,box.com;boxcloud.com;boxlocalhost.com;box.net
chatgpt,ChatGPT,approximate,chatgpt.com;chat.openai.com
amazon-bedrock-base,,,,
custom-internal-app,,,,
```

#### Processing Rules
1. **Lookup:** For each App-ID name in a security rule's `<application>` list, find matching `PANWAppName` (case-insensitive)
2. **Mapped Apps with Endpoints:**
   - If `GSAAppName` is non-empty AND `GSAEndpoints` is non-empty:
   - Create a web content filtering policy with FQDN rules from the endpoints
   - Policy name: `[GSAAppName]-[Action]`
   - Process endpoints through `ConvertTo-CleanDestination` and `Get-DestinationType`
   - Group by base domain, split by 300-char limit (same as custom URL categories)
   > **Note:** The dual FQDN pattern does NOT apply to custom URL category members (Phase 2) — those are taken as-is from the Panorama export, which already includes explicit wildcard entries where intended.
3. **Mapped Apps without Endpoints:**
   - If `GSAAppName` is non-empty but `GSAEndpoints` is empty:
   - Create a placeholder policy flagged for review
   - `ReviewDetails`: `Application '[GSAAppName]' mapped but no endpoints available`
4. **Unmapped Apps (empty GSAAppName):**
   - Do not create a policy
   - Add to security profile's `ReviewDetails`: `Unmapped applications: [app1, app2]`
   - Set security profile `ReviewNeeded` = `Yes`
5. **App Not Found in Mapping File:**
   - Treat same as unmapped
   - Log at WARN level
6. **No App Mappings File Provided:**
   - All application references are flagged for review (same as current v1.0 behaviour)
   - Log at INFO: `No app mappings file provided; application references will be flagged for review`

---

## Output Files

All output files are created in `$OutputBasePath` with consistent timestamp prefix.

### 1. Policies CSV
**Filename:** `[yyyyMMdd_HHmmss]_EIA_Policies.csv`

#### Description
Contains all web content filtering policies including custom URL category policies and predefined web category policies.

#### Fields

| Field | Description | Example | Notes |
|---|---|---|---|
| PolicyName | Policy name | `Corp-URL-Filter-WebCategories-Block` | Unique identifier |
| PolicyType | Type of policy | `WebContentFiltering` | Always `WebContentFiltering` |
| PolicyAction | Allow or Block | `Block`, `Allow` | From URL filtering profile action |
| Description | Policy description | `Blocked categories from Corp-URL-Filter profile` | From profile/category or generated |
| RuleType | Type of destination | `FQDN`, `URL`, `webCategory` | One type per row |
| RuleDestinations | Semicolon-separated list | `*.example.com;site.com` | Max 300 chars for FQDN/URL/IP |
| RuleName | Sub-rule identifier | `example.com`, `WebCategories` | For grouping/splitting |
| ReviewNeeded | Manual review flag | `Yes`, `No` | `Yes` if unmapped categories or non-standard action |
| ReviewDetails | Reason for review | `Alert action requires review; Unmapped categories found` | Semicolon-separated reasons |
| Provision | Provisioning flag | `Yes`, `No` | `No` if ReviewNeeded is `Yes` |

#### PolicyAction Mapping

| PANW URL Filter Action | EIA PolicyAction | ReviewNeeded | Notes |
|---|---|---|---|
| `allow` | `Allow` | No | Direct mapping |
| `block` | `Block` | No | Direct mapping |
| `alert` | `Block` | Yes | Non-standard action flagged for review |
| `continue` | `Block` | Yes | Non-standard action flagged for review |
| `override` | `Block` | Yes | Non-standard action flagged for review |

#### RuleDestinations Field
- Semicolon-separated list of destinations
- Character limit: 300 characters for FQDN and URL types
- **Web categories (`webCategory` type) have NO character limit** and are never split
- If limit exceeded, split into multiple rows with `-2`, `-3` suffix on RuleName

#### Provision Field
- **Default:** `Yes` (entry is ready for provisioning)
- **Exception:** `No` when `ReviewNeeded = Yes`
  - Unmapped categories require manual review
  - Non-standard actions (alert, continue, override) require review
  - Application-based rules require review

### 2. Security Profiles CSV
**Filename:** `[yyyyMMdd_HHmmss]_EIA_SecurityProfiles.csv`

#### Description
Contains aggregated security profile definitions that combine multiple security rules sharing the same user/group assignment into a single profile.

#### Fields

| Field | Description | Example | Notes |
|---|---|---|---|
| SecurityProfileName | Profile name | `SecurityProfile-All-Users` | Aggregated name or numbered |
| Priority | Profile priority | `1000` | Override profiles start at 1000; Default at 50000 |
| SecurityProfileLinks | Policy links with priorities | `Custom-Cat-Block:100;Corp-Filter-WebCategories-Block:200` | `PolicyName:LinkPriority` pairs |
| CADisplayName | CA policy display name | `SecurityProfile-All-Users` | Same as SecurityProfileName |
| EntraUsers | Semicolon-separated users | `user@domain.com` | From source-user (if email format) |
| EntraGroups | Semicolon-separated groups | `Finance;HR` | From source-user (if group name) |
| Description | Profile description | `Aggregated from 3 security rules` | Lists count of source rules |
| Provision | Provisioning flag | `Yes` | Always `Yes` for security profiles |
| Notes | Source rule traceability | `Allow-Web-Access, Allow-SaaS-Apps` | Comma-separated source rule names |

#### SecurityProfileLinks Format
- Semicolon-separated list of `PolicyName:LinkPriority` pairs
- LinkPriority is auto-assigned sequentially: 100, 200, 300, etc.
- Policy links are deduplicated across aggregated rules
- Ordering: Allow policies first (alphabetically), then Block policies (alphabetically)
- Example: `Internal-Sites-Allow:100;Corp-Filter-WebCategories-Allow:200;Blocked-Sites-Block:300;Corp-Filter-WebCategories-Block:400`

#### Priority Calculation
- **Override profiles** (specific user/group sets): start at 1000, increment by 100 (`SecurityProfile-001` = 1000, `SecurityProfile-002` = 1100, etc.) — lower number = higher precedence = evaluated first
- **Default profile** (All-Users): priority 50000 — highest number = lowest precedence = baseline
- If conflict detected: increment by 1 until unique

#### Source-User Mapping
- `any` → `EntraGroups` = `Replace_with_All_IA_Users_Group` → aggregated into `SecurityProfile-All-Users`
- Email format (contains `@`) → `EntraUsers`
- Other values (group names, domain\user format) → `EntraGroups`
- `unknown` → skipped with WARN log
- `pre-logon` → skipped with WARN log

#### Aggregation Rules
- Rules assigned to `any` → combined into single `SecurityProfile-All-Users`
- Rules with identical user/group sets → combined into `SecurityProfile-NNN`
- User/group matching: create key from sorted users + sorted groups (case-insensitive)
- Deduplication: same policy referenced by multiple rules appears only once in SecurityProfileLinks

### 3. Log File
**Filename:** `[yyyyMMdd_HHmmss]_Convert-PANW2EIA.log`
**Location:** Same directory as output CSV files (`$OutputBasePath`)

---

## Processing Logic

### Phase 1: Data Loading and Validation

#### 1.1 Initialize Logging
Create log file with timestamp prefix in `$OutputBasePath`.

#### 1.2 Load and Parse XML
1. Load `PanoramaXmlPath` as `[xml]` document
   - Fatal error if file missing or XML is malformed
2. Validate root element is `<config>` or contains `<config>` element
   - Fatal error if not a valid Panorama export

#### 1.3 Determine Scope
1. Enumerate all device-groups under `/config/devices/entry/device-group/entry`
2. If `-DeviceGroupName` parameter is specified:
   - Filter to matching device-group only
   - Fatal error if specified device-group not found
3. If not specified:
   - Process ALL device-groups
   - Log device-group names at INFO level
4. Check for shared section at `/config/shared`
   - Log whether shared objects are present

#### 1.4 Build Object Collections

For each device-group (and shared):

1. **Custom URL Categories** — Collect from shared and device-group scope
   - Device-group entries override shared entries with the same name
   - Only include entries where `<type>` = `URL List`
   - Skip `Category Match` type entries (log at INFO level)
   - Skip entries with empty `<list>` (log at WARN level)

2. **URL Filtering Profiles** — Collect from shared and device-group scope
   - Device-group entries override shared entries with the same name
   - Extract categories from `<allow>`, `<block>`, `<alert>`, `<continue>`, `<override>` child elements

3. **Profile Groups** — Collect from shared and device-group scope
   - Build lookup table: profile group name → URL filtering profile name

4. **Security Rules** — Collect from device-group only
   - Collect from `pre-rulebase/security/rules` (processed first)
   - Then from `post-rulebase/security/rules` (processed second)
   - Maintain processing order across both rulebases

#### 1.5 Build Lookup Tables
- Category mappings hashtable: `PANWCategory` → mapping object (GSACategory, MappingNotes) (from CSV)
- App mappings hashtable: `PANWAppName` → mapping object (GSAAppName, MatchType, GSAEndpoints) (from CSV, if provided)
- Custom URL categories hashtable: `name` → category object
- URL filtering profiles hashtable: `name` → profile object
- Profile groups hashtable: `name` → URL filtering profile name
- Custom category policies tracking hashtable: `name` → policy names (populated in Phase 2)

### Phase 2: Custom URL Category Processing

#### 2.1 Filter Custom URL Categories
For each custom URL category collected in Phase 1:
- Skip if `<type>` is not `URL List` (already filtered in 1.4)
- Skip if `<list>` has no `<member>` entries (log at WARN level)
- Process remaining categories

#### 2.2 Destination Processing
For each custom URL category:
1. Extract all `<member>` values from `<list>`
2. Deduplicate entries (case-insensitive)
3. Clean each entry using `ConvertTo-CleanDestination` (remove schema, port, query, fragment)
4. Classify each entry using `Get-DestinationType`:
   - IPv4 address → WARN and skip (EIA does not support IP address destinations); log the skipped IP and its source category name
   - IPv6 address → WARN and skip (not supported)
   - Contains `/` → classify as `URL`
   - Starts with `*.` → classify as `FQDN`
   - Default → classify as `FQDN`

#### 2.3 Grouping and Splitting
- **FQDNs and URLs:** Group by base domain using `Get-BaseDomain`, split by 300-char limit
- Use `Split-ByCharacterLimit` for splitting (same as ZIA2EIA)

#### 2.4 Policy Entry Creation

Create policy entries with default `Block` action:

| Field | Value |
|---|---|
| PolicyName | `[CategoryName]-Block` |
| PolicyType | `WebContentFiltering` |
| PolicyAction | `Block` |
| Description | From `<description>` element or `Converted from PANW custom URL category: [name]` |
| RuleType | `FQDN` or `URL` |
| RuleDestinations | Semicolon-separated entries |
| RuleName | Base domain / with numeric suffix if split |
| ReviewNeeded | `No` |
| ReviewDetails | (empty) |
| Provision | `Yes` |

Track created policies in `$customCategoryPoliciesHashtable` for Phase 3 lookup.

### Phase 3: URL Filtering Profile Processing

#### 3.1 Process Each URL Filtering Profile

For each URL filtering profile collected in Phase 1:
1. Extract categories from each action element: `<allow>`, `<block>`, `<alert>`, `<continue>`, `<override>`
2. Separate custom URL category references from PAN-DB predefined categories
   - A category is custom if it exists in `$customCategoriesHashtable`
   - Otherwise it is a PAN-DB predefined category

#### 3.2 Create Web Category Policies (Predefined Categories)

Group predefined categories by action and create one policy per action:

**Category Mapping Logic:**
For each PAN-DB category, look up in the category mappings hashtable:
- **Exact match** (MappingNotes does NOT contain 'Partial'): include `GSACategory` in `RuleDestinations`
- **Partial match** (MappingNotes contains 'Partial'): **exclude from `RuleDestinations`**, add to `ReviewDetails`
- **Unmapped/missing**: add `UNMAPPED:PANWCategoryName` placeholder to `RuleDestinations`, add to `ReviewDetails`

Only categories with exact mappings contribute valid GSA categories to `RuleDestinations`. Partial matches are excluded for manual review. Unmapped categories use the `UNMAPPED:` placeholder format.

**For `block` categories:**

| Field | Value |
|---|---|
| PolicyName | `[ProfileName]-WebCategories-Block` |
| PolicyType | `WebContentFiltering` |
| PolicyAction | `Block` |
| RuleType | `webCategory` |
| RuleDestinations | Only exactly-mapped GSA categories, semicolon-separated |
| RuleName | `WebCategories` |
| ReviewNeeded | `Yes` if any partial/unmapped categories; otherwise `No` |
| ReviewDetails | `Partial mappings: [list]; Unmapped categories: [list]` if applicable |
| Provision | `No` if ReviewNeeded; otherwise `Yes` |

> **Note:** Unmapped categories use `UNMAPPED:PANWCategoryName` format in `RuleDestinations`. Partial matches are excluded from `RuleDestinations` entirely (listed only in `ReviewDetails`).

**For `allow` categories:**

| Field | Value |
|---|---|
| PolicyName | `[ProfileName]-WebCategories-Allow` |
| PolicyAction | `Allow` |
| (other fields same pattern as above) | |

**For `alert` categories:**

| Field | Value |
|---|---|
| PolicyName | `[ProfileName]-WebCategories-Alert` |
| PolicyAction | `Block` |
| ReviewNeeded | `Yes` |
| ReviewDetails | `PANW 'alert' action requires review - mapped to Block` |
| Provision | `No` |

**For `continue` categories:**

| Field | Value |
|---|---|
| PolicyName | `[ProfileName]-WebCategories-Continue` |
| PolicyAction | `Block` |
| ReviewNeeded | `Yes` |
| ReviewDetails | `PANW 'continue' action requires review - mapped to Block` |
| Provision | `No` |

**For `override` categories:**

| Field | Value |
|---|---|
| PolicyName | `[ProfileName]-WebCategories-Override` |
| PolicyAction | `Block` |
| ReviewNeeded | `Yes` |
| ReviewDetails | `PANW 'override' action requires review - mapped to Block` |
| Provision | `No` |

#### 3.3 Track Custom Category References

For each URL filtering profile, track which custom URL categories are referenced under which action. This information is used in Phase 4 when building security profile policy links.

Store in a profile-level lookup:
- Profile name → list of `{ CustomCategoryName, Action }` pairs

When a custom category is referenced with action `Allow` and only a `Block` policy exists from Phase 2:
- Create an Allow version by duplicating all Block policy entries with `PolicyAction = Allow` and `PolicyName = [CategoryName]-Allow`
- Same duplication logic as ZIA2EIA spec (Phase 3, Section 3.4)

### Phase 4: Security Rule Processing

#### 4.1 Filter Security Rules
For each security rule collected in Phase 1:
1. Skip if `<disabled>` = `yes` (log count at INFO, names at DEBUG)
2. Skip if `<action>` is not `allow` (deny/drop/reset rules block traffic at firewall level)
3. **Apply policy name filter** using `Test-PolicyNameFilter` with `IncludePolicyName` and `ExcludePolicyName`:
   - If `IncludePolicyName` is specified: rule name must match at least one pattern (case-insensitive `-like`)
   - If `ExcludePolicyName` is specified: rule name must NOT match any pattern (exclude wins over include)
   - Log skipped rules at DEBUG level
4. Skip if no URL filtering profile is referenced AND no application references exist
5. Process remaining rules

#### 4.2 Resolve URL Filtering Profile
1. Check `<profile-setting>`:
   - If `<group>` → look up profile group → extract URL filtering profile name
   - If `<profiles><url-filtering>` → extract profile name directly
2. Look up the resolved profile name in the URL filtering profiles hashtable
3. If not found: log at WARN level (rule may still be processed for application references)

#### 4.3 Extract Users and Groups

Process `<source-user><member>` elements:
- `any` → `EntraGroups` = `Replace_with_All_IA_Users_Group`
- Contains `@` (email format) → add to `EntraUsers`
- `domain\username` format → add to `EntraGroups` as-is (flag for review: `Review source-user format`)
- `unknown` or `pre-logon` → skip with WARN log
- Other values → add to `EntraGroups` (treated as group names)

If no valid users and no valid groups remain: use `Replace_with_All_IA_Users_Group`.

#### 4.4 Process Application References

1. Check `<application><member>` elements
2. If any member is not `any` AND app mappings file is provided:
   - For each application name, look up in `$appMappingsHashtable`
   - **Mapped with endpoints:** Create web content filtering policy:
     - Parse `GSAEndpoints` (semicolon-separated)
     - Clean endpoints using `ConvertTo-CleanDestination`
     - Apply dual FQDN pattern: each endpoint produces two entries (`domain.com;*.domain.com`) to match both the bare domain and all subdomains
     - Classify as FQDN/URL/IP using `Get-DestinationType`
     - Group by base domain, split by 300-char limit
     - Policy name: `[GSAAppName]-[Action]` (action from rule's URL filter profile action context, default Block)
     - Deduplicate: if same `GSAAppName` policy already exists from another rule, reuse it
   - **Mapped without endpoints:** Create placeholder policy:
     - PolicyName: `[GSAAppName]-[Action]`
     - RuleDestinations: `PLACEHOLDER_[GSAAppName]`
     - ReviewNeeded: `Yes`
     - ReviewDetails: `Application '[GSAAppName]' mapped but no endpoints available`
   - **Unmapped (empty GSAAppName or not in file):**
     - Do NOT create a policy
     - Add to review list: `Unmapped applications: [app1, app2]`
     - Log at WARN level
3. If any member is not `any` AND no app mappings file is provided:
   - Flag for review: `Applications referenced (no mapping file): [app1, app2, ...]`
   - Log at INFO level

#### 4.5 Build Policy Links

For the resolved URL filtering profile, collect all related policy names:

1. **Web Category Policies** (from Phase 3):
   - `[ProfileName]-WebCategories-Block` (if block categories exist)
   - `[ProfileName]-WebCategories-Allow` (if allow categories exist)
   - `[ProfileName]-WebCategories-Alert` (if alert categories exist)
   - `[ProfileName]-WebCategories-Continue` (if continue categories exist)
   - `[ProfileName]-WebCategories-Override` (if override categories exist)

2. **Custom Category Policies** (from Phase 2/3):
   - For each custom category referenced in the profile:
     - If action is `block` → `[CategoryName]-Block`
     - If action is `allow` → `[CategoryName]-Allow`
     - If action is `alert`/`continue`/`override` → `[CategoryName]-Block` (with review flag)

3. **Application Policies** (from Phase 4.4):
   - For each mapped application with endpoints: `[GSAAppName]-[Action]`
   - For each mapped application without endpoints: `[GSAAppName]-[Action]` (review-flagged)

4. Store policy links and user/group info for aggregation (do NOT create security profiles yet)

#### 4.6 Collect for Aggregation

For each processed rule, store:
```
$policyInfo = @{
    RuleName    = rule name
    Emails      = extracted email list
    Groups      = extracted group list
    PolicyLinks = collected policy names (without priority suffixes)
    NeedsReview = whether review is needed
    ReviewReasons = list of review reasons
}
```

Add to `$policiesForAggregation` collection.

#### 4.7 Aggregate by User/Group Assignment

Follow the same aggregation pattern as `Convert-NSWG2EIA`:

1. **Separate "All users" rules** from specific user/group rules:
   - Rules where groups contain `Replace_with_All_IA_Users_Group` → `$allUsersPolicies`
   - All others → group by user/group combination key

2. **Create user/group combination key:**
   - Sort emails alphabetically, join with comma
   - Sort groups alphabetically, join with comma
   - Combined key: `{emails}|{groups}`
   - Rules with identical keys are aggregated

3. **Create Override security profiles for specific user/group sets:**
   - For each unique user/group key:
     - Collect all policy links from constituent rules
     - Deduplicate policy links
     - Order: Allow policies first (alphabetically), then Block policies (alphabetically)
     - Name: `SecurityProfile-001`, `SecurityProfile-002`, etc.
     - Priority: 1000 + ((index - 1) × 100) — lower number = higher precedence
     - Description: `Aggregated from N security rules`
     - Notes: comma-separated source rule names

4. **Create Default security profile for "All users":**
   - Aggregate all rules assigned to `any`
   - Collect and deduplicate policy links
   - Order: Allow first, then Block
   - Name: `SecurityProfile-All-Users`
   - Priority: 50000 — highest number = lowest precedence (baseline)
   - EntraGroups: `Replace_with_All_IA_Users_Group`

5. **Add priority suffixes to policy links:**
   - After aggregation, format links as `PolicyName:100;PolicyName:200;...`
   - Sequential priorities starting at 100, incrementing by 100

#### 4.8 Priority Conflict Resolution
Same algorithm as ZIA2EIA/NSWG2EIA: increment by 1 until unique.

#### 4.9 Cleanup Unreferenced Policies
After all security profiles are created, remove policies that are not referenced by any security profile's PolicyLinks. This avoids creating unused policies.

### Phase 5: Export and Summary

#### 5.1 Export Policies CSV
Export `$policies` collection to `[timestamp]_EIA_Policies.csv` using `Export-DataToFile` with UTF-8 BOM encoding.

#### 5.2 Export Security Profiles CSV
Export `$securityProfiles` collection to `[timestamp]_EIA_SecurityProfiles.csv` using `Export-DataToFile` with UTF-8 BOM encoding.

#### 5.3 Generate Summary Statistics

```
=== CONVERSION SUMMARY ===
Input: [PanoramaXmlPath]
Device Groups processed: X

Security rules loaded: A
  Pre-rulebase rules: A1
  Post-rulebase rules: A2
Rules processed (enabled + allow + URL filter or apps): B
Rules skipped (disabled): C
Rules skipped (deny/drop/reset): D
Rules skipped (no URL filter profile and no apps): E
Rules skipped (filtered by IncludePolicyName/ExcludePolicyName): E2
Rules with application references: F
  Applications mapped (with endpoints): F1
  Applications mapped (without endpoints): F2
  Applications unmapped: F3

URL Filtering Profiles processed: G
Custom URL Categories processed: H
  Categories skipped (Category Match type): H1
  Categories skipped (empty): H2
PAN-DB categories referenced: I
  Mapped to GSA (exact): I1
  Partial mappings (excluded, review needed): I2
  Unmapped: I3

Destinations classified:
  FQDNs: J
  URLs: K
  Skipped (IP addresses - not supported by EIA): L
  Skipped (IPv6/invalid): M

Policies created: N
  Custom category policies: N1
  Web category policies: N2
  Application policies: N3
  Policies flagged for review: N4
Security profiles created: O
  Default profile (All-Users): O1
  Override profiles (specific user/group): O2
  Rules aggregated: O3
Priority conflicts resolved: P

Output files:
  Policies: [path]
  Security Profiles: [path]
  Log File: [path]
```

---

## Function Parameters

### Required Parameters

| Parameter | Type | Description | Validation |
|---|---|---|---|
| PanoramaXmlPath | string | Path to Panorama XML export file | ValidateScript - file must exist, extension must be .xml |

### Optional Parameters

| Parameter | Type | Default | Description | Validation |
|---|---|---|---|---|
| CategoryMappingsPath | string | `PANW2EIA-CategoryMappings.csv` | Path to category mappings CSV | ValidateScript - file must exist |
| AppMappingsPath | string | (none) | Path to App-ID to GSA app mappings CSV | ValidateScript - file must exist (if provided) |
| DeviceGroupName | string | (all) | Filter to specific device-group | None (validated at runtime) |
| OutputBasePath | string | `$PWD` | Output directory | ValidateScript - directory must exist |
| IncludePolicyName | string[] | `$null` | Policy name patterns to include. Supports wildcards via `-like`. Case-insensitive. When specified, only security rules matching at least one pattern are processed | None |
| ExcludePolicyName | string[] | `$null` | Policy name patterns to exclude. Supports wildcards via `-like`. Case-insensitive. When specified, matching security rules are skipped. Exclude wins over include when both match | None |
| EnableDebugLogging | switch | `false` | Enable DEBUG level logging | None |

### Parameters NOT Included
- No PassThru parameter
- No batch size or processing limit parameters

---

## Internal Helper Functions

### Functions to Create (New)

#### 1. Import-PanoramaXml
**Purpose:** Load and validate the Panorama XML export, return parsed XML document

**Returns:** `[xml]` document object

**Logic:**
1. Load XML file using `[xml](Get-Content -Path $path -Raw)`
2. Validate root contains `<config>` element
3. Return parsed document

#### 2. Get-PANWCustomUrlCategories
**Purpose:** Extract custom URL categories from shared and device-group scope

**Returns:** Hashtable of category name → category data (members array, description, type)

**Logic:**
1. Collect entries from shared scope
2. Collect entries from device-group scope (overrides shared if same name)
3. Filter to `URL List` type only
4. Return merged hashtable

#### 3. Get-PANWUrlFilteringProfiles
**Purpose:** Extract URL filtering profiles from shared and device-group scope

**Returns:** Hashtable of profile name → profile data (categories per action)

**Logic:**
1. Collect entries from shared scope
2. Collect entries from device-group scope (overrides shared if same name)
3. For each profile, extract categories under `<allow>`, `<block>`, `<alert>`, `<continue>`, `<override>`
4. Return merged hashtable

#### 4. Get-PANWProfileGroups
**Purpose:** Build profile group → URL filtering profile lookup table

**Returns:** Hashtable of profile group name → URL filtering profile name

#### 5. Get-PANWSecurityRules
**Purpose:** Extract security rules from pre-rulebase and post-rulebase, maintaining order

**Returns:** Array of rule objects with properties: Name, Action, Disabled, SourceUsers, Applications, ProfileSetting, Description, RulebaseType (pre/post), Order

#### 6. Resolve-UrlFilteringProfile
**Purpose:** Given a security rule's profile-setting, resolve to the URL filtering profile name

**Returns:** URL filtering profile name string, or `$null` if not resolvable

**Logic:**
1. Check for `<group>` → look up profile groups hashtable → get URL filtering profile name
2. Check for `<profiles><url-filtering>` → return member value directly
3. Return `$null` if neither found

#### 7. Test-PolicyNameFilter
**Purpose:** Evaluate whether a security rule name should be processed based on include/exclude wildcard patterns

**Parameters:**
- `PolicyName` (string, mandatory) — the rule name to test
- `IncludePatterns` (string[]) — wildcard patterns to include
- `ExcludePatterns` (string[]) — wildcard patterns to exclude

**Returns:** `$true` if the rule should be processed, `$false` if filtered out

**Logic:**
```powershell
function Test-PolicyNameFilter {
    param(
        [Parameter(Mandatory)]
        [string]$PolicyName,
        [string[]]$IncludePatterns,
        [string[]]$ExcludePatterns
    )

    # If include patterns specified, policy must match at least one
    if ($IncludePatterns.Count -gt 0) {
        $included = $false
        foreach ($pattern in $IncludePatterns) {
            if ($PolicyName -like $pattern) { $included = $true; break }
        }
        if (-not $included) { return $false }
    }

    # If exclude patterns specified, policy must not match any (exclude wins)
    if ($ExcludePatterns.Count -gt 0) {
        foreach ($pattern in $ExcludePatterns) {
            if ($PolicyName -like $pattern) { return $false }
        }
    }

    return $true
}
```

### Functions to Reuse from Shared Internal Module

| Function | Purpose | Status |
|---|---|---|
| `Write-LogMessage` | Structured logging | ✅ Available |
| `Export-DataToFile` | CSV export | ✅ Available |
| `Get-DestinationType` | Classify FQDN/URL/IP | ✅ Available (from ZIA2EIA) |
| `Get-BaseDomain` | Extract base domain for grouping | ✅ Available |
| `Test-ValidIPv4Address` | Validate IPv4 format | ✅ Available |
| `Split-ByCharacterLimit` | Split destinations by 300-char limit | ✅ Available |
| `ConvertTo-CleanDestination` | Clean/normalise destination entries | ✅ Available |

---

## Logging Specifications

### Log Levels and Usage

| Level | Usage | Examples |
|---|---|---|
| INFO | Major milestones, counts, file operations | `Loaded 15 security rules from DG-1`, `Processed 4 URL filtering profiles` |
| WARN | Skipped items, unmapped categories, data issues | `Skipping IPv6 address`, `Custom URL category 'test' has no members` |
| ERROR | Fatal errors, missing files, invalid XML | `XML file not found`, `Invalid XML format` |
| DEBUG | Individual item processing, detailed flow | `Processing rule: Allow-Web-Access`, `Resolved profile group to url-filter-1` |

---

## Error Handling

### Fatal Errors (Stop Processing)

| Error | Condition | Action |
|---|---|---|
| Missing XML file | File not found | Throw error, exit |
| Invalid XML | XML parse error | Throw error, exit |
| Missing mappings file | CSV not found | Throw error, exit |
| Invalid device-group | Specified DG not found | Throw error, exit |
| No processable rules | No enabled allow rules with URL filtering | Throw error, exit |

### Non-Fatal Errors (Log and Continue)

| Error | Condition | Action |
|---|---|---|
| Category Match type | Custom URL category with type `Category Match` | INFO, skip |
| Empty custom category | No `<member>` entries in `<list>` | WARN, skip |
| IP address (IPv4) | Destination is an IPv4 address | WARN, skip (EIA does not support IP destinations) |
| IP address (IPv6) | Destination is an IPv6 address | WARN, skip (EIA does not support IP destinations) |
| Unmapped PAN-DB category | Not in mapping file | WARN, use `UNMAPPED:` placeholder |
| Profile group not found | Referenced profile group missing | WARN, skip rule |
| URL filter profile not found | Referenced profile missing | WARN, skip rule |
| Unknown source-user | `unknown` or `pre-logon` | WARN, skip user |

---

## Sample Files

### Location
All sample files should be created in: `Samples/PANW2EIA/`

### Required Samples

#### 1. sample_panorama_config.rename_to_xml
**Content:** Representative Panorama XML snippet demonstrating:
- Shared custom URL categories and URL filtering profiles
- At least one device-group with pre-rulebase and post-rulebase rules
- Rules with profile groups and direct profile references
- Rules with `any` source-user and specific users/groups
- Rules with application references (non-`any`)
- Disabled rules
- Rules with deny action (skipped)
- Custom URL categories with mixed FQDN/URL/IP entries
- URL filtering profiles with block, allow, alert, continue, and override categories
- Category Match type custom URL category (skipped)

#### 2. PANW2EIA-CategoryMappings.rename_to_csv
**Content:** Representative category mappings demonstrating:
- Mapped categories with exact match (e.g., `adult` → `PornographyAndSexuallyExplicit`)
- Mapped categories with partial match (e.g., `malware` → `CriminalActivity`, flagged for review)
- All common PAN-DB categories

#### 3. PANW2EIA-AppMappings.convert_to_csv
**Content:** App-ID to GSA application mappings demonstrating:
- Mapped apps with endpoints (e.g., `slack-base` → `Slack` with FQDNs)
- Mapped apps without endpoints (e.g., `office365-base` → `Office 365`)
- Unmapped apps (empty GSAAppName)
- Match types: `exact` and `approximate`

#### 4. sample_output_Policies.rename_to_csv
**Content:** Expected output showing:
- Custom category policies (FQDN/URL rules)
- Web category policies (block, allow, alert, continue, override)
- ReviewNeeded flags for non-standard actions and unmapped categories
- Provision = No for reviewed entries

#### 5. sample_output_SecurityProfiles.rename_to_csv
**Content:** Expected output showing:
- Aggregated security profiles (`SecurityProfile-All-Users`, `SecurityProfile-001`, etc.)
- Deduplicated `SecurityProfileLinks` in `PolicyName:LinkPriority` format
- User and group assignments from aggregated source-user fields
- Description showing aggregation count
- Notes showing source rule names

#### 6. README.md
**Content:** Documentation explaining sample files, expected conversion results, and usage instructions.

---

## Code Organization

### Region Structure

```powershell
function Convert-PANW2EIA {
    <# .SYNOPSIS, .DESCRIPTION, .PARAMETER, .EXAMPLE, .NOTES #>

    [CmdletBinding()]
    param(...)

    Set-StrictMode -Version Latest

    #region Helper Functions
    # Import-PanoramaXml
    # Get-PANWCustomUrlCategories
    # Get-PANWUrlFilteringProfiles
    # Get-PANWProfileGroups
    # Get-PANWSecurityRules
    # Resolve-UrlFilteringProfile
    # Test-PolicyNameFilter
    #endregion

    #region Initialization
    # Logging setup
    # Variable initialization
    #endregion

    #region Phase 1: Data Loading
    # Parse XML
    # Determine scope (device-groups)
    # Build object collections
    # Build lookup tables
    #endregion

    #region Phase 2: Custom URL Category Processing
    # Deduplicate and clean destinations
    # Classify FQDN/URL/IP
    # Group by base domain, split by char limit
    # Create policy entries
    #endregion

    #region Phase 3: URL Filtering Profile Processing
    # Process each profile's category actions
    # Map PAN-DB categories to GSA
    # Create web category policies per action
    # Track custom category references
    #endregion

    #region Phase 4: Security Rule Processing
    # Filter enabled allow rules with URL filter
    # Resolve URL filtering profiles
    # Extract users/groups
    # Detect application references
    # Build policy links
    # Create security profiles
    # Resolve priority conflicts
    # Cleanup unreferenced policies
    #endregion

    #region Phase 5: Export and Summary
    # Export CSVs
    # Generate statistics
    # Display summary
    #endregion
}
```

---

## Implementation Checklist

### Phase 1: Foundation
- [ ] Create function skeleton with parameters
- [ ] Implement XML loading and validation
- [ ] Implement device-group enumeration
- [ ] Build object collections (custom URL cats, profiles, profile groups, rules)
- [ ] Build lookup tables
- [ ] Load category mappings CSV

### Phase 2: Custom URL Categories
- [ ] Extract and deduplicate destinations
- [ ] Classify FQDN/URL/IP
- [ ] Group by base domain
- [ ] Split by character limit
- [ ] Create policy entries

### Phase 3: URL Filtering Profiles
- [ ] Extract categories per action
- [ ] Separate custom vs predefined categories
- [ ] Map predefined categories to GSA
- [ ] Create web category policies per action (block, allow, alert, continue, override)
- [ ] Track custom category references per profile

### Phase 4: Security Rules
- [ ] Filter rules (enabled, allow, has URL filter)
- [ ] Resolve URL filtering profile references (group + direct)
- [ ] Extract source-user assignments
- [ ] Detect application references
- [ ] Build policy links
- [ ] Create security profile entries
- [ ] Resolve priority conflicts
- [ ] Cleanup unreferenced policies

### Phase 5: Export and Testing
- [ ] Export Policies CSV
- [ ] Export Security Profiles CSV
- [ ] Generate summary statistics
- [ ] Create sample input/output files
- [ ] Test with real-world Panorama XML export
- [ ] Validate output against provisioning script

---

## Known Limitations

1. **XML Structure Assumption:** XPaths are based on standard Panorama XML schema; actual exports may vary by PAN-OS version
2. **Category Match custom URL categories:** Not processed (only URL List type is supported)
3. **IP Addresses:** EIA does not support IP address destinations; IPv4 and IPv6 addresses are logged and skipped
4. **CIDR Ranges:** Not supported (skipped with IP addresses)
5. **Port Numbers:** Not supported, cleaned from destinations
6. **Application Filtering:** Requires App Mappings CSV for endpoint-based conversion; unmapped apps are flagged for review
7. **Zone-based rules:** Source/destination zones are not mapped to EIA (EIA is zoneless)
8. **Address objects:** Source/destination address objects are not processed (EIA security profiles use user/group assignment, not network-based matching)
9. **NAT rules:** Out of scope
10. **Decryption policies:** Out of scope (EIA TLS inspection is handled separately)
11. **Schedule/time-based rules:** Not mapped to EIA (no equivalent), processed normally
12. **Rule ordering:** Pre-rulebase rules are processed before post-rulebase rules. Local firewall rules (which execute between pre and post) are not in the Panorama export.
13. **Device-group hierarchy:** Parent-child device-group inheritance is not resolved; each device-group is processed independently with shared objects.

---

## Future Enhancements

1. Add device-group hierarchy resolution (parent → child inheritance)
2. Add support for Category Match type custom URL categories
3. Add address object processing (FQDN address objects → EIA policies)
4. Add WhatIf support
5. Add PassThru parameter for pipeline support
6. Add support for local firewall XML exports (vsys-based, not device-group)
7. Expand App Mappings CSV with additional endpoint coverage

---

## References

### Palo Alto Documentation
- Panorama Configuration Export: https://docs.paloaltonetworks.com/panorama/admin/manage-panorama/administer-panorama/export-and-import-panorama-configuration
- URL Filtering Profiles: https://docs.paloaltonetworks.com/pan-os/admin/url-filtering
- PAN-DB URL Categories: https://docs.paloaltonetworks.com/pan-os/admin/url-filtering/pan-db-categorization
- Custom URL Categories: https://docs.paloaltonetworks.com/pan-os/admin/url-filtering/custom-url-categories

### Related Functions
- Convert-ZIA2EIA.ps1: Template for design patterns and shared helper functions
- Convert-NSWG2EIA.ps1: Reference for URL list and category conversion patterns
- Start-EntraInternetAccessProvisioning.ps1: Target provisioning script (defines output CSV format)
- Write-LogMessage.ps1: Shared logging function

### Microsoft Documentation
- Entra Internet Access: https://learn.microsoft.com/en-us/entra/global-secure-access/concept-internet-access
- Web Content Filtering: https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-configure-web-content-filtering

---

**End of Specification**
