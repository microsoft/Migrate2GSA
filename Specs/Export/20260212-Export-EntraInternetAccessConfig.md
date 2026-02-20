# Export Entra Internet Access Configuration - Technical Specifications

**Version:** 1.0  
**Date:** February 12, 2026  
**Purpose:** Export Microsoft Entra Internet Access (EIA) policies, security profiles, and Conditional Access policies to CSV format for backup, migration, or re-provisioning scenarios.  
**Status:** Draft  
**Target Module:** Migrate2GSA  
**Function Name:** Export-EntraInternetAccessConfig  
**Author:** Franck Heilmann and Andres Canello

---

## Overview

This specification defines how to export Entra Internet Access (EIA) configurations from an existing Entra tenant into CSV files. The exported CSVs are formatted to be directly compatible with the `Start-EntraInternetAccessProvisioning` function, enabling backup/restore and migration scenarios.

**Key Concept:** This is a direct export from Entra Internet Access without transformation. The function retrieves EIA policies, security profiles, and Conditional Access policies via Microsoft Graph API and formats them into the CSV structure expected by the provisioning function.

**Scope:**
- Exports Web Content Filtering Policies and their rules (FQDN, URL, webCategory, ipAddress)
- Exports TLS Inspection Policies and their rules (bypass, inspect)
- Exports Security Profiles with policy links and priorities
- Exports Conditional Access policies linked to security profiles (with user/group assignments)
- Each policy rule creates one row in Policies CSV (multi-rule policies have multiple rows)
- Each security profile creates one row in Security Profiles CSV

**Output:** Two timestamped CSV files in a structured folder, matching the format expected by `Start-EntraInternetAccessProvisioning`.

---

## 1. Function Definition

### 1.1 Function Name
```powershell
Export-EntraInternetAccessConfig
```

### 1.2 Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-OutputPath` | String | No | Current directory | Directory where timestamped backup folder will be created |
| `-IncludeConditionalAccessPolicies` | Switch | No | False | Include Conditional Access policies in the export (affects Security Profiles CSV creation) |
| `-LogPath` | String | No | Auto-generated | Path for log file (defaults to output folder) |

### 1.3 Parameter Validation Rules

**OutputPath:**
- If not specified, use current directory (`$PWD`)
- Must have write permissions to create subfolder
- Validate write permissions before starting export

**IncludeConditionalAccessPolicies:**
- When specified: Export security profiles WITH Conditional Access policy assignments
- When omitted: Export security profiles WITHOUT Conditional Access information (EntraUsers/EntraGroups/CADisplayName left empty)
- Does not affect whether Security Profiles CSV is created (see section 2.3)

**LogPath:**
- If not specified, automatically placed in the timestamped backup folder
- Named: `yyyyMMdd_HHmmss_Export-EIA.log`

### 1.4 Prerequisites
- Authenticated Microsoft Graph session (via `Connect-Entra` or `Connect-MgGraph`)
- PowerShell module: `Microsoft.Graph.Authentication`
- Required permission scopes:
  - `NetworkAccessPolicy.Read.All` (for EIA policies and security profiles)
  - `Policy.Read.All` (for Conditional Access policies, only if `-IncludeConditionalAccessPolicies` specified)
  - `User.Read.All` and `Directory.Read.All` (for user/group assignments, only if `-IncludeConditionalAccessPolicies` specified)

**Note:** These are read-only scopes since this function only exports data. The provisioning function requires ReadWrite scopes.

---

## 2. Output Structure and Naming Convention

### 2.1 Folder Structure
```
GSA-backup_yyyyMMdd_HHmmss/
└── InternetAccess/
    ├── yyyyMMdd_HHmmss_EIA_Policies.csv
    ├── yyyyMMdd_HHmmss_EIA_SecurityProfiles.csv (optional)
    └── yyyyMMdd_HHmmss_Export-EIA.log
```

**Example:**
```
GSA-backup_20260212_143022/
└── InternetAccess/
    ├── 20260212_143022_EIA_Policies.csv
    ├── 20260212_143022_EIA_SecurityProfiles.csv
    └── 20260212_143022_Export-EIA.log
```

### 2.2 Timestamp Format
- Format: `yyyyMMdd_HHmmss` (e.g., `20260212_143022`)
- Generated once at function start
- Used consistently for folder name, file names, and log entries

### 2.3 File Creation Logic

**Policies CSV (REQUIRED):**
- Always created
- Contains all Web Content Filtering and TLS Inspection policies
- At minimum, creates file with headers (if no policies exist)

**Security Profiles CSV (CONDITIONAL):**
- Created when ANY of the following conditions are true:
  - Security profiles exist in the tenant, OR
  - `-IncludeConditionalAccessPolicies` switch is specified
- NOT created when:
  - No security profiles exist AND
  - `-IncludeConditionalAccessPolicies` is NOT specified
- If created but no security profiles exist, file contains headers only

**Example Scenarios:**
| Security Profiles Exist | `-IncludeConditionalAccessPolicies` | SecurityProfiles CSV Created? |
|-------------------------|-------------------------------------|-------------------------------|
| Yes | Not specified | Yes (without CA info) |
| Yes | Specified | Yes (with CA info) |
| No | Not specified | No |
| No | Specified | Yes (headers only) |

### 2.4 File Naming
- **Policies CSV:** `{timestamp}_EIA_Policies.csv`
- **Security Profiles CSV:** `{timestamp}_EIA_SecurityProfiles.csv`
- **Log File:** `{timestamp}_Export-EIA.log`

---

## 3. CSV File Formats

### 3.1 Policies CSV Format

#### 3.1.1 Required Columns

```
PolicyName,PolicyType,PolicyAction,Description,RuleType,RuleDestinations,RuleName,Provision
```

#### 3.1.2 Column Definitions

| Column | Description | Data Type | Example Values |
|--------|-------------|-----------|----------------|
| `PolicyName` | Display name of the policy | String | `Dev_Tools-Allow`, `Social_Media-Block` |
| `PolicyType` | Type of policy | String | `WebContentFiltering`, `TLSInspection` |
| `PolicyAction` | Default action for the policy | String | For WebContentFiltering: `allow`, `block`<br>For TLSInspection: `bypass`, `inspect` |
| `Description` | Policy description | String | `Development tools`, `Block social media sites` |
| `RuleType` | Type of rule | String | For WebContentFiltering: `fqdn`, `url`, `webCategory`, `ipAddress`<br>For TLSInspection: `bypass`, `inspect` |
| `RuleDestinations` | Semicolon-separated list of destinations | String | `github.com;*.github.io`, `SocialNetworking;Entertainment` |
| `RuleName` | Name of the rule | String | `GitHub_StackOverflow`, `Social_Categories` |
| `Provision` | Flag indicating whether to provision this rule | String | `no` (default for exports) |

#### 3.1.3 Data Population Rules

**Provision Column:**
- Always set to `no` for exported records
- Allows manual review before re-provisioning

**Missing Data:**
- If description is not defined, leave field blank
- If rule name is not available, generate one from rule type: `Rule_{RuleType}_{Index}`
- Log warning for missing data but continue export

**Multiple Values in RuleDestinations:**
- Join multiple destinations with semicolon: `dest1;dest2;dest3`
- No spaces around semicolons
- For webCategory rules: semicolon-separated category names
- For FQDN/URL rules: semicolon-separated FQDNs/URLs
- For ipAddress rules: semicolon-separated IP addresses

**PolicyAction Values:**
- Export as lowercase: `allow`, `block`, `bypass`, `inspect`
- Matches provisioning function expectations

**Special Characters:**
- CSV-escape fields containing commas, quotes, or newlines
- Use standard CSV quoting (double quotes)

#### 3.1.4 Row Structure

**One row per policy rule:**
- Policies with multiple rules generate multiple rows
- Policy-level properties (PolicyName, PolicyType, PolicyAction, Description) are repeated for each rule
- Rules for the same policy must have identical values for:
  - `PolicyName`
  - `PolicyType`
  - `PolicyAction`
  - `Description` (if provided)
- Each row has unique rule properties:
  - `RuleType` (per rule)
  - `RuleDestinations` (per rule)
  - `RuleName` (per rule)

**Example Policies CSV:**
```csv
PolicyName,PolicyType,PolicyAction,Description,RuleType,RuleDestinations,RuleName,Provision
Dev_Tools-Allow,WebContentFiltering,allow,Development tools,fqdn,github.com;*.github.io;stackoverflow.com,GitHub_StackOverflow,no
Dev_Tools-Allow,WebContentFiltering,allow,Development tools,url,https://docs.microsoft.com/*;https://learn.microsoft.com/*,Microsoft_Docs,no
Dev_Tools-Allow,WebContentFiltering,allow,Development tools,webCategory,DeveloperTools;Programming,Dev_Categories,no
Social_Media-Block,WebContentFiltering,block,Block social media sites,webCategory,SocialNetworking;Entertainment,Social_Categories,no
TLS_Finance-Inspect,TLSInspection,inspect,Inspect financial traffic (default),bypass,*.internal-bank.com;secure-finance.contoso.com,Finance_Bypass,no
TLS_Finance-Inspect,TLSInspection,inspect,Inspect financial traffic (default),inspect,*.financial-services.com,Finance_Inspect,no
TLS_Internal-Bypass,TLSInspection,bypass,Bypass TLS for internal sites (default),bypass,*.internal.contoso.com;*.corp.local,Internal_Bypass,no
TLS_Internal-Bypass,TLSInspection,bypass,Bypass TLS for internal sites (default),inspect,suspicious.contoso.com,Suspicious_Inspect,no
```

### 3.2 Security Profiles CSV Format

#### 3.2.1 Required Columns

```
SecurityProfileName,Priority,SecurityProfileLinks,CADisplayName,EntraUsers,EntraGroups,Provision
```

#### 3.2.2 Column Definitions

| Column | Description | Data Type | Example Values |
|--------|-------------|-----------|----------------|
| `SecurityProfileName` | Display name of the security profile | String | `Profile_Finance_Strict`, `Profile_Marketing_Standard` |
| `Priority` | Processing priority of the security profile | Integer | `100`, `200`, `300` (higher = lower priority) |
| `SecurityProfileLinks` | Semicolon-separated PolicyName:Priority pairs | String | `Policy_Web_Finance:100;Policy_TLS_Finance:200` |
| `CADisplayName` | Conditional Access policy display name | String | `CA_Finance_Access`, `CA_Marketing_Access` (empty if no CA policy) |
| `EntraUsers` | Semicolon-separated user UPNs | String | `john.doe@contoso.com;jane.smith@contoso.com` (empty if no users) |
| `EntraGroups` | Semicolon-separated group display names | String | `Finance_Group;Executives_Group` (empty if no groups) |
| `Provision` | Flag indicating whether to provision this record | String | `no` (default for exports) |

#### 3.2.3 Data Population Rules

**Provision Column:**
- Always set to `no` for exported records
- Allows manual review before re-provisioning

**SecurityProfileLinks Format:**
- Format: `PolicyName1:Priority1;PolicyName2:Priority2`
- PolicyName: Display name of the policy (matches PolicyName in Policies CSV)
- Priority: Integer priority for this policy link within the security profile
- Multiple links separated by semicolons without spaces
- Example: `Dev_Tools-Allow:100;Marketing_Sites-Allow:200`

**SecurityProfileLinks Resolution:**
- Export should use policy display names (not IDs)
- Must match PolicyName entries in Policies CSV for provisioning to work
- If policy links cannot be resolved, log error and skip security profile

**Conditional Access Export:**
- **When `-IncludeConditionalAccessPolicies` is NOT specified:**
  - Leave `CADisplayName`, `EntraUsers`, and `EntraGroups` empty
  - Only export security profile metadata and policy links
  
- **When `-IncludeConditionalAccessPolicies` IS specified:**
  - Export linked CA policy display name in `CADisplayName`
  - Export user assignments in `EntraUsers` (UPN format, semicolon-separated)
  - Export group assignments in `EntraGroups` (display names, semicolon-separated)
  - If no CA policy is linked to the security profile, leave CA fields empty
  - Only export CA policies that reference GSA security profiles (not all CA policies)

**Missing Data:**
- If security profile has no description, leave blank (not exported in this CSV)
- If no policy links exist, skip this security profile entirely (log warning)
- If CA policy lookup fails, leave CA fields empty and log warning (continue export)

**Priority Values:**
- Export as integer values
- These represent security profile priorities (not policy link priorities)

**Multiple Values:**
- Users: Semicolon-separated UPNs without spaces
- Groups: Semicolon-separated display names without spaces
- Policy links: Semicolon-separated `PolicyName:Priority` pairs

**Special Characters:**
- CSV-escape fields containing commas, quotes, or newlines
- Use standard CSV quoting (double quotes)

#### 3.2.4 Row Structure

**One row per security profile:**
- Each security profile has exactly one row
- All policy links for that profile are combined into `SecurityProfileLinks` field
- If linked CA policy exists and `-IncludeConditionalAccessPolicies` is specified, include assignments

**Example Security Profiles CSV (with CA policies):**
```csv
SecurityProfileName,Priority,SecurityProfileLinks,CADisplayName,EntraUsers,EntraGroups,Provision
Profile_Finance_Strict,100,Policy_Web_Finance:100;Policy_TLS_Finance:200,CA_Finance_Access,john.doe@contoso.com;jane.smith@contoso.com,Finance_Group;Executives_Group,no
Profile_Marketing_Standard,200,Policy_Web_Marketing:150,CA_Marketing_Access,marketing.team@contoso.com,Marketing_Group,no
Profile_IT_NoCA,300,Policy_Web_Admin:50;Policy_TLS_Admin:75,,,,no
Profile_Dev_Tools,400,Dev_Tools-Allow:80,CA_Dev_Access,dev.team@contoso.com,Developers_Group,no
```

**Example Security Profiles CSV (without CA policies - IncludeConditionalAccessPolicies not specified):**
```csv
SecurityProfileName,Priority,SecurityProfileLinks,CADisplayName,EntraUsers,EntraGroups,Provision
Profile_Finance_Strict,100,Policy_Web_Finance:100;Policy_TLS_Finance:200,,,,no
Profile_Marketing_Standard,200,Policy_Web_Marketing:150,,,,no
Profile_IT_NoCA,300,Policy_Web_Admin:50;Policy_TLS_Admin:75,,,,no
Profile_Dev_Tools,400,Dev_Tools-Allow:80,,,,no
```

---

## 4. Export Process Flow

### 4.1 High-Level Flow

```
1. Validate parameters (OutputPath write permissions)
2. Generate timestamp
3. Create output folder structure: GSA-backup_{timestamp}/InternetAccess/
4. Initialize logging (set $script:LogPath)
5. Validate required PowerShell modules (Test-RequiredModules)
6. Test Graph connection with required scopes (Test-GraphConnection)
7. Validate GSA tenant onboarding status (Get-IntGSATenantStatus)
8. Export Part 1: Policies
   a. Retrieve all Web Content Filtering Policies
   b. For each policy, retrieve all policy rules
   c. Build Policies CSV rows (one row per rule)
   d. Write Policies CSV file
9. Export Part 2: Security Profiles (conditional)
   a. Determine if Security Profiles CSV should be created
   b. If yes:
      - Retrieve all Security Profiles
      - For each profile, retrieve policy links
      - If -IncludeConditionalAccessPolicies:
        * Find linked CA policy (by sessionControlsCloudAppSecuritySessionControlProfile)
        * Retrieve CA policy assignments (users/groups)
        * Resolve group IDs to names, user IDs to UPNs
      - Build Security Profiles CSV rows
      - Write Security Profiles CSV file
10. Generate summary report
11. Display completion message with folder location
```

### 4.2 Detailed Export Steps

#### 4.2.1 Authentication and Validation

**Module Validation:**
```powershell
# Validate required PowerShell modules are installed
$requiredModules = @(
    'Microsoft.Graph.Authentication'
)
Test-RequiredModules -RequiredModules $requiredModules
```

**Graph Connection Validation:**
```powershell
# Build required scopes based on parameters
$requiredScopes = @(
    'NetworkAccessPolicy.Read.All'
)

# Add CA-related scopes if including CA policies
if ($IncludeConditionalAccessPolicies) {
    $requiredScopes += 'Policy.Read.All'
    $requiredScopes += 'User.Read.All'
    $requiredScopes += 'Directory.Read.All'
}

# Validate Microsoft Graph authentication with required scopes
Test-GraphConnection -RequiredScopes $requiredScopes
```

**GSA Tenant Status Validation:**
```powershell
Write-LogMessage "Validating Global Secure Access tenant onboarding status..." -Level INFO -Component "Validation"
$tenantStatus = Get-IntGSATenantStatus
if ($tenantStatus.onboardingStatus -ne 'onboarded') {
    Write-LogMessage "Global Secure Access has not been activated on this tenant. Current onboarding status: $($tenantStatus.onboardingStatus). Please complete tenant onboarding before running this script." -Level ERROR -Component "Validation"
    throw "Tenant onboarding validation failed. Status: $($tenantStatus.onboardingStatus)"
}
Write-LogMessage "Global Secure Access tenant status validated: $($tenantStatus.onboardingStatus)" -Level SUCCESS -Component "Validation"
```

**Note:** These validation functions are internal functions that must be explicitly called within the function body. They are NOT automatically invoked by module initialization.

#### 4.2.2 Export Web Content Filtering Policies

**API Call:**
- Use existing internal function: `Get-IntFilteringPolicy -PolicyType webContentFiltering`
  - If this function doesn't support filtering by type, retrieve all and filter manually
- Retrieve all Web Content Filtering policies

**Data Extracted:**
- Policy ID (`id`)
- Policy Name (`name`)
- Policy Action (`action`) - lowercase: `allow` or `block`
- Policy Description (`description`)
- Created DateTime (`createdDateTime`)
- Modified DateTime (`lastModifiedDateTime`)

**For Each Policy, Retrieve Rules:**
- Use existing internal function: `Get-IntFilteringPolicyRule -PolicyId $policyId`
- Retrieve all rules for the policy

**Rule Data Extracted:**
- Rule ID (`id`)
- Rule Name (`name`)
- Rule Destination Type (`destinationType`): `fqdn`, `url`, `webCategory`, `ipAddress`
- Rule Destinations (`destinations`) - array of destination strings
  - Join with semicolon for CSV: `destination1;destination2`

**Build CSV Rows:**
- For each rule in each policy, create one CSV row:
  ```powershell
  [PSCustomObject]@{
      PolicyName = $policy.name
      PolicyType = "WebContentFiltering"
      PolicyAction = $policy.action.ToLower()  # ensure lowercase
      Description = $policy.description
      RuleType = $rule.destinationType
      RuleDestinations = ($rule.destinations -join ';')
      RuleName = $rule.name
      Provision = "no"
  }
  ```

**Error Handling:**
- If no policies found, create empty CSV with headers only
- If policy has no rules, log warning and skip policy
- If rule data is incomplete, log warning and skip rule
- Continue with remaining policies/rules on errors

#### 4.2.3 Export TLS Inspection Policies

**API Call:**
- Use existing internal function: `Get-IntFilteringPolicy -PolicyType forwardingPolicyLink`
  - Note: TLS Inspection policies may have a different policy type identifier in Graph API
  - Verify correct policy type identifier during implementation
- Alternative: `Get-IntFilteringPolicy` (retrieve all) and filter by policy type

**Data Extracted:**
- Policy ID (`id`)
- Policy Name (`name`)
- Default Action (`defaultAction`) - lowercase: `bypass` or `inspect`
- Policy Description (`description`)

**For Each Policy, Retrieve Rules:**
- Use existing internal function: `Get-IntFilteringPolicyRule -PolicyId $policyId`
- For TLS Inspection, rules specify override actions for specific destinations

**Rule Data Extracted:**
- Rule ID (`id`)
- Rule Name (`name`)
- Rule Action (`action`): `bypass` or `inspect` (overrides policy default)
- Rule Destination Type: `fqdn` or `webCategory` (TLS inspection doesn't support URL or ipAddress)
- Rule Destinations (`destinations`) - array of destination strings

**Build CSV Rows:**
- PolicyType: `TLSInspection`
- PolicyAction: Use policy's `defaultAction` (lowercase)
- RuleType: Use rule's `action` (`bypass` or `inspect`)
- For each rule in each policy, create one CSV row

**Error Handling:**
- Same as Web Content Filtering policies
- Handle different rule structure (action vs destination type)

#### 4.2.4 Write Policies CSV File

**Export:**
- Combine Web Content Filtering and TLS Inspection rows into single array
- Use `Export-Csv` cmdlet
- Parameters:
  - `-Path`: Full path to Policies CSV file
  - `-NoTypeInformation`: Exclude type info header
  - `-Encoding UTF8`: Standard encoding (with BOM for Excel compatibility)

**Validation:**
- Verify file created successfully
- Log file size and row count
- Display: "Exported X policies with Y total rules"

**Example Console Output:**
```
Exported 5 Web Content Filtering policies with 12 rules
Exported 2 TLS Inspection policies with 4 rules
Total: 7 policies with 16 rules
```

#### 4.2.5 Determine Security Profiles CSV Creation

**Decision Logic:**
```powershell
$shouldCreateSecurityProfilesCsv = $false
$securityProfiles = @()

# Check if security profiles exist
$securityProfiles = Get-IntSecurityProfile
if ($securityProfiles.Count -gt 0) {
    $shouldCreateSecurityProfilesCsv = $true
    Write-LogMessage "Found $($securityProfiles.Count) security profiles for export" -Level INFO -Component "SecurityProfiles"
}

# Override if -IncludeConditionalAccessPolicies is specified
if ($IncludeConditionalAccessPolicies) {
    $shouldCreateSecurityProfilesCsv = $true
    Write-LogMessage "Security Profiles CSV will be created (IncludeConditionalAccessPolicies specified)" -Level INFO -Component "SecurityProfiles"
}

if (-not $shouldCreateSecurityProfilesCsv) {
    Write-LogMessage "Security Profiles CSV will not be created (no profiles exist and IncludeConditionalAccessPolicies not specified)" -Level INFO -Component "SecurityProfiles"
}
```

#### 4.2.6 Export Security Profiles (Conditional)

**Only execute if:** `$shouldCreateSecurityProfilesCsv -eq $true`

**API Call:**
- Use existing internal function: `Get-IntSecurityProfile`
- Retrieve all filtering profiles (security profiles)

**Data Extracted:**
- Security Profile ID (`id`)
- Security Profile Name (`name`)
- Priority (`priority`)
- State (`state`) - Note: Not exported, but may be used for filtering
- Policy links (`policies`) - array of policy link objects

**For Each Security Profile, Process Policy Links:**

**Policy Links Structure:**
```json
"policies": [
  {
    "@odata.type": "#microsoft.graph.networkaccess.filteringPolicyLink",
    "id": "policy-link-id",
    "policyId": "policy-id-guid",
    "priority": 100
  },
  {
    "@odata.type": "#microsoft.graph.networkaccess.filteringPolicyLink",
    "id": "policy-link-id-2",
    "policyId": "policy-id-guid-2",
    "priority": 200
  }
]
```

**Resolve Policy IDs to Names:**
- For each policy link, extract `policyId`
- Look up policy name from previously retrieved policies:
  - Check WebContentFiltering policies cache
  - Check TLS Inspection policies cache
  - If not found, call `Get-IntFilteringPolicy -Id $policyId` to retrieve name
- Cache policy ID-to-name mappings for efficiency

**Build SecurityProfileLinks String:**
```powershell
$policyLinks = @()
foreach ($policyLink in $profile.policies) {
    $policyName = Get-PolicyNameById -PolicyId $policyLink.policyId
    if ($policyName) {
        $policyLinks += "$($policyName):$($policyLink.priority)"
    } else {
        Write-LogMessage "Failed to resolve policy ID $($policyLink.policyId) for profile '$($profile.name)'" -Level WARN -Component "SecurityProfiles"
    }
}
$securityProfileLinksString = $policyLinks -join ';'
```

**If SecurityProfileLinks is Empty:**
- Log warning: "Security Profile '$profileName' has no valid policy links"
- Skip this security profile (do not export)
- Continue with next profile

#### 4.2.7 Export Conditional Access Policies (If Requested)

**Only execute if:** `-IncludeConditionalAccessPolicies` switch is specified

**For Each Security Profile:**

**Step 1: Find Linked CA Policy**
- CA policies link to security profiles via `sessionControls.cloudAppSecurity.sessionControlProfileId`
- Query all CA policies: `GET /identity/conditionalAccess/policies`
- Filter where `sessionControls.cloudAppSecurity.sessionControlProfileId` equals security profile ID
- If multiple CA policies link to same security profile, log warning and use first one found

**Graph API Query:**
```powershell
# Retrieve all CA policies
$allCaPolicies = Invoke-InternalGraphRequest -Uri "/beta/identity/conditionalAccess/policies"

# Find CA policy linked to this security profile
$linkedCaPolicy = $allCaPolicies | Where-Object {
    $_.sessionControls.cloudAppSecurity.sessionControlProfileId -eq $profile.id
} | Select-Object -First 1
```

**Step 2: Extract CA Policy Information**
- If no linked CA policy found:
  - Leave `CADisplayName`, `EntraUsers`, `EntraGroups` empty
  - Log info: "Security Profile '$profileName' has no linked CA policy"
  - Continue with next profile

- If linked CA policy found:
  - Extract `displayName` → `CADisplayName`
  - Extract user assignments from `conditions.users.includeUsers`
  - Extract group assignments from `conditions.users.includeGroups`

**Step 3: Resolve User IDs to UPNs**
```powershell
$userUpns = @()
if ($linkedCaPolicy.conditions.users.includeUsers -and $linkedCaPolicy.conditions.users.includeUsers -ne 'None' -and $linkedCaPolicy.conditions.users.includeUsers -ne 'All') {
    foreach ($userId in $linkedCaPolicy.conditions.users.includeUsers) {
        # Skip special values
        if ($userId -in @('All', 'None', 'GuestsOrExternalUsers')) { continue }
        
        # Resolve user ID to UPN
        $user = Get-IntUser -Id $userId
        if ($user -and $user.userPrincipalName) {
            $userUpns += $user.userPrincipalName
        } else {
            Write-LogMessage "Failed to resolve user ID $userId for CA policy '$($linkedCaPolicy.displayName)'" -Level WARN -Component "ConditionalAccess"
        }
    }
}
$entraUsersString = $userUpns -join ';'
```

**Step 4: Resolve Group IDs to Display Names**
```powershell
$groupNames = @()
if ($linkedCaPolicy.conditions.users.includeGroups -and $linkedCaPolicy.conditions.users.includeGroups -ne 'None') {
    foreach ($groupId in $linkedCaPolicy.conditions.users.includeGroups) {
        # Skip special values
        if ($groupId -in @('None')) { continue }
        
        # Resolve group ID to display name
        $group = Get-IntGroup -Id $groupId
        if ($group -and $group.displayName) {
            $groupNames += $group.displayName
        } else {
            Write-LogMessage "Failed to resolve group ID $groupId for CA policy '$($linkedCaPolicy.displayName)'" -Level WARN -Component "ConditionalAccess"
        }
    }
}
$entraGroupsString = $groupNames -join ';'
```

**Caching Strategy:**
- Cache user ID-to-UPN mappings: `$script:UserCache = @{}`
- Cache group ID-to-name mappings: `$script:GroupCache = @{}`
- Reduces redundant Graph API calls across profiles

**Error Handling:**
- If user/group cannot be resolved (deleted), log warning and skip it
- Continue with remaining users/groups
- If all users/groups fail to resolve, leave field empty

#### 4.2.8 Build Security Profiles CSV Rows

```powershell
$securityProfileRows = @()

foreach ($profile in $securityProfiles) {
    # Build policy links string
    $securityProfileLinksString = Build-SecurityProfileLinksString -Profile $profile
    
    # Skip if no valid policy links
    if ([string]::IsNullOrWhiteSpace($securityProfileLinksString)) {
        Write-LogMessage "Skipping security profile '$($profile.name)' - no valid policy links" -Level WARN -Component "SecurityProfiles"
        continue
    }
    
    # Initialize CA fields
    $caDisplayName = ""
    $entraUsers = ""
    $entraGroups = ""
    
    # Populate CA fields if requested
    if ($IncludeConditionalAccessPolicies) {
        $caInfo = Get-LinkedCAPolicy -SecurityProfileId $profile.id
        if ($caInfo) {
            $caDisplayName = $caInfo.DisplayName
            $entraUsers = $caInfo.EntraUsers
            $entraGroups = $caInfo.EntraGroups
        }
    }
    
    # Create CSV row
    $securityProfileRows += [PSCustomObject]@{
        SecurityProfileName = $profile.name
        Priority = $profile.priority
        SecurityProfileLinks = $securityProfileLinksString
        CADisplayName = $caDisplayName
        EntraUsers = $entraUsers
        EntraGroups = $entraGroups
        Provision = "no"
    }
}
```

#### 4.2.9 Write Security Profiles CSV File

**Export:**
- Use `Export-Csv` cmdlet
- Parameters:
  - `-Path`: Full path to Security Profiles CSV file
  - `-NoTypeInformation`: Exclude type info header
  - `-Encoding UTF8`: Standard encoding (with BOM for Excel compatibility)

**Validation:**
- Verify file created successfully
- Log file size and row count
- Display: "Exported X security profiles"

**Example Console Output:**
```
Exported 4 security profiles with policy links
Exported 3 linked Conditional Access policies
```

---

## 5. Error Handling and Logging

### 5.1 Error Handling Strategy

**Continue on Errors:**
- Log errors but continue exporting remaining items
- Leave fields empty if data cannot be retrieved
- Do not throw terminating errors for individual policy/profile failures

**Terminating Errors:**
- Graph authentication failure
- No write permissions to output folder
- CSV export failure (disk full, permissions)
- Tenant not onboarded to GSA

### 5.2 Logging Requirements

**Use Internal Function:**
- `Write-LogMessage` (existing internal function)

**Log Levels:**
- `INFO`: Normal operations (policy/profile counts, progress)
- `WARN`: Missing data, unresolved references
- `ERROR`: Failed operations, API errors
- `SUCCESS`: Completed operations
- `SUMMARY`: Final statistics

**Log Content:**
- Timestamp for each entry
- Function start/end
- Policy and profile counts
- Warnings for missing data (policy links, CA policies, users, groups)
- API errors with details
- Export summary statistics

### 5.3 Console Output

**Progress Information:**
- Use `Write-Verbose` for detailed progress
- Use standard output for summary information
- Display completion message with folder location

**Example Completion Message:**
```
Export completed successfully!

Backup folder: C:\Backups\GSA-backup_20260212_143022\

Entra Internet Access (EIA):
  Exported: 5 Web Content Filtering Policies (12 rules)
  Exported: 2 TLS Inspection Policies (4 rules)
  Exported: 4 Security Profiles with policy links
  Exported: 3 linked Conditional Access policies
  Warnings: 2 (see log file for details)
  
Files created in InternetAccess\:
  - 20260212_143022_EIA_Policies.csv (8 KB)
  - 20260212_143022_EIA_SecurityProfiles.csv (3 KB)
  - 20260212_143022_Export-EIA.log (12 KB)

Total duration: 6.4 seconds
```

---

## 6. Usage Examples

### 6.1 Basic Export (Policies Only)
```powershell
Export-EntraInternetAccessConfig
```
Creates:
- `.\GSA-backup_20260212_143022\InternetAccess\20260212_143022_EIA_Policies.csv`
- Security Profiles CSV only if profiles exist
- Log file

### 6.2 Export with Conditional Access Policies
```powershell
Export-EntraInternetAccessConfig -IncludeConditionalAccessPolicies
```
Creates:
- Policies CSV (always)
- Security Profiles CSV with CA policy assignments (created even if no profiles exist)
- Log file

### 6.3 Export to Custom Location
```powershell
Export-EntraInternetAccessConfig -OutputPath "C:\GSA-Backups" -IncludeConditionalAccessPolicies
```
Creates output in: `C:\GSA-Backups\GSA-backup_20260212_143022\InternetAccess\`

### 6.4 Export with Custom Log Path
```powershell
Export-EntraInternetAccessConfig -OutputPath "C:\Backups" -LogPath "C:\Logs\EIA-Export.log" -IncludeConditionalAccessPolicies
```
Custom log location outside the backup folder.

### 6.5 Export with Verbose Output
```powershell
Export-EntraInternetAccessConfig -IncludeConditionalAccessPolicies -Verbose
```
Displays detailed progress information during export.

---

## 7. Restore Process

### 7.1 Using Exported CSVs with Provisioning Function

**Before Provisioning:**
1. Review both CSV files
2. Update `Provision` column: Change `no` to `yes` for records to provision
3. Optionally modify policy rules, security profiles, or assignments
4. Ensure all referenced policies exist before creating security profiles

**Provision Command:**
```powershell
# Provision policies and security profiles
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath "C:\Backups\GSA-backup_20260212_143022\InternetAccess\20260212_143022_EIA_Policies.csv" `
    -SecurityProfilesCsvPath "C:\Backups\GSA-backup_20260212_143022\InternetAccess\20260212_143022_EIA_SecurityProfiles.csv"

# Provision policies only (no security profiles or CA policies)
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath "C:\Backups\GSA-backup_20260212_143022\InternetAccess\20260212_143022_EIA_Policies.csv"
```

### 7.2 Selective Restore

**Restore Specific Policies:**
1. Edit Policies CSV
2. Set `Provision=yes` for desired policies
3. Keep `Provision=no` for policies to skip
4. Run provisioning function with Policies CSV only

**Restore Security Profiles Without CA Policies:**
1. Edit Security Profiles CSV
2. Clear `CADisplayName`, `EntraUsers`, `EntraGroups` columns
3. Set `Provision=yes` for desired profiles
4. Run provisioning function with `-SkipCAPoliciesProvisioning`

**Restore to Different Tenant:**
1. Export from source tenant
2. Review and modify CSV files as needed
3. Ensure users/groups exist in target tenant (or update assignments)
4. Run provisioning function in target tenant

---

## 8. Implementation Considerations

### 8.1 Performance Optimization

**Caching:**
- Cache policy ID-to-name mappings: `$script:PolicyCache = @{}`
- Cache user ID-to-UPN mappings: `$script:UserCache = @{}`
- Cache group ID-to-name mappings: `$script:GroupCache = @{}`
- Reduces redundant Graph API calls

**Batch Operations:**
- Process policies sequentially (no parallel processing for initial implementation)
- Batch Graph requests where possible (using `$batch` endpoint)
- Future enhancement: Parallel processing for large tenants

**Rate Limiting:**
- Use `Invoke-InternalGraphRequest` which handles throttling automatically
- Implements exponential backoff with jitter
- Respects Retry-After headers

### 8.2 Testing Strategy

**Unit Tests:**
- Parameter validation
- CSV formatting
- Timestamp generation
- Error handling for missing data
- SecurityProfileLinks string building

**Integration Tests:**
- Export from test tenant with known configuration
- Verify CSV format matches provisioning expectations
- Round-trip test: Export → Provision → Export → Compare
- Test with and without `-IncludeConditionalAccessPolicies`

**Edge Cases:**
- Tenant with no policies (empty CSV with headers)
- Tenant with no security profiles
- Policies with no rules (should skip)
- Security profiles with no policy links (should skip)
- Security profiles with CA policies that have "All users" assignment
- CA policies with deleted users/groups in assignments
- Special characters in policy/profile names
- Large tenants (50+ policies, 20+ security profiles)
- Policies referenced by security profiles that no longer exist

### 8.3 Dependencies

**Required Internal Functions (Existing):**
- `Get-IntFilteringPolicy` - Retrieve filtering policies
- `Get-IntFilteringPolicyRule` - Retrieve policy rules
- `Get-IntSecurityProfile` - Retrieve security profiles
- `Get-IntGroup` - Resolve group ID to display name
- `Get-IntUser` - Resolve user ID to UPN
- `Get-IntGSATenantStatus` - Validate GSA tenant onboarding
- `Write-LogMessage` - Unified logging
- `Invoke-InternalGraphRequest` - Graph API wrapper with error handling
- `Test-RequiredModules` - Validate PowerShell modules
- `Test-GraphConnection` - Validate Graph authentication and scopes

**Required Internal Functions (Status Unknown - May Need Creation):**
- `Get-IntFilteringPolicy` - Verify supports filtering by policy type (webContentFiltering vs TLS inspection)
- `Get-IntFilteringPolicyRule` - Verify returns all rule properties needed
- Conditional Access functions may need to be added if not already present

**PowerShell Modules:**
- `Microsoft.Graph.Authentication` (for Graph session)

---

## 9. Success Criteria

### 9.1 Functional Requirements
- ✅ Validate required modules (Microsoft.Graph.Authentication)
- ✅ Validate Graph connection with required scopes (NetworkAccessPolicy.Read.All + conditionally Policy.Read.All, User.Read.All, Directory.Read.All)
- ✅ Validate GSA tenant onboarding status before export
- ✅ Export all Web Content Filtering policies and rules
- ✅ Export all TLS Inspection policies and rules
- ✅ Generate Policies CSV matching `Start-EntraInternetAccessProvisioning` input format
- ✅ Conditionally export Security Profiles (based on existence and/or parameter)
- ✅ Export policy links with correct PolicyName:Priority format
- ✅ Conditionally export Conditional Access policy assignments (when `-IncludeConditionalAccessPolicies` specified)
- ✅ Resolve user IDs to UPNs and group IDs to display names
- ✅ Create timestamped backup folder structure
- ✅ Generate comprehensive log file
- ✅ Handle errors gracefully with clear messages
- ✅ Continue export when individual policies/profiles fail

### 9.2 Quality Requirements
- ✅ Exported CSVs can be directly used with provisioning function
- ✅ Round-trip success: Export → Provision → Verify (in test tenant)
- ✅ No data loss during export
- ✅ Proper CSV escaping for special characters
- ✅ Performance: Export completes in reasonable time (< 60 seconds for typical tenant)
- ✅ Clear error messages for missing permissions or API failures
- ✅ Policy metadata consistency across rows for same policy

### 9.3 Documentation Requirements
- ✅ Complete function documentation (comment-based help)
- ✅ Parameter descriptions with examples
- ✅ CSV format documentation
- ✅ Restore process examples
- ✅ Error handling guide

---

## 10. Internal Functions Assessment

### 10.1 Validation Functions (Must Be Explicitly Called)

**Important:** These internal functions exist but are NOT automatically invoked. They must be explicitly called within the function body.

| Function | Location | Purpose | Usage Pattern |
|----------|----------|---------|---------------|
| `Test-RequiredModules` | `internal/functions/` | Validates required modules are installed | Called at function start with module array |
| `Test-GraphConnection` | `internal/functions/` | Validates Graph authentication and scopes | Called after module validation with scope array |
| `Get-IntGSATenantStatus` | `internal/functions/` | Gets GSA tenant onboarding status | Called to verify tenant is onboarded |
| `Write-LogMessage` | `internal/functions/` | Unified logging function | Used throughout for all logging |

**Example Usage Pattern:**
```powershell
# Inside the function body (after parameter setup):
$requiredModules = @('Microsoft.Graph.Authentication')
Test-RequiredModules -RequiredModules $requiredModules

$requiredScopes = @('NetworkAccessPolicy.Read.All')
if ($IncludeConditionalAccessPolicies) {
    $requiredScopes += 'Policy.Read.All'
    $requiredScopes += 'User.Read.All'
    $requiredScopes += 'Directory.Read.All'
}
Test-GraphConnection -RequiredScopes $requiredScopes

Write-LogMessage "Validating Global Secure Access tenant onboarding status..." -Level INFO -Component "Validation"
$tenantStatus = Get-IntGSATenantStatus
if ($tenantStatus.onboardingStatus -ne 'onboarded') {
    throw "Tenant not onboarded"
}
```

### 10.2 Data Retrieval Functions

**Status: Verify Functionality**

| Function | Location | Expected Functionality | Verification Needed |
|----------|----------|------------------------|---------------------|
| `Get-IntFilteringPolicy` | `internal/functions/EIA/` | Retrieve filtering policies (web content filtering + TLS inspection) | Verify supports filtering by policy type or returns all |
| `Get-IntFilteringPolicyRule` | `internal/functions/EIA/` | Retrieve rules for a policy | Verify returns all rule properties (name, destinationType, destinations) |
| `Get-IntSecurityProfile` | `internal/functions/EIA/` | Retrieve security profiles | Verify returns policy links with priorities |
| `Get-IntGroup` | `internal/functions/` | Resolve group ID to display name | Already verified in EPA export |
| `Get-IntUser` | `internal/functions/` | Resolve user ID to UPN | Already verified in EPA export |

**Testing Required:**
```powershell
# Test policy retrieval
$allPolicies = Get-IntFilteringPolicy
$webPolicies = Get-IntFilteringPolicy -PolicyType webContentFiltering  # If supported
$tlsPolicies = Get-IntFilteringPolicy -PolicyType forwardingPolicyLink  # TLS inspection type

# Test rule retrieval
$rules = Get-IntFilteringPolicyRule -PolicyId "policy-guid"
# Verify $rules contains: id, name, destinationType, destinations

# Test security profile retrieval
$profiles = Get-IntSecurityProfile
# Verify $profiles contains: id, name, priority, policies (array with policyId and priority)
```

### 10.3 Functions That May Need Enhancement

#### Get-IntFilteringPolicy
**Current Status:** Assumed to exist  
**Possible Enhancement Needed:** Verify it supports:
- Retrieving all filtering policies (both web content filtering and TLS inspection)
- Filtering by policy type (optional parameter)
- Returning policy action (`action` or `defaultAction`)
- Returning policy description

**If enhancement needed:**
- Add parameter for filtering by policy type
- Ensure consistent property names for action (may differ between policy types)

#### Get-IntFilteringPolicyRule
**Current Status:** Assumed to exist  
**Possible Enhancement Needed:** Verify it supports:
- Retrieving all rules for a given policy ID
- Returning rule properties: id, name, destinationType, destinations (array)
- Supporting both web content filtering rules and TLS inspection rules

**If enhancement needed:**
- Ensure it works with both policy types
- Confirm destinations is returned as array (not string)

### 10.4 New Internal Functions Required

**Status:** Likely none needed for core export functionality

**Conditional Access Retrieval:**
- Use `Invoke-InternalGraphRequest` directly for CA policy queries
- No dedicated internal function needed (used infrequently)
- Query: `GET /beta/identity/conditionalAccess/policies`

**Alternative:** If CA policy export becomes common across multiple functions, consider creating:
- `Get-IntConditionalAccessPolicy` - Retrieve CA policies with optional filtering

---

## 11. Implementation Phases

### Phase 1: Scaffolding and Validation (Priority: High)
1. Implement parameter validation (OutputPath, IncludeConditionalAccessPolicies)
2. Generate timestamp
3. Create output folder structure
4. Initialize logging ($script:LogPath setup)
5. Call `Test-RequiredModules` with 'Microsoft.Graph.Authentication'
6. Call `Test-GraphConnection` with required scopes (conditional based on parameters)
7. Call `Get-IntGSATenantStatus` and validate onboarding

### Phase 2: Policies Export (Priority: High)
1. Retrieve Web Content Filtering policies using `Get-IntFilteringPolicy`
2. For each policy, retrieve rules using `Get-IntFilteringPolicyRule`
3. Build Policies CSV rows (one row per rule)
4. Retrieve TLS Inspection policies (verify correct policy type identifier)
5. For each TLS policy, retrieve rules
6. Build TLS Policies CSV rows
7. Combine and export to Policies CSV file

### Phase 3: Security Profiles Export (Priority: Medium)
1. Implement Security Profiles CSV creation logic (conditional)
2. Retrieve security profiles using `Get-IntSecurityProfile`
3. For each profile, extract policy links
4. Resolve policy IDs to names (build cache)
5. Build SecurityProfileLinks strings (PolicyName:Priority format)
6. Export to Security Profiles CSV (without CA info)

### Phase 4: Conditional Access Export (Priority: Medium)
1. Add CA policies retrieval logic (when `-IncludeConditionalAccessPolicies` specified)
2. For each security profile, find linked CA policy
3. Extract CA policy display name and conditions
4. Resolve user IDs to UPNs with caching
5. Resolve group IDs to display names with caching
6. Populate CA columns in Security Profiles CSV

### Phase 5: Error Handling and Polish (Priority: Low)
1. Implement comprehensive error handling for each phase
2. Add logging for all operations
3. Create summary report
4. Handle edge cases (empty tenants, missing data, deleted references)
5. Add progress indicators (Write-Verbose)

### Phase 6: Testing and Documentation (Priority: Low)
1. Unit tests for core functions
2. Integration tests with test tenant
3. Round-trip testing (export → provision)
4. Comment-based help
5. Update module documentation
6. Performance testing with large tenants

---

## 12. Open Questions and Decisions

### 12.1 Resolved

✅ **Export Scope:** Export all policies and security profiles (no filtering)  
✅ **Provision Default:** Set to `no` by default (allows manual review)  
✅ **CA Policy Export:** Only export CA policies linked to GSA security profiles  
✅ **Error Handling:** Continue on errors, leave fields empty  
✅ **Security Profiles CSV Creation:** Conditional (based on existence and/or parameter)  
✅ **SecurityProfileLinks Format:** `PolicyName:Priority` pairs, semicolon-separated  
✅ **WhatIf Support:** Not needed for export (read-only operation)  
✅ **Function Name:** Export-EntraInternetAccessConfig  
✅ **Output Structure:** Match existing export pattern (GSA-backup folder with subfolders)  
✅ **Module Validation:** Call Test-RequiredModules explicitly  
✅ **Graph Connection:** Call Test-GraphConnection with conditional scopes  
✅ **Tenant Validation:** Call Get-IntGSATenantStatus and verify onboarding  
✅ **Spec Date:** 20260212

### 12.2 Pending Verification

⚠️ **Policy Type Identifiers:**
- Verify correct policy type for TLS Inspection policies in Graph API
- May be `forwardingPolicyLink` or similar
- Test with `Get-IntFilteringPolicy` to confirm

⚠️ **Rule Structure Differences:**
- Verify rule property differences between Web Content Filtering and TLS Inspection
- TLS rules may have `action` property instead of `destinationType`
- Confirm destinations array format is consistent

⚠️ **Security Profile Policy Links:**
- Verify policy links structure in security profile object
- Confirm priority is included in policy link object
- Test retrieval and parsing

⚠️ **CA Policy Session Controls:**
- Verify correct property path for security profile link in CA policy
- Expected: `sessionControls.cloudAppSecurity.sessionControlProfileId`
- May vary based on Graph API version

⚠️ **Special CA Assignment Values:**
- Confirm handling of special values: 'All', 'None', 'GuestsOrExternalUsers'
- Determine if these should be exported or skipped

---

## 13. Appendix

### 13.1 Graph API Endpoints Reference

**Filtering Policies (Web Content Filtering):**
```
GET /beta/networkAccess/filteringProfiles/{id}/policies
GET /beta/networkAccess/forwardingPolicies (may be alternative endpoint)
```

**TLS Inspection Policies:**
```
GET /beta/networkAccess/forwardingProfiles/{id}/policies
Verify correct endpoint during implementation
```

**Policy Rules:**
```
GET /beta/networkAccess/filteringPolicies/{policyId}/policyRules
```

**Security Profiles (Filtering Profiles):**
```
GET /beta/networkAccess/filteringProfiles
GET /beta/networkAccess/filteringProfiles/{id}
```

**Conditional Access Policies:**
```
GET /beta/identity/conditionalAccess/policies
GET /beta/identity/conditionalAccess/policies/{id}
```

**User Resolution:**
```
GET /beta/users/{userId}
```

**Group Resolution:**
```
GET /beta/groups/{groupId}
```

**GSA Tenant Status:**
```
GET /beta/networkAccess/settings
```

### 13.2 Sample Policies CSV Output

**Scenario:** 2 Web Content Filtering policies and 1 TLS Inspection policy

```csv
PolicyName,PolicyType,PolicyAction,Description,RuleType,RuleDestinations,RuleName,Provision
Dev_Tools-Allow,WebContentFiltering,allow,Development tools,fqdn,github.com;*.github.io;stackoverflow.com,GitHub_StackOverflow,no
Dev_Tools-Allow,WebContentFiltering,allow,Development tools,url,https://docs.microsoft.com/*;https://learn.microsoft.com/*,Microsoft_Docs,no
Dev_Tools-Allow,WebContentFiltering,allow,Development tools,webCategory,DeveloperTools;Programming,Dev_Categories,no
Social_Media-Block,WebContentFiltering,block,Block social media sites,webCategory,SocialNetworking;Entertainment,Social_Categories,no
Social_Media-Block,WebContentFiltering,block,Block social media sites,fqdn,facebook.com;twitter.com;instagram.com,Social_Sites,no
TLS_Finance-Inspect,TLSInspection,inspect,Inspect financial traffic (default),bypass,*.internal-bank.com;secure-finance.contoso.com,Finance_Bypass,no
TLS_Finance-Inspect,TLSInspection,inspect,Inspect financial traffic (default),inspect,*.financial-services.com,Finance_Inspect,no
```

### 13.3 Sample Security Profiles CSV Output

**Scenario:** 3 security profiles, 2 with CA policies

**With CA Policies (IncludeConditionalAccessPolicies specified):**
```csv
SecurityProfileName,Priority,SecurityProfileLinks,CADisplayName,EntraUsers,EntraGroups,Provision
Profile_Finance_Strict,100,Dev_Tools-Allow:100;TLS_Finance-Inspect:200,CA_Finance_Access,john.doe@contoso.com;jane.smith@contoso.com,Finance_Group;Executives_Group,no
Profile_Dev_Tools,200,Dev_Tools-Allow:150,CA_Dev_Access,dev.team@contoso.com,Developers_Group,no
Profile_Marketing_NoCA,300,Social_Media-Block:50,,,,no
```

**Without CA Policies (IncludeConditionalAccessPolicies NOT specified):**
```csv
SecurityProfileName,Priority,SecurityProfileLinks,CADisplayName,EntraUsers,EntraGroups,Provision
Profile_Finance_Strict,100,Dev_Tools-Allow:100;TLS_Finance-Inspect:200,,,,no
Profile_Dev_Tools,200,Dev_Tools-Allow:150,,,,no
Profile_Marketing_NoCA,300,Social_Media-Block:50,,,,no
```

---

## References

- [Start-EntraInternetAccessProvisioning Function Specification](../Provision/20251016-Start-EntraInternetAccessProvisioning.md)
- [Export-EntraGlobalSecureAccessConfig Specification](./20260107-Export-EntraGlobalSecureAccessConfig.md)
- [Export-EntraPrivateAccessConfig Specification](./20260203-Export-EntraPrivateAccessConfig.md)
- [Microsoft Graph API - Network Access Filtering Policies](https://learn.microsoft.com/en-us/graph/api/resources/networkaccess-filteringpolicy)
- [Microsoft Graph API - Conditional Access Policies](https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesspolicy)
- [Microsoft Graph API - Global Secure Access](https://learn.microsoft.com/en-us/graph/api/resources/networkaccess-overview)
