---
sidebar_position: 2
title: Entra Internet Access (EIA) Automated Provisioning
---


## Overview

The `Start-EntraInternetAccessProvisioning` function provisions Microsoft Entra Internet Access filtering policies, security profiles, and Conditional Access policies from CSV configuration files into a target Entra tenant.

This function automates the deployment of:
- **Web Content Filtering Policies** and their rules (FQDN, URL, webCategory)
- **TLS Inspection Policies** and their rules (bypass, inspect)
- **Security Profiles** with policy links
- **Conditional Access Policies** with user/group assignments

All created objects are automatically suffixed with `[Migrate2GSA]` for easy identification.

## Features

### ✅ Comprehensive Provisioning
- Web content filtering policies (allow/block actions)
- TLS inspection policies (bypass/inspect default actions)
- Security profiles linking multiple policies with priorities
- Conditional Access policies enforcing security profiles

### ✅ Idempotent & Safe
- **Reuse existing objects**: Detects and reuses existing policies, security profiles
- **Add missing rules only**: When policy exists, adds only new rules
- **Name conflict detection**: Prevents duplicate objects
- **Priority conflict detection**: Validates security profile and policy link priorities
- **WhatIf mode**: Preview all operations before execution
- **Always disabled CA policies**: CA policies created in disabled state for admin validation

### ✅ Robust Validation
- CSV structural validation (required columns, data types)
- Policy metadata consistency validation
- User and group existence validation (stops if missing)
- Security profile priority conflict detection (CSV-to-CSV, CSV-to-Tenant)
- Policy link priority conflict detection (within profiles)
- Dependencies validation (policy references, user/group assignments)

### ✅ Flexible Filtering
- **Policy name filter**: Provision single policy for testing (`-PolicyName`)
- **Skip CA policies**: Create security profiles without CA policies (`-SkipCAPoliciesProvisioning`)
- **Provision field filtering**: Control provisioning per-row in CSV (`Provision=yes/no`)

### ✅ Comprehensive Logging & Reporting
- Color-coded console output with log levels (INFO, SUCCESS, WARN, ERROR)
- Timestamped log files for audit trail
- Component-based logging for categorization
- Results CSV export with updated Provision field for re-runs
- Summary statistics at completion

## Prerequisites

### Required PowerShell Modules
- **Microsoft.Graph.Authentication** (v2.0.0 or later)

Install using:
```powershell
Install-Module -Name Microsoft.Graph.Authentication -MinimumVersion 2.0.0 -Scope CurrentUser
```

### Required Microsoft Graph Permissions

**Always Required:**
- `NetworkAccess.ReadWrite.All` - For creating/updating GSA configurations

**Required if Provisioning CA Policies:**
- `Policy.ReadWrite.ConditionalAccess` - For creating CA policies
- `User.Read.All` - For resolving user assignments
- `Group.Read.All` - For resolving group assignments

### Tenant Prerequisites
- **Global Secure Access Onboarded**: Tenant must have completed GSA onboarding
- **Authentication**: User must connect via `Connect-MgGraph` or `Connect-Entra` before running script

Example authentication:
```powershell
# Connect with required scopes
Connect-MgGraph -Scopes "NetworkAccess.ReadWrite.All", "Policy.ReadWrite.ConditionalAccess", "User.Read.All", "Group.Read.All"
```

## CSV File Formats

### Policies CSV (REQUIRED)

Contains web content filtering policies, TLS inspection policies, and their rules.

**Structure:** Every row is a **rule** with policy metadata repeated.

**Required Columns:**
- `PolicyName` - Name of the policy (required on all rows)
- `PolicyType` - Type: `WebContentFiltering` or `TLSInspection`
- `PolicyAction` - For WebContentFiltering: `Allow` or `Block` | For TLSInspection: `Bypass` or `Inspect` (default action)
- `Description` - Policy description (optional, should be consistent across rows for same policy)
- `RuleType` - For WebContentFiltering: `FQDN`, `URL`, `webCategory` | For TLSInspection: `bypass`, `inspect`
- `RuleDestinations` - Semicolon-separated destinations (FQDNs, URLs, or category names)
- `RuleName` - Name of the rule
- `Provision` - Whether to provision: `yes` or `no`

**Example:**
```csv
PolicyName,PolicyType,PolicyAction,Description,RuleType,RuleDestinations,RuleName,Provision
Dev_Tools-Allow,WebContentFiltering,Allow,Development tools,FQDN,github.com;*.github.io;stackoverflow.com,GitHub_StackOverflow,yes
Dev_Tools-Allow,WebContentFiltering,Allow,Development tools,URL,https://docs.microsoft.com/*;https://learn.microsoft.com/*,Microsoft_Docs,yes
Dev_Tools-Allow,WebContentFiltering,Allow,Development tools,webCategory,DeveloperTools;Programming,Dev_Categories,yes
Social_Media-Block,WebContentFiltering,Block,Block social media sites,webCategory,SocialNetworking;Entertainment,Social_Categories,yes
TLS_Finance-Inspect,TLSInspection,Inspect,Inspect financial traffic,bypass,*.internal-bank.com;secure-finance.contoso.com,Finance_Bypass,yes
TLS_Finance-Inspect,TLSInspection,Inspect,Inspect financial traffic,inspect,*.financial-services.com,Finance_Inspect,yes
```

### Security Profiles CSV (OPTIONAL)

Contains security profiles with policy links and Conditional Access policies.

**Structure:** One row per **Security Profile** (1:1 with CA policy).

**Required Columns:**
- `SecurityProfileName` - Name of the security profile
- `Priority` - Profile processing priority (integer)
- `SecurityProfileLinks` - Semicolon-separated `PolicyName:Priority` pairs
- `CADisplayName` - CA policy name (required if users/groups specified)
- `EntraUsers` - Semicolon-separated user principal names (optional)
- `EntraGroups` - Semicolon-separated group display names (optional)
- `Provision` - Whether to provision: `yes` or `no`

**Example:**
```csv
SecurityProfileName,Priority,SecurityProfileLinks,CADisplayName,EntraUsers,EntraGroups,Provision
Profile_Finance_Strict,100,Policy_Web_Finance:100;Policy_TLS_Finance:200,CA_Finance_Access,john.doe@contoso.com;jane.smith@contoso.com,Finance_Group;Executives_Group,yes
Profile_Marketing_Standard,200,Policy_Web_Marketing:150,CA_Marketing_Access,marketing.team@contoso.com,Marketing_Group,yes
Profile_IT_NoCA,300,Policy_Web_Admin:50;Policy_TLS_Admin:75,,,,yes
```

**Notes:**
- Row 3 example: Empty `CADisplayName`, users, and groups → Security Profile created, CA policy skipped
- If both `EntraUsers` and `EntraGroups` are empty, CA policy is NOT created
- Policy links reference policies from the Policies CSV by `PolicyName`

## Usage Examples

### Example 1: Full Provisioning with WhatIf
```powershell
# Preview what will be provisioned
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath ".\policies.csv" `
    -SecurityProfilesCsvPath ".\security_profiles.csv" `
    -WhatIf
```

### Example 2: Full Provisioning (Policies + Security Profiles + CA Policies)
```powershell
# Provision all components
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath ".\policies.csv" `
    -SecurityProfilesCsvPath ".\security_profiles.csv"
```

### Example 3: Provision Only Policies (No Security Profiles)
```powershell
# Provision only web content filtering and TLS inspection policies
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath ".\policies.csv"
```

### Example 4: Test Single Policy
```powershell
# Provision only one specific policy (for testing)
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath ".\policies.csv" `
    -PolicyName "Finance_WebFilter"
```

### Example 5: Provision Without CA Policies
```powershell
# Create security profiles with policy links, but skip CA policy creation
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath ".\policies.csv" `
    -SecurityProfilesCsvPath ".\security_profiles.csv" `
    -SkipCAPoliciesProvisioning
```

### Example 6: Automated Execution (No Prompts)
```powershell
# Run without confirmation prompts (for automation)
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath ".\policies.csv" `
    -SecurityProfilesCsvPath ".\security_profiles.csv" `
    -Force
```

### Example 7: Custom Log Path
```powershell
# Specify custom log file path
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath ".\policies.csv" `
    -SecurityProfilesCsvPath ".\security_profiles.csv" `
    -LogPath "C:\Logs\EIA_Provisioning.log"
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `PoliciesCsvPath` | String | Yes | Path to CSV file containing policies and rules |
| `SecurityProfilesCsvPath` | String | No | Path to CSV file containing security profiles and CA policies |
| `PolicyName` | String | No | Filter to provision only this specific policy name (mutually exclusive with `SecurityProfilesCsvPath`) |
| `SkipCAPoliciesProvisioning` | Switch | No | Skip creation of ALL CA policies (security profiles still created) |
| `LogPath` | String | No | Custom log file path (default: timestamped in current directory) |
| `Force` | Switch | No | Skip confirmation prompts for automated execution |
| `WhatIf` | Switch | No | Preview operations without making changes |

## Provisioning Order

The function provisions objects in dependency order:

1. **Web Content Filtering Policies** (and their rules)
2. **TLS Inspection Policies** (and their rules)
3. **Security Profiles** (linking to policies created in steps 1-2)
4. **Conditional Access Policies** (linking to security profiles, created in DISABLED state)

## Naming Convention

All created objects are automatically suffixed with `[Migrate2GSA]`:
- **Policies:** `PolicyName[Migrate2GSA]` (e.g., `Finance_WebFilter[Migrate2GSA]`)
- **Security Profiles:** `SecurityProfileName[Migrate2GSA]` (e.g., `Finance_Profile[Migrate2GSA]`)
- **CA Policies:** `CADisplayName[Migrate2GSA]` (e.g., `Finance_Access[Migrate2GSA]`)

**CSV Handling:**
- **Input CSV:** Contains original names without suffix
- **Output CSV:** Maintains original names without suffix
- **Internal Processing:** Automatically appends suffix for creation and conflict detection

## Idempotent Behavior

The script is fully idempotent - running multiple times with the same CSV produces the same final state.

### Policy Re-Use
- Checks for existing policy with name `PolicyName[Migrate2GSA]`
- If exists: Reuses policy, adds only missing rules
- If not exists: Creates new policy with all rules

### Security Profile Re-Use
- Checks for existing profile with name `SecurityProfileName[Migrate2GSA]`
- If exists: Reuses profile, adds only missing policy links (if not linked to CA policy)
- If linked to CA policy: Skips policy link addition entirely
- If not exists: Creates new profile with all policy links

### Conditional Access Policy Conflict
- Checks for existing CA policy with name `CADisplayName[Migrate2GSA]`
- If exists: Skips CA policy creation entirely (not modified)
- Security Profile is still created/reused successfully

## Output Files

All output files are timestamped and created in the current directory:

```
$PWD/
  └── 20251028_143022_Start-EntraInternetAccessProvisioning.log
  └── 20251028_143022_policies_provisioned.csv
  └── 20251028_143022_security_profiles_provisioned.csv
  └── 20251028_143022_Start-EntraInternetAccessProvisioning_WhatIf.log (WhatIf mode only)
```

### Output CSV Provision Field
- **Successfully provisioned or reused:** `Provision=no` (skip on re-run)
- **Failed, filtered, or skipped:** `Provision=yes` (retry on re-run)

Output CSVs can be used as input for re-runs to retry only failed items.

## Error Handling

### Validation Errors (Stop Script)
- Missing CSV columns
- Policy metadata inconsistency
- Missing users/groups in target tenant
- Priority conflicts (Security Profile or Policy Link)

### Provisioning Errors (Continue)
- Individual policy/rule creation failures
- Individual security profile/CA policy creation failures
- Script logs error and continues with next object

## Troubleshooting

### "Missing required columns" Error
**Cause:** CSV file is missing required columns  
**Solution:** Ensure all required columns are present in CSV headers

### "Policy metadata inconsistency" Error
**Cause:** Same PolicyName has different PolicyType or PolicyAction values across rows  
**Solution:** Ensure all rows for the same policy have consistent metadata

### "User/Group not found in tenant" Error
**Cause:** EntraUsers or EntraGroups reference users/groups that don't exist  
**Solution:** Verify user/group names in target tenant or remove from CSV

### "Priority conflict detected" Error
**Cause:** Security Profile priority conflicts with existing profile or duplicate policy link priorities  
**Solution:** Update priorities in CSV to resolve conflicts

### "Cannot modify profile linked to CA policy" Warning
**Cause:** Security Profile already linked to CA policy, cannot add new policy links  
**Solution:** Manually unlink CA policy or create new Security Profile

## Best Practices

1. **Always run WhatIf first**: Preview operations before execution
   ```powershell
   Start-EntraInternetAccessProvisioning -PoliciesCsvPath ".\policies.csv" -WhatIf
   ```

2. **Test with single policy**: Use `-PolicyName` to test individual policies
   ```powershell
   Start-EntraInternetAccessProvisioning -PoliciesCsvPath ".\policies.csv" -PolicyName "Test_Policy"
   ```

3. **Validate users/groups**: Ensure all EntraUsers and EntraGroups exist in target tenant before provisioning

4. **Review CA policies before enabling**: CA policies are created in disabled state - validate assignments and conditions before enabling

5. **Use Provision field for selective provisioning**: Set `Provision=no` for rows you don't want to provision

6. **Keep output CSVs for re-runs**: Output CSVs automatically update Provision field for idempotent re-runs

## See Also

- [EntraPrivateAccessProvisioning.md](./EntraPrivateAccessProvisioning.md) - Provision Entra Private Access applications
- [Convert-ZIA2EIA.md](./Convert-ZIA2EIA.md) - Convert ZScaler Internet Access policies to Entra Internet Access
- [Microsoft Graph API - Network Access](https://learn.microsoft.com/en-us/graph/api/resources/networkaccess-overview)
- [Conditional Access in Microsoft Entra](https://learn.microsoft.com/en-us/entra/identity/conditional-access/)
