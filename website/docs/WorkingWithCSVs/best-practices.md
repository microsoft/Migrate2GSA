---
sidebar_position: 4
title: Best Practices
description: Cross-product best practices for editing, testing, and deploying CSV configurations.
---

# CSV Configuration Best Practices

This page provides cross-product guidance for working with CSV files effectively, whether you're deploying Entra Internet Access or Entra Private Access.

## Editing CSV Files

### Excel vs Text Editors

#### When to Use Excel ✅
- **Best for:** Initial review, sorting, filtering complex datasets
- **Advantages:** Visual layout, easy filtering, column management
- **Best practices:**
  - Open via **Data → From Text/CSV** (not double-click)
  - Set all columns to **Text format** (not General)
  - Save as **"CSV UTF-8 (Comma delimited)"**
  - Be cautious of auto-formatting

**Safe Excel Workflow:**
```
1. Excel → Data tab → Get Data → From Text/CSV
2. Select your CSV file
3. Set Delimiter: Comma
4. Click Transform Data
5. Select all columns → Right-click → Change Type → Text
6. Close & Load
7. Make edits
8. File → Save As → CSV UTF-8 (Comma delimited) (*.csv)
```

#### When to Use Text Editors ✅
- **Best for:** Small changes, bulk find/replace, avoiding formatting issues
- **Recommended editors:**
  - VS Code (with Rainbow CSV extension)
  - Notepad++
  - Sublime Text
  - Any plain text editor

- **Advantages:** No auto-formatting, precise control, version control friendly
- **Best for:**
  - Replacing placeholders across many rows
  - Fixing delimiter issues
  - Ensuring UTF-8 encoding

**VS Code CSV Tips:**
1. Install "Rainbow CSV" extension for colored columns
2. Use Find/Replace (Ctrl+H) for bulk updates
3. Enable "Files: Encoding" → UTF-8
4. Use **Edit Column** mode (Alt+Click) for vertical editing

### Common Excel Pitfalls to Avoid

| Issue | Cause | Solution |
|-------|-------|----------|
| **Leading zeros removed** | `0800123456` becomes `800123456` | Format column as Text before import |
| **Dates auto-converted** | `2-5` becomes `Feb 5` | Format column as Text before import |
| **Scientific notation** | `1234567890` becomes `1.23E+09` | Format column as Text before import |
| **Comma loss in port lists** | `80,443,8080` becomes `80 443 8080` | Quote the cell: `"80,443,8080"` |
| **Extra spaces added** | Excel adds trailing spaces | Use text editor or Find/Replace to remove |

### Delimiter Management

**CSV delimiter is COMMA**—but values containing commas must be quoted:

```csv
# Correct - ports with commas are quoted:
PolicyName,PolicyType,PolicyAction,RuleDestinations
Block_Social,WebContentFiltering,Block,"facebook.com;twitter.com"

# Also correct - ports with commas quoted:
SegmentId,EnterpriseAppName,Ports
SEG-001,GSA-WebApp,"80,443,8080"
```

**Semicolon is used WITHIN cells for lists:**
```csv
# Multiple groups separated by semicolon:
EntraGroups
HR-Users;HR-Admins;Finance-Team

# Multiple destinations separated by semicolon:
RuleDestinations
github.com;*.github.io;stackoverflow.com
```

---

## Testing Strategy

### Phase 1: Syntax Validation

Before provisioning, validate CSV syntax:

```powershell
# For EIA: Import CSV and check for errors
$policies = Import-Csv -Path ".\policies.csv"
$profiles = Import-Csv -Path ".\security_profiles.csv"

# Validate required columns exist
$requiredPolicyCols = @('PolicyName', 'PolicyType', 'PolicyAction', 'RuleType', 'RuleDestinations', 'RuleName', 'Provision')
$policyCols = $policies[0].PSObject.Properties.Name
$missing = $requiredPolicyCols | Where-Object { $_ -notin $policyCols }
if ($missing) { Write-Warning "Missing columns: $($missing -join ', ')" }

# Check for placeholder values
$policies | Where-Object { $_.EntraGroups -like '*_Replace_Me*' } |
    Select-Object PolicyName, EntraGroups
```

### Phase 2: Preview with WhatIf

**Always use `-WhatIf` first** to see what will be created without actually creating it:

**EIA Example:**
```powershell
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath ".\policies.csv" `
    -SecurityProfilesCsvPath ".\security_profiles.csv" `
    -WhatIf
```

**EPA Example:**
```powershell
Start-EntraPrivateAccessProvisioning `
    -ProvisioningConfigPath ".\epa_config.csv" `
    -WhatIf
```

Review the output carefully:
- ✅ Object names look correct
- ✅ No placeholder values visible
- ✅ Group assignments are as expected
- ✅ Priorities/orders make sense

### Phase 3: Pilot Deployment

**Start small and expand gradually**:

#### Option A: Selective Provisioning (Recommended)

Set `Provision=no` for most items, enable only a few for testing:

```csv
# EIA: Test with one policy first
PolicyName,PolicyType,PolicyAction,...,Provision
Test_Policy,WebContentFiltering,Allow,...,yes
Block_Social,WebContentFiltering,Block,...,no
Block_Malware,WebContentFiltering,Block,...,no
```

```csv
# EPA: Test with one application first
SegmentId,EnterpriseAppName,...,Provision
SEG-001,GSA-TestApp,...,Yes
SEG-002,GSA-ProductionApp,...,No
SEG-003,GSA-CriticalApp,...,No
```

#### Option B: Test Security Profile/Group

Create a dedicated test profile assigned to a small pilot group:

```csv
# EIA: Add test profile with priority 999 (lowest)
SecurityProfileName,Priority,SecurityProfileLinks,CADisplayName,EntraGroups,Provision
Test_Profile,999,Block_Malware:100,CA_Test_Pilot,IT_Test_Group,yes
Standard_Profile,100,Block_Social:100;Block_Malware:200,CA_Standard,All_Users,no
```

**Pilot group strategy:**
1. Create Entra group: `GSA-Pilot-Users`
2. Add 3-5 volunteers from IT team
3. Deploy configuration assigned only to pilot group
4. Monitor for 2-3 days
5. Gather feedback and adjust
6. Expand to broader population

### Phase 4: Incremental Rollout

**Don't deploy everything at once.** Use a phased approach:

**Week 1:** Security threats only (malware, phishing)
```csv
Provision=yes: Block_Malware, Block_Phishing
Provision=no: Everything else
```

**Week 2:** Add productivity policies
```csv
Provision=yes: Block_Malware, Block_Phishing, Block_Social
Provision=no: Everything else
```

**Week 3:** Add TLS inspection
```csv
Provision=yes: All WebContentFiltering + TLS policies
```

**Week 4:** Full deployment
```csv
Provision=yes: Everything
```

### Phase 5: Production Monitoring

After deployment, monitor these areas:

**EIA Monitoring:**
- Entra Portal → Global Secure Access → Internet Access → Traffic logs
- Watch for unexpected blocks
- Review user feedback/helpdesk tickets
- Check policy hit counts

**EPA Monitoring:**
- Entra Portal → Enterprise Applications → Check sign-in logs
- Verify connector health
- Test application access from different users
- Check for connectivity issues

---

## Version Control

### Why Version Control CSV Files?

- **Track changes:** Who changed what and when
- **Rollback capability:** Restore previous working configuration
- **Collaboration:** Multiple team members can propose changes
- **Audit trail:** Compliance and change management documentation
- **Branching:** Test changes in dev/test branches before production

### Git Workflow for CSV Configurations

```bash
# Initialize repository
cd C:\GSAConfigs
git init
git add policies.csv security_profiles.csv
git commit -m "Initial EIA configuration"

# Create development branch for testing
git checkout -b test-social-media-block
# Make changes to CSVs...
git add policies.csv
git commit -m "Added social media blocking policy"

# Test in non-production environment
# If successful, merge to main
git checkout main
git merge test-social-media-block

# Tag production releases
git tag -a v1.0-prod -m "Production release 2026-02-27"
```

### CSV-Friendly Git Practices

**Use descriptive commit messages:**
```bash
❌ git commit -m "update"
✅ git commit -m "Added TLS bypass for banking sites in Finance profile"
```

**Review diffs before committing:**
```bash
git diff policies.csv
```

**Use `.gitignore` for working files:**
```
# .gitignore
*.log
*_backup*.csv
.DS_Store
*.tmp
```

### Backup Strategy

**Local backups with timestamps:**
```powershell
# PowerShell: Create timestamped backup before editing
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
Copy-Item "policies.csv" "backups/policies_$timestamp.csv"
Copy-Item "security_profiles.csv" "backups/security_profiles_$timestamp.csv"
```

**Cloud backups:**
- Store CSVs in OneDrive/SharePoint (with versioning enabled)
- Use Azure DevOps Repos or GitHub (private repos for sensitive data)
- Scheduled backups to blob storage

---

## Multi-Tenant Deployment

### Scenario: Dev → Test → Prod Promotion

**Challenge:** Deploy same configuration across multiple tenants

**Solution: Parameterized CSVs**

#### Step 1: Create Template CSV with Placeholders

```csv
# policies_template.csv
PolicyName,PolicyType,PolicyAction,...,EntraGroups
Block_Social,WebContentFiltering,Block,...,{{ALL_USERS_GROUP}}
Allow_DevTools,WebContentFiltering,Allow,...,{{DEVELOPERS_GROUP}}
```

#### Step 2: Environment-Specific Parameter Files

```powershell
# dev_params.ps1
$params = @{
    ALL_USERS_GROUP = "Dev-All-Users"
    DEVELOPERS_GROUP = "Dev-Developers"
}

# test_params.ps1
$params = @{
    ALL_USERS_GROUP = "Test-All-Users"
    DEVELOPERS_GROUP = "Test-Developers"
}

# prod_params.ps1
$params = @{
    ALL_USERS_GROUP = "All-Company-Users"
    DEVELOPERS_GROUP = "IT-Department"
}
```

#### Step 3: Replace Placeholders Before Provisioning

```powershell
# deploy_to_env.ps1
param(
    [Parameter(Mandatory)]
    [ValidateSet('dev', 'test', 'prod')]
    [string]$Environment
)

# Load parameters
. ".\$Environment_params.ps1"

# Read template
$content = Get-Content ".\policies_template.csv" -Raw

# Replace placeholders
foreach ($key in $params.Keys) {
    $content = $content -replace "{$($key)}", $params[$key]
}

# Save environment-specific CSV
$content | Out-File ".\policies_$Environment.csv" -Encoding UTF8

# Connect to appropriate tenant
Connect-MgGraph -TenantId $params.TenantId

# Deploy
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath ".\policies_$Environment.csv" `
    -SecurityProfilesCsvPath ".\security_profiles_$Environment.csv"
```

### Tenant-to-Tenant Migration

**Use case:** Backup/restore, corporate acquisitions, environment replication

**EIA Export → Edit → Import:**
```powershell
# Source tenant: Export
Connect-MgGraph -TenantId "source-tenant-id"
Export-EIAConfig -OutputPath "C:\Backup\"

# Edit CSVs: Update group names for target tenant

# Target tenant: Import
Connect-MgGraph -TenantId "target-tenant-id"
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath "C:\Backup\policies.csv" `
    -SecurityProfilesCsvPath "C:\Backup\security_profiles.csv"
```

**EPA Export → Edit → Import:**
```powershell
# Source tenant: Export
Connect-MgGraph -TenantId "source-tenant-id"
Export-EPAConfig -OutputPath "C:\Backup\"

# Edit CSV: Update connector groups and group names for target tenant

# Target tenant: Import
Connect-MgGraph -TenantId "target-tenant-id"
Start-EntraPrivateAccessProvisioning `
    -ProvisioningConfigPath "C:\Backup\epa_config.csv"
```

---

## Selective Provisioning Patterns

### Pattern 1: Department-by-Department Rollout

```csv
# Mark policies for specific departments with Provision=yes
PolicyName,PolicyType,PolicyAction,...,Provision
# Week 1: IT Department only
IT_Policies,...,yes

# Week 2-4: Other departments (set to no initially)
Finance_Policies,...,no
HR_Policies,...,no
Sales_Policies,...,no
```

### Pattern 2: Policy-Type Phasing

```csv
# Phase 1: Security threats only
Block_Malware,WebContentFiltering,Block,...,yes
Block_Phishing,WebContentFiltering,Block,...,yes

# Phase 2: Add productivity controls (change to yes later)
Block_Social,WebContentFiltering,Block,...,no
Block_Entertainment,WebContentFiltering,Block,...,no

# Phase 3: Add TLS inspection (change to yes later)
TLS_Bypass_Finance,TLSInspection,Bypass,...,no
```

### Pattern 3: Priority-Based Testing

**EIA:** Test high-priority profiles first (lower priority number = higher precedence):

```csv
SecurityProfileName,Priority,...,Provision
Test_Profile,100,...,yes        # Deploy first (highest priority)
Standard_Profile,200,...,no     # Deploy after testing
Guest_Profile,300,...,no        # Deploy last
```

### Pattern 4: Canary Deployment

**Create two identical profiles with different groups:**

```csv
# Canary group (5% of users)
Canary_Profile,100,Block_Social:100,...,GSA-Canary-Group,yes

# Main population (wait 1 week)
Production_Profile,200,Block_Social:100,...,All-Users,no
```

After 1 week of monitoring canary:
- If successful → Set `Production_Profile` `Provision=yes`
- If issues found → Fix policies and re-test canary

---

## Performance & Scale Considerations

### EIA Limits

- **Filtering Policies:** Maximum 100 policies per tenant
- **Rules per Policy:** Recommended < 100 rules per policy (no hard limit)
- **Security Profiles:** Recommended < 20 profiles (no hard limit)

**Optimization strategies:**
1. **Use web categories instead of FQDNs:** One category rule can replace hundreds of FQDN rules
2. **Consolidate similar policies:** Merge rules into fewer policiespolicies
3. **Remove unused policies:** Clean up test/deprecated policies regularly

### EPA Limits

- **Enterprise Applications:** No documented hard limit (thousands supported)
- **Segments per Application:** Recommended < 500 segments per app
- **Connector Groups:** Plan for geographic distribution and redundancy

**Optimization strategies:**
1. **Group related segments:** Multi-segment apps instead of many single-segment apps
2. **Use Quick Access for broad access:** Instead of hundreds of individual segments
3. **Plan connector placement:** Co-locate connectors with target applications

---

## Troubleshooting Workflow

When provisioning fails or produces unexpected results:

### Step 1: Check CSV Syntax

```powershell
# Import and validate structure
$data = Import-Csv -Path ".\policies.csv"
$data | Format-Table -AutoSize | Out-String -Width 200
```

### Step 2: Review Provisioning Logs

Provisioning functions create detailed log files:
- **EIA:** `YYYYMMDD_HHMMSS_EIA_Provisioning.log`
- **EPA:** `YYYYMMDD_HHMMSS_EPA_Provisioning.log`

Look for:
- ERROR messages
- WARNING about placeholders
- INFO about skipped rows (`Provision=no`)
- HTTP response codes from Graph API

### Step 3: Verify Graph Permissions

```powershell
# Check current scopes
(Get-MgContext).Scopes

# Reconnect with required scopes if missing
Connect-MgGraph -Scopes "NetworkAccessPolicy.ReadWrite.All","Application.ReadWrite.All","Group.Read.All"
```

### Step 4: Incremental Testing

Set all `Provision=no` except ONE row, then provision:
```csv
# Test one row at a time
PolicyName,...,Provision
Test_Policy_1,...,yes
Test_Policy_2,...,no
Test_Policy_3,...,no
```

This isolates which specific row is causing the issue.

### Step 5: Manual Verification

After provisioning, verify in Entra Portal:
- **EIA:** Global Secure Access → Internet Access → Filtering policies
- **EPA:** Enterprise Applications → Search for your app names
- **CA Policies:** Entra ID → Security → Conditional Access

---

## Next Steps

Ready to apply these best practices?

- **[Deploy EIA Configuration](../Provision/EntraInternetAccessProvisioning.md)** - Provision Entra Internet Access
- **[Deploy EPA Configuration](../Provision/EntraPrivateAccessProvisioning.md)** - Provision Entra Private Access
- **[Migration Scenarios](../migration-scenarios.md)** - Find your platform-specific guide

---

:::tip Pro Tip
Combine these best practices with the [Migration Workflow](../migration-workflow.md) for a comprehensive deployment strategy. Start small, test thoroughly, and expand incrementally!
:::
