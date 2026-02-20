---
sidebar_position: 2
---

# Getting Started with Greenfield EIA Deployment

Learn how to use the Migrate2GSA toolkit to deploy Entra Internet Access from scratch - no migration required!

## What is GreenField Deployment?

**GreenField deployment** means deploying Entra Internet Access from scratch - without migrating from another security platform. You're starting with a clean slate and building your security configuration directly.

:::tip When to Use GreenField Approach
- You're new to SSE/SASE solutions and starting fresh
- You want to deploy EIA without an existing platform to migrate from
- You're expanding to a new region or business unit
- You want to test EIA configurations before production rollout
- You prefer building configurations step-by-step with templates
:::

## Why Use This Toolkit for GreenField?

While the toolkit was originally built for migrations, it's **equally powerful for new deployments**:

### 1️⃣ **CSV-Based Configuration**
Instead of clicking through the Entra portal, define your entire configuration in CSV files:
- **Policies CSV**: Define web filtering and TLS inspection policies
- **Security Profiles CSV**: Link policies to user groups with priorities

### 2️⃣ **Ready-to-Use Templates**
Start with proven configurations for common scenarios:
- Basic security baseline
- Block social media and entertainment
- Strict controls for regulated industries
- Developer-friendly environments

### 3️⃣ **Automated Provisioning**
Run one PowerShell command to deploy everything:
```powershell
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath ".\policies.csv" `
    -SecurityProfilesCsvPath ".\security_profiles.csv"
```

### 4️⃣ **Built-in Best Practices**
- Priority management (no conflicts)
- Validation before deployment
- Idempotent operations (safe to re-run)
- Comprehensive logging

## Prerequisites

Before starting:
- ✅ Active Microsoft Entra ID tenant
- ✅ Global Secure Access license
- ✅ Global administrator or appropriate delegated permissions
- ✅ PowerShell 7.0 or higher
- ✅ [Migrate2GSA toolkit installed](../installation.md)
- ✅ [Understanding of EIA concepts](../UnderstandingGSA/EIA-Configuration-Model.md) (Rules, Policies, Security Profiles, Conditional Access)

---

## Understanding CSV File Structure

Your configuration consists of **TWO CSV files** that work together:

### Policies CSV
**Every row = ONE rule for a policy**

A policy with multiple rules will have multiple rows with the same PolicyName:

```csv
PolicyName,PolicyType,PolicyAction,Description,RuleType,RuleDestinations,RuleName,Provision
Block_Social,WebContentFiltering,Block,Block social media sites,webCategory,SocialNetworking;Entertainment,Social_Categories,yes
Block_Social,WebContentFiltering,Block,Block social media sites,FQDN,facebook.com;twitter.com,Facebook_Twitter,yes
Block_Social,WebContentFiltering,Block,Block social media sites,FQDN,instagram.com;*.instagram.com,Instagram_Sites,yes
```

This creates **one policy** named "Block_Social" with **three rules**.

:::info Key Columns Explained
- **PolicyName**: Groups rules into policies (same name = same policy)
- **PolicyType**: `WebContentFiltering` or `TLSInspection`
- **PolicyAction**: `allow`/`block` (WebContentFiltering) or `bypass`/`inspect` (TLSInspection default)
- **Description**: Human-readable description
- **RuleType**: What to match - `FQDN`, `URL`, `webCategory`, `bypass`, `inspect`
- **RuleDestinations**: Semicolon-separated destinations
- **RuleName**: Unique identifier for this specific rule
- **Provision**: `yes` to deploy, `no` to skip
:::

### Security Profiles CSV
**One row = ONE complete Security Profile + Conditional Access Policy**

```csv
SecurityProfileName,Priority,SecurityProfileLinks,CADisplayName,EntraUsers,EntraGroups,Provision
Standard_Profile,100,Block_Social:100;Allow_Microsoft:200,CA_Standard,john@contoso.com,All_Users;Finance_Team,yes
```

This creates:
1. **Security Profile** "Standard_Profile" linking to 2 policies
2. **Conditional Access Policy** "CA_Standard" assigned to specified users/groups

:::info Key Columns Explained
- **SecurityProfileName**: Name of the security profile
- **Priority**: Profile priority (lower = higher priority)
- **SecurityProfileLinks**: `PolicyName:Priority` pairs (semicolon-separated)
  - Lower priority number = evaluated first
  - Example: `Allow_Microsoft:100;Block_Social:200` means Allow_Microsoft is checked first
- **CADisplayName**: Name of the Conditional Access policy
- **EntraUsers**: Semicolon-separated user emails
- **EntraGroups**: Semicolon-separated group names (must match Entra exactly!)
- **Provision**: `yes` to deploy, `no` to skip
:::

:::warning Policy Link Priority Order
In `SecurityProfileLinks`, **lower priority policies are evaluated FIRST**. Use this carefully:
- Allow policies first: `Allow_Microsoft:100;Block_Social:200` ✅
- Block policies first: `Block_Social:100;Allow_Microsoft:200` ⚠️ (Allow might never trigger!)
:::

---

## Template Library

Ready-to-use CSV templates for common scenarios. Choose one, customize, and deploy!

### How to Use Templates

1. **Copy the CSV content** from the template below (Policies + Security Profiles)
2. **Save to files**: `policies.csv` and `security_profiles.csv`
3. **Edit the Security Profiles CSV**: Replace placeholder groups with your Entra group names
4. **Optional**: Adjust policies to match your requirements
5. **Preview first**: Run provisioning with `-WhatIf` to validate
6. **Deploy**: Run the provisioning command

```powershell
# Preview changes
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath ".\policies.csv" `
    -SecurityProfilesCsvPath ".\security_profiles.csv" `
    -WhatIf

# Deploy for real
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath ".\policies.csv" `
    -SecurityProfilesCsvPath ".\security_profiles.csv"
```

:::tip Start Simple
If this is your first deployment, start with **Template 1: Basic Security Baseline**. Add more complexity later!
:::

---

## Template 1: Basic Security Baseline ⭐

**Best for:** First-time deployments, general office environments

**What it does:**
- ✅ Blocks high-risk categories (malware, phishing, adult content, gambling)
- ✅ Allows all other web browsing
- ✅ Bypasses TLS inspection for common banking sites
- ✅ Applies to all users

### 📄 Policies CSV
```csv
PolicyName,PolicyType,PolicyAction,Description,RuleType,RuleDestinations,RuleName,Provision
Block_HighRisk,WebContentFiltering,Block,Block dangerous categories,webCategory,Malware;Phishing;AdultContent;Gambling;IllegalDrugs,High_Risk_Categories,yes
TLS_Bypass_Finance,TLSInspection,Bypass,Don't decrypt banking sites,FQDN,*.bankofamerica.com;*.chase.com;*.wellsfargo.com;*.paypal.com,Banking_Sites,yes
```

### 📄 Security Profiles CSV
```csv
SecurityProfileName,Priority,SecurityProfileLinks,CADisplayName,EntraUsers,EntraGroups,Provision
Basic_Security,100,Block_HighRisk:100;TLS_Bypass_Finance:200,CA_Basic_Security,,All_Company_Users,yes
```

**Customization:**
- Replace `All_Company_Users` with your Entra group name
- Add more banking sites to the TLS bypass list if needed

---

## Template 2: Block Social Media & Entertainment

**Best for:** Organizations wanting to prevent entertainment sites during work hours

**What it does:**
- ✅ Blocks social media (Facebook, Twitter, LinkedIn, etc.)
- ✅ Blocks streaming media and entertainment
- ✅ Blocks online gaming
- ✅ Allows everything else

### 📄 Policies CSV
```csv
PolicyName,PolicyType,PolicyAction,Description,RuleType,RuleDestinations,RuleName,Provision
Block_SocialMedia,WebContentFiltering,Block,Block social networking,webCategory,SocialNetworking,Social_Sites,yes
Block_Entertainment,WebContentFiltering,Block,Block streaming and games,webCategory,Entertainment;StreamingMedia;OnlineGaming,Entertainment_Sites,yes
```

### 📄 Security Profiles CSV
```csv
SecurityProfileName,Priority,SecurityProfileLinks,CADisplayName,EntraUsers,EntraGroups,Provision
Standard_Restricted,100,Block_SocialMedia:100;Block_Entertainment:200,CA_Standard_Restricted,,General_Employees,yes
```

**Advanced:** Add exceptions for specific teams:
```csv
SecurityProfileName,Priority,SecurityProfileLinks,CADisplayName,EntraUsers,EntraGroups,Provision
Standard_Restricted,100,Block_SocialMedia:100;Block_Entertainment:200,CA_Standard_Restricted,,General_Employees,yes
Marketing_Access,200,Allow_SocialMedia:100,CA_Marketing_Access,,Marketing_Team,yes
```

Then create an Allow policy for Marketing:
```csv
PolicyName,PolicyType,PolicyAction,Description,RuleType,RuleDestinations,RuleName,Provision
Allow_SocialMedia,WebContentFiltering,Allow,Marketing team needs social media,webCategory,SocialNetworking,Social_Allowed,yes
```

---

## Template 3: Developer-Friendly Environment 💻

**Best for:** IT/Development teams that need access to technical resources

**What it does:**
- ✅ Allows developer tools (GitHub, Stack Overflow, npm, etc.)
- ✅ Allows cloud platforms (AWS, Azure, Google Cloud)
- ✅ Blocks only critical threats (malware, phishing)
- ✅ Very permissive for productivity

### 📄 Policies CSV
```csv
PolicyName,PolicyType,PolicyAction,Description,RuleType,RuleDestinations,RuleName,Provision
Allow_DevTools,WebContentFiltering,Allow,Developer resources,FQDN,github.com;*.github.io;stackoverflow.com;*.stackoverflow.com;npmjs.com;*.npmjs.com,Dev_Sites,yes
Allow_CloudPlatforms,WebContentFiltering,Allow,Cloud services,FQDN,*.azure.com;*.aws.amazon.com;*.cloud.google.com,Cloud_Services,yes
Block_OnlyThreats,WebContentFiltering,Block,Security threats only,webCategory,Malware;Phishing,Threats_Only,yes
```

### 📄 Security Profiles CSV
```csv
SecurityProfileName,Priority,SecurityProfileLinks,CADisplayName,EntraUsers,EntraGroups,Provision
Developer_Profile,100,Allow_DevTools:100;Allow_CloudPlatforms:200;Block_OnlyThreats:300,CA_Developer_Access,,IT_Department;Developers,yes
```

**Customization:**
- Add more developer tools to `Allow_DevTools`
- Add private package registries (JFrog, Nexus, etc.)

---

## Template 4: Finance & HR (Strict Compliance) 🔒

**Best for:** Departments handling sensitive data, regulated industries

**What it does:**
- ✅ Blocks social media completely
- ✅ Blocks entertainment and shopping
- ✅ Blocks file sharing sites
- ✅ Allows only business-critical sites
- ✅ Inspects most traffic for threats
- ✅ Bypasses TLS for financial compliance sites

### 📄 Policies CSV
```csv
PolicyName,PolicyType,PolicyAction,Description,RuleType,RuleDestinations,RuleName,Provision
Allow_Business,WebContentFiltering,Allow,Business critical sites,webCategory,Business;Productivity,Business_Sites,yes
Allow_Microsoft,WebContentFiltering,Allow,Microsoft services,FQDN,*.microsoft.com;*.office.com;*.office365.com;*.azure.com,Microsoft_Suite,yes
Block_Social,WebContentFiltering,Block,No social media,webCategory,SocialNetworking,Social_Block,yes
Block_Shopping,WebContentFiltering,Block,No shopping,webCategory,Shopping;OnlineAuctions,Shopping_Block,yes
Block_FileSharing,WebContentFiltering,Block,No file sharing,webCategory,FileSharing;PersonalCloudStorage,FileShare_Block,yes
TLS_Bypass_Compliance,TLSInspection,Bypass,Financial compliance sites,FQDN,*.treasurydirect.gov;*.sec.gov;*.finra.org,Compliance_Sites,yes
TLS_Inspect_Default,TLSInspection,Inspect,Inspect all other traffic,webCategory,AllCategories,Inspect_All,yes
```

### 📄 Security Profiles CSV
```csv
SecurityProfileName,Priority,SecurityProfileLinks,CADisplayName,EntraUsers,EntraGroups,Provision
Finance_Strict,100,Allow_Microsoft:100;Allow_Business:200;Block_Social:300;Block_Shopping:400;Block_FileSharing:500;TLS_Bypass_Compliance:600;TLS_Inspect_Default:700,CA_Finance_Strict,,Finance_Team;HR_Team,yes
```

:::warning Strict Policy
This is a very restrictive configuration. Test thoroughly before applying to production!
:::

---

## Template 5: Guest/Contractor Network 🔐

**Best for:** External users, contractors, guest WiFi

**What it does:**
- ✅ Blocks almost everything except essential business sites
- ✅ Allows Microsoft/Office 365
- ✅ Allows basic web search
- ✅ Blocks file downloads/uploads
- ✅ Heavy TLS inspection

### 📄 Policies CSV
```csv
PolicyName,PolicyType,PolicyAction,Description,RuleType,RuleDestinations,RuleName,Provision
Allow_Microsoft_Only,WebContentFiltering,Allow,Microsoft services only,FQDN,*.microsoft.com;*.office.com;*.office365.com,MS_Only,yes
Allow_BasicSearch,WebContentFiltering,Allow,Search engines,webCategory,SearchEngines,Search_Allowed,yes
Block_Everything_Else,WebContentFiltering,Block,Block all other sites,webCategory,SocialNetworking;Entertainment;Shopping;OnlineAuctions;FileSharing;PersonalCloudStorage;Games,Block_All,yes
TLS_Inspect_Everything,TLSInspection,Inspect,Inspect all traffic,webCategory,AllCategories,Inspect_All,yes
```

### 📄 Security Profiles CSV
```csv
SecurityProfileName,Priority,SecurityProfileLinks,CADisplayName,EntraUsers,EntraGroups,Provision
Guest_Restricted,100,Allow_Microsoft_Only:100;Allow_BasicSearch:200;Block_Everything_Else:300;TLS_Inspect_Everything:400,CA_Guest_Access,,Guest_Network;External_Contractors,yes
```

---

## Customization Guide

### Common Modifications

#### Adding More Sites to Allow/Block
Just append to `RuleDestinations` with semicolon:
```csv
# Before:
RuleDestinations: github.com;npmjs.com

# After:
RuleDestinations: github.com;npmjs.com;bitbucket.com;gitlab.com
```

#### Adding More Web Categories
Check the [EIA Configuration Model](../UnderstandingGSA/EIA-Configuration-Model.md#web-categories-reference) for the full category list and add with semicolon:
```csv
# Before:
RuleDestinations: SocialNetworking

# After:
RuleDestinations: SocialNetworking;InstantMessaging;WebChat
```

#### Creating Department-Specific Profiles
Copy an existing profile row and modify:
```csv
SecurityProfileName,Priority,SecurityProfileLinks,CADisplayName,EntraUsers,EntraGroups,Provision
IT_Profile,100,Allow_DevTools:100;Block_Threats:200,CA_IT_Access,,IT_Department,yes
Finance_Profile,200,Allow_Business:100;Block_Social:200,CA_Finance_Access,,Finance_Team,yes
Marketing_Profile,300,Allow_Social:100;Block_Threats:200,CA_Marketing_Access,,Marketing_Team,yes
```

#### Adjusting Priorities
Lower number = higher priority = evaluated first:
```csv
# Allow policies first (100, 200, 300)
Allow_Microsoft:100
Allow_DevTools:200
Allow_Business:300

# Block policies after (400, 500, 600)
Block_Social:400
Block_Entertainment:500
Block_Malware:600
```

---

## Testing Your Configuration

### Step 1: Validate CSVs
Check for common issues:
- ✅ All required columns present
- ✅ No duplicate PolicyNames with different PolicyTypes or PolicyActions
- ✅ Group names match Entra exactly (case-sensitive!)
- ✅ Priorities are unique within each Security Profile

### Step 2: Preview with WhatIf
```powershell
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath ".\policies.csv" `
    -SecurityProfilesCsvPath ".\security_profiles.csv" `
    -WhatIf
```

This shows what will be created **WITHOUT** actually creating anything.

### Step 3: Deploy to Test Group
Create a test Security Profile assigned to a small pilot group first:
```csv
SecurityProfileName,Priority,SecurityProfileLinks,CADisplayName,EntraUsers,EntraGroups,Provision
Test_Profile,999,Your_Policies_Here,CA_Test_Pilot,,IT_Test_Group,yes
```

### Step 4: Monitor and Adjust
After deployment:
1. Check Entra portal: Global Secure Access → Internet Access
2. Review logs for blocked/allowed traffic
3. Adjust policies based on user feedback
4. Re-run provisioning (it's idempotent!)

---

## Troubleshooting

### "Group not found" error
- Verify group name matches Entra exactly (case-sensitive)
- Check if group exists: `Get-MgGroup -Filter "displayName eq 'YourGroupName'"`
- Make sure you're connected: `Connect-MgGraph -Scopes "Group.Read.All"`

### "Priority conflict detected"
- Ensure each Security Profile has unique priority (100, 200, 300 - not 100, 100, 100)
- Ensure policy link priorities are unique within each profile

### "Policy already exists"
- This is OK! The script reuses existing policies (idempotent)
- It will add missing rules only

### "Too many policies" (limit: 100)
- Consolidate similar policies
- Consider merging rules into fewer policies
- Use web categories instead of individual FQDNs

---

## Download Templates

:::info Coming Soon
Pre-configured CSV files will be available in the GitHub repository under `Samples/GreenField/` folder. For now, copy the CSV content from this page into your own files.
:::

**GitHub Path:** `Samples/GreenField/EntraInternetAccess/`
- `Template1_BasicSecurity/`
- `Template2_BlockSocialMedia/`
- `Template3_DeveloperFriendly/`
- `Template4_StrictCompliance/`
- `Template5_GuestNetwork/`

---

## Next Steps

1. **[Review EIA Concepts](../UnderstandingGSA/EIA-Configuration-Model.md)** - Understand the 4-layer architecture if you haven't already
2. **Copy a template** - Choose from the 5 templates above
3. **Customize CSVs** - Replace group names and adjust policies
4. **Deploy** - Head to [Provisioning Guide](../Provision/EntraInternetAccessProvisioning.md) for deployment instructions

**Questions?** Refer to the [EIA Configuration Model](../UnderstandingGSA/EIA-Configuration-Model.md) for conceptual guidance or reach out to the community!
