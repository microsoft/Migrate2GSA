---
sidebar_position: 2
title: EIA CSV Configuration
description: Complete guide to Entra Internet Access CSV file structure, validation, and samples.
---

# Entra Internet Access CSV Configuration

This guide covers everything you need to know about working with CSV files for Entra Internet Access (EIA), whether you're migrating from another platform or deploying from scratch.

## CSV File Structure

Your Entra Internet Access configuration consists of **TWO CSV files** that work together:

### 1. Policies CSV
Defines web content filtering policies and TLS inspection policies with their rules.

**Structure:** Each row = ONE rule. Multiple rows with the same `PolicyName` form one policy with multiple rules.

### 2. Security Profiles CSV
Links policies together and assigns them to user/group populations via Conditional Access.

**Structure:** Each row = ONE complete security profile with linked policies and CA assignments.

:::info Relationship
Policies CSV defines **what** to filter → Security Profiles CSV defines **who** gets filtered by linking policies.
:::

---

## Policies CSV

### Column Reference

| Column | Required | Description | Example Values |
|--------|----------|-------------|----------------|
| **PolicyName** | Yes | Name of the policy (same name = same policy with multiple rules) | `Social_Media-Block` |
| **PolicyType** | Yes | Type of policy | `WebContentFiltering`, `TLSInspection` |
| **PolicyAction** | Yes | Default action for the policy | `allow`, `block` (WebContentFiltering)<br/>`bypass`, `inspect` (TLSInspection) |
| **Description** | No | Human-readable description | `Block social media and entertainment sites` |
| **RuleType** | Yes | What type of destination to match | `FQDN`, `URL`, `webCategory`, `bypass`, `inspect` |
| **RuleDestinations** | Yes | Semicolon-separated list of destinations | `facebook.com;twitter.com;instagram.com` |
| **RuleName** | Yes | Unique identifier for this specific rule | `Facebook_Twitter_Instagram` |
| **Provision** | Yes | Whether to deploy this rule | `yes`, `no` |

### Rule Types Explained

#### For WebContentFiltering Policies

**FQDN Rules** - Match specific domains:
- `contoso.com` - Exact match
- `*.contoso.com` - Wildcard subdomain match
- Multiple: `github.com;stackoverflow.com;npmjs.com`

**URL Rules** - Match specific paths:
- `https://contoso.com/admin/*` - Path-based match
- `https://docs.microsoft.com/*` - All Microsoft Docs
- Protocol must be included

**webCategory Rules** - Match web category groups:
- `SocialNetworking` - Facebook, Twitter, LinkedIn, etc.
- `Malware;Phishing;AdultContent` - Multiple categories
- See [Web Categories Reference](#web-categories-reference) for full list

#### For TLSInspection Policies

**bypass Rules** - Don't decrypt matching traffic:
- `*.bankofamerica.com;*.chase.com` - Banking sites
- `*.internal.contoso.com` - Internal corporate sites

**inspect Rules** - Decrypt and scan matching traffic:
- `suspicious.contoso.com` - Specific threat investigation
- `*.financial-services.com` - Industry-specific inspection

### Example: Multi-Rule Policy

```csv
PolicyName,PolicyType,PolicyAction,Description,RuleType,RuleDestinations,RuleName,Provision
Block_Social,WebContentFiltering,Block,Block social media sites,webCategory,SocialNetworking;Entertainment,Social_Categories,yes
Block_Social,WebContentFiltering,Block,Block social media sites,FQDN,facebook.com;*.facebook.com;twitter.com,Facebook_Twitter,yes
Block_Social,WebContentFiltering,Block,Block social media sites,FQDN,instagram.com;*.instagram.com;tiktok.com,Instagram_TikTok,yes
```

This creates **one policy** named "Block_Social" with **three rules** (1 category-based, 2 FQDN-based).

---

## Security Profiles CSV

### Column Reference

| Column | Required | Description | Example Values |
|--------|----------|-------------|----------------|
| **SecurityProfileName** | Yes | Name of the security profile | `Standard_Profile` |
| **Priority** | Yes | Profile priority (lower = higher priority) | `100`, `200`, `300` |
| **SecurityProfileLinks** | Yes | Linked policies with their priorities | `Block_Social:100;Allow_Microsoft:200` |
| **CADisplayName** | Yes | Name of the Conditional Access policy | `CA_Standard_Users` |
| **EntraUsers** | No | Semicolon-separated user emails | `john@contoso.com;jane@contoso.com` |
| **EntraGroups** | No | Semicolon-separated group display names | `All_Users;Finance_Team` |
| **Provision** | Yes | Whether to deploy this profile | `yes`, `no` |

### Security Profile Links Format

**Format:** `PolicyName:Priority;PolicyName:Priority;...`

- **Separator:** Semicolon (`;`) between policy links
- **Priority:** Lower number = evaluated first
- **Order matters:** Explicitly set priorities to control evaluation order

**Example:**
```
Allow_Microsoft:100;Block_Social:200;TLS_Bypass_Internal:300
```
1. First check: Allow Microsoft sites (priority 100)
2. Then check: Block social media (priority 200)
3. Finally: TLS bypass internal sites (priority 300)

:::warning Priority Best Practice
Put **Allow** policies with lower priorities (100-299) and **Block** policies with higher priorities (300-599) to avoid unintentional blocks.
:::

### Example: Complete Security Profile

```csv
SecurityProfileName,Priority,SecurityProfileLinks,CADisplayName,EntraUsers,EntraGroups,Provision
Finance_Profile,100,Allow_Microsoft:100;Block_Social:200;TLS_Inspect_Finance:300,CA_Finance_Team,,Finance_Users,yes
```

This creates:
1. Security Profile "Finance_Profile" with 3 linked policies
2. Conditional Access policy "CA_Finance_Team" assigned to "Finance_Users" group

---

## Validation Checklist

Before provisioning your CSV files, validate these items:

### ✅ File Format

- [ ] CSV uses comma delimiter (not semicolon or tab)
- [ ] No extra commas in description fields (break cells)
- [ ] UTF-8 encoding (avoid special character issues)
- [ ] Column headers match exactly (case-sensitive)
- [ ] No empty rows between data

### ✅ Policies CSV

- [ ] All required columns present (`PolicyName`, `PolicyType`, `PolicyAction`, `RuleType`, `RuleDestinations`, `RuleName`, `Provision`)
- [ ] `Policy Type` is either `WebContentFiltering` or `TLSInspection`
- [ ] `PolicyAction` matches policy type:
  - WebContentFiltering: `allow` or `block`
  - TLSInspection: `bypass` or `inspect`
- [ ] `RuleType` matches policy type:
  - WebContentFiltering: `FQDN`, `URL`, or `webCategory`
  - TLSInspection: `bypass` or `inspect`
- [ ] `RuleDestinations` use semicolon separator (no commas)
- [ ] FQDNs are valid (no protocol prefix unless `URL` type)
- [ ] Web categories match [official EIA categories](#web-categories-reference)
- [ ] `RuleName` is unique across all rules
- [ ] `Provision` is either `yes` or `no`

**Common Issues to Fix:**
- ❌ `PolicyAction: Allow` (uppercase) → ✅ `allow` (lowercase)
- ❌ `RuleDestinations: facebook.com, twitter.com` (comma) → ✅ `facebook.com;twitter.com` (semicolon)
- ❌ `webCategory: Social Networking` (space) → ✅ `webCategory: SocialNetworking` (no space - check official name)

### ✅ Security Profiles CSV

- [ ] All required columns present (`SecurityProfileName`, `Priority`, `SecurityProfileLinks`, `CADisplayName`, `EntraUsers`, `EntraGroups`, `Provision`)
- [ ] `Priority` is unique across all profiles (no duplicates)
- [ ] `SecurityProfileLinks` format correct: `PolicyName:Priority;PolicyName:Priority`
- [ ] All referenced `PolicyName` values exist in Policies CSV
- [ ] Policy link priorities are unique within each profile
- [ ] `EntraGroups` names match Entra ID exactly (case-sensitive!)
- [ ] `EntraUsers` use correct email format (UPN)
- [ ] At least one of `EntraUsers` or `EntraGroups` is populated
- [ ] `Provision` is either `yes` or `no`

**Common Issues to Fix:**
- ❌ `SecurityProfileLinks: Block_Social,Allow_Microsoft` (comma separator) → ✅ `Block_Social:100;Allow_Microsoft:200` (use `:Priority` and `;`)
- ❌ `EntraGroups: all users` → ✅ `All Users` (match exact casing from Entra)
- ❌ `Priority: 100` duplicated across 3 profiles → ✅ Use `100`, `200`, `300` (unique values)

### ✅ Migration-Specific Placeholders

If your CSV came from a conversion tool, replace these placeholders:

- [ ] Replace `Replace_with_All_IA_Users_Group` with your actual "All Users" group name
- [ ] Replace `Placeholder_Replace_Me` with appropriate group names
- [ ] Review rows with `ReviewNeeded=Yes` (if column present)
- [ ] Verify auto-mapped categories are correct
- [ ] Check for IP address rules flagged for review (EIA doesn't support IP filtering yet)

### ✅ Entra ID Validation

Before provisioning, verify these objects exist:

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Group.Read.All"

# Verify a group exists (repeat for each group in your CSV)
Get-MgGroup -Filter "displayName eq 'YourGroupName'"

# List all groups if unsure of exact names
Get-MgGroup | Select-Object DisplayName, Id | Sort-Object DisplayName
```

---

## Common Issues & Fixes

### Issue: "Group not found" Error

**Cause:** Group name in CSV doesn't match Entra ID display name exactly (case-sensitive).

**Solution:**
1. Run `Get-MgGroup | Select-Object DisplayName` to get exact names
2. Update CSV with exact casing: `All Users` not `all users`
3. Check for extra spaces: `Finance Team` not `Finance  Team`

### Issue: "Priority conflict detected"

**Cause:** Multiple security profiles have the same priority number.

**Solution:**
```csv
# Before (WRONG - duplicate 100):
Profile_A,100,...
Profile_B,100,...

# After (CORRECT - unique priorities):
Profile_A,100,...
Profile_B,200,...
```

### Issue: "Policy not found in Policies CSV"

**Cause:** Security Profile links reference a policy name that doesn't exist in Policies CSV.

**Solution:**
1. Check for typos: `Block_Social` vs `Block Social` (underscore vs space)
2. Verify exact `PolicyName` match between files
3. Ensure the policy row has `Provision=yes` in Policies CSV

### Issue: "Invalid web category"

**Cause:** Category name doesn't match official EIA category list.

**Solution:**
1. Check [Web Categories Reference](#web-categories-reference) for correct names
2. Common mistakes:
   - ❌ `Social Networking` → ✅ `SocialNetworking` (no space)
   - ❌ `Adult` → ✅ `AdultContent` (full name)
   - ❌ `Ads` → ✅ `AdvertisementsAndPopUps` (full name)

### Issue: "Too many policies" (limit: 100 policies)

**Cause:** EIA has a limit of 100 filtering policies per tenant.

**Solution:**
1. **Consolidate similar policies:** Merge rules from multiple policies into fewer policies
2. **Use web categories instead of FQDNs:** One category rule can replace hundreds of FQDN rules
3. **Remove unused/duplicate policies:** Delete policies no longer needed

**Example Consolidation:**
```csv
# Before (3 policies):
Block_Facebook,WebContentFiltering,Block,...,FQDN,facebook.com;*.facebook.com,...
Block_Twitter,WebContentFiltering,Block,...,FQDN,twitter.com;*.twitter.com,...
Block_Instagram,WebContentFiltering,Block,...,FQDN,instagram.com;*.instagram.com,...

# After (1 policy with 3 rules or 1 category rule):
Block_Social,WebContentFiltering,Block,...,webCategory,SocialNetworking,...
```

### Issue: CSV formatting errors in Excel

**Cause:** Excel auto-formatting corrupts data (leading zeros removed, dates converted, etc.).

**Solution:**
1. **Use Text Import Wizard:**
   - Open Excel → Data tab → Get Data → From Text/CSV
   - Set delimiter to comma
   - Set all columns to "Text" format (not General)
2. **Or use VS Code/text editor** for safer editing
3. **Save as:** "CSV UTF-8 (Comma delimited) (*.csv)"

### Issue: "Wildcard not working as expected"

**Cause:** Wildcards only work at subdomain level, not mid-domain.

**Solution:**
```csv
# Supported wildcards:
✅ *.contoso.com        (matches sub.contoso.com, app.sub.contoso.com)
✅ *.azure.com          (matches portal.azure.com, login.azure.com)

# Not supported:
❌ contoso.*            (asterisk in TLD)
❌ con*.com             (mid-domain wildcard)
❌ *contoso.com         (no dot after asterisk)
```

---

## Web Categories Reference

EIA supports the following web categories for `webCategory` rules:

### Security & Threats
- `Malware` - Known malware distribution sites
- `Phishing` - Phishing and spoofing sites
- `Spyware` - Spyware and adware distribution
- `Hacking` - Hacking tools and exploits

### Productivity & Business
- `Business` - Business and economy sites
- `Productivity` - Productivity tools and services
- `CloudStorage` - Cloud file storage services
- `Collaboration` - Collaboration platforms

### Social & Communication
- `SocialNetworking` - Facebook, Twitter, LinkedIn, etc.
- `InstantMessaging` - Chat and messaging platforms
- `WebMail` - Web-based email services

### Entertainment & Media
- `Entertainment` - General entertainment sites
- `StreamingMedia` - Video and audio streaming
- `OnlineGaming` - Gaming platforms and sites
- `Games` - Browser-based games

### Lifestyle & Shopping
- `Shopping` - E-commerce and retail sites
- `OnlineAuctions` - Auction sites (eBay, etc.)
- `TravelAndLeisure` - Travel booking and leisure

### Adult & Restricted
- `AdultContent` - Adult and mature content
- `Gambling` - Online gambling and betting
- `IllegalDrugs` - Illegal drug-related content
- `Alcohol` - Alcohol-related content
- `Tobacco` - Tobacco-related content

### Technical & Development
- `CodeRepositories` - GitHub, GitLab, Bitbucket, etc.
- `SearchEngines` - Google, Bing, DuckDuckGo, etc.
- `FileSharing` - File sharing and torrents
- `PersonalCloudStorage` - Personal cloud storage

### Advertising & Marketing
- `AdvertisementsAndPopUps` - Ad networks and pop-ups
- `Marketing` - Marketing and advertising platforms

:::tip Full Category List
For the complete, up-to-date list of categories, see [Microsoft's documentation](https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-configure-web-content-filtering#web-categories).
:::

---

## Samples

Example CSV configurations for greenfield deployments. Choose one, customize, and deploy!

### Sample 1: Basic Security Baseline ⭐

**Best for:** First-time deployments, general office environments

**What it does:**
- ✅ Blocks malware, phishing, adult content, gambling
- ✅ Allows all other web browsing
- ✅ Bypasses TLS for common banking sites
- ✅ Applies to all users

#### Policies CSV
```csv
PolicyName,PolicyType,PolicyAction,Description,RuleType,RuleDestinations,RuleName,Provision
Block_HighRisk,WebContentFiltering,Block,Block dangerous categories,webCategory,Malware;Phishing;AdultContent;Gambling;IllegalDrugs,High_Risk_Categories,yes
TLS_Bypass_Finance,TLSInspection,Bypass,Don't decrypt banking sites,FQDN,*.bankofamerica.com;*.chase.com;*.wellsfargo.com;*.paypal.com,Banking_Sites,yes
```

#### Security Profiles CSV
```csv
SecurityProf ileName,Priority,SecurityProfileLinks,CADisplayName,EntraUsers,EntraGroups,Provision
Basic_Security,100,Block_HighRisk:100;TLS_Bypass_Finance:200,CA_Basic_Security,,All_Company_Users,yes
```

**Customization:** Replace `All_Company_Users` with your Entra group name.

---

### Sample 2: Block Social Media & Entertainment

**Best for:** Organizations preventing entertainment during work hours

**What it does:**
- ✅ Blocks social media, streaming, gaming
- ✅ Blocks security threats
- ✅ Allows everything else

#### Policies CSV
```csv
PolicyName,PolicyType,PolicyAction,Description,RuleType,RuleDestinations,RuleName,Provision
Block_SocialMedia,WebContentFiltering,Block,Block social networking,webCategory,SocialNetworking,Social_Sites,yes
Block_Entertainment,WebContentFiltering,Block,Block streaming and games,webCategory,Entertainment;StreamingMedia;OnlineGaming,Entertainment_Sites,yes
Block_HighRisk,WebContentFiltering,Block,Block dangerous categories,webCategory,Malware;Phishing,Security_Threats,yes
```

#### Security Profiles CSV
```csv
SecurityProfileName,Priority,SecurityProfileLinks,CADisplayName,EntraUsers,EntraGroups,Provision
Standard_Restricted,100,Block_HighRisk:100;Block_SocialMedia:200;Block_Entertainment:300,CA_Standard_Restricted,,General_Employees,yes
```

---

### Sample 3: Developer-Friendly Environment 💻

**Best for:** IT/Development teams needing technical resources

**What it does:**
- ✅ Allows GitHub, Stack Overflow, npm, cloud platforms
- ✅ Blocks only critical threats
- ✅ Very permissive for productivity

#### Policies CSV
```csv
PolicyName,PolicyType,PolicyAction,Description,RuleType,RuleDestinations,RuleName,Provision
Allow_DevTools,WebContentFiltering,Allow,Developer resources,FQDN,github.com;*.github.io;stackoverflow.com;*.npmjs.com,Dev_Sites,yes
Allow_CloudPlatforms,WebContentFiltering,Allow,Cloud services,FQDN,*.azure.com;*.aws.amazon.com;*.cloud.google.com,Cloud_Services,yes
Block_OnlyThreats,WebContentFiltering,Block,Security threats only,webCategory,Malware;Phishing,Threats_Only,yes
```

#### Security Profiles CSV
```csv
SecurityProfileName,Priority,SecurityProfileLinks,CADisplayName,EntraUsers,EntraGroups,Provision
Developer_Profile,100,Block_OnlyThreats:100;Allow_DevTools:200;Allow_CloudPlatforms:300,CA_Developer_Access,,IT_Department;Developers,yes
```

---

### Sample 4: Finance & HR (Strict Compliance) 🔒

**Best for:** Regulated industries, sensitive data handling

**What it does:**
- ✅ Allows only business-critical sites
- ✅ Blocks social, shopping, file sharing
- ✅ Inspects most traffic, bypasses compliance sites

#### Policies CSV
```csv
PolicyName,PolicyType,PolicyAction,Description,RuleType,RuleDestinations,RuleName,Provision
Allow_Business,WebContentFiltering,Allow,Business critical sites,webCategory,Business;Productivity,Business_Sites,yes
Allow_Microsoft,WebContentFiltering,Allow,Microsoft services,FQDN,*.microsoft.com;*.office.com;*.office365.com,Microsoft_Suite,yes
Block_Social,WebContentFiltering,Block,No social media,webCategory,SocialNetworking,Social_Block,yes
Block_Shopping,WebContentFiltering,Block,No shopping,webCategory,Shopping;OnlineAuctions,Shopping_Block,yes
Block_FileSharing,WebContentFiltering,Block,No file sharing,webCategory,FileSharing;PersonalCloudStorage,FileShare_Block,yes
TLS_Bypass_Compliance,TLSInspection,Bypass,Financial compliance,FQDN,*.treasurydirect.gov;*.sec.gov,Compliance_Sites,yes
```

#### Security Profiles CSV
```csv
SecurityProfileName,Priority,SecurityProfileLinks,CADisplayName,EntraUsers,EntraGroups,Provision
Finance_Strict,100,Allow_Microsoft:100;Allow_Business:200;Block_Social:300;Block_Shopping:400;Block_FileSharing:500;TLS_Bypass_Compliance:600,CA_Finance_Strict,,Finance_Team;HR_Team,yes
```

:::warning
This is a very restrictive configuration. Test thoroughly before production deployment!
:::

---

## Next Steps

### Ready to Deploy?

1. **[Provision EIA Configuration](../Provision/EntraInternetAccessProvisioning.md)** - Deploy your CSV files to Microsoft Graph
2. **[Best Practices](./best-practices.md)** - Learn testing strategies and deployment patterns
3. **[Understanding EIA Model](../UnderstandingGSA/EIA-Configuration-Model.md)** - Review conceptual architecture

### Need More Samples?

- **[Sample Files in GitHub](https://github.com/microsoft/Migrate2GSA/tree/main/Samples/EIA)** - Additional examples
- **[Migration Scenarios](../migration-scenarios.md)** - Platform-specific conversion guides

---

:::info Questions?
- Review [Understanding GSA](../UnderstandingGSA/EIA-Configuration-Model.md) for conceptual guidance
- Check [Provisioning Docs](../Provision/EntraInternetAccessProvisioning.md) for deployment details
- Contact the team at **migrate2gsateam@microsoft.com**
:::
