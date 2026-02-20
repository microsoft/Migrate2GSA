---
sidebar_position: 1
---

# Entra Internet Access Configuration Model

This guide explains the core concepts you need to understand before deploying Entra Internet Access (EIA) from scratch or when migrating from other platforms.

## The Four Core Components

Entra Internet Access uses a four-layer architecture where each layer builds upon the previous:

<div style={{margin: '2rem 0', overflowX: 'auto'}}>
  <div style={{display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.75rem', minWidth: '600px'}}>
    <div style={{flex: '1', padding: '0.75rem', backgroundColor: '#e3f2fd', borderRadius: '8px', border: '2px solid #1976d2', textAlign: 'center', minWidth: '120px'}}>
      <strong>1. Rules</strong><br/>
      <small>Filter criteria</small>
    </div>
    <div style={{fontSize: '1.5rem', color: '#666', flexShrink: 0}}>→</div>
    <div style={{flex: '1', padding: '0.75rem', backgroundColor: '#fff3e0', borderRadius: '8px', border: '2px solid #f57c00', textAlign: 'center', minWidth: '120px'}}>
      <strong>2. Policies</strong><br/>
      <small>Group rules</small>
    </div>
    <div style={{fontSize: '1.5rem', color: '#666', flexShrink: 0}}>→</div>
    <div style={{flex: '1', padding: '0.75rem', backgroundColor: '#f3e5f5', borderRadius: '8px', border: '2px solid #7b1fa2', textAlign: 'center', minWidth: '140px'}}>
      <strong>3. Security Profiles</strong><br/>
      <small>Link policies</small>
    </div>
    <div style={{fontSize: '1.5rem', color: '#666', flexShrink: 0}}>→</div>
    <div style={{flex: '1', padding: '0.75rem', backgroundColor: '#e8f5e9', borderRadius: '8px', border: '2px solid #388e3c', textAlign: 'center', minWidth: '150px'}}>
      <strong>4. Conditional Access</strong><br/>
      <small>Assign to users</small>
    </div>
  </div>
</div>

**In this guide:**
- [Rules - The Building Blocks](#1-rules---the-building-blocks)
- [Policies - Grouping Rules Together](#2-policies---grouping-rules-together)
- [Security Profiles - Linking Multiple Policies](#3-security-profiles---linking-multiple-policies)
- [Conditional Access - Assigning to Users](#4-conditional-access---assigning-to-users)
- [Decision Guide - How Many Policies Do I Need?](#decision-guide-designing-your-configuration)
- [Common Configuration Patterns](#common-patterns)
- [Available Web Categories](#web-categories-reference)
- [TLS Inspection Considerations](#tls-inspection-considerations)

### 1. Rules - The Building Blocks

**Rules** are the most granular level - each rule specifies *what* to match and *what action* to take.

#### Rule Types for Web Content Filtering
- **FQDN Rules**: Match specific domains
  - Example: `facebook.com`, `*.microsoft.com`, `github.com`
- **URL Rules**: Match specific paths or patterns
  - Example: `https://example.com/admin/*`, `https://docs.microsoft.com/*`
- **Web Category Rules**: Match groups of related sites
  - Example: `SocialNetworking`, `Gambling`, `AdultContent`, `Business`

#### Rule Types for TLS Inspection
- **Bypass Rules**: Don't decrypt matching traffic
  - Example: `*.internal.contoso.com`, `*.bankofamerica.com`
- **Inspect Rules**: Decrypt and scan matching traffic
  - Example: `*.financial-services.com`, `suspicious.contoso.com`

:::info Rules vs Policies
A **Rule** is a single filtering criterion (e.g., "block facebook.com"). A **Policy** is a container that groups multiple related rules together with a common action.
:::

### 2. Policies - Grouping Related Rules

**Policies** are containers that group multiple rules together. Each policy has:
- **A unique name**: e.g., "Social_Media-Block"
- **A type**: `WebContentFiltering` or `TLSInspection`
- **An action**: Applies to all rules in the policy
  - For WebContentFiltering: `Allow` or `Block`
  - For TLSInspection: `Bypass` or `Inspect` (default action when no rules match)
- **Multiple rules**: Each targeting different destinations

:::info Policy Types & Creation Order
**Other Policy Types:** Global Secure Access supports additional policy types like Threat Intelligence policies. This toolkit currently focuses on `WebContentFiltering` and `TLSInspection` policies only.

**UI Creation Order:** Although the logical object model is Rules → Policies (rules are the building blocks), the Entra Internet Access UI requires you to **create the Policy first** as the envelope/container, then add rules to it. When using this toolkit's CSV-based approach, you define both simultaneously - each CSV row represents one rule, and rows sharing the same `PolicyName` are grouped into a single policy.
:::

#### Example: Web Content Filtering Policy (with 2 Filtering rules)
```csv
PolicyName: "Social_Media-Block"
PolicyType: WebContentFiltering
PolicyAction: Block
Rules:
  - Rule 1: webCategory → SocialNetworking;Entertainment;Games
  - Rule 2: FQDN → facebook.com;twitter.com;instagram.com
```

This policy blocks social media using both category-based and FQDN-based rules.

#### Example: TLS Inspection Policy (with 2 Inspection rules)
```csv
PolicyName: "TLS_Internal-Bypass"
PolicyType: TLSInspection
PolicyAction: Bypass (default)
Rules:
  - Rule 1: bypass → *.internal.contoso.com;*.corp.local
  - Rule 2: inspect → suspicious.contoso.com (override default)
```

This policy bypasses TLS inspection for internal sites by default, but inspects suspicious.contoso.com.

:::tip Why Group Rules into Policies?
Policies make management easier - update one policy name instead of tracking individual rules. They also provide logical grouping (e.g., all social media rules in one policy).
:::

📖 **Learn more:**
- [Web Content Filtering Documentation](https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-configure-web-content-filtering)
- [TLS Inspection Documentation](https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-transport-layer-security)

### 3. Security Profiles - Linking Multiple Policies

**Security Profiles** bundle multiple policies together and assign priorities for policy evaluation order:

```
Security Profile: "Corporate Standard"
├── Policy: Web_Allow_Microsoft_Sites [Priority: 100] ← Evaluated first
├── Policy: Web_Block_Social_Media [Priority: 200]
└── Policy: TLS_Bypass_Banking [Priority: 300]
```

**Why priorities matter:** Lower number = higher priority = evaluated first. Allow policies typically get lower numbers (higher priority) than Block policies.

:::tip Priority Best Practice
- Allow policies: 100, 200, 300...
- Block policies: 400, 500, 600...
This ensures explicit allows are processed before broad blocks.
:::

### 4. Conditional Access - Assigning to Users and Groups

**Conditional Access (CA) policies** assign Security Profiles to users and groups, enforcing the internet access rules:

```
CA Policy: "Finance Team Internet Access"
├── Security Profile: "Corporate Standard" (contains all the policies)
├── Assigned to:
│   ├── Group: Finance_Users
│   └── User: finance.admin@contoso.com
└── State: Enabled (after admin validation)
```

:::info Complete Flow
A user in Finance_Users tries to access facebook.com:
1. **CA Policy** checks: Is user in Finance_Users? ✓
2. **Security Profile** applies: Corporate Standard
3. **Policies** evaluated by priority: Web_Allow_Microsoft_Sites (no match) → Web_Block_Social_Media (match!)
4. **Rules** checked: webCategory rule matches "SocialNetworking"
5. **Result**: Access BLOCKED
:::

## Decision Guide: Designing Your Configuration

### Scenario 1: "I want to block social media for everyone"

**Solution:**
1. Create **Policy** named "Block_Social_Media"
   - PolicyType: WebContentFiltering
   - PolicyAction: Block
   - Add **Rule 1**: 
     - RuleType: webCategory
     - RuleDestinations: `SocialNetworking;Entertainment`
   - Add **Rule 2** (optional, for more specific blocking):
     - RuleType: FQDN
     - RuleDestinations: `facebook.com;twitter.com;instagram.com`

2. Create **Security Profile** named "Standard_Profile"
   - Link to "Block_Social_Media" policy (Priority: 100)

3. Create **Conditional Access Policy** named "CA_Standard_Access"
   - Assign Security Profile: "Standard_Profile"
   - Assign Group: "All_Users"

### Scenario 2: "Block social media, except for Marketing team"

**Solution:**
1. Create TWO policies:
   - Policy A: "Block_Social_Media" (Action: Block, webCategory: SocialNetworking)
   - Policy B: "Allow_Social_Media" (Action: Allow, webCategory: SocialNetworking)

2. Create TWO Security Profiles:
   - Profile A: "Standard_Users" → Links to Policy A only
   - Profile B: "Marketing_Users" → Links to Policy B only

3. Create TWO Conditional Access Policies:
   - CA 1: Assign Profile A to "All_Users" group
   - CA 2: Assign Profile B to "Marketing_Team" group

:::info User in Multiple Groups?
If a user is in both groups, **both** CA policies apply. The Marketing profile will allow access because Allow policies typically have higher priority.
:::

### Scenario 3: "Different rules for different departments"

**Solution:** Create separate Security Profiles for each department:

```
Profile: "Finance_Strict"
├── Block_Social_Media [Priority: 100]
├── Block_Entertainment [Priority: 200]
└── TLS_Inspect_All [Priority: 300]

Profile: "IT_Relaxed"
├── Allow_Developer_Tools [Priority: 100]
├── Block_Gambling [Priority: 200]
└── TLS_Bypass_GitHub [Priority: 300]

Profile: "Guest_Restricted"
└── Block_Everything_Except_Microsoft [Priority: 100]
```

Each profile gets its own CA policy assigned to the respective group.

## Common Patterns

### Pattern 1: Restrictive (Default Deny)
**Philosophy:** Block everything except what's explicitly allowed

```csv
PolicyName,PolicyAction,RuleType,RuleDestinations
Allow_Microsoft,Allow,FQDN,*.microsoft.com;*.office.com
Allow_Business_Tools,Allow,FQDN,salesforce.com;*.google.com
Block_Everything_Else,Block,webCategory,AllCategories
```

### Pattern 2: Permissive (Default Allow)
**Philosophy:** Allow everything except what's explicitly blocked

```csv
PolicyName,PolicyAction,RuleType,RuleDestinations
Block_Adult_Content,Block,webCategory,AdultContent;Gambling
Block_Malware,Block,webCategory,Malware;Phishing
Block_Social_Media,Block,webCategory,SocialNetworking
```

### Pattern 3: Balanced
**Philosophy:** Block risky categories, allow productivity tools

```csv
PolicyName,PolicyAction,RuleType,RuleDestinations
Block_High_Risk,Block,webCategory,AdultContent;Gambling;Malware;Phishing
Allow_Productivity,Allow,webCategory,Business;CloudStorage;Productivity
Block_Entertainment,Block,webCategory,Entertainment;SocialNetworking;Games
```

## Web Categories Reference

Microsoft GSA provides pre-defined web categories. Here are the most commonly used:

### Security & Compliance
- `AdultContent` - Adult/mature content
- `Gambling` - Online gambling and betting
- `IllegalDrugs` - Drug-related content
- `Malware` - Known malicious sites
- `Phishing` - Phishing and fraud sites

### Productivity
- `Business` - Business and economy sites
- `CloudStorage` - Cloud storage services
- `Productivity` - Productivity tools
- `DeveloperTools` - Developer resources

### Entertainment & Social
- `SocialNetworking` - Facebook, Twitter, LinkedIn, etc.
- `Entertainment` - Streaming media, videos
- `Games` - Online gaming
- `Sports` - Sports content

### Technology
- `ComputerAndTechnology` - Tech news and resources
- `SearchEngines` - Google, Bing, etc.
- `SoftwareUpdates` - Software update sites

:::tip Full Category List
For the complete list of available categories, see [Microsoft's GSA documentation](https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-configure-web-content-filtering).
:::

## TLS Inspection Considerations

### When to BYPASS (Don't Decrypt)
- Banking and financial sites (privacy/compliance)
- Healthcare sites (HIPAA compliance)
- Government sites (security requirements)
- Sites with certificate pinning (technical limitation)

### When to INSPECT (Decrypt)
- General browsing (detect threats)
- Unknown sites (security scanning)
- File downloads (malware detection)
- Suspicious domains

:::info Microsoft System Bypass List
Microsoft maintains a **system bypass list** of destinations that are automatically excluded from TLS inspection for technical or privacy reasons. These destinations are bypassed regardless of your configured TLS inspection policies. The list includes Microsoft services, certificate validation endpoints, and other critical infrastructure.

📖 **Learn more:** [What destinations are included in the system bypass?](https://learn.microsoft.com/en-us/entra/global-secure-access/faq-transport-layer-security#what-destinations-are-included-in-the-system-bypass)
:::

**Example TLS Policy with Multiple Rules:**
```csv
PolicyName,PolicyType,PolicyAction,RuleType,RuleDestinations,RuleName
TLS_Internal-Bypass,TLSInspection,Bypass,bypass,*.internal.contoso.com;*.corp.local,Internal_Corporate
TLS_Internal-Bypass,TLSInspection,Bypass,inspect,suspicious.contoso.com,Suspicious_Override
```
This policy bypasses TLS for internal sites (rule 1) but inspects suspicious ones (rule 2 overrides default).

---

## Next Steps

Now that you understand the EIA configuration model:

1. **[GreenField Deployment](../GreenField/EntraInternetAccess.md)** - Deploy EIA from scratch using CSV templates
2. **[Migrate from Other Platforms](../migration-workflow.md)** - Export, transform, and provision from ZScaler, Netskope, Forcepoint, or Cisco Umbrella
3. **[Export Existing Configuration](../MigrationSources/GSA/EIAExport.md)** - Backup your current EIA setup for disaster recovery or tenant migration
4. **[Provisioning Reference](../Provision/EntraInternetAccessProvisioning.md)** - Detailed provisioning function documentation

📖 **Additional Resources:**
- [Web Content Filtering Documentation](https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-configure-web-content-filtering)
- [TLS Inspection Documentation](https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-transport-layer-security)
- [Conditional Access Overview](https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview)
