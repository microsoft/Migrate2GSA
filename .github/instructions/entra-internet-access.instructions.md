---
applyTo: '**/GSA/**,**/EIA/**,**/ZIA2EIA/**,**/NSWG2EIA/**,**/ForcepointWS2EIA/**,**/CiscoUmbrella/**,Specs/**'
description: 'Entra Internet Access (EIA) policy model, object hierarchy, and Graph API structure'
---

# Entra Internet Access Policy Model

This document describes the Entra Internet Access (EIA) object model used within Global Secure Access (GSA). Use it as context when writing specs, code, or migration logic.

## Object Hierarchy

```
── Independent Policy Objects ──────────────────────────

Filtering Policy (action: block/allow)
  └── policyRules[]
        ├── fqdnFilteringRule (destinations: fqdn[])
        ├── webCategoryFilteringRule (destinations: webCategory[])
        └── urlFilteringRule (destinations: url[])  ← uses fqdnFilteringRule @odata.type with ruleType "url"

TLS Inspection Policy (defaultAction: bypass/inspect)
  └── policyRules[] (tlsInspectionRule)
        ├── action: bypass | inspect
        ├── priority (lower = higher precedence)
        └── matchingConditions.destinations (fqdn and/or webCategory)

Threat Intelligence Policy
  └── system-managed, "Block Malicious Destinations"

Cloud Firewall Policy (defaultAction: allow/block)
  └── network-level firewall rules (L3/L4)

── Aggregation & Assignment ────────────────────────────

Conditional Access Policy
  └── references a Security Profile (via sessionControls.globalSecureAccessFilteringProfile)
        └── Security Profile (filteringProfile)
              ├── name, description, state, priority
              └── policyLinks[] (each links to an independent policy above)
                    ├── filteringPolicyLink (priority, state, loggingState, action)
                    ├── tlsInspectionPolicyLink (state)
                    ├── threatIntelligencePolicyLink (state)
                    └── cloudFirewallPolicyLink (state)
```

## Key Concepts

### Filtering Policy (Web Content Filtering)
- **Action is at the policy level** (block or allow), not per-rule. All rules in a policy share the same action.
- A policy contains one or more **policy rules** of different types:
  - **fqdnFilteringRule**: matches FQDNs (supports wildcards like `*.example.com`)
  - **webCategoryFilteringRule**: matches predefined web categories (e.g., `Gambling`, `SocialNetworking`, `Chat`)
  - **urlFilteringRule**: matches full URLs (uses `fqdnFilteringRule` OData type with `ruleType: url`)
- Rules have a name and a list of destinations.
- Policies are created at: `POST /beta/networkAccess/filteringPolicies`
- Rules are added to a policy at: `POST /beta/networkAccess/filteringPolicies/{policyId}/policyRules`

### TLS Inspection Policy
- Has a **defaultAction** (`bypass` or `inspect`) that applies when no rules match.
- Contains **tlsInspectionRule** entries, each with:
  - **action**: `bypass` or `inspect` (per-rule, unlike filtering policies)
  - **priority**: numeric, lower = evaluated first
  - **matchingConditions.destinations**: FQDNs and/or web categories
  - **settings.status**: `enabled` or `disabled`
- A system-managed bypass rule is auto-created for system bypass categories.
- Created at: `POST /beta/networkAccess/tlsInspectionPolicies`

### Threat Intelligence Policy
- System-managed policy named "Block Malicious Destinations".
- Linked to profiles via `threatIntelligencePolicyLink`.
- Cannot be user-created; it is auto-provisioned per tenant.

### Cloud Firewall Policy
- Manages network-level firewall rules (L3/L4).
- Linked to profiles via `cloudFirewallPolicyLink`.
- Has a **defaultAction** (`allow` or `block`).

### Security Profile (Filtering Profile)
- Aggregates multiple policies via **policy links** with individual priorities.
- Properties: `name`, `description`, `state` (enabled/disabled), `priority`.
- **Priority** is unique per profile; determines evaluation order when multiple profiles apply (lower = higher precedence). The Baseline Profile has priority 65000 (lowest).
- Contains an array of policy links, each of a specific type:
  - **filteringPolicyLink**: links a Filtering Policy. Has `priority`, `state`, `loggingState`, `action`.
  - **tlsInspectionPolicyLink**: links a TLS Inspection Policy. Has `state`.
  - **threatIntelligencePolicyLink**: links a Threat Intelligence Policy. Has `state`.
  - **cloudFirewallPolicyLink**: links a Cloud Firewall Policy. Has `state`.
- Policy links within a profile are evaluated by priority (lower = first).
- Created at: `POST /beta/networkAccess/filteringProfiles`
- Policy links added at: `POST /beta/networkAccess/filteringProfiles/{profileId}/policies`

### Conditional Access Policy (CA Policy)
- Assigns a Security Profile to users/groups.
- Uses `sessionControls.globalSecureAccessFilteringProfile` to reference the profile by ID.
- The CA policy targets the GSA application IDs:
  - `c08f52c9-8f03-4558-a0ea-9a4c878cf343` (Internet Access)
  - `5dc48733-b5df-475c-a49b-fa307ef00853` (Microsoft Traffic)
- Standard CA conditions apply (users, groups, platforms, locations, etc.).
- Must be in `enabled` state to enforce the profile.

## Web Categories

Entra uses a fixed set of ~70 predefined web categories (e.g., `Gambling`, `SocialNetworking`, `Hacking`, `CodeRepositories`, `Business`). Categories use PascalCase names as identifiers. Each category also has a `displayName` and a `group` classification. See `Samples/NSWG2EIA/EntraWebCategories.rename_to_csv` for the full list.

## Graph API Endpoints (beta)

| Resource | Endpoint |
|----------|----------|
| Filtering Policies | `/beta/networkAccess/filteringPolicies` |
| Policy Rules | `/beta/networkAccess/filteringPolicies/{id}/policyRules` |
| TLS Inspection Policies | `/beta/networkAccess/tlsInspectionPolicies` |
| TLS Inspection Rules | `/beta/networkAccess/tlsInspectionPolicies/{id}/policyRules` |
| Threat Intelligence Policies | `/beta/networkAccess/threatIntelligencePolicies` |
| Security Profiles | `/beta/networkAccess/filteringProfiles` |
| Profile Policy Links | `/beta/networkAccess/filteringProfiles/{id}/policies` |
| Conditional Access Policies | `/beta/identity/conditionalAccess/policies` |
| Tenant Status | `/beta/networkAccess/settings` |

Required Graph scopes: `NetworkAccess.ReadWrite.All`, plus `Policy.ReadWrite.ConditionalAccess`, `User.Read.All`, `Group.Read.All` when managing CA policies.

## CSV Input Format (Migrate2GSA)

### Policies CSV
One row per policy rule. All rows for the same `PolicyName` must share the same `PolicyType`, `PolicyAction`, and `Description`.

| Column | Values | Description |
|--------|--------|-------------|
| PolicyName | string | Logical policy name |
| PolicyType | `WebContentFiltering`, `TLSInspection` | Type of policy |
| PolicyAction | `Block`, `Allow`, `Bypass`, `Inspect` | Action (policy-level for WCF, default-action for TLSi) |
| Description | string | Policy description |
| RuleType | `FQDN`, `URL`, `webCategory`, `bypass`, `inspect` | Type of rule |
| RuleDestinations | semicolon-separated | FQDNs, URLs, or category names |
| RuleName | string | Display name for the rule |
| Provision | `yes`, `no` | Whether to provision this row |

### Security Profiles CSV
One row per security profile.

| Column | Values | Description |
|--------|--------|-------------|
| SecurityProfileName | string | Profile name |
| Priority | integer | Profile priority (lower = higher precedence) |
| SecurityProfileLinks | `PolicyName:Priority;...` | Semicolon-separated policy links with priority |
| CADisplayName | string | Conditional Access policy display name (optional) |
| EntraUsers | semicolon-separated UPNs | Users to assign via CA (optional) |
| EntraGroups | semicolon-separated names | Groups to assign via CA (optional) |
| Provision | `yes`, `no` | Whether to provision this row |

## OData Types Reference

| Object | @odata.type |
|--------|-------------|
| Filtering Policy | `#microsoft.graph.networkaccess.filteringPolicy` |
| Filtering Policy Link | `#microsoft.graph.networkaccess.filteringPolicyLink` |
| TLS Inspection Policy | `#microsoft.graph.networkaccess.tlsInspectionPolicy` |
| TLS Inspection Policy Link | `#microsoft.graph.networkaccess.tlsInspectionPolicyLink` |
| TLS Inspection Rule | `#microsoft.graph.networkaccess.tlsInspectionRule` |
| Threat Intelligence Policy | `#microsoft.graph.networkaccess.threatIntelligencePolicy` |
| Threat Intelligence Policy Link | `#microsoft.graph.networkaccess.threatIntelligencePolicyLink` |
| Cloud Firewall Policy | `#microsoft.graph.networkaccess.cloudFirewallPolicy` |
| Cloud Firewall Policy Link | `#microsoft.graph.networkaccess.cloudFirewallPolicyLink` |
| FQDN Filtering Rule | `#microsoft.graph.networkaccess.fqdnFilteringRule` |
| Web Category Filtering Rule | `#microsoft.graph.networkaccess.webCategoryFilteringRule` |
| FQDN destination | `#microsoft.graph.networkaccess.fqdn` |
| URL destination | `#microsoft.graph.networkaccess.url` |
| Web Category destination | `#microsoft.graph.networkaccess.webCategory` |
