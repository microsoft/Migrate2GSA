# Global Secure Access Filtering Profiles - CSV Definition

## Overview

This document defines the CSV column structure for creating **Microsoft Global Secure Access filtering profiles, policies, and rules** using Microsoft Graph PowerShell. The CSV serves as input for automated provisioning of web filtering configurations.

## Architecture

Global Secure Access filtering is organized in a three-tier hierarchy:

```
Filtering Profile
├── Filtering Policy 1
│   ├── Rule 1 (FQDN)
│   ├── Rule 2 (Web Category)
│   └── Rule 3 (IP Address)
├── Filtering Policy 2
│   ├── Rule 4 (URL)
│   └── Rule 5 (IP Subnet)
└── Conditional Access Integration
```

### Key Concepts

- **Filtering Profile**: Groups multiple filtering policies and integrates with Conditional Access policies
- **Filtering Policy**: Contains related filtering rules (e.g., "Social Media Blocking", "Business Apps")
- **Policy Rule**: Individual filtering rule targeting specific destinations with allow/block actions

## CSV Column Reference

### Grouping and Identification

| Column | Type | Required | Description |
|--------|------|----------|-------------|
| `ProfileName` | String | Yes | Name of the filtering profile that groups policies |
| `ProfileDescription` | String | No | Description of the filtering profile purpose |
| `ProfilePriority` | Int64 | No | Priority for profile processing (lower = higher priority) |
| `PolicyName` | String | Yes | Name of the filtering policy within the profile |
| `PolicyDescription` | String | No | Description of the filtering policy purpose |
| `RuleName` | String | Yes | Name of the individual filtering rule |
| `RuleDescription` | String | No | Description of what this rule does |

### Rule Configuration

| Column | Type | Required | Values | Description |
|--------|------|----------|--------|-------------|
| `RuleType` | String | Yes | `fqdn`, `webCategory`, `ipAddress`, `ipRange`, `ipSubnet`, `url` | Type of filtering rule |
| `Action` | String | Yes | `allow`, `block` | Action to take when rule matches |

### Destination Configuration

**Choose ONE based on RuleType:**

| Column | Type | Required When | Example | Description |
|--------|------|---------------|---------|-------------|
| `DestinationFQDN` | String | RuleType = `fqdn` | `*.facebook.com`, `example.com` | Fully qualified domain name |
| `DestinationURL` | String | RuleType = `url` | `https://example.com/api/*` | Specific URL pattern |
| `DestinationIPAddress` | String | RuleType = `ipAddress` | `192.168.1.1` | Single IP address |
| `DestinationIPRange` | String | RuleType = `ipRange` | `192.168.1.1-192.168.1.100` | Range of IP addresses |
| `DestinationIPSubnet` | String | RuleType = `ipSubnet` | `192.168.1.0/24` | IP subnet in CIDR notation |
| `WebCategoryName` | String | RuleType = `webCategory` | `Social Media`, `Gaming`, `Adult Content` | Web category name |
| `WebCategoryId` | String | Optional | | Web category identifier if known |

### Conditional Access Integration

| Column | Type | Required | Description |
|--------|------|----------|-------------|
| `ConditionalAccessPolicyName` | String | No | Name of associated Conditional Access policy |
| `ConditionalAccessPolicyId` | String | No | ID of associated Conditional Access policy |

### User and Group Targeting

| Column | Type | Required | Example | Description |
|--------|------|----------|---------|-------------|
| `TargetGroups` | String | No | `IT-Users,Finance-Team` | Comma-separated list of Entra groups |
| `TargetUsers` | String | No | `user1@domain.com,user2@domain.com` | Comma-separated list of user UPNs |
| `ExcludeGroups` | String | No | `IT-Admins,Executives` | Groups to exclude from the rule |
| `ExcludeUsers` | String | No | `admin@domain.com` | Users to exclude from the rule |

### Processing Control

| Column | Type | Required | Values | Description |
|--------|------|----------|--------|-------------|
| `Enabled` | Boolean | No | `True`, `False` | Whether this rule should be enabled |
| `Priority` | Int32 | No | Positive integer | Rule priority within policy (lower = higher priority) |
| `CreateProfile` | Boolean | No | `True`, `False` | Whether to create the filtering profile |
| `CreatePolicy` | Boolean | No | `True`, `False` | Whether to create the filtering policy |
| `CreateRule` | Boolean | No | `True`, `False` | Whether to create this rule |

### Migration Tracking

| Column | Type | Required | Description |
|--------|------|----------|-------------|
| `SourceSystem` | String | No | Source system (e.g., 'Zscaler', 'Manual') |
| `SourceRuleId` | String | No | Original rule ID from source system |
| `SourcePolicyName` | String | No | Original policy name from source system |

### Validation and Results

| Column | Type | Description |
|--------|------|-------------|
| `ValidationStatus` | String | Validation result: 'Valid', 'Warning', 'Error' |
| `ValidationMessage` | String | Detailed validation or error message |
| `ConflictDetected` | Boolean | Whether conflicts were detected with existing rules |
| `ConflictingRules` | String | Names/IDs of conflicting rules |
| `ProvisioningStatus` | String | Status: 'Pending', 'Success', 'Failed', 'Skipped' |
| `ProvisioningMessage` | String | Detailed provisioning result message |
| `CreatedProfileId` | String | ID of created filtering profile |
| `CreatedPolicyId` | String | ID of created filtering policy |
| `CreatedRuleId` | String | ID of created filtering rule |

### Metadata

| Column | Type | Description |
|--------|------|-------------|
| `CreatedDate` | DateTime | When this CSV entry was created |
| `ProcessedDate` | DateTime | When this entry was processed |
| `LastModifiedDate` | DateTime | When this entry was last modified |
| `Notes` | String | Additional notes or comments |
| `Tags` | String | Comma-separated tags for categorization |

## Example CSV Rows

### Example 1: Block Social Media FQDN

```csv
ProfileName,ProfileDescription,PolicyName,RuleName,RuleType,Action,DestinationFQDN,TargetGroups,Enabled,CreateProfile,CreatePolicy,CreateRule
Corporate-Web-Filtering,"Corporate web filtering policies",Social-Media-Blocking,Block-Facebook,fqdn,block,*.facebook.com,All-Users,True,True,True,True
```

### Example 2: Allow Business Application

```csv
ProfileName,ProfileDescription,PolicyName,RuleName,RuleType,Action,DestinationFQDN,TargetGroups,Enabled,CreateProfile,CreatePolicy,CreateRule
Corporate-Web-Filtering,"Corporate web filtering policies",Business-Applications,Allow-Salesforce,fqdn,allow,*.salesforce.com,"Sales-Team,Management",True,False,True,True
```

### Example 3: Block Web Category

```csv
ProfileName,ProfileDescription,PolicyName,RuleName,RuleType,Action,WebCategoryName,TargetGroups,Enabled,CreateProfile,CreatePolicy,CreateRule
Corporate-Web-Filtering,"Corporate web filtering policies",Category-Blocking,Block-Gaming,webCategory,block,Gaming,All-Users,True,False,True,True
```

## Data Validation Rules

### Required Fields
- `ProfileName` - Must not be empty
- `PolicyName` - Must not be empty  
- `RuleName` - Must not be empty
- `RuleType` - Must be valid rule type
- `Action` - Must be 'allow' or 'block'

### Rule Type Validation
- `fqdn` requires `DestinationFQDN`
- `webCategory` requires `WebCategoryName`
- `ipAddress` requires `DestinationIPAddress`
- `ipRange` requires `DestinationIPRange`
- `ipSubnet` requires `DestinationIPSubnet`
- `url` requires `DestinationURL`

### Format Validation
- IP addresses must be valid IPv4 format
- CIDR subnets must have valid prefix length (0-32)
- FQDNs support wildcard patterns (e.g., *.domain.com)
- URLs must be valid HTTP/HTTPS format

## Processing Logic

### Profile Creation
1. Group rows by `ProfileName`
2. Create profile if `CreateProfile = True` in any row for that profile
3. Set profile priority from `ProfilePriority` column

### Policy Creation
1. Group rows by `ProfileName` + `PolicyName`
2. Create policy if `CreatePolicy = True` in any row for that policy
3. Link policy to profile

### Rule Creation
1. Create individual rules where `CreateRule = True`
2. Set rule priority from `Priority` column
3. Configure destinations based on `RuleType`
4. Link rule to policy

### Conditional Access Integration
1. Link profiles to Conditional Access policies via `ConditionalAccessPolicyName`
2. Apply user/group targeting through Conditional Access

## Best Practices

### Naming Conventions
- Use descriptive, consistent names for profiles and policies
- Include action in rule names (e.g., "Block-Facebook", "Allow-Office365")
- Use kebab-case or PascalCase consistently

### Rule Organization
- Group related rules into logical policies
- Use priority to control rule processing order
- Keep profiles focused on specific use cases

### Validation
- Always validate CSV data before provisioning
- Test with a small subset first
- Review conflict detection results

### Incremental Deployment
- Start with `CreateProfile = True` for first rule in each profile
- Set `CreateProfile = False` for subsequent rules in same profile
- Use `Enabled = False` for testing without activation

## PowerShell Implementation

The CSV structure is designed to work with PowerShell scripts that:

1. **Parse and validate** the CSV data
2. **Group rules** into policies and profiles
3. **Create filtering profiles** using Microsoft Graph
4. **Create filtering policies** and link to profiles
5. **Create individual rules** and link to policies
6. **Link to Conditional Access** policies for user targeting
7. **Update CSV with results** and created object IDs

## Microsoft Graph API Mapping

The CSV maps to these Microsoft Graph resources:

- **FilteringProfile**: `/beta/networkAccess/filteringProfiles`
- **FilteringPolicy**: `/beta/networkAccess/filteringPolicies`
- **PolicyRule**: Rules within policies (fqdnFilteringRule, webCategoryFilteringRule)
- **PolicyLink**: Links between profiles and policies

## Migration from ZScaler

When migrating from ZScaler:

1. Set `SourceSystem = "Zscaler"`
2. Include original `SourceRuleId` and `SourcePolicyName`
3. Map ZScaler categories to GSA web categories
4. Convert ZScaler URL patterns to FQDN rules where appropriate
5. Review and adjust user/group targeting

This CSV structure provides a comprehensive foundation for managing Global Secure Access filtering configurations at scale.
