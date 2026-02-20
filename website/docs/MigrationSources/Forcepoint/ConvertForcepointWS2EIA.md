---
sidebar_position: 1
title: Forcepoint Web Security to Entra Internet Access (EIA) Configuration Transformer
---

## Overview

The `Convert-ForcepointWS2EIA` function converts Forcepoint Web Security (FWS) policy configuration to Microsoft Entra Internet Access (EIA) format. It processes a matrix-style CSV file where rows represent web categories (predefined or user-defined FQDNs) and columns represent security groups, with cell values indicating the policy action (Block, Allow, Continue, Do not block).

## Prerequisites

### Required Input Files

1. **Forcepoint Policies CSV** (matrix format)
   - Manually exported from Forcepoint Web Security
   - Matrix-style format with categories/FQDNs as rows and security groups as columns
   - Sample file: `Samples/ForcepointWS2EIA/sample_forcepoint_policies.rename_to_csv`

2. **Category Mappings CSV**
   - CSV file mapping Forcepoint predefined categories to GSA categories
   - Sample file: `Samples/ForcepointWS2EIA/Forcepoint-to-GSA-CategoryMapping.rename_to_csv`

### PowerShell Requirements

- PowerShell 7.0 or higher
- Migrate2GSA module installed

## Installation

```powershell
# Import the module
Import-Module Migrate2GSA

# Verify the function is available
Get-Command Convert-ForcepointWS2EIA
```

## Syntax

```powershell
Convert-ForcepointWS2EIA
    -ForcepointPoliciesPath <string>
    -CategoryMappingsPath <string>
    [-OutputBasePath <string>]
    [-EnableDebugLogging]
    [<CommonParameters>]
```

## Parameters

### -ForcepointPoliciesPath
Path to the Forcepoint Policies CSV export file. This should be a matrix-style CSV where rows represent web categories or FQDNs and columns represent security groups with their disposition settings.

- **Type**: String
- **Required**: Yes

### -CategoryMappingsPath
Path to the Forcepoint to GSA category mappings CSV file. This file provides mapping between Forcepoint predefined web categories and Microsoft GSA (Global Secure Access) web categories.

- **Type**: String
- **Required**: Yes

### -OutputBasePath
Base directory for output CSV files and log file.

- **Type**: String
- **Default**: Current directory
- **Required**: No (uses default if not specified)

### -EnableDebugLogging
Enable verbose debug logging for detailed processing information.

- **Type**: Switch
- **Default**: False
- **Required**: No

## Examples

### Example 1: Basic Conversion
```powershell
Convert-ForcepointWS2EIA `
    -ForcepointPoliciesPath "C:\FWS\policies.csv" `
    -CategoryMappingsPath "C:\FWS\mappings.csv"
```
Converts Forcepoint configuration from specified paths using default output directory.

### Example 2: Custom Output Path
```powershell
Convert-ForcepointWS2EIA `
    -ForcepointPoliciesPath ".\policies.csv" `
    -CategoryMappingsPath ".\mappings.csv" `
    -OutputBasePath "C:\Output"
```
Converts Forcepoint configuration and saves output to C:\Output.

### Example 3: With Debug Logging
```powershell
Convert-ForcepointWS2EIA `
    -ForcepointPoliciesPath ".\policies.csv" `
    -CategoryMappingsPath ".\mappings.csv" `
    -EnableDebugLogging
```
Converts Forcepoint configuration with detailed debug logging enabled.

## Input File Format

### Forcepoint Policies CSV Structure

The input CSV uses a matrix format where:
- **Rows**: Represent web categories or FQDNs
- **Columns**: Represent security groups and their disposition settings
- **Cells**: Contain policy actions (Block, Allow, Continue, Do not block)

```csv
Parent Category Name,Child Category Name,DEFAULT Disposition,Finance Group Disposition,Marketing Group Disposition
Abortion,Abortion,Do not block,Block,Do not block
Adult Material,Adult Content,Block,Block,Block
User-Defined,example.com,Block,Allow,Block
```

#### Column Structure

1. **Parent Category Name**: Predefined category group name, or "User-Defined" for custom FQDNs
2. **Child Category Name**: Specific category name (used for mapping) or the actual FQDN
3. **DEFAULT Disposition**: Default policy action for all users
4. **[GroupName] Disposition**: Policy action for specific security group

#### Action Values

All action values are case-insensitive:

| Forcepoint Action | Maps to EIA | Notes |
|-------------------|-------------|-------|
| Block | block | Blocks access |
| Continue | block | Warning + block (flagged for review) |
| Allow | allow | Allows access |
| Do not block | allow | Does not restrict access |

### Category Mappings CSV Structure

```csv
ForcepointCategory,GSACategory,MappingNotes
Abortion,Uncategorized,No direct GSA category match
Adult Content,PornographyAndSexuallyExplicit,Direct mapping
Drugs,IllegalDrug,Semantic match
```

- **ForcepointCategory**: Child category name from Forcepoint CSV
- **GSACategory**: Target GSA category name (leave blank or "Unmapped" if no match)
- **MappingNotes**: Optional notes explaining the mapping rationale

## Output Files

The function generates three output files with timestamp prefix `[yyyyMMdd_HHmmss]`:

### 1. Policies CSV (`[timestamp]_EIA_Policies.csv`)

Contains all web content filtering policies with rules for blocked/allowed categories and FQDNs.

**Key Fields:**
- **PolicyName**: Sequential name with action suffix (e.g., "Web Content Filtering 1-Block")
- **PolicyAction**: "Block" or "Allow" (one action per policy)
- **RuleType**: "webCategory" or "FQDN"
- **RuleDestinations**: Semicolon-separated categories or single FQDN
- **ReviewNeeded**: "Yes" if unmapped categories or Continue action present
- **Provision**: "Yes" unless review needed

### 2. Security Profiles CSV (`[timestamp]_EIA_SecurityProfiles.csv`)

Contains security profile definitions linking policies to security groups.

**Key Fields:**
- **SecurityProfileName**: Sequential name (e.g., "Security_Profile_1")
- **Priority**: 500, 600, 700... for groups; 60000 for DEFAULT
- **SecurityProfileLinks**: Policy references with priorities (Allow policies first, then Block)
- **EntraGroups**: Semicolon-separated group names or placeholder for DEFAULT

### 3. Log File (`[timestamp]_Convert-ForcepointWS2EIA.log`)

Detailed processing log with statistics and warnings.

## Conversion Process

### Phase 1: Data Loading
- Loads Forcepoint policies CSV and category mappings
- Identifies security group columns (columns ending with "Disposition")
- Builds category mapping lookup table

### Phase 2: Policy Parsing
- Processes each security group (including DEFAULT)
- Collects dispositions for each category/FQDN
- Maps Forcepoint categories to GSA categories
- Identifies user-defined FQDNs
- Flags unmapped categories and Continue actions

### Phase 3: Policy Deduplication
- Generates hash for each unique policy definition
- Reuses policies when multiple groups have identical rules
- Creates separate Block and Allow policies as needed
- Assigns unique sequential policy numbers

### Phase 4: Security Profile Creation
- Groups security groups by shared policies
- Assigns priorities based on CSV column order
- Links Allow and Block policies (Allow policies first)
- Handles DEFAULT group with special placeholder

### Phase 5: Export and Summary
- Exports policies and security profiles to CSV
- Validates against GSA limits (100 policies, 1000 rules, 8000 FQDNs, 256 profiles)
- Displays conversion statistics

## Key Features

### Policy Deduplication

Security groups with identical rules share the same policies, reducing the total policy count:

```
Group1: Block [Abortion, Adult Content], Allow [LinkedIn]
Group2: Block [Abortion, Adult Content], Allow [LinkedIn]
→ Creates ONE Block policy and ONE Allow policy used by both groups
```

### Mixed Policies

Groups with both blocked and allowed items create TWO separate policies:

```
Finance Group: Block [Gambling], Allow [LinkedIn, example.com]
→ Creates:
   - "Web Content Filtering 1-Block" (Gambling)
   - "Web Content Filtering 2-Allow" (LinkedIn, example.com)
```

### Unmapped Categories

Categories without GSA mappings are flagged for review:

```
Input: "Custom Category" (not in mapping file)
Output: "Custom Category_Unmapped" with ReviewNeeded=Yes
```

### Continue Action Handling

Continue actions are converted to Block and flagged:

```
Input: "Continue" disposition
Output: Action=Block, ReviewNeeded=Yes, ReviewDetails="Continue action converted to Block"
```

### DEFAULT Group

Special handling for baseline policies:

- Always receives priority 60000 (lowest priority)
- EntraGroups set to "Replace_with_All_IA_Users_Group" placeholder
- Must be replaced with actual Entra group name for all Internet Access users

## Review Workflow

Rules with `ReviewNeeded=Yes` require manual review before provisioning:

1. **Unmapped Categories**: Verify category mappings are correct
2. **Continue Actions**: Confirm Block action is appropriate (was originally a warning)
3. **Update Provision Flag**: Change to "Yes" after review

## Known Limitations

### GSA Service Limits

- Maximum 100 policies
- Maximum 1000 rules
- Maximum 8000 FQDNs
- Maximum 256 security profiles

The function validates these limits and displays warnings if exceeded.

### Technical Limitations

- Column headers must end with " Disposition" suffix
- User-Defined detection relies on "User-Defined" parent category name
- No FQDN validation performed
- Group names must be compatible with Entra (special characters preserved)

## Troubleshooting

### Common Issues

**"Invalid CSV structure: minimum 3 columns required"**
- Ensure CSV has Parent Category Name, Child Category Name, and at least one Disposition column

**"No security group columns found"**
- Verify column headers end with " Disposition"
- Check that there is at least a "DEFAULT Disposition" column

**"Category mappings CSV is empty"**
- Verify the mapping file path is correct
- Ensure file has header row and data rows

**"Disposition column not found for group"**
- Group name must match column header (without " Disposition" suffix)
- Column matching is case-insensitive

### Debug Mode

Enable debug logging for detailed processing information:

```powershell
Convert-ForcepointWS2EIA ... -EnableDebugLogging
```

Debug output includes:
- Group processing details
- Policy definition hashes for deduplication
- Category mapping lookups
- Policy and security profile creation

## Sample Files

Sample files are provided in `Samples/ForcepointWS2EIA/`:

- `sample_forcepoint_policies.rename_to_csv`: Example policy matrix
- `Forcepoint-to-GSA-CategoryMapping.rename_to_csv`: Category mappings
- `README.md`: Detailed explanation of sample data

Rename files to `.csv` extension before testing.

## Next Steps

After conversion:

1. **Review Output**: Check policies and security profiles CSVs
2. **Verify Mappings**: Confirm unmapped categories are addressed
3. **Update Placeholders**: Replace DEFAULT group placeholder with actual Entra group
4. **Provision to EIA**: Use `Start-EntraInternetAccessProvisioning` to deploy
