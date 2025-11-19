# Netskope Secure Web Gateway to Entra Internet Access Sample Files

This directory contains sample input files for the `Convert-NSWG2EIA` function, which converts Netskope Secure Web Gateway (NSWG) Real-time Protection policies to Microsoft Entra Internet Access (EIA) format.

## Overview

The samples demonstrate various policy configurations and conversion scenarios including:
- Real-time Protection policies with different actions (Allow, Block, Alert)
- Custom categories with inclusions, exclusions, and predefined categories
- URL lists with exact and regex types
- Predefined category mappings
- User and group assignments
- Application objects

## File Naming Convention

Sample files use the `.rename_to_json` or `.rename_to_csv` extension to prevent accidental processing. Before using these files with the conversion function, rename them to have the correct extension:

- `sample_real_time_protection_policies.rename_to_json` → `real_time_protection_policies.json`
- `sample_url_lists.rename_to_json` → `url_lists.json`
- `sample_custom_categories.rename_to_json` → `custom_categories.json`
- `sample_NSWG2EIA-CategoryMappings.rename_to_csv` → `NSWG2EIA-CategoryMappings.csv`

## Sample Files

### 1. sample_real_time_protection_policies.rename_to_json

Contains representative Real-time Protection policies showing:
- **Policy with "All" users assignment** - Creates "SecurityProfile-All-Users"
- **Policies with custom category references** - Links to custom category policies
- **Policies with predefined category references** - Creates webCategory policies
- **Policies with application objects** - Flagged for manual review
- **Policies with specific user/group assignments** - Creates numbered security profiles
- **Policies with Alert/User Alert actions** - Converted to Block with review flag
- **Disabled policies** - Skipped during conversion
- **NPA policies** (accessMethod = "Client") - Skipped during conversion
- **Policies with app_tags filtering** - Skipped during conversion

### 2. sample_url_lists.rename_to_json

Contains representative URL lists showing:
- **Exact type URL lists with FQDNs** - Processed normally
- **Exact type URL lists with URLs** (with paths) - Classified as URL type
- **Exact type URL lists with IP addresses** - Flagged for review (not yet supported in EIA)
- **Regex type URL lists** - Flagged for review with Provision=No

### 3. sample_custom_categories.rename_to_json

Contains representative custom categories showing:
- **Category with predefined categories only** - Creates webCategory policies
- **Category with URL list inclusions** - Links to URL list Allow/Block policies
- **Category with URL list exclusions** - Links to URL list policies with INVERSE action
- **Category with both predefined categories and URL lists** - Creates multiple policy links
- **Category with duplicate URL lists** (in both inclusion and exclusion) - Flagged for review

### 4. sample_NSWG2EIA-CategoryMappings.rename_to_csv

Sample mapping file with:
- **Common mapped predefined categories** - Map to GSA web categories
- **Unmapped categories** - Use blank or "Unmapped" GSACategory value

## Expected Conversion Results

When running the conversion with these sample files, you should expect:

### Policies Created

1. **URL List Policies** (2 per URL list: Allow and Block)
   - `Whitelist URLs-Allow` and `Whitelist URLs-Block`
   - `SSL Bypass URLs-Allow` and `SSL Bypass URLs-Block`
   - `Regex Patterns-Allow` and `Regex Patterns-Block` (flagged for review)

2. **Custom Category WebCategory Policies** (for predefined categories)
   - `Potentially malicious sites-WebCategories-Allow`
   - `Potentially malicious sites-WebCategories-Block`

3. **Predefined Category Policies** (from RT policies)
   - `Block Advertisements-WebCategories-Block`
   - `Allow Cloud Storage-WebCategories-Allow`

4. **Application Policies** (flagged for review)
   - `Allow GitHub Copilot-Application-Allow`

### Security Profiles Created

1. **SecurityProfile-All-Users** - Aggregates policies assigned to "All" users
2. **SecurityProfile-001** - Aggregates policies for specific user/group set 1
3. **SecurityProfile-002** - Aggregates policies for specific user/group set 2

### Policy Linking Examples

**RT Policy referencing custom category with inclusions:**
- Action: Block
- Custom category: "Potentially malicious sites"
- Inclusions: URL list "Whitelist URLs"
- Links created:
  - `Whitelist URLs-Block` (inclusion with Block action)
  - `Potentially malicious sites-WebCategories-Block` (predefined categories)

**RT Policy referencing custom category with exclusions:**
- Action: Block
- Custom category: "Safe Sites"
- Exclusions: URL list "Whitelist URLs"
- Links created:
  - `Whitelist URLs-Allow` (exclusion with Block action - INVERSE)

## Usage Example

```powershell
# 1. Rename sample files to remove .rename_to_ prefix
Copy-Item "sample_real_time_protection_policies.rename_to_json" -Destination "real_time_protection_policies.json"
Copy-Item "sample_url_lists.rename_to_json" -Destination "url_lists.json"
Copy-Item "sample_custom_categories.rename_to_json" -Destination "custom_categories.json"
Copy-Item "sample_NSWG2EIA-CategoryMappings.rename_to_csv" -Destination "NSWG2EIA-CategoryMappings.csv"

# 2. Run the conversion
Convert-NSWG2EIA -RealTimeProtectionPoliciesPath "real_time_protection_policies.json" `
                 -UrlListsPath "url_lists.json" `
                 -CustomCategoriesPath "custom_categories.json" `
                 -CategoryMappingsPath "NSWG2EIA-CategoryMappings.csv" `
                 -EnableDebugLogging

# 3. Review output files
# - [timestamp]_EIA_Policies.csv
# - [timestamp]_EIA_SecurityProfiles.csv
# - [timestamp]_Convert-NSWG2EIA.log
```

## Testing Scenarios Covered

The sample files cover all testing scenarios from the specification:

1. ✅ URL List with FQDNs and URLs
2. ✅ Custom Category with Predefined Categories and URL List Exclusion
3. ✅ URL List with Regex Type
4. ✅ RT Policy Referencing Custom Category with URL Lists
5. ✅ RT Policy with Multiple Applications
6. ✅ Policy Aggregation - All Users
7. ✅ Policy Aggregation - Same User Set with Duplicate References
8. ✅ X500 Group Path Parsing
9. ✅ Mixed User Assignment
10. ✅ Custom Category with Duplicate URL List References
11. ✅ Unreferenced Policy Cleanup
12. ✅ Priority Conflicts

## Notes

- The sample data is representative but simplified for testing purposes
- Real-world Netskope exports will contain many more policies and categories
- Always review the output CSV files before provisioning to EIA
- Pay special attention to policies with ReviewNeeded=Yes

## Support

For questions or issues with the conversion function, please refer to the main documentation or open an issue in the repository.
