# PANW to EIA Conversion Samples

This directory contains sample files for testing the `Convert-PANW2EIA` function, which converts Palo Alto Networks Panorama configuration to Microsoft Entra Internet Access (EIA) format.

## Input Files

### sample_panorama_config.rename_to_xml
Sample Panorama XML configuration export demonstrating:
- Shared custom URL categories and URL filtering profiles
- One device-group (`DG-Corporate`) with pre-rulebase and post-rulebase rules
- Rules with profile group references (`Default-Profile-Group`, `Strict-Profile-Group`, `Guest-Profile-Group`)
- Rules with direct URL filtering profile references
- Rules with `any` source-user and specific users/groups
- Rules with application references (non-`any`) — flagged for review
- Disabled rules (skipped)
- Deny/drop action rules (skipped)
- Rules without URL filtering profiles (skipped)
- Custom URL categories with mixed FQDN, URL, and IP entries (under `profiles/custom-url-category`, matching real Panorama XML structure)
- URL filtering profiles with block, allow, alert, continue, and override categories
- Category Match type custom URL category (skipped)
- Empty custom URL category (skipped)
- `unknown` and `pre-logon` source-user values (skipped with warning)
- `domain\user` format source-users (flagged for review)

### PANW2EIA-CategoryMappings.rename_to_csv
Category mappings file demonstrating:
- Mapped PAN-DB categories (e.g., `adult` → `AdultContent`)
- Unmapped categories with `Unmapped` value (e.g., `unknown` → `Unmapped`)
- Unmapped categories with empty string (e.g., `peer-to-peer` → empty)
- All common PAN-DB predefined web categories

## Output Files

### sample_output_Policies.rename_to_csv
Expected output showing:
- Custom category policies with FQDN, URL, and ipAddress rules
- Web category policies per URL filtering profile per action (Block, Allow, Alert, Continue, Override)
- `ReviewNeeded = Yes` for alert/continue/override actions and unmapped categories
- `Provision = No` for entries requiring review
- Duplicate removal from custom URL categories
- URL schema stripping

### sample_output_SecurityProfiles.rename_to_csv
Expected output showing:
- Aggregated security profiles (`SecurityProfile-All-Users`, `SecurityProfile-001`, etc.)
- `SecurityProfileLinks` in `PolicyName:LinkPriority` format with deduplicated links
- Override profiles (specific users/groups) starting at priority 1000
- Default profile (`SecurityProfile-All-Users`) at priority 50000
- User and group assignments from aggregated source-user fields
- `CA-[SecurityProfileName]` display name format
- Default group (`Replace_with_All_IA_Users_Group`) for `any` source-user
- Application-based rules flagged for review

## Testing

To test with these sample files:

```powershell
# Navigate to the samples directory
cd Samples\PANW2EIA

# Rename sample files (remove .rename_to_ prefix)
Copy-Item sample_panorama_config.rename_to_xml panorama_config.xml
Copy-Item PANW2EIA-CategoryMappings.rename_to_csv PANW2EIA-CategoryMappings.csv

# Run the conversion
Convert-PANW2EIA -PanoramaXmlPath ".\panorama_config.xml" -CategoryMappingsPath ".\PANW2EIA-CategoryMappings.csv" -OutputBasePath ".\output"

# Run with policy name filtering
Convert-PANW2EIA -PanoramaXmlPath ".\panorama_config.xml" -CategoryMappingsPath ".\PANW2EIA-CategoryMappings.csv" -OutputBasePath ".\output" -IncludePolicyName "Allow-*"

# Compare output with expected results
# Output files will be in .\output\ with timestamp prefix
```

## Processing Overview

The conversion processes the Panorama XML in five phases:

1. **Data Loading** — Parse XML, enumerate device-groups, build object collections and lookup tables
2. **Custom URL Categories** — Process URL List type categories into FQDN/URL/IP policy entries
3. **URL Filtering Profiles** — Map PAN-DB categories to GSA categories, create web category policies
4. **Security Rules** — Filter enabled allow rules with URL filtering, build security profiles with policy links
5. **Export** — Generate Policies and Security Profiles CSV files with summary statistics

### Skipped Elements
- **Disabled rules:** `Old-Policy-Disabled` (disabled=yes)
- **Deny/drop rules:** `Block-All-Malware` (action=deny), `Drop-Unknown` (action=drop)
- **No URL filter:** `Allow-DNS` (no profile-setting with URL filtering)
- **Category Match:** `Predefined-Group-Cat` (type=Category Match)
- **Empty categories:** `Empty-Category` (no members)
- **Source-users:** `unknown` and `pre-logon` values skipped with warning

### Review Items
- **Alert/Continue/Override actions:** Mapped to Block with review flag
- **Unmapped categories:** `peer-to-peer` and `unknown-category` use `UNMAPPED:` placeholder format
- **Application references:** `Allow-SaaS-Apps` rule references office365, salesforce, slack
- **domain\user format:** `CORP\contractors` flagged for source-user format review
