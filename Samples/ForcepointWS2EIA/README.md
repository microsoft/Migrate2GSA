# Forcepoint Web Security to EIA Conversion Samples

This directory contains sample files for testing the `Convert-ForcepointWS2EIA` function.

## Input Files

### sample_forcepoint_policies.rename_to_csv
Sample Forcepoint Web Security policy export (matrix format) demonstrating:
- Predefined web categories (Abortion, Adult Material, Gambling, Drugs, Social Networking)
- User-Defined FQDN entries (example.com, internal.company.com, test-site.com, trusted-partner.com)
- DEFAULT disposition column (baseline for all users)
- Multiple security groups (Marketing Users, Engineering Users, Finance Team, Sales Team)
- Various actions (Block, Allow, Continue, Do not block)
- Identical policies across different groups (for deduplication testing)
- Mixed policies (groups with both Block and Allow rules)

**Note:** Rename this file to `.csv` to use for testing.

### Forcepoint-to-GSA-CategoryMapping.rename_to_csv
Category mapping file demonstrating:
- Comprehensive Forcepoint-to-GSA category mappings (130+ categories)
- Mapped predefined categories (Adult Content → PornographyAndSexuallyExplicit, LinkedIn → ProfessionalNetworking)
- Unmapped categories with empty GSACategory (Abortion, Pro-Choice, Pro-Life, and others)
- Mapping notes explaining the rationale for each mapping

**Note:** Rename this file to `.csv` to use for testing.

## Expected Output

### Policies CSV
The conversion creates policies with these characteristics:
- **Sequential policy numbering**: Web Content Filtering 1-Block, Web Content Filtering 2-Allow, etc.
- **One action per policy**: Each policy has only Block or Allow action
- **Web categories**: Combined into single rules with semicolon-separated destinations
- **FQDNs**: Individual rules (one row per FQDN)
- **Review flags**: Set per rule for unmapped categories or Continue actions
- **Policy deduplication**: Groups with identical rules share the same policy

### Security Profiles CSV
The conversion creates security profiles with:
- **Sequential profile names**: Security_Profile_1, Security_Profile_2, etc.
- **Priority assignment**: 500, 600, 700, 800 for groups; 60000 for DEFAULT
- **Policy links**: Allow policies first, then Block policies (e.g., "Web Content Filtering 3-Allow:100;Web Content Filtering 2-Block:200")
- **Group consolidation**: Multiple groups sharing policies combined in EntraGroups field
- **DEFAULT handling**: Special placeholder "Replace_with_All_IA_Users_Group"

## Testing

To test with these sample files:

```powershell
# Navigate to the samples directory
cd C:\Git\Migrate2GSAPublic\Samples\ForcepointWS2EIA

# Rename the sample files
Rename-Item "sample_forcepoint_policies.rename_to_csv" "sample_forcepoint_policies.csv"
Rename-Item "Forcepoint-to-GSA-CategoryMapping.rename_to_csv" "Forcepoint-to-GSA-CategoryMapping.csv"

# Run the conversion
Convert-ForcepointWS2EIA `
    -ForcepointPoliciesPath "sample_forcepoint_policies.csv" `
    -CategoryMappingsPath "Forcepoint-to-GSA-CategoryMapping.csv" `
    -OutputBasePath "." `

# Review the output files
# - [timestamp]_EIA_Policies.csv
# - [timestamp]_EIA_SecurityProfiles.csv
# - [timestamp]_Convert-ForcepointWS2EIA.log
```

## Expected Behavior

### Category Processing

**Mapped Categories:**
- Adult Content → PornographyAndSexuallyExplicit
- Nudity → Nudity
- Gambling → Gambling
- Drugs → IllegalDrug
- Facebook → SocialNetworking
- LinkedIn → ProfessionalNetworking
- Twitter → SocialNetworking

**Unmapped Categories:**
- Abortion → Abortion_Unmapped (no GSA mapping)
- Pro-Choice → Pro-Choice_Unmapped (no GSA mapping)

**User-Defined FQDNs:**
- example.com
- internal.company.com
- test-site.com
- trusted-partner.com

### Action Mapping
- **Block** → Block
- **Allow** → Allow
- **Continue** → Block (with review flag)
- **Do not block** → Allow

### Group Processing

**Marketing Users (Priority 500):**
- Blocks: Abortion, Pro-Choice, Adult Content, Nudity, Gambling, Drugs, Facebook, Twitter, test-site.com
- Allows: LinkedIn, example.com, internal.company.com, trusted-partner.com

**Engineering Users (Priority 600):**
- Blocks: Abortion, Adult Content, Nudity, Gambling (Continue action), Drugs, example.com, test-site.com
- Allows: Pro-Choice, Facebook, LinkedIn, Twitter, internal.company.com, trusted-partner.com

**Finance Team (Priority 700):**
- Blocks: Adult Content, Nudity, Gambling, Drugs, Facebook, Twitter, example.com, test-site.com
- Allows: Abortion, Pro-Choice, LinkedIn, internal.company.com, trusted-partner.com

**Sales Team (Priority 800):**
- Blocks: Abortion, Pro-Choice, Adult Content, Nudity, Gambling, Drugs, Facebook, Twitter, test-site.com
- Allows: LinkedIn, example.com, internal.company.com, trusted-partner.com

**DEFAULT (Priority 60000):**
- Blocks: Adult Content, Nudity, Drugs, example.com
- Allows: Abortion, Pro-Choice, Gambling, Facebook, LinkedIn, Twitter, internal.company.com, test-site.com, trusted-partner.com

### Deduplication

Based on the sample data:
- **Marketing Users and Sales Team**: Have identical dispositions for all categories and FQDNs, sharing the same policies
- **Groups with identical block/allow combinations**: Consolidated into a single security profile with both group names in EntraGroups field

### Review Requirements

Rules requiring review (ReviewNeeded=Yes, Provision=No):
1. **Unmapped categories**: Abortion_Unmapped, Pro-Choice_Unmapped (in any policy containing these categories)
2. **Continue actions**: Gambling for Engineering Users group (Continue converted to Block)

## Sample Structure

The input CSV follows this matrix format:

```
Parent Category Name | Child Category Name | DEFAULT Disposition | Marketing Users Disposition | Engineering Users Disposition | Finance Team Disposition | Sales Team Disposition
---------------------|---------------------|---------------------|-----------------------------|------------------------------|--------------------------|------------------------
Abortion             | Abortion            | Do not block        | Block                       | Block                        | Do not block             | Block
Adult Material       | Adult Content       | Block               | Block                       | Block                        | Block                    | Block
User-Defined         | example.com         | Block               | Allow                       | Block                        | Block                    | Allow
```

- **Rows**: Web categories or FQDNs
- **Columns**: Security groups with disposition values
- **Cells**: Policy actions (Block, Allow, Continue, Do not block)

## Notes

- The sample includes realistic Forcepoint Web Security policy data
- Output file names include timestamps
- The log file contains detailed processing information including deduplication results
- Groups are processed in column order for priority assignment
- Empty dispositions are skipped (no action taken)
- User-Defined entries are treated as FQDNs (no category mapping needed)
- The DEFAULT group receives special handling (priority 60000, special placeholder in EntraGroups)

## Key Features Demonstrated

1. **Policy Deduplication**: Multiple groups with identical rules share policies
2. **Mixed Policies**: Groups with both Block and Allow rules create separate policies
3. **Unmapped Categories**: Categories without GSA mappings are flagged
4. **Continue Action**: Converted to Block with review flag
5. **FQDN Filtering**: User-Defined entries processed as individual FQDN rules
6. **Priority Assignment**: Column order determines security profile priority
7. **DEFAULT Handling**: Baseline policies for all users
8. **Review Workflow**: Per-rule review flags for manual verification
