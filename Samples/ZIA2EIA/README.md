# ZIA to EIA Conversion Samples

This directory contains sample files for testing the `Convert-ZIA2EIA` function.

## Input Files

### sample_url_filtering_policy.json
Sample ZScaler Internet Access URL filtering policy export demonstrating:
- Enabled and disabled rules
- Rules with users and groups
- Rules with no users/groups (default assignment)
- BLOCK, ALLOW, and CAUTION actions
- References to custom and predefined categories
- Priority conflicts
- Deleted users
- Rules with timeWindows (processed normally)

### sample_url_categories.json
Sample ZScaler URL categories export demonstrating:
- Custom categories with various URL types (FQDNs, URLs, IP addresses)
- URLs with schemas, ports, query strings, and fragments (cleaned during processing)
- Wildcard patterns (*.domain.com, domain*.com)
- Duplicate entries (removed during deduplication)
- Empty custom categories (skipped)
- Predefined categories (no URL lists)
- Non-URL category type (skipped)

### sample_ZIA2EIA-CategoryMappings.json
Sample category mappings file demonstrating:
- Mapped predefined categories (with GSACategory)
- Unmapped categories with "Unmapped" value
- Unmapped categories with empty string
- Unmapped categories with null value

## Output Files

### sample_output_Policies.csv
Expected output showing:
- Custom category policies (Block and Allow versions)
- Predefined category policies (one per rule)
- Multiple RuleType values (FQDN, URL, ipAddress, webCategory)
- Destinations grouped by base domain
- ReviewNeeded flags for unmapped categories and CAUTION actions
- ReviewDetails with semicolon-separated reasons

### sample_output_SecurityProfiles.csv
Expected output showing:
- Security profiles with user and group assignments
- PolicyLinks referencing multiple policies
- Priority conflict resolution (urlRule1 and urlRule5 both have order=10)
- Default group assignment for rules with no users/groups

## Testing

To test with these sample files:

```powershell
# Navigate to the samples directory
cd C:\Git\Migrate2GSAPublic\Samples\ZIA2EIA

# Run the conversion
Convert-ZIA2EIA `
    -UrlFilteringPolicyPath "sample_url_filtering_policy.json" `
    -UrlCategoriesPath "sample_url_categories.json" `
    -CategoryMappingsPath "sample_ZIA2EIA-CategoryMappings.json" `
    -OutputBasePath "." `
    -EnableDebugLogging

# Review the output files
# - [timestamp]_EIA_Policies.csv
# - [timestamp]_EIA_SecurityProfiles.csv
# - [timestamp]_Convert-ZIA2EIA.log
```

## Expected Behavior

### Custom Categories
- **Custom_Web_Cat_01**: Processed as Block policy (used by urlRule1, urlRule3, urlRule5)
- **Dev_Tools**: Processed as Allow policy (used by urlRule2)
- **Test_Category**: Processed as Block policy (used by urlRule3)
- **Empty_Category**: Skipped (no destinations)

### URL Processing
- Schemas removed: `https://site-with-schema.com` → `site-with-schema.com`
- Ports removed: `domain-with-port.com:8080` → `domain-with-port.com`
- Query strings removed: `url-with-query.com?param=value` → `url-with-query.com`
- Fragments removed: `url-with-fragment.com#section` → `url-with-fragment.com`
- IPv4 with port/path: `192.168.1.200:8080` → skipped
- Duplicates removed: `duplicate.com` appears only once

### Classification
- **FQDNs**: `example.com`, `*.contoso.com`, `company.com`, etc.
- **URLs**: `test.*.wildcard.com`, `url-with-path.com/path/to/resource`, etc.
- **IP Addresses**: `192.168.1.100`, `10.0.0.5`

### Category Mappings
- **Mapped**: OTHER_ADULT_MATERIAL → AdultContent, SOCIAL_NETWORKING → SocialNetworking, INTERNET_GAMBLING → Gambling
- **Unmapped**: PHISHING → PHISHING_Unmapped, SPAM → SPAM_Unmapped, MALWARE_SITES → MALWARE_SITES_Unmapped

### Rule Processing
- **urlRule1**: Priority 100, Block, 2 users, 2 groups, references Custom_Web_Cat_01 and 2 predefined categories
- **urlRule2**: Priority 200, Allow, 0 users, 1 group, references Dev_Tools (creates Allow policy)
- **urlRule3**: Priority 300, CAUTION→Block (flagged for review), no users/groups (default assignment), references Test_Category and predefined categories
- **urlRule4**: Skipped (disabled)
- **urlRule5**: Priority 101 (conflict with urlRule1, incremented from 100), Block, 1 user (1 deleted user skipped), 1 group

## Notes

- The sample files include various edge cases to test the function's robustness
- Output file names include timestamps, so compare content rather than exact filenames
- The log file contains detailed processing information including warnings for cleaned URLs and skipped entries
