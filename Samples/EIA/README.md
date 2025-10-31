# Entra Internet Access Provisioning - Sample CSV Files

This directory contains sample CSV files for provisioning Entra Internet Access filtering policies, security profiles, and Conditional Access policies.

## Files

### sample_policies.csv
Contains web content filtering policies, TLS inspection policies, and their rules.

**Included Policies:**
- **Dev_Tools-Allow** - Web content filtering policy allowing development tools (GitHub, StackOverflow, Microsoft Docs)
- **Social_Media-Block** - Web content filtering policy blocking social media and entertainment sites
- **Productivity-Allow** - Web content filtering policy allowing business productivity tools (Office, Teams)
- **Security_Threats-Block** - Web content filtering policy blocking malware, phishing, spyware
- **TLS_Internal-Bypass** - TLS inspection policy bypassing internal corporate sites
- **TLS_Finance-Inspect** - TLS inspection policy inspecting financial traffic
- **Marketing_Sites-Allow** - Web content filtering policy allowing marketing analytics tools

### sample_security_profiles.csv
Contains security profiles with policy links and Conditional Access policies.

**Included Profiles:**
- **Profile_Finance_Strict** - Finance team profile (blocks threats/social, inspects financial TLS)
- **Profile_Marketing_Standard** - Marketing team profile (blocks threats/social, allows marketing tools)
- **Profile_Developers** - Developer profile (blocks threats, allows dev tools, bypasses internal TLS)
- **Profile_General_Users** - General users profile (blocks threats/social, allows productivity tools)
- **Profile_IT_Admin_NoCA** - IT admin profile without CA policy (allows dev tools and productivity)

## Customization Required

Before running provisioning, you must customize these files:

### 1. Update User Principal Names
Replace placeholder user principal names with actual users from your tenant:
```csv
# Replace in sample_security_profiles.csv
john.doe@contoso.com → actual.user@yourtenant.com
jane.smith@contoso.com → another.user@yourtenant.com
marketing.team@contoso.com → marketing@yourtenant.com
dev.lead@contoso.com → devlead@yourtenant.com
_Replace_Me → your.user@yourtenant.com
```

### 2. Update Group Display Names
Replace placeholder group names with actual groups from your tenant:
```csv
# Replace in sample_security_profiles.csv
Finance_Group → Your-Finance-Group
Executives_Group → Your-Executives-Group
Marketing_Group → Your-Marketing-Group
Developers_Group → Your-Dev-Group
Engineering_Group → Your-Engineering-Group
All_Users_Group → Your-All-Users-Group
```

### 3. Update Internal Domains
Replace placeholder internal domains with your organization's domains:
```csv
# Replace in sample_policies.csv
*.internal.contoso.com → *.internal.yourdomain.com
*.corp.local → *.corp.yourdomain.local
intranet.contoso.com → intranet.yourdomain.com
*.internal-bank.com → *.yourbank.com
secure-finance.contoso.com → secure-finance.yourdomain.com
```

### 4. Review and Adjust Policies
- Add or remove FQDNs, URLs, and web categories as needed
- Adjust policy actions (Allow/Block, Bypass/Inspect) based on your requirements
- Modify policy descriptions for your organization

### 5. Review and Adjust Priorities
- Security Profile priorities (100, 200, 300, etc.) - lower numbers = higher priority
- Policy Link priorities within each profile (50, 100, 150, etc.) - evaluation order within profile

## Usage Examples

### Preview Provisioning (WhatIf)
```powershell
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath ".\Samples\EIA\sample_policies.csv" `
    -SecurityProfilesCsvPath ".\Samples\EIA\sample_security_profiles.csv" `
    -WhatIf
```

### Provision Policies Only (No Security Profiles)
```powershell
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath ".\Samples\EIA\sample_policies.csv"
```

### Provision Everything
```powershell
# Ensure you've customized users and groups first!
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath ".\Samples\EIA\sample_policies.csv" `
    -SecurityProfilesCsvPath ".\Samples\EIA\sample_security_profiles.csv"
```

### Provision Without CA Policies
```powershell
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath ".\Samples\EIA\sample_policies.csv" `
    -SecurityProfilesCsvPath ".\Samples\EIA\sample_security_profiles.csv" `
    -SkipCAPoliciesProvisioning
```

### Test Single Policy
```powershell
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath ".\Samples\EIA\sample_policies.csv" `
    -PolicyName "Dev_Tools-Allow"
```

## Important Notes

1. **Always run WhatIf first** to preview what will be provisioned
2. **Validate users and groups** exist in your tenant before provisioning
3. **CA policies are created in disabled state** - review and enable manually after validation
4. **All objects are suffixed with [Migrate2GSA]** for easy identification
5. **Re-running is safe** - the script is idempotent and will skip existing objects

## See Also

- [EntraInternetAccessProvisioning.md](../../Docs/EntraInternetAccessProvisioning.md) - Full documentation
- [Microsoft Graph API - Network Access](https://learn.microsoft.com/en-us/graph/api/resources/networkaccess-overview)
