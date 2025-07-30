# Migrate2GSA - Global Secure Access Migration Toolkit

## Overview

The **Migrate2GSA** toolkit provides automated export and import capabilities for migrating filtering configurations **from multiple sources** to Microsoft Global Secure Access (GSA). This multi-source migration framework enables organizations to:

- **Export configurations from various sources** (Zscaler, Palo Alto, existing GSA, etc.) to a standardized CSV format
- **Edit and customize** configurations in the intermediate CSV format before deployment
- **Import configurations** from CSV to create new GSA resources
- **Migrate configurations** between different security platforms and tenants
- **Audit and review** filtering policies with full administrative control

## 🏗️ Architecture & Design

### Multi-Source Support
The toolkit follows a **modular transformer architecture** where each source platform has its own dedicated transformer:

```
Source Platforms → Transformers → CSV Format → Provisioning → GSA Destination
```

#### Supported Sources
- **Microsoft Entra (GSA)** - Current implementation for testing and backup scenarios
- **Zscaler** - Planned (ZPA/ZIA configurations)
- **Palo Alto** - Planned (Prisma Access configurations)
- **Other platforms** - Extensible architecture for future sources

#### CSV as Intermediate Storage
The **CSV file serves as a universal intermediate format** that:
- ✅ **Decouples source from destination** - Any source can target any destination
- ✅ **Enables administrative review** - Full visibility of all configurations before deployment
- ✅ **Supports manual editing** - Administrators can modify, filter, or enhance rules
- ✅ **Provides audit trail** - Complete record of what will be deployed
- ✅ **Allows incremental migration** - Deploy configurations in phases
- ✅ **Enables testing workflows** - Validate configurations before production deployment

## 🚀 Quick Start

### Prerequisites
- PowerShell 5.1 or later
- Microsoft Graph PowerShell SDK
- Required permissions:
  - `NetworkAccess.Read.All` (for export)
  - `NetworkAccess.ReadWrite.All` (for import)
  - `Policy.Read.All`
  - `Directory.Read.All`

### Installation
```powershell
# Install required modules
Install-Module Microsoft.Graph.Authentication -Force
Install-Module Microsoft.Graph.Identity.DirectoryManagement -Force
```

## 📁 Tool Structure

The toolkit follows a **modular architecture** where each source platform has dedicated transformers:

```
Migrate2GSA/
├── Transformers/                              # Source-specific export tools
│   ├── Entra/                                # Microsoft Entra/GSA source
│   │   └── Get-GSA-FilteringProfiles2CSV.ps1 # GSA → CSV transformer
│   ├── Zscaler/                              # Planned: Zscaler source
│   │   └── Get-Zscaler-FilteringProfiles2CSV.ps1
│   └── PaloAlto/                             # Planned: Palo Alto source
│       └── Get-PA-FilteringProfiles2CSV.ps1
├── Provision2GSA/                            # Destination provisioning
│   └── Provision-GSAFilteringProfiles.ps1   # CSV → GSA provisioner
├── CSVs/                                     # Generated CSV files
└── logs/                                     # Execution logs
```

### Current Implementation Status
- ✅ **Entra Transformer** - Fully implemented (backup/testing scenarios)
- 🚧 **Zscaler Transformer** - Planned integration with existing ZScaler2GSA toolkit
- 🚧 **Palo Alto Transformer** - Future enhancement
- ✅ **GSA Provisioner** - Universal import tool supporting all sources

---

## 📤 Export Tool: Get-GSA-FilteringProfiles2CSV.ps1

### Purpose
**Entra/GSA Transformer** - Exports existing Global Secure Access filtering profiles, policies, and rules to the standardized CSV format. This transformer serves as:
- 🔄 **Backup tool** for existing GSA configurations
- 🧪 **Testing platform** for validating the migration workflow
- 📋 **Template generator** for understanding CSV structure before migrating from other sources

### Command Line Arguments

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `OutputBasePath` | String | No | Current directory | Base directory for output files and logs |
| `EnableDebugLogging` | Switch | No | False | Enable verbose debug logging |
| `TenantId` | String | No | Current tenant | Specific tenant ID for authentication |
| `ProfileNameFilter` | String | No | All profiles | Filter by specific filtering profile name |
| `IncludeMetadata` | Switch | No | False | Include additional metadata and timestamps |

### Usage Examples

```powershell
# Basic export - all profiles
.\Get-GSA-FilteringProfiles2CSV.ps1

# Export with debug logging
.\Get-GSA-FilteringProfiles2CSV.ps1 -EnableDebugLogging

# Export specific profile only
.\Get-GSA-FilteringProfiles2CSV.ps1 -ProfileNameFilter "Social Media"

# Export to specific directory with debug
.\Get-GSA-FilteringProfiles2CSV.ps1 -OutputBasePath "C:\GSA-Export" -EnableDebugLogging
```

### Output Structure
```
OutputBasePath/
├── CSVs/
│   └── YYYYMMDD_HHMMSS_GSA_Filtering_Import.csv
└── logs/
    └── YYYYMMDD_HHMMSS_GSA_Import.log
```

---

## 📥 Import Tool: Provision-GSAFilteringProfiles.ps1

### Purpose
**Universal GSA Provisioner** - Creates new Global Secure Access filtering profiles, policies, and rules from the standardized CSV file. This tool:
- 🔄 **Supports all source platforms** through the common CSV format
- ✅ **Validates configurations** before deployment
- 🎯 **Provides granular control** over what gets created
- 📊 **Offers dry-run capabilities** for safe testing

> **💡 Key Advantage**: The CSV format allows administrators to **review, modify, and customize** all configurations before deployment, regardless of the source platform.

### Command Line Arguments

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `CSVFilePath` | String | **Yes** | - | Path to the GSA filtering CSV file |
| `OutputBasePath` | String | No | Current directory | Base directory for output files and logs |
| `ValidateOnly` | Switch | No | False | Perform validation only without creating resources |
| `EnableDebugLogging` | Switch | No | False | Enable verbose debug logging |
| `TenantId` | String | No | Current tenant | Specific tenant ID for authentication |
| `ProfileNameFilter` | String | No | All profiles | Process only specific profile name |

### Usage Examples

```powershell
# Validate CSV without creating resources
.\Provision-GSAFilteringProfiles.ps1 -CSVFilePath "export.csv" -ValidateOnly

# Import all configurations
.\Provision-GSAFilteringProfiles.ps1 -CSVFilePath "export.csv"

# Import specific profile only
.\Provision-GSAFilteringProfiles.ps1 -CSVFilePath "export.csv" -ProfileNameFilter "Social Media"

# Import with debug logging
.\Provision-GSAFilteringProfiles.ps1 -CSVFilePath "export.csv" -EnableDebugLogging
```

---

## 📋 CSV Structure Definition

The **CSV format serves as the universal intermediate storage** between any source platform and GSA destination. This standardized format enables:

- 🔍 **Administrative Review** - Full visibility of all configurations before deployment
- ✏️ **Manual Editing** - Modify rules, priorities, descriptions, and targeting
- 🎯 **Selective Deployment** - Choose which rules to deploy using boolean flags
- 🔄 **Iterative Migration** - Deploy configurations in phases or test batches
- 📊 **Audit Trail** - Complete record of migration decisions and changes

### CSV Editing Workflow
1. **Source Export** → Generate CSV from any supported source platform
2. **Administrative Review** → Open CSV in Excel or text editor
3. **Customization** → Modify rules, update Conditional Access policies, adjust priorities
4. **Validation** → Run provisioning tool in validation mode
5. **Deployment** → Import customized configurations to GSA

### Core CSV Fields

### Required Fields (Core)

| Field Name | Type | Description | Example |
|------------|------|-------------|---------|
| `ProfileName` | String | Name of the filtering profile | "Social Media" |
| `PolicyName` | String | Name of the filtering policy | "Social NetWork" |
| `RuleName` | String | Name of the filtering rule | "social network" |
| `RuleType` | Enum | Type of filtering rule | "webCategory", "fqdn", "url", "ipAddress" |
| `Action` | Enum | Action to take | "allow", "block" |

### Destination Fields (Conditional)

| Field Name | Type | Required When | Description | Example |
|------------|------|---------------|-------------|---------|
| `DestinationFQDN` | String | RuleType = "fqdn" | Fully qualified domain name | "example.com" |
| `DestinationURL` | String | RuleType = "url" | Specific URL pattern | "https://example.com/*" |
| `DestinationIPAddress` | String | RuleType = "ipAddress" | Single IP address | "192.168.1.1" |
| `DestinationIPRange` | String | RuleType = "ipRange" | IP address range | "192.168.1.1-192.168.1.100" |
| `DestinationIPSubnet` | String | RuleType = "ipSubnet" | CIDR notation subnet | "192.168.1.0/24" |
| `WebCategoryName` | String | RuleType = "webCategory" | Web category name | "SocialNetworking" |
| `WebCategoryId` | String | RuleType = "webCategory" | Web category identifier | (Optional) |

### Profile & Policy Metadata

| Field Name | Type | Description | Example |
|------------|------|-------------|---------|
| `ProfileDescription` | String | Profile description | "Blocks social media sites" |
| `ProfilePriority` | Integer | Profile priority (1-1000) | 150 |
| `PolicyDescription` | String | Policy description | "Social networking policy" |
| `RuleDescription` | String | Rule description | "Imported from GSA configuration" |

### Conditional Access Integration

| Field Name | Type | Description | Example |
|------------|------|-------------|---------|
| `ConditionalAccessPolicyName` | String | Associated CA policy name | "SSE SWG Social Network Allowed" |
| `ConditionalAccessPolicyId` | String | CA policy GUID | "445e069e-7db8-44e9-a550-42bf6a8c7c46" |
| `TargetGroups` | String | Semicolon-separated group names | "Cloud-FRVPN; IT-Users" |
| `TargetUsers` | String | Semicolon-separated users | "John Doe (john@company.com)" |
| `ExcludeGroups` | String | Groups to exclude | "IT-Admins" |
| `ExcludeUsers` | String | Users to exclude | "admin@company.com" |

### Control & Restriction Fields

| Field Name | Type | Description | Example |
|------------|------|-------------|---------|
| `TimeRestriction` | String | Time-based restrictions | "9AM-5PM Mon-Fri" |
| `LocationRestriction` | String | Location-based restrictions | "Corporate Network" |
| `DeviceRestriction` | String | Device-based restrictions | "Managed Devices Only" |
| `Enabled` | Boolean | Whether rule is enabled | true |
| `Priority` | Integer | Rule priority | 10 |

### Tracking & Audit Fields

| Field Name | Type | Description | Example |
|------------|------|-------------|---------|
| `SourceSystem` | String | Origin system identifier | "GSA-Import" |
| `SourceRuleId` | String | Original rule GUID | "abc123..." |
| `SourcePolicyName` | String | Original policy name | "Original Policy" |
| `CreatedProfileId` | String | Created profile GUID | "def456..." |
| `CreatedPolicyId` | String | Created policy GUID | "ghi789..." |
| `CreatedRuleId` | String | Created rule GUID | "jkl012..." |

### Status & Processing Fields

| Field Name | Type | Description | Example |
|------------|------|-------------|---------|
| `CreateProfile` | Boolean | Whether to create new profile | true |
| `CreatePolicy` | Boolean | Whether to create new policy | false |
| `CreateRule` | Boolean | Whether to create new rule | true |
| `ValidationStatus` | String | Validation result | "Valid", "Error" |
| `ValidationMessage` | String | Validation details | "Missing required field" |
| `ConflictDetected` | Boolean | Whether conflicts found | false |
| `ConflictingRules` | String | Conflicting rule details | "" |
| `ProvisioningStatus` | String | Provisioning status | "Pending", "Success", "Failed" |
| `ProvisioningMessage` | String | Provisioning result details | "Successfully created" |

### Date & Metadata Fields

| Field Name | Type | Description | Example |
|------------|------|-------------|---------|
| `CreatedDate` | String | Creation timestamp | "30/07/2025 12:19:35" |
| `ProcessedDate` | String | Processing timestamp | "30/07/2025 13:45:22" |
| `LastModifiedDate` | String | Last modification timestamp | "30/07/2025 12:19:35" |
| `Notes` | String | Additional notes | "Imported from existing GSA" |
| `Tags` | String | Comma-separated tags | "gsa-import,web-category" |

---

## 🔧 Validation Rules

### Rule Type Validation

| Rule Type | Required Field | Validation |
|-----------|----------------|------------|
| `fqdn` | `DestinationFQDN` | Must be valid domain name |
| `webCategory` | `WebCategoryName` | Must be recognized category |
| `ipAddress` | `DestinationIPAddress` | Must match IP format (x.x.x.x) |
| `ipRange` | `DestinationIPRange` | Must be valid range format |
| `ipSubnet` | `DestinationIPSubnet` | Must match CIDR format (x.x.x.x/y) |
| `url` | `DestinationURL` | Must be valid URL pattern |

### Action Validation
- Must be one of: `allow`, `block`

### Required Field Validation
- `ProfileName`, `PolicyName`, `RuleName`, `RuleType`, `Action` are mandatory

---

## 🔄 Migration Workflow

### Multi-Source Migration Process

1. **Source Export** (Platform-Specific Transformer)
   ```powershell
   # From existing GSA (backup/testing)
   .\Transformers\Entra\Get-GSA-FilteringProfiles2CSV.ps1 -OutputBasePath "C:\Migration"
   
   # From Zscaler (planned)
   .\Transformers\Zscaler\Get-Zscaler-FilteringProfiles2CSV.ps1 -OutputBasePath "C:\Migration"
   
   # From Palo Alto (planned)
   .\Transformers\PaloAlto\Get-PA-FilteringProfiles2CSV.ps1 -OutputBasePath "C:\Migration"
   ```

2. **Administrative Review and Customization**
   ```
   📝 Open: C:\Migration\CSVs\YYYYMMDD_HHMMSS_GSA_Filtering_Import.csv
   
   ✏️ Edit Rules:
   - Modify rule names and descriptions
   - Update Conditional Access policy references
   - Adjust priorities and actions
   - Add/remove rules as needed
   - Set CreateProfile/CreatePolicy/CreateRule flags for selective deployment
   
   💾 Save: Customized CSV ready for deployment
   ```

3. **Validation** (Dry Run)
   ```powershell
   .\Provision2GSA\Provision-GSAFilteringProfiles.ps1 -CSVFilePath "export.csv" -ValidateOnly
   ```

4. **Selective Deployment**
   ```powershell
   # Deploy all configurations
   .\Provision2GSA\Provision-GSAFilteringProfiles.ps1 -CSVFilePath "export.csv"
   
   # Deploy specific profile only
   .\Provision2GSA\Provision-GSAFilteringProfiles.ps1 -CSVFilePath "export.csv" -ProfileNameFilter "Social Media"
   ```

### Benefits of CSV Intermediate Format
- ✅ **Platform Independence** - Same destination tool works with any source
- ✅ **Administrative Control** - Full review and modification capabilities  
- ✅ **Incremental Migration** - Deploy rules in phases using boolean flags
- ✅ **Testing Workflow** - Validate before production deployment
- ✅ **Audit Trail** - Complete record of migration decisions

---

## 📊 Supported Rule Types

| Type | Description | Use Case |
|------|-------------|----------|
| `fqdn` | Domain-based filtering | Block/allow specific domains |
| `webCategory` | Category-based filtering | Block entire categories (Social Media, Gaming) |
| `ipAddress` | Single IP filtering | Block/allow specific servers |
| `ipRange` | IP range filtering | Block/allow IP ranges |
| `ipSubnet` | Subnet filtering | Block/allow entire subnets |
| `url` | URL pattern filtering | Block/allow specific URL patterns |

---

## 🔍 Troubleshooting

### Common Issues

**Authentication Errors**
- Ensure proper Graph permissions are granted
- Use `-TenantId` parameter for specific tenant

**Validation Errors**
- Check required fields are populated
- Verify rule types match destination fields
- Ensure actions are "allow" or "block"

**Import Failures**
- Run with `-ValidateOnly` first
- Check logs in the `logs` folder
- Use `-EnableDebugLogging` for detailed output

### Log Files
- Logs are automatically created in `OutputBasePath/logs/`
- Each execution creates timestamped log files
- Debug logging provides detailed API call information

---

## 📞 Support & Integration

### Integration with ZScaler2GSA Toolkit
This Migrate2GSA toolkit is designed to complement the existing **ZScaler2GSA** migration tools:
- 🔗 **Shared CSV Format** - Compatible with ZScaler2GSA export formats
- 🔄 **Unified Workflow** - Consistent migration experience across platforms
- 📈 **Extensible Architecture** - Easy addition of new source platforms

### Planned Enhancements
- **Zscaler Integration** - Direct integration with ZPA/ZIA APIs
- **Palo Alto Support** - Prisma Access configuration export
- **Advanced Filtering** - Rule deduplication and conflict detection
- **Bulk Operations** - Multi-tenant and batch processing capabilities

For issues and feature requests, please refer to the main ZScaler2GSA documentation.

---

*Last Updated: July 30, 2025*
