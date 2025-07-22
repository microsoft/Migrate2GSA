# ZScaler2GSA AI Coding Agent Instructions

## Project Overview

ZScaler2GSA is a PowerShell-based migration toolkit for transitioning from **Zscaler services** (ZPA/ZIA) to **Microsoft Entra Private Access** within Global Secure Access (GSA). The toolkit provides automated configuration export, transformation, and provisioning capabilities.

## Architecture & Components

### Major Components
- **ZPA2EPA/**: Zscaler Private Access to Entra Private Access migration tools
- **ZIA2EIA/**: Zscaler Internet Access export tools
- **HelperTools/**: Utilities for validation and comparison

### Key Workflows
1. **Export** → **Transform** → **Provision** pipeline for ZPA configurations
2. **Export-only** workflow for ZIA configurations (transformation pending)
3. **Validation** workflow using helper tools for data integrity checks

## Critical Developer Knowledge

### PowerShell Class-Based Architecture
All main export scripts use PowerShell classes for API management:
- **ZPABackup** class handles OAuth2 authentication and ZPA API operations
- **ZIABackup** class manages session-based authentication with API key obfuscation
- Classes encapsulate authentication, session management, and batch operations

### Authentication Patterns
- **ZPA**: OAuth2 client credentials flow with SecureString protection
- **ZIA**: Session-based with timestamp-obfuscated API keys using official ZIA algorithm
- **Entra**: Microsoft Graph PowerShell SDK with required scopes: `Application.ReadWrite.All`, `Group.Read.All`, `Directory.Read.All`

### Data Flow Architecture
```
ZPA/ZIA APIs → JSON Export → CSV Transformation → Entra Provisioning
```

### Error Handling Strategy
- **Comprehensive logging** with color-coded console output and file logging
- **Graceful degradation**: Individual failures don't stop batch operations
- **Retry-friendly**: Failed operations marked for re-execution via CSV status columns
- **Validation-first**: All inputs validated before processing begins

## Project-Specific Conventions

### File Naming Patterns
- Export scripts: `Export-{Service}Config.ps1`
- Transformation: `Transform-{Source}2{Target}.ps1`
- Provisioning: `Provision-{Target}Config.ps1`
- Timestamped outputs: `YYYYMMDD_HHMMSS_{purpose}.{ext}`

### Parameter Conventions
- **Mandatory security**: All credentials as `[SecureString]`
- **Validation attributes**: File paths validated with `[ValidateScript]`
- **FilterPattern parameters**: Support wildcard matching with `*` and `?`
- **WhatIf support**: All provisioning scripts support dry-run mode

### Logging Standards
```powershell
Write-Log "message" -Level "INFO|WARN|ERROR|SUCCESS|DEBUG" -Component "ComponentName"
```

### CSV Data Structure Patterns
All transformation outputs include standard columns:
- **OriginalAppName/EnterpriseAppName**: Source and target naming
- **Conflict/ConflictingEnterpriseApp**: GSA-style conflict detection results  
- **Provision**: "Yes/No" flag for controlling batch operations
- **ProvisioningResult**: Status tracking for retry scenarios

## Integration & Dependencies

### External API Integration
- **Zscaler APIs**: REST with different auth patterns (OAuth2 vs session-based)
- **Microsoft Graph**: PowerShell SDK with app registration requirements
- **Entra Private Access**: Beta APIs requiring specific permissions

### Conflict Detection Algorithm
Uses **interval-based overlap detection** for:
- IP ranges (CIDR expansion to integer ranges)
- Port ranges (single ports and ranges)
- FQDN conflicts with wildcard domain handling

### Data Processing Patterns
- **Deduplication**: ID-based using hashtables for O(1) lookup
- **Filtering**: Multi-stage with exact match and wildcard patterns
- **Grouping**: Application-centric with per-segment processing
- **Batching**: Progress tracking with configurable batch sizes

## Development Workflow

### Script Execution Order
1. Run export scripts with appropriate credentials
2. Use helper tools to validate data integrity
3. Run transformation with filtering as needed
4. Review and resolve conflicts in generated CSV
5. Replace placeholder values (ConditionalAccessPolicy, EntraGroup, ConnectorGroup)
6. Execute provisioning with WhatIf mode first

### Testing Approach
- **WhatIf mode**: All provisioning scripts support dry-run
- **Incremental filtering**: Use name patterns to test subsets
- **Validation scripts**: Helper tools verify data consistency
- **Output verification**: Check timestamped CSV files and logs

### Debugging Best Practices
- Enable `$EnableDebugLogging` for detailed operation tracing  
- Check `script.log` files for complete execution history
- Use `Compare-AppSegmentsAndGroups.ps1` to verify data relationships
- Validate JSON structure with built-in format detection logic

## Key Files to Reference

- **`Export-ZPAConfig.ps1`**: OAuth2 authentication and API batching patterns
- **`Transform-ZPA2EPA.ps1`**: Complex filtering, conflict detection, and CSV generation
- **`Provision-EntraPrivateAccessConfig.ps1`**: Graph API integration and retry logic
- **`Compare-AppSegmentsAndGroups.ps1`**: Data validation and consistency checking patterns

## Common Gotchas

- **JSON format variations**: APIs return both direct arrays and paginated objects with `.list` property
- **ID normalization**: Always convert IDs to strings for hashtable keys and comparisons  
- **SecureString handling**: Convert to plain text only within try-catch blocks
- **Progress reporting**: Use `Write-Progress` for long-running operations with time estimates
- **CSV placeholder replacement**: Scripts generate templates requiring manual value replacement before provisioning
