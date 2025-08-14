# ZIA Configuration Export Tool

## Overview

This PowerShell script provides a comprehensive backup solution for Zscaler Internet Access (ZIA) configurations. It connects to the ZIA API to export various policy configurations to JSON files for backup, migration, or analysis purposes.

## Purpose

The `Export-ZIAConfig.ps1` script is designed to:

- Create complete backups of ZIA configurations
- Export configurations to structured JSON files
- Support migration planning from ZIA to Microsoft Entra Internet Access (EIA)
- Provide a foundation for configuration analysis and comparison

## Features

- **Comprehensive Configuration Export**: Backs up multiple ZIA policy types
- **Secure Authentication**: Uses obfuscated API keys following ZIA security standards
- **Timestamped Backups**: Creates organized backup directories with timestamps
- **Individual and Complete Exports**: Saves both individual configuration files and a complete backup
- **Detailed Logging**: Provides verbose output for monitoring backup progress
- **Error Handling**: Robust error handling with detailed diagnostic information

## Supported Configuration Types

The script exports the following ZIA configuration types:

| Configuration Type | Description | API Endpoint |
|-------------------|-------------|--------------|
| URL Filtering Policy | Web content filtering rules and policies | `/urlFilteringRules` |
| URL Categories | Custom and standard URL categories | `/urlCategories` |
| SSL Inspection Policy | SSL/TLS inspection rules and settings | `/sslInspectionRules` |
| File Type Control | File upload/download control policies | `/fileTypeRules` |
| Firewall Control | Network firewall filtering rules | `/firewallFilteringRules` |

## Prerequisites

- PowerShell 5.1 or later
- Network connectivity to ZIA API endpoints
- Valid ZIA administrator credentials
- ZIA API key/token with appropriate permissions

## Parameters

### Required Parameters

- **`Username`** (string): ZIA administrator username
- **`Password`** (SecureString): ZIA administrator password
- **`ApiKey`** (string): ZIA API key/token

### Optional Parameters

- **`BaseUrl`** (string): ZIA API base URL (defaults to `https://zsapi.zscaler.net/api/v1`)
- **`OutputDirectory`** (string): Output directory for backup files (defaults to script directory)

## Usage Examples

### Basic Usage

```powershell
# Prompt for secure password input
$securePassword = Read-Host "Enter ZIA Password" -AsSecureString

# Run the backup with minimum required parameters
.\Export-ZIAConfig.ps1 -Username "admin@company.com" -Password $securePassword -ApiKey "your-api-key"
```

### Advanced Usage with Custom Settings

```powershell
# Convert plain text password to SecureString (for automation scenarios)
$securePassword = ConvertTo-SecureString "your-password" -AsPlainText -Force

# Run backup with custom API URL and output directory
.\Export-ZIAConfig.ps1 `
    -Username "admin@company.com" `
    -Password $securePassword `
    -ApiKey "your-api-key" `
    -BaseUrl "https://admin.zscaler.net/api/v1" `
    -OutputDirectory "C:\ZIA-Backups"
```

## Migration to Entra Internet Access

This script is part of a larger migration toolkit for moving from Zscaler to Microsoft Entra Internet Access. The exported configurations can be:

- Analyzed for policy coverage and gaps
- Transformed to EIA equivalent configurations
- Used for migration planning and validation
- Compared with post-migration EIA settings

## Troubleshooting

### Common Issues

1. **Authentication Failures**
   - Verify username, password, and API key
   - Check API base URL for your ZIA instance
   - Ensure account has administrative privileges

2. **API Connection Issues**
   - Verify network connectivity to ZIA API endpoints
   - Check firewall and proxy settings
   - Validate API base URL format

3. **Permission Errors**
   - Ensure API key has required read permissions
   - Verify account access to configuration endpoints
   - Check ZIA role assignments

### Verbose Output

Use PowerShell's `-Verbose` parameter for detailed execution information:

```powershell
.\Export-ZIAConfig.ps1 -Username "admin@company.com" -Password $securePassword -ApiKey "your-api-key" -Verbose
```

