---
sidebar_position: 1
title: Export Netskope Config
---

## Overview

`Export-NetskopeConfig` is a PowerShell function that exports Netskope configurations to JSON files for backup and migration purposes. It connects to the Netskope API using an API token and exports various configuration types including Private Access applications, publishers, URL lists, policies, and custom profiles.

## Prerequisites

- PowerShell 7 or higher
- Network access to your Netskope tenant
- Valid Netskope API token with appropriate permissions
- `Migrate2GSA` PowerShell module installed

### Netskope API Token

To generate an API token in Netskope:

1. Log in to your Netskope tenant portal
2. Navigate to **Settings** > **Tools** > **REST API v2**
3. Click **New Token**
4. Provide a name for the token
5. Select appropriate permissions (read access required for all configuration endpoints)
6. Copy the generated token (you won't be able to see it again)

### Required API Permissions

The API token must have read permissions for the following endpoints:
- Private Access applications (`/api/v2/steering/apps/private`)
- Publishers (`/api/v2/infrastructure/publishers`)
- URL Lists (`/api/v2/policy/urllist`)
- NPA Policies (`/api/v2/policy/npa`)
- NPA Policy Groups (`/api/v2/policy/npa/policygroups`)
- Custom Categories (`/api/v2/profiles/customcategories`)
- Destinations (`/api/v2/profiles/destinations`)

## Syntax

```powershell
Export-NetskopeConfig 
    -ApiToken <SecureString>
    -TenantUrl <String>
    [-OutputDirectory <String>]
    [-RequestDelay <Int32>]
    [<CommonParameters>]
```

## Parameters

### -ApiToken

The Netskope API token. Must be provided as a SecureString for security.

- **Type**: SecureString
- **Required**: Yes
- **Position**: Named
- **Default value**: None
- **Accept pipeline input**: False

### -TenantUrl

The base tenant URL (e.g., "https://contoso.goskope.com"). Must be a valid HTTPS URL without trailing slashes.

- **Type**: String
- **Required**: Yes
- **Position**: Named
- **Default value**: None
- **Accept pipeline input**: False

### -OutputDirectory

The output directory for backup files. If not specified, uses the current directory.

- **Type**: String
- **Required**: No
- **Position**: Named
- **Default value**: Current directory
- **Accept pipeline input**: False

### -RequestDelay

Delay in seconds between API requests to avoid rate limiting.

- **Type**: Int32
- **Required**: No
- **Position**: Named
- **Default value**: 1
- **Accept pipeline input**: False
- **Valid range**: 0-60

## Outputs

**System.Boolean**

Returns `$true` if the backup completed successfully, `$false` otherwise.

## Examples

### Example 1: Basic Export

```powershell
# Import the module
Import-Module Migrate2GSA

# Prompt for API token securely
$token = Read-Host "Enter API Token" -AsSecureString

# Export configuration
Export-NetskopeConfig -ApiToken $token -TenantUrl "https://contoso.goskope.com"
```

This example performs a basic export with default settings.

### Example 2: Export to Custom Directory

```powershell
# Convert token to SecureString
$token = ConvertTo-SecureString "your-api-token" -AsPlainText -Force

# Export to specific directory
Export-NetskopeConfig `
    -ApiToken $token `
    -TenantUrl "https://contoso.goskope.com" `
    -OutputDirectory "C:\Backups\Netskope"
```

This example exports configuration to a custom directory.

### Example 3: Export with Custom Request Delay

```powershell
$token = Read-Host "Enter API Token" -AsSecureString

Export-NetskopeConfig `
    -ApiToken $token `
    -TenantUrl "https://contoso.goskope.com" `
    -RequestDelay 2
```

This example adds a 2-second delay between API requests to handle rate limiting.

### Example 4: Export with Debug Logging

```powershell
$token = Read-Host "Enter API Token" -AsSecureString

Export-NetskopeConfig `
    -ApiToken $token `
    -TenantUrl "https://contoso.goskope.com" `
    -Debug
```

This example enables debug mode to see raw API responses and detailed logging.


## Output Structure

The function creates a timestamped backup directory with the following structure:

```
backup_20251015_143022/
├── private_apps.json
├── publishers.json
├── url_lists.json
├── npa_policies.json
├── npa_policy_groups.json
├── custom_categories.json
├── destinations.json
├── netskope_complete_backup.json
└── Export-NetskopeConfig.log
```

### Individual Configuration Files

Each configuration type is saved as a separate JSON file:

- **private_apps.json** - Netskope Private Access applications
- **publishers.json** - Netskope Publishers (connectors)
- **url_lists.json** - Custom URL lists used in policies
- **npa_policies.json** - Netskope Private Access policies
- **npa_policy_groups.json** - NPA policy groups
- **custom_categories.json** - Custom URL categories
- **destinations.json** - Network destinations and locations

### Complete Backup File

The `netskope_complete_backup.json` file contains all configurations in a single file with metadata:

```json
{
    "timestamp": "20251015_143022",
    "tenant_url": "https://contoso.goskope.com",
    "backup_type": "Netskope_Configuration",
    "configurations": {
        "private_apps": [...],
        "publishers": [...],
        "url_lists": [...],
        "npa_policies": [...],
        "npa_policy_groups": [...],
        "custom_categories": [...],
        "destinations": [...]
    }
}
```

## Configuration Objects Exported

The function exports the following configuration objects:

| Object Type | API Endpoint | Description |
|------------|--------------|-------------|
| Private Applications | `/api/v2/steering/apps/private` | Netskope Private Access applications |
| Publishers | `/api/v2/infrastructure/publishers` | Netskope Publishers (similar to connectors) |
| URL Lists | `/api/v2/policy/urllist` | Custom URL lists used in policies |
| NPA Policies | `/api/v2/policy/npa` | Netskope Private Access policies |
| NPA Policy Groups | `/api/v2/policy/npa/policygroups` | NPA policy groups |
| Custom Categories | `/api/v2/profiles/customcategories` | Custom URL categories |
| Destinations | `/api/v2/profiles/destinations` | Network destinations and locations |

## Error Handling

The function handles various error conditions gracefully:

### Authentication Errors

- **401 Unauthorized**: Invalid or expired API token
- **403 Forbidden**: Insufficient permissions for endpoint
- **404 Not Found**: Endpoint not available or feature not enabled

### API Errors

- **429 Rate Limit**: Rate limit exceeded (increase RequestDelay parameter)
- **500 Server Error**: Netskope API server error

### Behavior on Errors

- If one configuration type fails to export, the function continues with remaining types
- All errors are logged to the log file
- A summary is displayed at the end showing success/failure counts
- The function returns `$false` if no configurations were successfully exported


## Logging

The function uses the internal `Write-LogMessage` function for all logging:

- **INFO**: General information and progress updates
- **SUCCESS**: Successful operations
- **WARN**: Warnings for missing data or failed exports
- **ERROR**: Error conditions
- **DEBUG**: Detailed debugging information (when `-Debug` is used)
- **SUMMARY**: Summary information and statistics

Log files are automatically created in the backup directory with the name `Export-NetskopeConfig.log`.

### Debug Mode

When the `-Debug` parameter is specified:
- Raw API responses are logged for troubleshooting
- Additional detailed information is displayed
- Useful for diagnosing API issues or unexpected behavior

## Rate Limiting

Netskope API does not have well-documented rate limits, but the function includes configurable delays:

- Default delay: 1 second between requests
- Adjustable via `-RequestDelay` parameter (0-60 seconds)
- If you encounter rate limiting (HTTP 429), increase the delay

## Troubleshooting

### "Invalid tenant URL" Error

**Cause**: Tenant URL doesn't meet validation requirements

**Solution**: Ensure URL:
- Uses HTTPS protocol
- Is a valid URI format
- Has no trailing slashes
- Example: `https://contoso.goskope.com`

### "Authentication failed: Invalid or expired API token"

**Cause**: API token is incorrect or has expired

**Solution**:
1. Generate a new API token in Netskope portal
2. Verify token has required permissions
3. Ensure token is correctly converted to SecureString

### "Endpoint not available or feature not enabled"

**Cause**: API endpoint returns 404 (not found)

**Solution**:
1. Verify feature is enabled in your Netskope tenant
2. Check API token has appropriate permissions
3. Confirm tenant URL is correct

### No Data Exported

**Cause**: Configuration objects may be empty or not configured

**Solution**:
- Check the log file for specific errors
- Verify configurations exist in Netskope portal
- Review API token permissions

### Rate Limiting Errors

**Cause**: Too many requests to Netskope API

**Solution**:
- Increase the `-RequestDelay` parameter value
- Wait before retrying the export

## Feedback and Support

For issues, questions, or feedback, please refer to the main repository documentation.
