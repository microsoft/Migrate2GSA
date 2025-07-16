# ZScaler2GSA

This is experimental code, use it at your own risk.

## Export-ZPAConfig.ps1 - ZPA Configuration Export Tool

### Overview

This PowerShell script provides a comprehensive backup solution for your Zscaler Private Access (ZPA) environment. It connects to the ZPA management API and exports all critical configuration elements to JSON files, ensuring you have a complete snapshot of your ZPA setup for backup, auditing, or migration purposes.

### What It Does

The script automatically exports the following ZPA configurations:

- **Application Segments** - Your published applications and services
- **Segment Groups** - Logical groupings of application segments
- **Server Groups** - Collections of application servers
- **App Connectors** - Connector instances and their configurations
- **Connector Groups** - Groupings of app connectors
- **Access Policies** - Security policies controlling user access
- **Policy Sets** - Collections of related policies
- **Service Edges** - Cloud-based access points
- **Service Edge Groups** - Groupings of service edges
- **Identity Provider Controllers** - IdP integrations and settings
- **SCIM Groups** - User group mappings from identity providers
- **SAML Attributes** - SAML assertion configurations
- **Machine Groups** - Device-based access groupings
- **Posture Profiles** - Device compliance policies
- **Trusted Networks** - Network location definitions

### Key Features

- **Complete Configuration Export**: Captures all major ZPA configuration elements in a single run
- **Timestamped Backups**: Each backup is organized with date/time stamps for easy version tracking
- **Multiple Output Formats**: Creates both individual configuration files and a complete consolidated backup
- **Secure Authentication**: Uses OAuth2 client credentials with SecureString for enhanced security
- **Error Handling**: Robust error handling with detailed logging
- **Flexible Output**: Configurable backup directory location

### Security Features

- **SecureString Protection**: Client secrets are encrypted in memory and never visible in command history
- **Minimal Exposure**: Credentials are only decrypted briefly during API authentication
- **Read-Only Operations**: Script only reads configuration data, never modifies ZPA settings
- **Automatic Cleanup**: Sensitive data is cleared from memory immediately after use

### Requirements

- PowerShell 5.1 or later
- ZPA API credentials (Client ID, Client Secret, Customer ID)
- Network access to ZPA management APIs
- Write permissions to the backup directory

### Usage

#### Interactive Usage (Recommended for Security)

```powershell
# First, securely enter your client secret
$secureSecret = Read-Host "Enter Client Secret" -AsSecureString

# Run the backup
.\Scripts\Export-ZPAConfig.ps1 -CustomerId "your-customer-id" -ClientId "your-client-id" -ClientSecret $secureSecret
```

#### Advanced Usage with Custom Settings

```powershell
# For beta environment with custom output location
$secureSecret = Read-Host "Enter Client Secret" -AsSecureString
.\Scripts\Export-ZPAConfig.ps1 -CustomerId "12345" -ClientId "api-client" -ClientSecret $secureSecret -BaseUrl "https://config.zpabeta.net" -OutputDirectory "C:\ZPA-Backups"
```

### Output

The script creates a timestamped directory containing:

- Individual JSON files for each configuration type (e.g., `application_segments.json`)
- A complete consolidated backup file (`zpa_complete_backup.json`)
- Detailed console output showing backup progress and results
