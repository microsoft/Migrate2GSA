<#
.SYNOPSIS
    Zscaler Private Access (ZPA) Configuration Backup Script
    Exports ZPA configurations to JSON files

.DESCRIPTION
    This PowerShell script connects to the ZPA API using OAuth2 authentication
    and exports various configuration types to JSON files for backup purposes.

.PARAMETER CustomerId
    The ZPA customer ID

.PARAMETER ClientId
    The OAuth2 client ID for API authentication

.PARAMETER ClientSecret
    The OAuth2 client secret for API authentication

.PARAMETER BaseUrl
    The ZPA API base URL (defaults to production cloud)

.PARAMETER OutputDirectory
    The output directory for backup files (defaults to "zpa_backup")

.EXAMPLE
    $secureSecret = Read-Host "Enter Client Secret" -AsSecureString
    .\Export-ZPAConfig.ps1 -CustomerId "12345" -ClientId "client123" -ClientSecret $secureSecret

.EXAMPLE
    $secureSecret = ConvertTo-SecureString "your-secret" -AsPlainText -Force
    .\Export-ZPAConfig.ps1 -CustomerId "12345" -ClientId "client123" -ClientSecret $secureSecret -BaseUrl "https://config.zpabeta.net" -OutputDirectory "C:\Backups\ZPA"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CustomerId,
    
    [Parameter(Mandatory = $true)]
    [string]$ClientId,
    
    [Parameter(Mandatory = $true)]
    [SecureString]$ClientSecret,
    
    [Parameter(Mandatory = $false)]
    [string]$BaseUrl = "https://config.private.zscaler.com",
    
    [Parameter(Mandatory = $false)]
    [string]$OutputDirectory = "zpa_backup"
)

class ZPABackup {
    [string]$CustomerId
    [string]$ClientId
    [SecureString]$ClientSecret
    [string]$BaseUrl
    [string]$AccessToken
    [Microsoft.PowerShell.Commands.WebRequestSession]$Session

    ZPABackup([string]$CustomerId, [string]$ClientId, [SecureString]$ClientSecret, [string]$BaseUrl) {
        $this.CustomerId = $CustomerId
        $this.ClientId = $ClientId
        $this.ClientSecret = $ClientSecret
        $this.BaseUrl = $BaseUrl
        $this.Session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    }

    [bool] Authenticate() {
        try {
            $authUrl = "$($this.BaseUrl)/signin"
            
            # Convert SecureString to plain text for API call
            $plainSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($this.ClientSecret))
            
            # Create basic auth header
            $credentials = "$($this.ClientId):$plainSecret"
            $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($credentials))
            
            # Clear the plain text variable for security
            $plainSecret = $null
            
            $headers = @{
                "Authorization" = "Basic $encodedCredentials"
                "Content-Type" = "application/x-www-form-urlencoded"
            }
            
            $body = @{
                "grant_type" = "client_credentials"
                "scope" = "read"
            }
            
            $response = Invoke-RestMethod -Uri $authUrl -Method Post -Headers $headers -Body $body -WebSession $this.Session
            
            if ($response.access_token) {
                $this.AccessToken = $response.access_token
                $this.Session.Headers.Add("Authorization", "Bearer $($this.AccessToken)")
                $this.Session.Headers.Add("Content-Type", "application/json")
                Write-Host "ZPA Authentication successful" -ForegroundColor Green
                return $true
            }
            else {
                Write-Error "ZPA Authentication failed: No access token received"
                return $false
            }
        }
        catch {
            Write-Error "ZPA Authentication failed: $($_.Exception.Message)"
            return $false
        }
    }

    [object] BackupApplicationSegments() {
        return $this.InvokeZPAApi("/mgmtconfig/v1/admin/customers/$($this.CustomerId)/application")
    }

    [object] BackupSegmentGroups() {
        return $this.InvokeZPAApi("/mgmtconfig/v1/admin/customers/$($this.CustomerId)/segmentGroup")
    }

    [object] BackupServerGroups() {
        return $this.InvokeZPAApi("/mgmtconfig/v1/admin/customers/$($this.CustomerId)/serverGroup")
    }

    [object] BackupAppConnectors() {
        return $this.InvokeZPAApi("/mgmtconfig/v1/admin/customers/$($this.CustomerId)/connector")
    }

    [object] BackupConnectorGroups() {
        return $this.InvokeZPAApi("/mgmtconfig/v1/admin/customers/$($this.CustomerId)/connectorGroup")
    }

    [object] BackupAccessPolicies() {
        return $this.InvokeZPAApi("/mgmtconfig/v1/admin/customers/$($this.CustomerId)/policySet/rules")
    }

    [object] BackupPolicySets() {
        return $this.InvokeZPAApi("/mgmtconfig/v1/admin/customers/$($this.CustomerId)/policySet")
    }

    [object] BackupServiceEdges() {
        return $this.InvokeZPAApi("/mgmtconfig/v1/admin/customers/$($this.CustomerId)/serviceEdge")
    }

    [object] BackupServiceEdgeGroups() {
        return $this.InvokeZPAApi("/mgmtconfig/v1/admin/customers/$($this.CustomerId)/serviceEdgeGroup")
    }

    [object] BackupIdpControllers() {
        return $this.InvokeZPAApi("/mgmtconfig/v1/admin/customers/$($this.CustomerId)/idp")
    }

    [object] BackupScimGroups() {
        return $this.InvokeZPAApi("/mgmtconfig/v1/admin/customers/$($this.CustomerId)/scimgroup")
    }

    [object] BackupSamlAttributes() {
        return $this.InvokeZPAApi("/mgmtconfig/v1/admin/customers/$($this.CustomerId)/samlAttribute")
    }

    [object] BackupMachineGroups() {
        return $this.InvokeZPAApi("/mgmtconfig/v1/admin/customers/$($this.CustomerId)/machineGroup")
    }

    [object] BackupPostureProfiles() {
        return $this.InvokeZPAApi("/mgmtconfig/v1/admin/customers/$($this.CustomerId)/posture")
    }

    [object] BackupTrustedNetworks() {
        return $this.InvokeZPAApi("/mgmtconfig/v1/admin/customers/$($this.CustomerId)/network")
    }

    [object] InvokeZPAApi([string]$Endpoint) {
        try {
            $url = "$($this.BaseUrl)$Endpoint"
            $response = Invoke-RestMethod -Uri $url -Method Get -WebSession $this.Session
            return $response
        }
        catch {
            Write-Warning "Failed to retrieve data from $Endpoint : $($_.Exception.Message)"
            return $null
        }
    }

    [bool] FullBackup([string]$OutputDir) {
        if (-not $this.Authenticate()) {
            return $false
        }

        # Create output directory with timestamp
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $backupDir = "$OutputDir`_$timestamp"
        
        if (-not (Test-Path $backupDir)) {
            New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
        }

        Write-Host "Starting ZPA configuration backup..." -ForegroundColor Yellow

        # Backup configurations
        $configs = @{
            "application_segments" = $this.BackupApplicationSegments()
            "segment_groups" = $this.BackupSegmentGroups()
            "server_groups" = $this.BackupServerGroups()
            "app_connectors" = $this.BackupAppConnectors()
            "connector_groups" = $this.BackupConnectorGroups()
            "access_policies" = $this.BackupAccessPolicies()
            "policy_sets" = $this.BackupPolicySets()
            "service_edges" = $this.BackupServiceEdges()
            "service_edge_groups" = $this.BackupServiceEdgeGroups()
            "idp_controllers" = $this.BackupIdpControllers()
            "scim_groups" = $this.BackupScimGroups()
            "saml_attributes" = $this.BackupSamlAttributes()
            "machine_groups" = $this.BackupMachineGroups()
            "posture_profiles" = $this.BackupPostureProfiles()
            "trusted_networks" = $this.BackupTrustedNetworks()
        }

        # Save individual files
        foreach ($configName in $configs.Keys) {
            $configData = $configs[$configName]
            if ($configData) {
                $filename = Join-Path $backupDir "$configName.json"
                $configData | ConvertTo-Json -Depth 10 | Out-File -FilePath $filename -Encoding UTF8
                Write-Host "Saved $configName to $filename" -ForegroundColor Green
            }
            else {
                Write-Warning "No data retrieved for $configName"
            }
        }

        # Save complete backup
        $completeBackup = @{
            "timestamp" = $timestamp
            "customer_id" = $this.CustomerId
            "backup_type" = "ZPA_Configuration"
            "configurations" = $configs
        }

        $completeFilename = Join-Path $backupDir "zpa_complete_backup.json"
        $completeBackup | ConvertTo-Json -Depth 10 | Out-File -FilePath $completeFilename -Encoding UTF8

        Write-Host "Complete ZPA backup saved to $completeFilename" -ForegroundColor Green
        Write-Host "Backup completed successfully!" -ForegroundColor Green
        return $true
    }
}

# Main execution
try {
    Write-Host "ZPA Configuration Backup Script" -ForegroundColor Cyan
    Write-Host "================================" -ForegroundColor Cyan
    
    # Create backup instance
    $backup = [ZPABackup]::new($CustomerId, $ClientId, $ClientSecret, $BaseUrl)
    
    # Perform backup
    $success = $backup.FullBackup($OutputDirectory)
    
    if ($success) {
        Write-Host "`nBackup completed successfully!" -ForegroundColor Green
        exit 0
    }
    else {
        Write-Error "Backup failed!"
        exit 1
    }
}
catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
    exit 1
}