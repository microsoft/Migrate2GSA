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
            Write-Host "Starting ZPA authentication process..." -ForegroundColor Gray
            $authUrl = "$($this.BaseUrl)/signin"
            Write-Host "Authentication URL: $authUrl" -ForegroundColor Gray
            
            Write-Host "Converting client secret for API authentication..." -ForegroundColor Gray
            # Convert SecureString to plain text for API call
            $plainSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($this.ClientSecret))
            
            Write-Host "Creating authentication credentials..." -ForegroundColor Gray
            # Create basic auth header
            $credentials = "$($this.ClientId):$plainSecret"
            $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($credentials))
            
            # Clear the plain text variable for security
            $plainSecret = $null
            Write-Host "Client secret cleared from memory" -ForegroundColor Gray
            
            Write-Host "Preparing authentication headers..." -ForegroundColor Gray
            $headers = @{
                "Authorization" = "Basic $encodedCredentials"
                "Content-Type" = "application/x-www-form-urlencoded"
            }
            
            $body = @{
                "grant_type" = "client_credentials"
                "scope" = "read"
            }
            
            Write-Host "Sending authentication request to ZPA API..." -ForegroundColor Gray
            $response = Invoke-RestMethod -Uri $authUrl -Method Post -Headers $headers -Body $body -WebSession $this.Session
            
            if ($response.access_token) {
                Write-Host "Access token received successfully" -ForegroundColor Gray
                $this.AccessToken = $response.access_token
                $this.Session.Headers.Add("Authorization", "Bearer $($this.AccessToken)")
                $this.Session.Headers.Add("Content-Type", "application/json")
                Write-Host "Session headers configured with bearer token" -ForegroundColor Gray
                Write-Host "ZPA Authentication successful" -ForegroundColor Green
                return $true
            }
            else {
                Write-Error "ZPA Authentication failed: No access token received"
                Write-Host "Response received but no access token found" -ForegroundColor Red
                return $false
            }
        }
        catch {
            Write-Error "ZPA Authentication failed: $($_.Exception.Message)"
            Write-Host "Authentication error details: $($_.Exception.GetType().Name)" -ForegroundColor Red
            if ($_.Exception.Response) {
                Write-Host "HTTP Status Code: $($_.Exception.Response.StatusCode)" -ForegroundColor Red
                Write-Host "HTTP Status Description: $($_.Exception.Response.StatusDescription)" -ForegroundColor Red
            }
            return $false
        }
    }

    [object] BackupApplicationSegments() {
        Write-Host "Backing up Application Segments..." -ForegroundColor Gray
        return $this.InvokeZPAApi("/mgmtconfig/v1/admin/customers/$($this.CustomerId)/application")
    }

    [object] BackupSegmentGroups() {
        Write-Host "Backing up Segment Groups..." -ForegroundColor Gray
        return $this.InvokeZPAApi("/mgmtconfig/v1/admin/customers/$($this.CustomerId)/segmentGroup")
    }

    [object] BackupServerGroups() {
        Write-Host "Backing up Server Groups..." -ForegroundColor Gray
        return $this.InvokeZPAApi("/mgmtconfig/v1/admin/customers/$($this.CustomerId)/serverGroup")
    }

    [object] BackupAppConnectors() {
        Write-Host "Backing up App Connectors..." -ForegroundColor Gray
        return $this.InvokeZPAApi("/mgmtconfig/v1/admin/customers/$($this.CustomerId)/connector")
    }

    [object] BackupConnectorGroups() {
        Write-Host "Backing up Connector Groups..." -ForegroundColor Gray
        return $this.InvokeZPAApi("/mgmtconfig/v1/admin/customers/$($this.CustomerId)/connectorGroup")
    }

    [object] BackupAccessPolicies() {
        Write-Host "Backing up Access Policies..." -ForegroundColor Gray
        return $this.InvokeZPAApi("/mgmtconfig/v1/admin/customers/$($this.CustomerId)/policySet/rules")
    }

    [object] BackupPolicySets() {
        Write-Host "Backing up Policy Sets..." -ForegroundColor Gray
        return $this.InvokeZPAApi("/mgmtconfig/v1/admin/customers/$($this.CustomerId)/policySet")
    }

    [object] BackupServiceEdges() {
        Write-Host "Backing up Service Edges..." -ForegroundColor Gray
        return $this.InvokeZPAApi("/mgmtconfig/v1/admin/customers/$($this.CustomerId)/serviceEdge")
    }

    [object] BackupServiceEdgeGroups() {
        Write-Host "Backing up Service Edge Groups..." -ForegroundColor Gray
        return $this.InvokeZPAApi("/mgmtconfig/v1/admin/customers/$($this.CustomerId)/serviceEdgeGroup")
    }

    [object] BackupIdpControllers() {
        Write-Host "Backing up IDP Controllers..." -ForegroundColor Gray
        return $this.InvokeZPAApi("/mgmtconfig/v1/admin/customers/$($this.CustomerId)/idp")
    }

    [object] BackupScimGroups() {
        Write-Host "Backing up SCIM Groups..." -ForegroundColor Gray
        return $this.InvokeZPAApi("/mgmtconfig/v1/admin/customers/$($this.CustomerId)/scimgroup")
    }

    [object] BackupSamlAttributes() {
        Write-Host "Backing up SAML Attributes..." -ForegroundColor Gray
        return $this.InvokeZPAApi("/mgmtconfig/v1/admin/customers/$($this.CustomerId)/samlAttribute")
    }

    [object] BackupMachineGroups() {
        Write-Host "Backing up Machine Groups..." -ForegroundColor Gray
        return $this.InvokeZPAApi("/mgmtconfig/v1/admin/customers/$($this.CustomerId)/machineGroup")
    }

    [object] BackupPostureProfiles() {
        Write-Host "Backing up Posture Profiles..." -ForegroundColor Gray
        return $this.InvokeZPAApi("/mgmtconfig/v1/admin/customers/$($this.CustomerId)/posture")
    }

    [object] BackupTrustedNetworks() {
        Write-Host "Backing up Trusted Networks..." -ForegroundColor Gray
        return $this.InvokeZPAApi("/mgmtconfig/v1/admin/customers/$($this.CustomerId)/network")
    }

    [object] InvokeZPAApi([string]$Endpoint) {
        try {
            $url = "$($this.BaseUrl)$Endpoint"
            Write-Host "Making API call to: $url" -ForegroundColor Gray
            
            $response = Invoke-RestMethod -Uri $url -Method Get -WebSession $this.Session
            
            if ($response) {
                if ($response -is [array]) {
                    Write-Host "API call successful - Retrieved $($response.Count) items from $Endpoint" -ForegroundColor Gray
                } elseif ($response.PSObject.Properties['list'] -and $response.list -is [array]) {
                    Write-Host "API call successful - Retrieved $($response.list.Count) items from $Endpoint" -ForegroundColor Gray
                } else {
                    Write-Host "API call successful - Retrieved data from $Endpoint" -ForegroundColor Gray
                }
            } else {
                Write-Host "API call successful but no data returned from $Endpoint" -ForegroundColor Yellow
            }
            
            return $response
        }
        catch {
            Write-Warning "Failed to retrieve data from $Endpoint : $($_.Exception.Message)"
            Write-Host "API call error details for $Endpoint" -ForegroundColor Red
            Write-Host "Error type: $($_.Exception.GetType().Name)" -ForegroundColor Red
            
            if ($_.Exception.Response) {
                Write-Host "HTTP Status Code: $($_.Exception.Response.StatusCode)" -ForegroundColor Red
                Write-Host "HTTP Status Description: $($_.Exception.Response.StatusDescription)" -ForegroundColor Red
            }
            
            return $null
        }
    }

    [bool] FullBackup([string]$OutputDir) {
        Write-Host "Starting full backup process..." -ForegroundColor Gray
        
        if (-not $this.Authenticate()) {
            Write-Host "Full backup cancelled due to authentication failure" -ForegroundColor Red
            return $false
        }

        # Create output directory with timestamp
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $backupDir = "$OutputDir`_$timestamp"
        
        Write-Host "Creating backup directory: $backupDir" -ForegroundColor Gray
        if (-not (Test-Path $backupDir)) {
            New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
            Write-Host "Backup directory created successfully" -ForegroundColor Gray
        } else {
            Write-Host "Backup directory already exists" -ForegroundColor Yellow
        }

        Write-Host "Starting ZPA configuration backup..." -ForegroundColor Yellow
        Write-Host "Backup timestamp: $timestamp" -ForegroundColor Gray

        # Backup configurations
        Write-Host "Initializing configuration backup operations..." -ForegroundColor Gray
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

        Write-Host "Configuration data collection completed. Starting file export..." -ForegroundColor Gray
        
        # Track backup statistics
        $successCount = 0
        $failureCount = 0
        $totalConfigs = $configs.Keys.Count
        
        # Save individual files
        foreach ($configName in $configs.Keys) {
            $configData = $configs[$configName]
            if ($configData) {
                try {
                    $filename = Join-Path $backupDir "$configName.json"
                    Write-Host "Writing $configName to file: $filename" -ForegroundColor Gray
                    
                    $configData | ConvertTo-Json -Depth 10 | Out-File -FilePath $filename -Encoding UTF8
                    
                    # Verify file was created and get size
                    if (Test-Path $filename) {
                        $fileSize = (Get-Item $filename).Length
                        Write-Host "Saved $configName to $filename (Size: $fileSize bytes)" -ForegroundColor Green
                        $successCount++
                    } else {
                        Write-Warning "File was not created for $configName"
                        $failureCount++
                    }
                }
                catch {
                    Write-Warning "Failed to save $configName : $($_.Exception.Message)"
                    $failureCount++
                }
            }
            else {
                Write-Warning "No data retrieved for $configName"
                $failureCount++
            }
        }

        Write-Host "Individual file export completed. Successfully saved: $successCount/$totalConfigs configurations" -ForegroundColor Gray
        
        # Save complete backup
        Write-Host "Creating complete backup file..." -ForegroundColor Gray
        $completeBackup = @{
            "timestamp" = $timestamp
            "customer_id" = $this.CustomerId
            "backup_type" = "ZPA_Configuration"
            "configurations" = $configs
        }

        try {
            $completeFilename = Join-Path $backupDir "zpa_complete_backup.json"
            Write-Host "Writing complete backup to: $completeFilename" -ForegroundColor Gray
            
            $completeBackup | ConvertTo-Json -Depth 10 | Out-File -FilePath $completeFilename -Encoding UTF8
            
            # Verify complete backup file
            if (Test-Path $completeFilename) {
                $fileSize = (Get-Item $completeFilename).Length
                Write-Host "Complete ZPA backup saved to $completeFilename (Size: $fileSize bytes)" -ForegroundColor Green
            } else {
                Write-Warning "Complete backup file was not created"
                return $false
            }
        }
        catch {
            Write-Error "Failed to create complete backup file: $($_.Exception.Message)"
            return $false
        }

        Write-Host "Backup operation summary:" -ForegroundColor Gray
        Write-Host "- Total configurations: $totalConfigs" -ForegroundColor Gray
        Write-Host "- Successful backups: $successCount" -ForegroundColor Gray
        Write-Host "- Failed backups: $failureCount" -ForegroundColor Gray
        Write-Host "- Backup directory: $backupDir" -ForegroundColor Gray
        
        Write-Host "Backup completed successfully!" -ForegroundColor Green
        return $true
    }
}

# Main execution
try {
    Write-Host "ZPA Configuration Backup Script" -ForegroundColor Cyan
    Write-Host "================================" -ForegroundColor Cyan
    
    # Log script initialization
    Write-Host "Script started at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host "Validating input parameters..." -ForegroundColor Gray
    
    # Log parameters (excluding sensitive data)
    Write-Host "Customer ID: $CustomerId" -ForegroundColor Gray
    Write-Host "Client ID: $ClientId" -ForegroundColor Gray
    Write-Host "Base URL: $BaseUrl" -ForegroundColor Gray
    Write-Host "Output Directory: $OutputDirectory" -ForegroundColor Gray
    Write-Host "Client Secret: [PROTECTED]" -ForegroundColor Gray
    
    Write-Host "Creating ZPA backup instance..." -ForegroundColor Gray
    # Create backup instance
    $backup = [ZPABackup]::new($CustomerId, $ClientId, $ClientSecret, $BaseUrl)
    Write-Host "ZPA backup instance created successfully" -ForegroundColor Gray
    
    Write-Host "Initiating backup process..." -ForegroundColor Gray
    # Perform backup
    $success = $backup.FullBackup($OutputDirectory)
    
    if ($success) {
        Write-Host "`nBackup process completed successfully!" -ForegroundColor Green
        Write-Host "Script execution finished at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
        exit 0
    }
    else {
        Write-Error "Backup process failed!"
        Write-Host "Script execution failed at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Red
        exit 1
    }
}
catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
    Write-Host "Error occurred at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Red
    Write-Host "Error type: $($_.Exception.GetType().Name)" -ForegroundColor Red
    Write-Host "Error details: $($_.Exception.ToString())" -ForegroundColor Red
    
    if ($_.Exception.InnerException) {
        Write-Host "Inner exception: $($_.Exception.InnerException.Message)" -ForegroundColor Red
    }
    
    Write-Host "Stack trace:" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    exit 1
}