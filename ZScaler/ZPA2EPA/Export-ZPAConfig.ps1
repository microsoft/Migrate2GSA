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
    The output directory for backup files (defaults to the script directory)

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
    [string]$OutputDirectory = (Get-Location).Path
)

# Global variables for ZPA session
$script:ZPAHeaders = $null
$script:ZPAAccessToken = $null

function Connect-ZPAApi {
    <#
    .SYNOPSIS
        Authenticates with the ZPA API and sets up the session
    
    .PARAMETER ClientId
        The OAuth2 client ID for API authentication
    
    .PARAMETER ClientSecret
        The OAuth2 client secret for API authentication
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        
        [Parameter(Mandatory = $true)]
        [SecureString]$ClientSecret
    )
    
    try {
        Write-Host "Starting ZPA authentication process..." -ForegroundColor Gray
        $authUrl = "$BaseUrl/signin"
        Write-Host "Authentication URL: $authUrl" -ForegroundColor Gray
        
        # Convert SecureString to plain text for API call
        $plainSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecret))
        
        $headers = @{
            "Content-Type" = "application/x-www-form-urlencoded"
        }
        
        $body = @{
            "client_id" = $ClientId
            "client_secret" = $plainSecret
        }
                  
        Write-Host "Sending authentication request to ZPA API..." -ForegroundColor Gray
        
        $response = Invoke-RestMethod -Uri $authUrl -Method Post -Headers $headers -Body $body
        if ($response.access_token) {
            Write-Host "Access token received successfully" -ForegroundColor Gray
            $script:ZPAAccessToken = $response.access_token
            
            # Set up headers for subsequent API calls
            $script:ZPAHeaders = @{
                "Authorization" = "Bearer $script:ZPAAccessToken"
                "Content-Type" = "application/json"
            }
            
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

function Invoke-ZPAApi {
    <#
    .SYNOPSIS
        Makes an API call to the ZPA API
    
    .PARAMETER Endpoint
        The API endpoint to call
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Endpoint
    )
    
    try {
        $url = "$BaseUrl$Endpoint"
        Write-Host "Making API call to: $url" -ForegroundColor Gray
        
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $script:ZPAHeaders
        
        if ($response) {
            if ($response -is [array]) {
                Write-Host "API call successful - Retrieved $($response.Count) items" -ForegroundColor Gray
            } elseif ($response.PSObject.Properties['list'] -and $response.list -is [array]) {
                Write-Host "API call successful - Retrieved $($response.list.Count) items" -ForegroundColor Gray
            } else {
                Write-Host "API call successful - Retrieved data" -ForegroundColor Gray
            }
        } else {
            Write-Host "API call successful but no data returned" -ForegroundColor Yellow
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

function Get-ZPAApplicationSegments {
    <#
    .SYNOPSIS
        Backs up ZPA Application Segments
    #>
    Write-Host "Backing up Application Segments..." -ForegroundColor Green
    return Invoke-ZPAApi -Endpoint "/mgmtconfig/v1/admin/customers/$CustomerId/application"
}

function Get-ZPASegmentGroups {
    <#
    .SYNOPSIS
        Backs up ZPA Segment Groups
    #>
    Write-Host "Backing up Segment Groups..." -ForegroundColor Green
    return Invoke-ZPAApi -Endpoint "/mgmtconfig/v1/admin/customers/$CustomerId/segmentGroup"
}

function Get-ZPAServerGroups {
    <#
    .SYNOPSIS
        Backs up ZPA Server Groups
    #>
    Write-Host "Backing up Server Groups..." -ForegroundColor Green
    return Invoke-ZPAApi -Endpoint "/mgmtconfig/v1/admin/customers/$CustomerId/serverGroup"
}

function Get-ZPAAppConnectors {
    <#
    .SYNOPSIS
        Backs up ZPA App Connectors
    #>
    Write-Host "Backing up App Connectors..." -ForegroundColor Green
    return Invoke-ZPAApi -Endpoint "/mgmtconfig/v1/admin/customers/$CustomerId/connector"
}

function Get-ZPAConnectorGroups {
    <#
    .SYNOPSIS
        Backs up ZPA Connector Groups
    #>
    Write-Host "Backing up Connector Groups..." -ForegroundColor Green
    return Invoke-ZPAApi -Endpoint "/mgmtconfig/v1/admin/customers/$CustomerId/appConnectorGroup"
}

function Get-ZPAAccessPolicies {
    <#
    .SYNOPSIS
        Backs up ZPA Access Policies
    #>
    Write-Host "Backing up Access Policies..." -ForegroundColor Green
    return Invoke-ZPAApi -Endpoint "/mgmtconfig/v1/admin/customers/$CustomerId/policySet/rules/policyType/ACCESS_POLICY"
}

function Get-ZPAClientForwardingPolicy {
    <#
    .SYNOPSIS
        Backs up ZPA Client Forwarding Policy
    #>
    Write-Host "Backing up Client Forwarding Policy..." -ForegroundColor Green
    return Invoke-ZPAApi -Endpoint "/mgmtconfig/v1/admin/customers/$CustomerId/policySet/rules/policyType/CLIENT_FORWARDING_POLICY"
}

function Get-ZPAServiceEdges {
    <#
    .SYNOPSIS
        Backs up ZPA Service Edges
    #>
    Write-Host "Backing up Service Edges..." -ForegroundColor Green
    return Invoke-ZPAApi -Endpoint "/mgmtconfig/v1/admin/customers/$CustomerId/serviceEdge"
}

function Get-ZPAServiceEdgeGroups {
    <#
    .SYNOPSIS
        Backs up ZPA Service Edge Groups
    #>
    Write-Host "Backing up Service Edge Groups..." -ForegroundColor Green
    return Invoke-ZPAApi -Endpoint "/mgmtconfig/v1/admin/customers/$CustomerId/serviceEdgeGroup"
}

function Get-ZPAIdpControllers {
    <#
    .SYNOPSIS
        Backs up ZPA IDP Controllers
    #>
    Write-Host "Backing up IDP Controllers..." -ForegroundColor Green
    return Invoke-ZPAApi -Endpoint "/mgmtconfig/v2/admin/customers/$CustomerId/idp"
}

function Get-ZPAScimGroups {
    <#
    .SYNOPSIS
        Backs up ZPA SCIM Groups for a specific IDP
    
    .PARAMETER IdpId
        The IDP ID to retrieve SCIM groups for
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$IdpId
    )
    
    Write-Host "Backing up SCIM Groups for IDP ID: $IdpId..." -ForegroundColor Green
    return Invoke-ZPAApi -Endpoint "/userconfig/v1/customers/$CustomerId/scimgroup/idpId/$IdpId"
}

function Get-AllZPAScimGroups {
    <#
    .SYNOPSIS
        Backs up ZPA SCIM Groups for all IDPs
    #>
        
    # First get all IDP controllers
    $idpControllers = Get-ZPAIdpControllers
    
    if (-not $idpControllers -or -not $idpControllers.list) {
        Write-Warning "No IDP controllers found or unable to retrieve IDP controllers"
        return $null
    }
    Write-Host "Backing up SCIM Groups for all IDPs..." -ForegroundColor Green

    $allScimGroups = @()
    
    foreach ($idp in $idpControllers.list) {
        if ($idp.id) {
            Write-Host "Retrieving SCIM groups for IDP: $($idp.name) (ID: $($idp.id))" -ForegroundColor Green
            $scimGroups = Get-ZPAScimGroups -IdpId $idp.id
            
            if ($scimGroups -and $null -ne $scimGroups) {
                # Add IDP information to each SCIM group for context
                if ($scimGroups.list -and $scimGroups.list.Count -gt 0) {
                    foreach ($group in $scimGroups.list) {
                        $group | Add-Member -NotePropertyName "sourceIdpId" -NotePropertyValue $idp.id -Force
                        $group | Add-Member -NotePropertyName "sourceIdpName" -NotePropertyValue $idp.name -Force
                    }
                    $allScimGroups += $scimGroups.list
                    Write-Host "Added $($scimGroups.list.Count) SCIM groups from IDP: $($idp.name)" -ForegroundColor Green
                } elseif ($scimGroups -is [array] -and $scimGroups.Count -gt 0) {
                    foreach ($group in $scimGroups) {
                        $group | Add-Member -NotePropertyName "sourceIdpId" -NotePropertyValue $idp.id -Force
                        $group | Add-Member -NotePropertyName "sourceIdpName" -NotePropertyValue $idp.name -Force
                    }
                    $allScimGroups += $scimGroups
                    Write-Host "Added $($scimGroups.Count) SCIM groups from IDP: $($idp.name)" -ForegroundColor Green
                } elseif ($scimGroups.PSObject.Properties.Count -gt 0 -and 
                         -not $scimGroups.list -and 
                         -not $scimGroups.PSObject.Properties['totalCount'] -and
                         -not $scimGroups.PSObject.Properties['totalPages']) {
                    # Single group object returned (not an API response wrapper)
                    $scimGroups | Add-Member -NotePropertyName "sourceIdpId" -NotePropertyValue $idp.id -Force
                    $scimGroups | Add-Member -NotePropertyName "sourceIdpName" -NotePropertyValue $idp.name -Force
                    $allScimGroups += $scimGroups
                    Write-Host "Added 1 SCIM group from IDP: $($idp.name)" -ForegroundColor Green
                } else {
                    Write-Host "No SCIM groups found for IDP: $($idp.name) (ID: $($idp.id))" -ForegroundColor Yellow
                }
            } else {
                Write-Host "No SCIM groups found for IDP: $($idp.name) (ID: $($idp.id))" -ForegroundColor Yellow
            }
        } else {
            Write-Warning "IDP controller found without ID: $($idp.name)"
        }
    }
    
    Write-Host "Total SCIM groups collected from all IDPs: $($allScimGroups.Count)" -ForegroundColor Gray
    
    # Return in the same format as other API calls
    return @{
        "totalCount" = $allScimGroups.Count
        "list" = $allScimGroups
    }
}

function Get-ZPAMachineGroups {
    <#
    .SYNOPSIS
        Backs up ZPA Machine Groups
    #>
    Write-Host "Backing up Machine Groups..." -ForegroundColor Green
    return Invoke-ZPAApi -Endpoint "/mgmtconfig/v1/admin/customers/$CustomerId/machineGroup"
}

function Start-ZPAFullBackup {
    <#
    .SYNOPSIS
        Performs a full backup of ZPA configurations
    
    .PARAMETER OutputDir
        The output directory for backup files
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputDir
    )
    
    Write-Host "Starting full backup process..." -ForegroundColor Green

    # Create output directory with timestamp inside the specified directory
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    
    # Ensure the base output directory exists
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
        Write-Host "Created base output directory: $OutputDir" -ForegroundColor Gray
    }
    
    # Create timestamped backup folder inside the output directory
    $backupDir = Join-Path $OutputDir "backup_$timestamp"
    
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
        "application_segments" = Get-ZPAApplicationSegments
        "segment_groups" = Get-ZPASegmentGroups
        "server_groups" = Get-ZPAServerGroups
        "app_connectors" = Get-ZPAAppConnectors
        "connector_groups" = Get-ZPAConnectorGroups
        "access_policies" = Get-ZPAAccessPolicies
        "client_forwarding_policy" = Get-ZPAClientForwardingPolicy
        "service_edges" = Get-ZPAServiceEdges
        "service_edge_groups" = Get-ZPAServiceEdgeGroups
        "idp_controllers" = Get-ZPAIdpControllers
        "scim_groups" = Get-AllZPAScimGroups
        "machine_groups" = Get-ZPAMachineGroups
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
        "customer_id" = $CustomerId
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
    
    Write-Host "Authenticating with ZPA API..." -ForegroundColor Gray
    # Authenticate with ZPA API
    $authSuccess = Connect-ZPAApi -ClientId $ClientId -ClientSecret $ClientSecret
    
    if (-not $authSuccess) {
        Write-Error "Failed to authenticate with ZPA API"
        Write-Host "Script execution failed at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "ZPA authentication successful" -ForegroundColor Gray
    Write-Host "Initiating backup process..." -ForegroundColor Gray
    
    # Perform backup
    $success = Start-ZPAFullBackup -OutputDir $OutputDirectory
    
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