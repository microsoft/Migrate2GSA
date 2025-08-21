<#
.SYNOPSIS
    Provisions Microsoft Entra Private Access applications from CSV configuration data.

.DESCRIPTION
    This script reads CSV configuration files containing Entra Private Access application details
    and provisions them automatically. It provides comprehensive logging, error handling, and
    supports retry scenarios through output CSV generation.

.PARAMETER ProvisioningConfigPath
    Path to the CSV provisioning configuration file.

.PARAMETER AppNamePrefix
    Optional filter to provision only applications with names starting with this prefix.

.PARAMETER ConnectorGroupFilter
    Optional filter to provision only applications using this connector group.

.PARAMETER LogPath
    Path for the log file. Defaults to .\GSA_Provisioning.log

.PARAMETER WhatIf
    Enable dry-run mode to preview changes without executing them.

.PARAMETER Force
    Skip confirmation prompts for automated execution.

.EXAMPLE
    .\Provision-EntraPrivateAccessConfig.ps1 -ProvisioningConfigPath ".\config.csv"

.EXAMPLE
    .\Provision-EntraPrivateAccessConfig.ps1 -ProvisioningConfigPath ".\config.csv" -AppNamePrefix "GSA-" -WhatIf

.NOTES
    Author: Andres Canello
    Version: 1.0
    Requires: PowerShell 7+, Entra PowerShell Beta Modules
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true, HelpMessage="Path to CSV provisioning config file")]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$ProvisioningConfigPath,
       
    [Parameter(HelpMessage="Application name filter")]
    [string]$AppNamePrefix = "",
    
    [Parameter(HelpMessage="Connector group filter")]
    [string]$ConnectorGroupFilter = "",
     
    [Parameter(HelpMessage="Log file path")]
    [string]$LogPath = ".\Provision-EntraPrivateAccessConfig.log",
    
    [Parameter(HelpMessage="Enable WhatIf mode")]
    [switch]$WhatIf,
    
    [Parameter(HelpMessage="Skip confirmation prompts")]
    [switch]$Force
)

#region Global Variables
$Global:ProvisioningStats = @{
    TotalRecords = 0
    ProcessedRecords = 0
    SuccessfulApps = 0
    SuccessfulSegments = 0
    FailedApps = 0
    FailedSegments = 0
    FilteredRecords = 0
    StartTime = Get-Date
    EndTime = $null
}

$Global:ConnectorGroupCache = @{}
$Global:EntraGroupCache = @{}
$Global:ProvisioningResults = @()
$Global:RecordLookup = @{}
#endregion

#region Logging Functions
function Write-LogMessage {
    <#
    .SYNOPSIS
        Writes structured log messages to console and file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS', 'DEBUG', 'SUMMARY')]
        [string]$Level = 'INFO',
        
        [Parameter()]
        [string]$Component = 'Main'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [$Component] $Message"
    
    # Color mapping for console output
    $colorMap = @{
        'INFO'    = 'White'
        'WARN'    = 'Yellow'
        'ERROR'   = 'Red'
        'SUCCESS' = 'Green'
        'DEBUG'   = 'Cyan'
        'SUMMARY' = 'Magenta'
    }
    
    # Write to console with color
    Write-Host $logEntry -ForegroundColor $colorMap[$Level]
    
    # Write to log file
    try {
        Add-Content -Path $LogPath -Value $logEntry -Encoding UTF8
    }
    catch {
        Write-Warning "Failed to write to log file: $_"
    }
}

function Write-ProgressUpdate {
    <#
    .SYNOPSIS
        Updates progress bar and statistics.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [int]$Current,
        
        [Parameter(Mandatory=$true)]
        [int]$Total,
        
        [Parameter(Mandatory=$true)]
        [string]$Activity,
        
        [Parameter()]
        [string]$Status = "Processing..."
    )
    
    $percentComplete = [math]::Round(($Current / $Total) * 100, 2)
    $elapsed = (Get-Date) - $Global:ProvisioningStats.StartTime
    
    if ($Current -gt 0) {
        $estimatedTotal = $elapsed.TotalSeconds * ($Total / $Current)
        $remaining = [TimeSpan]::FromSeconds($estimatedTotal - $elapsed.TotalSeconds)
        $eta = "ETA: {0:mm\:ss}" -f $remaining
    } else {
        $eta = "ETA: Calculating..."
    }
    
    Write-Progress -Activity $Activity -Status "$Status - $eta" -PercentComplete $percentComplete -CurrentOperation "Item $Current of $Total"
}
#endregion

#region Authentication Functions
function Test-RequiredModules {
    <#
    .SYNOPSIS
        Validates that all required PowerShell modules are installed.
    #>
    [CmdletBinding()]
    param()
    
    Write-LogMessage "Validating required PowerShell modules..." -Level INFO -Component "ModuleCheck"
    
    $requiredModules = @(
        'Microsoft.Entra.Beta.Groups',
        'Microsoft.Entra.Beta.Authentication',
        'Microsoft.Entra.Beta.NetworkAccess'
    )
    
    $missingModules = @()
    $installedModules = @()
    
    foreach ($moduleName in $requiredModules) {
        try {
            $module = Get-Module -Name $moduleName -ListAvailable -ErrorAction Stop
            if ($module) {
                $installedModules += $moduleName
                $latestVersion = ($module | Sort-Object Version -Descending | Select-Object -First 1).Version
                Write-LogMessage "✅ $moduleName (v$latestVersion) - Available" -Level SUCCESS -Component "ModuleCheck"
            } else {
                $missingModules += $moduleName
            }
        }
        catch {
            $missingModules += $moduleName
        }
    }
    
    if ($missingModules.Count -gt 0) {
        Write-LogMessage "❌ Missing required PowerShell modules:" -Level ERROR -Component "ModuleCheck"
        foreach ($missingModule in $missingModules) {
            Write-LogMessage "   - $missingModule" -Level ERROR -Component "ModuleCheck"
        }
        
        Write-LogMessage "Please install missing modules using the following commands:" -Level INFO -Component "ModuleCheck"
        Write-LogMessage "Install-Module -Name Microsoft.Entra.Beta -Force -AllowClobber" -Level INFO -Component "ModuleCheck"
        
        throw "Required PowerShell modules are missing: $($missingModules -join ', ')"
    }
    
    Write-LogMessage "All required PowerShell modules are installed" -Level SUCCESS -Component "ModuleCheck"
    
    # Check PowerShell version requirement
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -lt 7) {
        Write-LogMessage "❌ PowerShell version $psVersion detected. PowerShell 7.0 or later is required." -Level ERROR -Component "ModuleCheck"
        Write-LogMessage "Please upgrade to PowerShell 7+ and try again." -Level ERROR -Component "ModuleCheck"
        Write-LogMessage "Download PowerShell 7+ from: https://github.com/PowerShell/PowerShell/releases" -Level INFO -Component "ModuleCheck"
        throw "PowerShell 7.0 or later is required. Current version: $psVersion"
    } else {
        Write-LogMessage "✅ PowerShell version $psVersion - Compatible" -Level SUCCESS -Component "ModuleCheck"
    }
    
    return $true
}

function Validate-EntraConnection {
    <#
    .SYNOPSIS
        Validates Entra PowerShell connection and required permissions.
    #>
    [CmdletBinding()]
    param()
    
    Write-LogMessage "Validating Entra PowerShell connection..." -Level INFO -Component "Auth"
    
    try {
        # Check if already connected
        $context = Get-EntraContext -ErrorAction SilentlyContinue
        
        if (-not $context) {
            Write-LogMessage "No active Entra PowerShell connection found." -Level WARN -Component "Auth"
            Write-LogMessage "Please connect to Entra PowerShell with the following command:" -Level INFO -Component "Auth"
            Write-LogMessage "Connect-Entra -Scopes 'NetworkAccessPolicy.ReadWrite.All', 'Application.ReadWrite.All', 'NetworkAccess.ReadWrite.All' -ContextScope Process" -Level INFO -Component "Auth"
            throw "Entra PowerShell connection required"
        }
        
        # Validate tenant and account
        Write-LogMessage "Entra PowerShell connected to tenant: $($context.TenantId)" -Level INFO -Component "Auth"
        Write-LogMessage "Connected as: $($context.Account)" -Level INFO -Component "Auth"
        
        # Check required scopes
        $requiredScopes = @(
            'NetworkAccessPolicy.ReadWrite.All',
            'Application.ReadWrite.All',
            'NetworkAccess.ReadWrite.All'
        )
        
        $missingScopes = @()
        foreach ($scope in $requiredScopes) {
            if ($scope -notin $context.Scopes) {
                $missingScopes += $scope
            }
        }
        
        if ($missingScopes.Count -gt 0) {
            Write-LogMessage "Missing required scopes: $($missingScopes -join ', ')" -Level ERROR -Component "Auth"
            Write-LogMessage "Please reconnect with: Connect-Entra -Scopes '$($requiredScopes -join "', '")' -ContextScope Process" -Level INFO -Component "Auth"
            throw "Insufficient Entra permissions"
        }
        
        Write-LogMessage "Entra PowerShell connection validated successfully" -Level SUCCESS -Component "Auth"
        return $true
    }
    catch {
        Write-LogMessage "Failed to validate Entra PowerShell connection: $_" -Level ERROR -Component "Auth"
        throw
    }
}
#endregion

#region Configuration Management
function Import-ProvisioningConfig {
    <#
    .SYNOPSIS
        Loads and validates CSV provisioning configuration.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConfigPath,
        
        [Parameter()]
        [string]$AppFilter = "",
        
        [Parameter()]
        [string]$ConnectorFilter = ""
    )
    
    Write-LogMessage "Loading provisioning configuration from: $ConfigPath" -Level INFO -Component "Config"
    
    try {
        # Import CSV
        $configData = Import-Csv -Path $ConfigPath
        
        if (-not $configData -or $configData.Count -eq 0) {
            throw "No data found in configuration file"
        }
        
        Write-LogMessage "Loaded $($configData.Count) configuration records" -Level INFO -Component "Config"
        
        # Validate required columns
        $requiredColumns = @(
            'EnterpriseAppName',
            'SegmentId',
            'destinationHost',
            'DestinationType',
            'Protocol',
            'Ports',
            'ConnectorGroup',
            'Provision',
            'EntraGroup'
        )

        $actualColumns = $configData[0].PSObject.Properties.Name
        $missingColumns = $requiredColumns | Where-Object { $_ -notin $actualColumns }

        if ($missingColumns.Count -gt 0) {
            throw "Missing required columns: $($missingColumns -join ', ')"
        }

        Write-LogMessage "All required columns found. Filtering to include only required columns..." -Level INFO -Component "Config"
        
        # Filter to only include required columns and add ProvisioningResult for tracking
        $filteredConfigData = @()
        foreach ($row in $configData) {
            $filteredRow = New-Object PSObject
            
            # Add only required columns
            foreach ($column in $requiredColumns) {
                $filteredRow | Add-Member -MemberType NoteProperty -Name $column -Value $row.$column
            }
            
            # Add ProvisioningResult column for tracking
            $filteredRow | Add-Member -MemberType NoteProperty -Name 'ProvisioningResult' -Value '' -Force
            
            $filteredConfigData += $filteredRow
        }
        
        # Update configData to use filtered version
        $configData = $filteredConfigData
        
        # Add unique record IDs for efficient lookup
        $recordId = 1
        foreach ($row in $configData) {
            $row | Add-Member -MemberType NoteProperty -Name 'UniqueRecordId' -Value $recordId -Force
            $recordId++
        }
        
        Write-LogMessage "Added unique record IDs to $($configData.Count) records" -Level INFO -Component "Config"
        
        Write-LogMessage "Configuration data filtered to include only required columns" -Level INFO -Component "Config"        # Filter data
        $filteredData = $configData | Where-Object {
            $includeRecord = $true
            
            # Check if provisioning is enabled
            if ($_.Provision -eq 'No') {
                $_.ProvisioningResult = "Filtered: Provision field set to No"
                $includeRecord = $false
            }
            
            # Apply app name filter
            if ($AppFilter -and $_.EnterpriseAppName -notlike "*$AppFilter*") {
                $_.ProvisioningResult = "Filtered: App name does not match filter '$AppFilter'"
                $includeRecord = $false
            }
            
            # Apply connector group filter
            if ($ConnectorFilter -and $_.ConnectorGroup -notlike "*$ConnectorFilter*") {
                $_.ProvisioningResult = "Filtered: Connector group does not match filter '$ConnectorFilter'"
                $includeRecord = $false
            }
            
            if (-not $includeRecord) {
                $Global:ProvisioningStats.FilteredRecords++
            }
            
            return $includeRecord
        }
        
        Write-LogMessage "After filtering: $($filteredData.Count) records to process, $($Global:ProvisioningStats.FilteredRecords) filtered out" -Level INFO -Component "Config"
        
        # Store all records (including filtered) for results export
        $Global:ProvisioningResults = $configData
        
        # Create global lookup hashtable for O(1) record access
        $Global:RecordLookup = @{}
        foreach ($record in $configData) {
            $Global:RecordLookup[$record.UniqueRecordId] = $record
        }
        
        Write-LogMessage "Created lookup hashtable with $($Global:RecordLookup.Count) record mappings" -Level INFO -Component "Config"
        
        return $filteredData
    }
    catch {
        Write-LogMessage "Failed to import configuration: $_" -Level ERROR -Component "Config"
        throw
    }
}

function Show-ProvisioningPlan {
    <#
    .SYNOPSIS
        Displays detailed provisioning plan and statistics.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$ConfigData
    )
    
    Write-LogMessage "=== PROVISIONING PLAN ===" -Level SUMMARY -Component "Plan"
    
    # Group by application
    $appGroups = $ConfigData | Group-Object -Property EnterpriseAppName
    
    Write-LogMessage "Applications to provision: $($appGroups.Count)" -Level SUMMARY -Component "Plan"
    Write-LogMessage "Total segments to create: $($ConfigData.Count)" -Level SUMMARY -Component "Plan"
    
    # Only show detailed plan information when WhatIf is enabled
    if ($WhatIf) {
        foreach ($appGroup in $appGroups) {
            Write-LogMessage "  App: $($appGroup.Name)" -Level INFO -Component "Plan"
            Write-LogMessage "    Segments: $($appGroup.Count)" -Level INFO -Component "Plan"
            
            $connectorGroups = $appGroup.Group | Select-Object -ExpandProperty ConnectorGroup -Unique
            Write-LogMessage "    Connector Groups: $($connectorGroups -join ', ')" -Level INFO -Component "Plan"
            
            # Validate connector group consistency
            if ($connectorGroups.Count -gt 1) {
                Write-LogMessage "    ⚠️  WARNING: Application '$($appGroup.Name)' has segments with different connector groups!" -Level WARN -Component "Plan"
                Write-LogMessage "    ⚠️  Only the first connector group '$($connectorGroups[0])' will be used for the entire application." -Level WARN -Component "Plan"
                
                # Show breakdown by connector group
                $cgBreakdown = $appGroup.Group | Group-Object -Property ConnectorGroup
                foreach ($cgGroup in $cgBreakdown) {
                    Write-LogMessage "      - $($cgGroup.Name): $($cgGroup.Count) segments" -Level WARN -Component "Plan"
                }
            }
            
            $protocols = $appGroup.Group | Select-Object -ExpandProperty Protocol -Unique
            Write-LogMessage "    Protocols: $($protocols -join ', ')" -Level INFO -Component "Plan"
        }
    }
    
    $Global:ProvisioningStats.TotalRecords = $ConfigData.Count
}
#endregion

#region Resource Resolution
function Resolve-ConnectorGroups {
    <#
    .SYNOPSIS
        Maps connector group names to IDs and validates existence.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$ConfigData
    )
    
    Write-LogMessage "Resolving connector groups..." -Level INFO -Component "ConnectorGroups"
    
    try {
        # Get unique connector group names
        $connectorGroupNames = $ConfigData | Select-Object -ExpandProperty ConnectorGroup -Unique | Where-Object { $_ -and $_ -ne "Placeholder_Replace_Me" }
        
        Write-LogMessage "Found $($connectorGroupNames.Count) unique connector groups to resolve" -Level INFO -Component "ConnectorGroups"
        
        if ($connectorGroupNames.Count -eq 0) {
            Write-LogMessage "No valid connector groups found in configuration data. All entries appear to be placeholders." -Level WARN -Component "ConnectorGroups"
            Write-LogMessage "Please replace 'Placeholder_Replace_Me' values with actual connector group names in your CSV." -Level WARN -Component "ConnectorGroups"
            Write-LogMessage "Provisioning will fail without valid connector groups." -Level ERROR -Component "ConnectorGroups"
            throw "No valid connector groups found in configuration"
        }
        
        # Get all connector groups from Entra
        $allConnectorGroups = Get-EntraBetaApplicationProxyConnectorGroup
        
        # Extract applicationProxy connector groups from the response
        $applicationProxyConnectorGroups = $allConnectorGroups | Where-Object { $_.connectorGroupType -eq "applicationProxy" }
        
        # Display all applicationProxy connector groups found in tenant
        if ($applicationProxyConnectorGroups -and $applicationProxyConnectorGroups.Count -gt 0) {
            Write-LogMessage "Found $($applicationProxyConnectorGroups.Count) Application Proxy connector groups in tenant:" -Level INFO -Component "ConnectorGroups"
            foreach ($cg in $applicationProxyConnectorGroups) {
                Write-LogMessage "  - $($cg.name) (ID: $($cg.id)) [Default: $($cg.isDefault)]" -Level INFO -Component "ConnectorGroups"
            }
        } else {
            Write-LogMessage "No Application Proxy connector groups found in tenant" -Level WARN -Component "ConnectorGroups"
        }
        
        foreach ($groupName in $connectorGroupNames) {
            $connectorGroup = $applicationProxyConnectorGroups | Where-Object { $_.name -eq $groupName }
            
            if ($connectorGroup) {
                $Global:ConnectorGroupCache[$groupName] = $connectorGroup.id
                Write-LogMessage "Resolved connector group '$groupName' to ID: $($connectorGroup.id)" -Level SUCCESS -Component "ConnectorGroups"
            } else {
                Write-LogMessage "Connector group '$groupName' not found in tenant" -Level ERROR -Component "ConnectorGroups"
                $Global:ConnectorGroupCache[$groupName] = $null
            }
        }
        
        Write-LogMessage "Connector group resolution completed" -Level SUCCESS -Component "ConnectorGroups"
    }
    catch {
        Write-LogMessage "Failed to resolve connector groups: $_" -Level ERROR -Component "ConnectorGroups"
        throw
    }
}

function Resolve-EntraGroups {
    <#
    .SYNOPSIS
        Finds and caches Entra ID groups for application assignments.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$ConfigData
    )
    
    Write-LogMessage "Resolving Entra ID groups..." -Level INFO -Component "EntraGroups"
    
    try {
        # Group by application and get EntraGroup from first segment only (like connector groups)
        $appGroups = $ConfigData | Group-Object -Property EnterpriseAppName
        $groupNames = @()
        
        foreach ($appGroup in $appGroups) {
            $firstSegmentGroup = $appGroup.Group[0].EntraGroup
            if ($firstSegmentGroup -and $firstSegmentGroup -ne "Placeholder_Replace_Me" -and $firstSegmentGroup -ne "") {
                $groupNames += $firstSegmentGroup
            }
        }
        
        # Remove duplicates in case multiple apps use the same group
        $groupNames = $groupNames | Select-Object -Unique
        
        if ($groupNames.Count -eq 0) {
            Write-LogMessage "No Entra groups to resolve (all placeholders or empty)" -Level INFO -Component "EntraGroups"
            return
        }
        
        Write-LogMessage "Found $($groupNames.Count) unique Entra groups to resolve (from first segments only)" -Level INFO -Component "EntraGroups"
        
        foreach ($groupName in $groupNames) {
            try {
                $group = Get-EntraBetaGroup -Filter "displayName eq '$groupName'" -ErrorAction Stop
                
                if ($group) {
                    $Global:EntraGroupCache[$groupName] = $group.Id
                    Write-LogMessage "Resolved Entra group '$groupName' to ID: $($group.Id)" -Level SUCCESS -Component "EntraGroups"
                } else {
                    Write-LogMessage "Entra group '$groupName' not found" -Level WARN -Component "EntraGroups"
                    $Global:EntraGroupCache[$groupName] = $null
                }
            }
            catch {
                Write-LogMessage "Failed to resolve Entra group '$groupName': $_" -Level ERROR -Component "EntraGroups"
                $Global:EntraGroupCache[$groupName] = $null
            }
        }
        
        Write-LogMessage "Entra group resolution completed" -Level SUCCESS -Component "EntraGroups"
    }
    catch {
        Write-LogMessage "Failed to resolve Entra groups: $_" -Level ERROR -Component "EntraGroups"
        throw
    }
}

function Validate-ApplicationDependencies {
    <#
    .SYNOPSIS
        Validates that all applications have their required dependencies resolved.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$ConfigData
    )
    
    Write-LogMessage "Validating application dependencies..." -Level INFO -Component "Validation"
    
    $validApplications = @()
    $skippedApplications = @()
    
    # Group by application to check each one
    $appGroups = $ConfigData | Group-Object -Property EnterpriseAppName
    
    foreach ($appGroup in $appGroups) {
        $appName = $appGroup.Name
        $segments = $appGroup.Group
        $hasUnresolvedDependencies = $false
        
        # Check connector groups for this application
        $connectorGroups = $segments | Select-Object -ExpandProperty ConnectorGroup -Unique
        $unresolvedConnectorGroups = @()
        
        foreach ($cgName in $connectorGroups) {
            if ($cgName -eq "Placeholder_Replace_Me") {
                $unresolvedConnectorGroups += $cgName
            } elseif (-not $Global:ConnectorGroupCache.ContainsKey($cgName) -or -not $Global:ConnectorGroupCache[$cgName]) {
                $unresolvedConnectorGroups += $cgName
            }
        }
        
        if ($unresolvedConnectorGroups.Count -gt 0) {
            $hasUnresolvedDependencies = $true
            Write-LogMessage "❌ Skipping application '$appName': Unresolved connector groups found" -Level ERROR -Component "Validation"
            
            foreach ($unresolvedCG in $unresolvedConnectorGroups) {
                if ($unresolvedCG -eq "Placeholder_Replace_Me") {
                    Write-LogMessage "   - '$unresolvedCG' (placeholder - replace with actual connector group name)" -Level ERROR -Component "Validation"
                } else {
                    Write-LogMessage "   - '$unresolvedCG' (not found in tenant)" -Level ERROR -Component "Validation"
                }
            }
            
            # Mark all segments of this application as skipped
            foreach ($segment in $segments) {
                # Direct lookup instead of filtering
                $resultRecord = $Global:RecordLookup[$segment.UniqueRecordId]
                
                Write-LogMessage "DEBUG: Found record with UniqueRecordId: $($segment.UniqueRecordId)" -Level DEBUG -Component "Main"

                if ($resultRecord) {
                    $resultRecord.ProvisioningResult = "Skipped: Unresolved connector groups - $($unresolvedConnectorGroups -join ', ')"
                }
            }
            
            $skippedApplications += $appName
        } else {
            # Application has all dependencies resolved
            $validApplications += $segments
        }
    }
    
    if ($skippedApplications.Count -gt 0) {
        Write-LogMessage "⚠️  Skipped $($skippedApplications.Count) applications due to unresolved dependencies:" -Level WARN -Component "Validation"
        foreach ($skippedApp in $skippedApplications) {
            Write-LogMessage "   - $skippedApp" -Level WARN -Component "Validation"
        }
    }
    
    Write-LogMessage "Validation completed: $($validApplications.Count) segments from valid applications will be processed" -Level SUCCESS -Component "Validation"
    
    return $validApplications
}
#endregion

#region Application Provisioning
function New-PrivateAccessApplication {
    <#
    .SYNOPSIS
        Creates or updates Private Access applications.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$AppName,
        
        [Parameter(Mandatory=$true)]
        [string]$ConnectorGroupName
    )
    
    Write-LogMessage "Processing Private Access application: $AppName" -Level INFO -Component "AppProvisioning"
    
    try {
        # Check if application already exists
        $existingApp = Get-EntraBetaPrivateAccessApplication -ApplicationName $AppName -ErrorAction SilentlyContinue
        
        if ($existingApp) {
            Write-LogMessage "Application '$AppName' already exists. Will add segments to existing app." -Level INFO -Component "AppProvisioning"
            return @{ Success = $true; AppId = $existingApp.AppId; AppObjectId = $existingApp.Id; Action = "ExistingApp" }
        }
        
        # Get connector group ID
        $connectorGroupId = $Global:ConnectorGroupCache[$ConnectorGroupName]
        if (-not $connectorGroupId) {
            throw "Connector group '$ConnectorGroupName' not found"
        }
        
        if ($WhatIf) {
            Write-LogMessage "[WHATIF] Would create Private Access application: $AppName" -Level INFO -Component "AppProvisioning"
            return @{ Success = $true; AppId = "whatif-app-id"; Action = "WhatIf" }
        }
        
        # Create new application
        $appParams = @{
            ApplicationName = $AppName
            ConnectorGroupId = $connectorGroupId
            # Add other required parameters for Private Access application
        }
        
        New-EntraBetaPrivateAccessApplication @appParams
        
        # Retry logic to retrieve the created application with exponential backoff
        $maxRetries = 5
        $baseDelay = 2  # seconds
        $newApp = $null
        
        for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
            try {
                Write-LogMessage "Attempting to retrieve created application '$AppName' (attempt $attempt/$maxRetries)" -Level INFO -Component "AppProvisioning"
                
                $newApp = Get-EntraBetaPrivateAccessApplication -ApplicationName $AppName -ErrorAction Stop
                
                if ($newApp) {
                    Write-LogMessage "Successfully retrieved created application '$AppName' on attempt $attempt" -Level SUCCESS -Component "AppProvisioning"
                    break
                }
            }
            catch {
                $delay = $baseDelay * [math]::Pow(2, $attempt - 1)  # Exponential backoff: 2, 4 seconds
                
                if ($attempt -eq $maxRetries) {
                    Write-LogMessage "Failed to retrieve application '$AppName' after $maxRetries attempts. Final error: $_" -Level ERROR -Component "AppProvisioning"
                    throw "Failed to retrieve created application '$AppName' after $maxRetries retry attempts"
                }
                
                Write-LogMessage "Failed to retrieve application '$AppName' on attempt $attempt. Retrying in $delay seconds... Error: $_" -Level WARN -Component "AppProvisioning"
                Start-Sleep -Seconds $delay
            }
        }
        
        if (-not $newApp) {
            throw "Failed to retrieve created application '$AppName' after creation and $maxRetries retry attempts"
        }
        
        Write-LogMessage "Successfully created Private Access application: $AppName (ID: $($newApp.Id))" -Level SUCCESS -Component "AppProvisioning"
        
        return @{ Success = $true; AppId = $newApp.AppId; AppObjectId = $newApp.Id; Action = "Created" }
    }
    catch {
        Write-LogMessage "Failed to create Private Access application '$AppName': $_" -Level ERROR -Component "AppProvisioning"
        return @{ Success = $false; Error = $_.Exception.Message; Action = "Failed" }
    }
}

function New-ApplicationSegments {
    <#
    .SYNOPSIS
        Creates network segments for Private Access applications with duplicate detection.
    
    .DESCRIPTION
        Creates network segments for Entra Private Access applications. If a segment with the same
        host and port already exists on the application, the function will detect the duplicate
        error and return success with an "AlreadyExists" action instead of failing.
    
    .PARAMETER AppId
        The application ID where the segment will be created.
    
    .PARAMETER SegmentConfig
        PSCustomObject containing segment configuration including destinationHost, Protocol, Ports, etc.
    
    .OUTPUTS
        Returns a hashtable with Success (boolean), Action (string), and optional Error or SegmentId.
        Action values: "Created", "AlreadyExists", "WhatIf", "Failed"
    
    .EXAMPLE
        New-ApplicationSegments -AppId "app-123" -SegmentConfig $segmentObject
        Creates a new segment or detects if it already exists.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$AppId,
        
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$SegmentConfig
    )
    
    $segmentName = $SegmentConfig.SegmentId
    Write-LogMessage "Creating application segment: $segmentName" -Level INFO -Component "SegmentProvisioning"
    
    try {
        # Validate segment configuration
        if (-not $SegmentConfig.destinationHost -or -not $SegmentConfig.Protocol -or -not $SegmentConfig.Ports) {
            throw "Invalid segment configuration: missing required fields"
        }
        
        # Parse ports - convert to string array format expected by Entra API
        $portArray = @()
        $portString = $SegmentConfig.Ports -replace '\s', ''
        $portParts = $portString -split ','
        
        foreach ($portPart in $portParts) {
            if ($portPart -match '(\d+)-(\d+)') {
                # Port range format: "8080-8090"
                $portArray += $portPart
            } elseif ($portPart -match '^\d+$') {
                # Single port format: "443"
                $portArray += $portPart
            } else {
                Write-LogMessage "Invalid port specification: $portPart" -Level WARN -Component "SegmentProvisioning"
            }
        }
        
        if ($portArray.Count -eq 0) {
            throw "No valid ports found in configuration: $($SegmentConfig.Ports)"
        }
        
        if ($WhatIf) {
            Write-LogMessage "[WHATIF] Would create segment: $segmentName" -Level INFO -Component "SegmentProvisioning"
            return @{ Success = $true; Action = "WhatIf" }
        }
        
        # Create segment parameters
        $segmentParams = @{
            ApplicationId = $AppId
            DestinationHost = $SegmentConfig.destinationHost
            DestinationType = $SegmentConfig.DestinationType
            Protocol = $SegmentConfig.Protocol
            Ports = $portArray
        }
        
        # Create the segment
        $newSegment = New-EntraBetaPrivateAccessApplicationSegment @segmentParams -ErrorAction Stop
        
        Write-LogMessage "Successfully created application segment: $segmentName (ID: $($newSegment.Id))" -Level SUCCESS -Component "SegmentProvisioning"
        
        return @{ Success = $true; SegmentId = $newSegment.Id; Action = "Created" }
    }
    catch {
        # Check if the error is due to duplicate application segment
        $errorMessage = $_.Exception.Message
        $isDuplicateSegment = $false
        
        # Check specific patterns for duplicate segment detection
        if ($errorMessage -match 'Invalid_AppSegments_Duplicate' -or 
            $errorMessage -match 'Application segment host and port already exists') {
            $isDuplicateSegment = $true
        }
        
        # Also check the inner exception and response content for the error code
        if (-not $isDuplicateSegment -and $_.Exception.InnerException) {
            $innerMessage = $_.Exception.InnerException.Message
            if ($innerMessage -match 'Invalid_AppSegments_Duplicate' -or 
                $innerMessage -match 'Application segment host and port already exists') {
                $isDuplicateSegment = $true
            }
        }
        
        if ($isDuplicateSegment) {
            Write-LogMessage "Application segment '$segmentName' already exists on application. Marking as existing." -Level INFO -Component "SegmentProvisioning"
            return @{ Success = $true; Action = "AlreadyExists" }
        }
        
        Write-LogMessage "Failed to create application segment '$segmentName': $_" -Level ERROR -Component "SegmentProvisioning"
        return @{ Success = $false; Error = $_.Exception.Message; Action = "Failed" }
    }
}

function Set-ApplicationGroupAssignments {
    <#
    .SYNOPSIS
        Assigns Entra ID groups to Private Access applications.
    
    .DESCRIPTION
        Assigns an Entra ID group to a Private Access application. The function includes
        duplicate assignment checking to prevent assigning the same group multiple times
        to the same application with the same role.
    
    .PARAMETER AppId
        The application ID of the Private Access application.
    
    .PARAMETER GroupName
        The display name of the Entra ID group to assign to the application.
    
    .OUTPUTS
        Returns a hashtable with Success (boolean), Action (string), and optional Error (string).
        Action values: "Assigned", "AlreadyAssigned", "Skipped", "Failed"
    
    .EXAMPLE
        Set-ApplicationGroupAssignments -AppId "app-123" -GroupName "MyGroup"
        Assigns the group "MyGroup" to application "app-123" if not already assigned.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$AppId,
        
        [Parameter(Mandatory=$true)]
        [string]$GroupName
    )
    
    if ($GroupName -eq "Placeholder_Replace_Me" -or [string]::IsNullOrWhiteSpace($GroupName)) {
        Write-LogMessage "Skipping group assignment (placeholder group name)" -Level INFO -Component "GroupAssignment"
        return @{ Success = $true; Action = "Skipped" }
    }
    
    Write-LogMessage "Assigning group '$GroupName' to application" -Level INFO -Component "GroupAssignment"
    
    try {
        $groupId = $Global:EntraGroupCache[$GroupName]
        if (-not $groupId) {
            throw "Group '$GroupName' not found or not resolved"
        }
        
        if ($WhatIf) {
            Write-LogMessage "[WHATIF] Would assign group '$GroupName' to application" -Level INFO -Component "GroupAssignment"
            return @{ Success = $true; Action = "WhatIf" }
        }
        
        # Get the service principal for the application
        $servicePrincipal = Get-EntraBetaServicePrincipal -Filter "appId eq '$AppId'"
        
        if (-not $servicePrincipal) {
            throw "Service principal not found for application ID: $AppId"
        }
        
        # Find the User app role from the service principal's app roles
        $userAppRole = $servicePrincipal.AppRoles | Where-Object { $_.DisplayName -eq "User" -and $_.IsEnabled -eq $true }
        
        if (-not $userAppRole) {
            # Fallback to default role if User role not found
            Write-LogMessage "User app role not found for application, using default role" -Level WARN -Component "GroupAssignment"
            $appRoleId = "00000000-0000-0000-0000-000000000000"
        } else {
            $appRoleId = $userAppRole.Id
            Write-LogMessage "Found User app role ID: $appRoleId for application" -Level INFO -Component "GroupAssignment"
        }
        
        # Check if the group is already assigned to the application with this role
        Write-LogMessage "Checking for existing group assignment..." -Level INFO -Component "GroupAssignment"
        try {
            $existingAssignments = Get-EntraBetaServicePrincipalAppRoleAssignedTo -ServicePrincipalId $servicePrincipal.Id -ErrorAction Stop
            
            $existingAssignment = $existingAssignments | Where-Object { 
                $_.PrincipalId -eq $groupId -and $_.AppRoleId -eq $appRoleId 
            }
            
            if ($existingAssignment) {
                Write-LogMessage "Group '$GroupName' is already assigned to application with role ID '$appRoleId'" -Level INFO -Component "GroupAssignment"
                return @{ Success = $true; Action = "AlreadyAssigned" }
            }
            
            Write-LogMessage "No existing assignment found for group '$GroupName' with role ID '$appRoleId'" -Level INFO -Component "GroupAssignment"
        }
        catch {
            Write-LogMessage "Warning: Could not check existing assignments: $_. Proceeding with assignment attempt." -Level WARN -Component "GroupAssignment"
        }

        # Create app role assignment
        $assignmentParams = @{
            GroupId = $groupId
            PrincipalId = $groupId
            ResourceId = $servicePrincipal.Id
            AppRoleId = $appRoleId
        }
        
        New-EntraBetaGroupAppRoleAssignment @assignmentParams
        
        Write-LogMessage "Successfully assigned group '$GroupName' to application" -Level SUCCESS -Component "GroupAssignment"
        
        return @{ Success = $true; Action = "Assigned" }
    }
    catch {
        Write-LogMessage "Failed to assign group '$GroupName' to application: $_" -Level ERROR -Component "GroupAssignment"
        return @{ Success = $false; Error = $_.Exception.Message; Action = "Failed" }
    }
}
#endregion

#region Results and Reporting
function Export-ProvisioningResults {
    <#
    .SYNOPSIS
        Exports provisioning results to CSV for retry scenarios.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$InputPath
    )
    
    Write-LogMessage "Exporting provisioning results..." -Level INFO -Component "Export"
    
    try {
        # Generate output filename
        $inputFile = Get-Item $InputPath
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $baseName = $inputFile.BaseName
        $outputFileName = "${timestamp}_${baseName}_provisioned.csv"
        $outputPath = Join-Path $inputFile.Directory.FullName $outputFileName
        
        # Export results
        $Global:ProvisioningResults | Export-Csv -Path $outputPath -NoTypeInformation
        
        Write-LogMessage "Provisioning results exported to: $outputPath" -Level SUCCESS -Component "Export"
        return $outputPath
    }
    catch {
        Write-LogMessage "Failed to export provisioning results: $_" -Level ERROR -Component "Export"
        throw
    }
}

function Show-ExecutionSummary {
    <#
    .SYNOPSIS
        Displays comprehensive execution summary and statistics.
    #>
    [CmdletBinding()]
    param()
    
    $Global:ProvisioningStats.EndTime = Get-Date
    $duration = $Global:ProvisioningStats.EndTime - $Global:ProvisioningStats.StartTime
    
    Write-LogMessage "=== EXECUTION SUMMARY ===" -Level SUMMARY -Component "Summary"
    Write-LogMessage "Execution Duration: $($duration.ToString('hh\:mm\:ss'))" -Level SUMMARY -Component "Summary"
    Write-LogMessage "Total Records: $($Global:ProvisioningStats.TotalRecords)" -Level SUMMARY -Component "Summary"
    Write-LogMessage "Processed Records: $($Global:ProvisioningStats.ProcessedRecords)" -Level SUMMARY -Component "Summary"
    Write-LogMessage "Filtered Records: $($Global:ProvisioningStats.FilteredRecords)" -Level SUMMARY -Component "Summary"
    Write-LogMessage "Successful Applications: $($Global:ProvisioningStats.SuccessfulApps)" -Level SUMMARY -Component "Summary"
    Write-LogMessage "Failed Applications: $($Global:ProvisioningStats.FailedApps)" -Level SUMMARY -Component "Summary"
    Write-LogMessage "Successful Segments: $($Global:ProvisioningStats.SuccessfulSegments)" -Level SUMMARY -Component "Summary"
    Write-LogMessage "Failed Segments: $($Global:ProvisioningStats.FailedSegments)" -Level SUMMARY -Component "Summary"
    
    if ($Global:ProvisioningStats.FailedApps -gt 0 -or $Global:ProvisioningStats.FailedSegments -gt 0) {
        Write-LogMessage "❌ Some provisioning operations failed. Check the log for details." -Level ERROR -Component "Summary"
        Write-LogMessage "💡 Use the generated CSV file to retry failed operations." -Level INFO -Component "Summary"
    } else {
        Write-LogMessage "✅ All provisioning operations completed successfully!" -Level SUCCESS -Component "Summary"
    }
}
#endregion

#region Main Execution
function Invoke-ProvisioningProcess {
    <#
    .SYNOPSIS
        Main orchestration function for the provisioning process.
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-LogMessage "Starting Entra Private Access provisioning process..." -Level INFO -Component "Main"
        Write-LogMessage "WhatIf Mode: $WhatIf" -Level INFO -Component "Main"
        
        # Validate required PowerShell modules are installed
        Test-RequiredModules
        
        # Validate Entra authentication
        Validate-EntraConnection
        
        # Send script execution as a custom header for reporting
        $customHeaders = New-EntraBetaCustomHeaders Provision-EntraPrivateAccessConfig
        $null = Invoke-GraphRequest -Method GET -Headers $customHeaders -OutputType PSObject -Uri "/beta/networkAccess/tenantStatus"

        # Import and validate configuration
        $configData = Import-ProvisioningConfig -ConfigPath $ProvisioningConfigPath -AppFilter $AppNamePrefix -ConnectorFilter $ConnectorGroupFilter
        
        if ($configData.Count -eq 0) {
            Write-LogMessage "No records to process after filtering" -Level WARN -Component "Main"
            return
        }
        
        # Show provisioning plan
        Show-ProvisioningPlan -ConfigData $configData
        
        # Confirm execution unless Force is specified
        if (-not $Force -and -not $WhatIf) {
            $confirmation = Read-Host "Proceed with provisioning? (y/N)"
            if ($confirmation -notmatch '^[Yy]') {
                Write-LogMessage "Provisioning cancelled by user" -Level INFO -Component "Main"
                return
            }
        }
        
        # Resolve dependencies
        Resolve-ConnectorGroups -ConfigData $configData
        Resolve-EntraGroups -ConfigData $configData
        
        # Validate dependencies and filter out applications with unresolved dependencies
        $validConfigData = Validate-ApplicationDependencies -ConfigData $configData
        
        if ($validConfigData.Count -eq 0) {
            Write-LogMessage "No applications can be processed due to unresolved dependencies. Exiting." -Level ERROR -Component "Main"
            return
        }
        
        if ($validConfigData.Count -lt $configData.Count) {
            Write-LogMessage "Proceeding with $($validConfigData.Count) segments from applications with resolved dependencies" -Level INFO -Component "Main"
            Write-LogMessage "$(($configData.Count - $validConfigData.Count)) segments were skipped due to dependency issues" -Level WARN -Component "Main"
        }
        
        # Group configuration by application (now using filtered data)
        $appGroups = $validConfigData | Group-Object -Property EnterpriseAppName
        $currentAppNumber = 0
        
        foreach ($appGroup in $appGroups) {
            $appName = $appGroup.Name
            $segments = $appGroup.Group
            $currentAppNumber++
            
            # Add visual separator and enhanced app header
            Write-LogMessage " " -Level INFO -Component "Main"
            Write-LogMessage "╔═══════════════════════════════════════════════════════════════════════════════════════" -Level SUMMARY -Component "Main"
            Write-LogMessage "║ 📱 APPLICATION [$currentAppNumber/$($appGroups.Count)]: $appName" -Level SUMMARY -Component "Main"
            Write-LogMessage "║ 🔗 Segments: $($segments.Count) | Connector: $($segments[0].ConnectorGroup) | Group: $($segments[0].EntraGroup)" -Level SUMMARY -Component "Main"
            Write-LogMessage "╚═══════════════════════════════════════════════════════════════════════════════════════" -Level SUMMARY -Component "Main"
            
            # Get connector group for first segment (assuming all segments for an app use same connector group)
            $connectorGroupName = $segments[0].ConnectorGroup
            
            # Get Entra group from first segment (assuming all segments for an app use same group)
            $entraGroupName = $segments[0].EntraGroup
            
            # Create or get application
            $appResult = New-PrivateAccessApplication -AppName $appName -ConnectorGroupName $connectorGroupName
            
            if ($appResult.Success) {
                if ($appResult.Action -eq "Created") {
                    $Global:ProvisioningStats.SuccessfulApps++
                }
                
                # Assign group to the application (once per app, using first segment's group)
                if ($entraGroupName -and $entraGroupName -ne "Placeholder_Replace_Me") {
                    Write-LogMessage "Assigning group '$entraGroupName' to application '$appName'" -Level INFO -Component "Main"
                    $assignmentResult = Set-ApplicationGroupAssignments -AppId $appResult.AppId -GroupName $entraGroupName
                    if (-not $assignmentResult.Success) {
                        Write-LogMessage "Failed to assign group '$entraGroupName' to application '$appName': $($assignmentResult.Error)" -Level WARN -Component "Main"
                    }
                }
                
                # Process segments for this application
                Write-LogMessage "🔧 Processing $($segments.Count) segments for application '$appName'..." -Level INFO -Component "Main"
                foreach ($segment in $segments) {
                    Write-ProgressUpdate -Current $Global:ProvisioningStats.ProcessedRecords -Total $Global:ProvisioningStats.TotalRecords -Activity "Provisioning Segments" -Status "Processing $($segment.EnterpriseAppName)"
                    
                    $segmentResult = New-ApplicationSegments -AppId $appResult.AppObjectId -SegmentConfig $segment
                    
                    if ($segmentResult.Success) {
                        $Global:ProvisioningStats.SuccessfulSegments++
                        
                        # Direct lookup instead of filtering
                        $resultRecord = $Global:RecordLookup[$segment.UniqueRecordId]
                        
                        if ($resultRecord) {
                            if ($segmentResult.Action -eq "AlreadyExists") {
                                $resultRecord.ProvisioningResult = "AlreadyExists"
                                $resultRecord.Provision = "No"  # Mark as completed since segment already exists
                            } elseif ($appResult.Action -eq "ExistingApp") {
                                $resultRecord.ProvisioningResult = "AddedToExisting"
                                $resultRecord.Provision = "No"  # Mark as completed
                            } else {
                                $resultRecord.ProvisioningResult = "Provisioned"
                                $resultRecord.Provision = "No"  # Mark as completed
                            }
                        }
                    } else {
                        $Global:ProvisioningStats.FailedSegments++
                        
                        # Direct lookup instead of filtering
                        $resultRecord = $Global:RecordLookup[$segment.UniqueRecordId]
                        
                        if ($resultRecord) {
                            $resultRecord.ProvisioningResult = "Error: $($segmentResult.Error)"
                            # Keep Provision as "Yes" for retry
                        }
                    }
                    
                    $Global:ProvisioningStats.ProcessedRecords++
                }
                
                # Application completed successfully
                Write-LogMessage "✅ Application '$appName' completed: $($segments.Count) segments processed" -Level SUCCESS -Component "Main"
            } else {
                $Global:ProvisioningStats.FailedApps++
                
                # Mark all segments for this app as failed
                foreach ($segment in $segments) {
                    # Direct lookup instead of filtering
                    $resultRecord = $Global:RecordLookup[$segment.UniqueRecordId]
                    
                    if ($resultRecord) {
                        $resultRecord.ProvisioningResult = "Skipped: App creation failed - $($appResult.Error)"
                        # Keep Provision as "Yes" for retry
                    }
                    
                    $Global:ProvisioningStats.ProcessedRecords++
                }
                
                # Application failed
                Write-LogMessage "❌ Application '$appName' failed: $($appResult.Error)" -Level ERROR -Component "Main"
            }
        }
        
        # Complete progress bar
        Write-Progress -Activity "Provisioning Segments" -Completed
        
        # Export results
        $outputPath = Export-ProvisioningResults -InputPath $ProvisioningConfigPath
        
        # Show summary
        Show-ExecutionSummary
        
        Write-LogMessage "Provisioning process completed successfully" -Level SUCCESS -Component "Main"
        Write-LogMessage "Results exported to: $outputPath" -Level INFO -Component "Main"
    }
    catch {
        Write-LogMessage "Provisioning process failed: $_" -Level ERROR -Component "Main"
        throw
    }
}

# Execute main process
try {
    Invoke-ProvisioningProcess
}
catch {
    Write-LogMessage "Fatal error during provisioning: $_" -Level ERROR -Component "Main"
    exit 1
}
#endregion
