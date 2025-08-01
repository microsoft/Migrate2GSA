#Requires -Version 7.0


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
    Requires: PowerShell 7+, Microsoft Graph PowerShell SDK, Entra PowerShell
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
$Global:ApplicationCache = @{}
$Global:ProvisioningResults = @()
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
function Validate-MicrosoftGraph {
    <#
    .SYNOPSIS
        Validates Microsoft Graph connection and required permissions.
    #>
    [CmdletBinding()]
    param()
    
    Write-LogMessage "Validating Microsoft Graph connection..." -Level INFO -Component "Auth"
    
    try {
        # Check if already connected
        $context = Get-MgContext
        
        if (-not $context) {
            Write-LogMessage "No active Microsoft Graph connection found." -Level WARN -Component "Auth"
            Write-LogMessage "Please connect to Microsoft Graph with the following command:" -Level INFO -Component "Auth"
            Write-LogMessage "Connect-MgGraph -Scopes 'Application.ReadWrite.All', 'Group.Read.All', 'Directory.Read.All' -ContextScope Process" -Level INFO -Component "Auth"
            throw "Microsoft Graph connection required"
        }
        
        # Validate tenant
        Write-LogMessage "Connected to tenant: $($context.TenantId)" -Level INFO -Component "Auth"
        Write-LogMessage "Connected as: $($context.Account)" -Level INFO -Component "Auth"
        
        # Check required scopes
        $requiredScopes = @(
            'Application.ReadWrite.All',
            'Group.Read.All',
            'Directory.Read.All'
        )
        
        $missingScopes = @()
        foreach ($scope in $requiredScopes) {
            if ($scope -notin $context.Scopes) {
                $missingScopes += $scope
            }
        }
        
        if ($missingScopes.Count -gt 0) {
            Write-LogMessage "Missing required scopes: $($missingScopes -join ', ')" -Level ERROR -Component "Auth"
            Write-LogMessage "Please reconnect with: Connect-MgGraph -Scopes '$($requiredScopes -join "', '")' -ContextScope Process" -Level INFO -Component "Auth"
            throw "Insufficient permissions"
        }
        
        Write-LogMessage "Microsoft Graph connection validated successfully" -Level SUCCESS -Component "Auth"
        return $true
    }
    catch {
        Write-LogMessage "Failed to validate Microsoft Graph connection: $_" -Level ERROR -Component "Auth"
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
            'destinationHost',
            'DestinationType',
            'Protocol',
            'Ports',
            'ConnectorGroup',
            'Provision'
        )
        
        $actualColumns = $configData[0].PSObject.Properties.Name
        $missingColumns = $requiredColumns | Where-Object { $_ -notin $actualColumns }
        
        if ($missingColumns.Count -gt 0) {
            throw "Missing required columns: $($missingColumns -join ', ')"
        }
        
        # Add ProvisioningResult column if it doesn't exist
        if ('ProvisioningResult' -notin $actualColumns) {
            Write-LogMessage "Adding ProvisioningResult column to configuration data" -Level INFO -Component "Config"
            $configData | ForEach-Object {
                $_ | Add-Member -MemberType NoteProperty -Name 'ProvisioningResult' -Value '' -Force
            }
        }
        
        # Filter data
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
        $allConnectorGroups = Invoke-GraphRequest -Method GET -Uri "/beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups"
        
        # Extract applicationProxy connector groups from the response
        $applicationProxyConnectorGroups = $allConnectorGroups.value | Where-Object { $_.connectorGroupType -eq "applicationProxy" }
        
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
        # Get unique group names (excluding placeholders)
        $groupNames = $ConfigData | 
            Select-Object -ExpandProperty EntraGroup -Unique | 
            Where-Object { $_ -and $_ -ne "Placeholder_Replace_Me" -and $_ -ne "" }
        
        if ($groupNames.Count -eq 0) {
            Write-LogMessage "No Entra groups to resolve (all placeholders)" -Level INFO -Component "EntraGroups"
            return
        }
        
        Write-LogMessage "Found $($groupNames.Count) unique Entra groups to resolve" -Level INFO -Component "EntraGroups"
        
        foreach ($groupName in $groupNames) {
            try {
                $group = Get-MgGroup -Filter "displayName eq '$groupName'" -ErrorAction Stop
                
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
                $resultRecord = $Global:ProvisioningResults | Where-Object { 
                    $_.EnterpriseAppName -eq $segment.EnterpriseAppName -and 
                    $_.destinationHost -eq $segment.destinationHost -and 
                    $_.Protocol -eq $segment.Protocol 
                }
                
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
            $Global:ApplicationCache[$AppName] = $existingApp.Id
            return @{ Success = $true; AppId = $existingApp.Id; Action = "ExistingApp" }
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
        
        # Get the created application to retrieve the actual object with ID
        $newApp = Get-EntraBetaPrivateAccessApplication -ApplicationName $AppName -ErrorAction Stop
        
        if (-not $newApp) {
            throw "Failed to retrieve created application '$AppName' after creation"
        }
        
        $Global:ApplicationCache[$AppName] = $newApp.Id
        Write-LogMessage "Successfully created Private Access application: $AppName (ID: $($newApp.Id))" -Level SUCCESS -Component "AppProvisioning"
        
        return @{ Success = $true; AppId = $newApp.Id; Action = "Created" }
    }
    catch {
        Write-LogMessage "Failed to create Private Access application '$AppName': $_" -Level ERROR -Component "AppProvisioning"
        return @{ Success = $false; Error = $_.Exception.Message; Action = "Failed" }
    }
}

function New-ApplicationSegments {
    <#
    .SYNOPSIS
        Creates network segments for Private Access applications.
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
            Write-LogMessage "[WHATIF]   Destination: $($SegmentConfig.destinationHost)" -Level INFO -Component "SegmentProvisioning"
            Write-LogMessage "[WHATIF]   Protocol: $($SegmentConfig.Protocol)" -Level INFO -Component "SegmentProvisioning"
            Write-LogMessage "[WHATIF]   Ports: $($SegmentConfig.Ports)" -Level INFO -Component "SegmentProvisioning"
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
        $newSegment = New-EntraBetaPrivateAccessApplicationSegment @segmentParams
        
        Write-LogMessage "Successfully created application segment: $segmentName (ID: $($newSegment.Id))" -Level SUCCESS -Component "SegmentProvisioning"
        
        return @{ Success = $true; SegmentId = $newSegment.Id; Action = "Created" }
    }
    catch {
        Write-LogMessage "Failed to create application segment '$segmentName': $_" -Level ERROR -Component "SegmentProvisioning"
        return @{ Success = $false; Error = $_.Exception.Message; Action = "Failed" }
    }
}

function Set-ApplicationGroupAssignments {
    <#
    .SYNOPSIS
        Assigns Entra ID groups to Private Access applications.
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
        
        # Create app role assignment
        # Note: This is a simplified example. The actual implementation may require
        # specific role IDs and additional parameters depending on the Entra configuration
        $assignmentParams = @{
            PrincipalId = $groupId
            ResourceId = $AppId
            AppRoleId = "00000000-0000-0000-0000-000000000000" # Default role
        }
        
        # This would be the actual assignment call - implementation may vary
        New-MgGroupAppRoleAssignment -GroupId $groupId -BodyParameter $assignmentParams
        
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
        
        # Validate authentication
        Validate-MicrosoftGraph
        
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
        
        foreach ($appGroup in $appGroups) {
            $appName = $appGroup.Name
            $segments = $appGroup.Group
            
            Write-LogMessage "Processing application: $appName ($($segments.Count) segments)" -Level INFO -Component "Main"
            
            # Get connector group for first segment (assuming all segments for an app use same connector group)
            $connectorGroupName = $segments[0].ConnectorGroup
            
            # Create or get application
            $appResult = New-PrivateAccessApplication -AppName $appName -ConnectorGroupName $connectorGroupName
            
            if ($appResult.Success) {
                if ($appResult.Action -eq "Created") {
                    $Global:ProvisioningStats.SuccessfulApps++
                }
                
                # Process segments for this application
                foreach ($segment in $segments) {
                    Write-ProgressUpdate -Current $Global:ProvisioningStats.ProcessedRecords -Total $Global:ProvisioningStats.TotalRecords -Activity "Provisioning Segments" -Status "Processing $($segment.EnterpriseAppName)"
                    
                    $segmentResult = New-ApplicationSegments -AppId $appResult.AppId -SegmentConfig $segment
                    
                    if ($segmentResult.Success) {
                        $Global:ProvisioningStats.SuccessfulSegments++
                        
                        # Assign groups if specified
                        if ($segment.EntraGroup -and $segment.EntraGroup -ne "Placeholder_Replace_Me") {
                            $assignmentResult = Set-ApplicationGroupAssignments -AppId $appResult.AppId -GroupName $segment.EntraGroup
                        }
                        
                        # Update result status
                        $resultRecord = $Global:ProvisioningResults | Where-Object { 
                            $_.EnterpriseAppName -eq $segment.EnterpriseAppName -and 
                            $_.destinationHost -eq $segment.destinationHost -and 
                            $_.Protocol -eq $segment.Protocol 
                        }
                        
                        if ($resultRecord) {
                            if ($appResult.Action -eq "ExistingApp") {
                                $resultRecord.ProvisioningResult = "AddedToExisting"
                            } else {
                                $resultRecord.ProvisioningResult = "Provisioned"
                            }
                            $resultRecord.Provision = "No"  # Mark as completed
                        }
                    } else {
                        $Global:ProvisioningStats.FailedSegments++
                        
                        # Update result status
                        $resultRecord = $Global:ProvisioningResults | Where-Object { 
                            $_.EnterpriseAppName -eq $segment.EnterpriseAppName -and 
                            $_.destinationHost -eq $segment.destinationHost -and 
                            $_.Protocol -eq $segment.Protocol 
                        }
                        
                        if ($resultRecord) {
                            $resultRecord.ProvisioningResult = "Error: $($segmentResult.Error)"
                            # Keep Provision as "Yes" for retry
                        }
                    }
                    
                    $Global:ProvisioningStats.ProcessedRecords++
                }
            } else {
                $Global:ProvisioningStats.FailedApps++
                
                # Mark all segments for this app as failed
                foreach ($segment in $segments) {
                    $resultRecord = $Global:ProvisioningResults | Where-Object { 
                        $_.EnterpriseAppName -eq $segment.EnterpriseAppName -and 
                        $_.destinationHost -eq $segment.destinationHost -and 
                        $_.Protocol -eq $segment.Protocol 
                    }
                    
                    if ($resultRecord) {
                        $resultRecord.ProvisioningResult = "Skipped: App creation failed - $($appResult.Error)"
                        # Keep Provision as "Yes" for retry
                    }
                    
                    $Global:ProvisioningStats.ProcessedRecords++
                }
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
