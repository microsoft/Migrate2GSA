<#
.SYNOPSIS
    Provisions Microsoft Entra Private Access applications from CSV configuration data.

.DESCRIPTION
    This script reads CSV configuration files containing Entra Private Access application details
    and provisions them automatically. It provides comprehensive logging, error handling, and
    supports retry scenarios through output CSV generation.
    
    The script supports assigning multiple Entra ID groups per Enterprise Application using
    semicolon-separated values in the EntraGroups column. Groups are aggregated across all
    segments of an application, deduplicated, and assigned at the application level.

.PARAMETER ProvisioningConfigPath
    Path to the CSV provisioning configuration file.

.PARAMETER AppNamePrefix
    Optional filter to provision only applications with names starting with this prefix.

.PARAMETER ConnectorGroupFilter
    Optional filter to provision only applications using this connector group.

.PARAMETER LogPath
    Path for the log file. Defaults to .\GSA_Provisioning.log

.PARAMETER Force
    Skip confirmation prompts for automated execution.

.EXAMPLE
    Start-EntraPrivateAccessProvisioning -ProvisioningConfigPath ".\config.csv"

.EXAMPLE
    Start-EntraPrivateAccessProvisioning -ProvisioningConfigPath ".\config.csv" -AppNamePrefix "GSA-" -WhatIf

.NOTES
    Author: Andres Canello
    Version: 2.0
    Requires: PowerShell 7+, Entra PowerShell Beta Modules
#>

function Start-EntraPrivateAccessProvisioning {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param (
        [Parameter(Mandatory=$true, HelpMessage="Path to CSV provisioning config file")]
        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [string]$ProvisioningConfigPath,
           
        [Parameter(HelpMessage="Application name filter")]
        [string]$AppNamePrefix = "",
        
        [Parameter(HelpMessage="Connector group filter")]
        [string]$ConnectorGroupFilter = "",
         
    [Parameter(HelpMessage="Log file path")]
    [string]$LogPath = "$PWD\Start-EntraPrivateAccessConfig.log",
    
    [Parameter(HelpMessage="Skip confirmation prompts")]
    [switch]$Force,
    
    [Parameter(HelpMessage="Skip creating segments on existing applications (workaround for duplicate segment bug)")]
    [switch]$SkipExistingApps = $true
)#region Global Variables
# Set script-scoped LogPath for Write-LogMessage to find
$script:LogPath = $LogPath

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
$Global:MissingGroups = @()
$Global:ProvisioningResults = @()
$Global:RecordLookup = @{}
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

function Test-EntraConnection {
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
            'EntraGroups'
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
    if ($WhatIfPreference) {
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
            
            # Get aggregated Entra groups
            $aggregatedGroups = Get-AggregatedEntraGroups -Segments $appGroup.Group
            if ($aggregatedGroups.Count -gt 0) {
                Write-LogMessage "    Entra Groups ($($aggregatedGroups.Count)):" -Level INFO -Component "Plan"
                foreach ($groupName in $aggregatedGroups) {
                    Write-LogMessage "      - $groupName" -Level INFO -Component "Plan"
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
        $connectorGroupParams = @{}
        if ($DebugPreference -eq 'Continue') {
            $connectorGroupParams['Debug'] = $true
        }
        $allConnectorGroups = Get-IntApplicationProxyConnectorGroup @connectorGroupParams
        
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
    
    .DESCRIPTION
        Parses the EntraGroups column (semicolon-separated), aggregates groups across all segments
        per application, deduplicates, filters out placeholders, and resolves all unique groups.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$ConfigData
    )
    
    Write-LogMessage "Resolving Entra ID groups..." -Level INFO -Component "EntraGroups"
    
    try {
        # Group by application to aggregate groups from all segments
        $appGroups = $ConfigData | Group-Object -Property EnterpriseAppName
        $allGroupNames = @()
        
        foreach ($appGroup in $appGroups) {
            # Aggregate groups from ALL segments for this application
            foreach ($segment in $appGroup.Group) {
                $groupsField = $segment.EntraGroups
                
                if ([string]::IsNullOrWhiteSpace($groupsField)) {
                    continue
                }
                
                # Split by semicolon and process each group
                $groupNames = $groupsField -split ';' | ForEach-Object { $_.Trim() } | Where-Object { 
                    -not [string]::IsNullOrWhiteSpace($_) -and $_ -notmatch '_Replace_Me'
                }
                
                # Add to collection
                $allGroupNames += $groupNames
            }
        }
        
        # Remove duplicates (case-insensitive)
        $uniqueGroupNames = $allGroupNames | Sort-Object -Unique
        
        if ($uniqueGroupNames.Count -eq 0) {
            Write-LogMessage "No Entra groups to resolve (all placeholders or empty)" -Level INFO -Component "EntraGroups"
            return
        }
        
        Write-LogMessage "Found $($uniqueGroupNames.Count) unique Entra groups to resolve across all segments" -Level INFO -Component "EntraGroups"
        
        foreach ($groupName in $uniqueGroupNames) {
            try {
                $groupParams = @{
                    Filter = "displayName eq '$groupName'"
                    ErrorAction = 'Stop'
                }
                if ($DebugPreference -eq 'Continue') {
                    $groupParams['Debug'] = $true
                }
                $group = Get-IntGroup @groupParams
                
                if ($group) {
                    $Global:EntraGroupCache[$groupName] = $group.Id
                    Write-LogMessage "Resolved Entra group '$groupName' to ID: $($group.Id)" -Level SUCCESS -Component "EntraGroups"
                } else {
                    Write-LogMessage "⚠️  Entra group '$groupName' not found in tenant" -Level WARN -Component "EntraGroups"
                    $Global:EntraGroupCache[$groupName] = $null
                    $Global:MissingGroups += $groupName
                }
            }
            catch {
                Write-LogMessage "Failed to resolve Entra group '$groupName': $_" -Level ERROR -Component "EntraGroups"
                $Global:EntraGroupCache[$groupName] = $null
                if ($groupName -notin $Global:MissingGroups) {
                    $Global:MissingGroups += $groupName
                }
            }
        }
        
        Write-LogMessage "Entra group resolution completed" -Level SUCCESS -Component "EntraGroups"
    }
    catch {
        Write-LogMessage "Failed to resolve Entra groups: $_" -Level ERROR -Component "EntraGroups"
        throw
    }
}

function Get-AggregatedEntraGroups {
    <#
    .SYNOPSIS
        Gets aggregated, deduplicated Entra groups for an application.
    
    .DESCRIPTION
        Parses EntraGroups from all segments of an application, splits semicolon-separated values,
        filters placeholders, deduplicates, and returns sorted array of group names.
    
    .PARAMETER Segments
        Array of segment objects for an application.
    
    .OUTPUTS
        Array of unique group names (case-insensitive, sorted alphabetically).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$Segments
    )
    
    $allGroupNames = @()
    
    foreach ($segment in $Segments) {
        $groupsField = $segment.EntraGroups
        
        if ([string]::IsNullOrWhiteSpace($groupsField)) {
            continue
        }
        
        # Split by semicolon and process each group
        $groupNames = $groupsField -split ';' | ForEach-Object { $_.Trim() } | Where-Object { 
            -not [string]::IsNullOrWhiteSpace($_) -and $_ -notmatch '_Replace_Me'
        }
        
        $allGroupNames += $groupNames
    }
    
    # Remove duplicates (case-insensitive) and sort
    $uniqueGroupNames = $allGroupNames | Sort-Object -Unique
    
    return $uniqueGroupNames
}

function Test-MissingGroupsAndUsers {
    <#
    .SYNOPSIS
        Validates that all required Entra groups and users exist before provisioning.
    
    .DESCRIPTION
        Checks if any groups or users referenced in the configuration could not be resolved
        in Entra ID. If missing items are found, displays a comprehensive list and stops
        script execution to prevent provisioning failures.
        
        Note: User provisioning is not currently implemented. EntraUsers column is ignored
        for now but validated for future enhancement.
    
    .PARAMETER ConfigData
        Array of configuration records to validate.
    
    .OUTPUTS
        Throws an error if missing groups or users are detected, stopping execution.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$ConfigData
    )
    
    Write-LogMessage "Validating all Entra groups and users exist..." -Level INFO -Component "Validation"
    
    $hasErrors = $false
    
    # Check for missing groups
    if ($Global:MissingGroups.Count -gt 0) {
        $hasErrors = $true
        Write-LogMessage "❌ ERROR: The following Entra groups were not found in the tenant:" -Level ERROR -Component "Validation"
        foreach ($missingGroup in ($Global:MissingGroups | Sort-Object -Unique)) {
            Write-LogMessage "   - $missingGroup" -Level ERROR -Component "Validation"
        }
        Write-LogMessage "" -Level ERROR -Component "Validation"
    }
    
    # Future Enhancement: User validation
    # TODO: Add user resolution and validation logic similar to groups
    # The EntraUsers column exists in the CSV but is not currently processed by this script.
    # When user provisioning is implemented, add validation here to check for missing users.
    
    if ($hasErrors) {
        Write-LogMessage "" -Level ERROR -Component "Validation"
        Write-LogMessage "⛔ Provisioning cannot proceed due to missing Entra groups." -Level ERROR -Component "Validation"
        Write-LogMessage "Please ensure all referenced groups exist in your Entra ID tenant before running this script." -Level ERROR -Component "Validation"
        throw "Validation failed: Missing Entra groups detected. Cannot proceed with provisioning."
    }
    
    Write-LogMessage "✅ All referenced Entra groups exist in the tenant" -Level SUCCESS -Component "Validation"
}

function Test-ApplicationDependencies {
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
        $skipApp = $false
        
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
        
        # Check Entra groups for this application (aggregated from all segments)
        $aggregatedGroups = Get-AggregatedEntraGroups -Segments $segments
        $unresolvedEntraGroups = @()
        
        foreach ($groupName in $aggregatedGroups) {
            if (-not $Global:EntraGroupCache.ContainsKey($groupName) -or -not $Global:EntraGroupCache[$groupName]) {
                $unresolvedEntraGroups += $groupName
            }
        }
        
        # Report unresolved connector groups
        if ($unresolvedConnectorGroups.Count -gt 0) {
            $skipApp = $true
            Write-LogMessage "❌ Skipping application '$appName': Unresolved connector groups found" -Level ERROR -Component "Validation"
            
            foreach ($unresolvedCG in $unresolvedConnectorGroups) {
                if ($unresolvedCG -eq "Placeholder_Replace_Me") {
                    Write-LogMessage "   - '$unresolvedCG' (placeholder - replace with actual connector group name)" -Level ERROR -Component "Validation"
                } else {
                    Write-LogMessage "   - '$unresolvedCG' (not found in tenant)" -Level ERROR -Component "Validation"
                }
            }
        }
        
        # Report unresolved Entra groups (warning only, don't skip app)
        if ($unresolvedEntraGroups.Count -gt 0) {
            Write-LogMessage "⚠️  Warning for application '$appName': Some Entra groups could not be resolved" -Level WARN -Component "Validation"
            foreach ($unresolvedGroup in $unresolvedEntraGroups) {
                Write-LogMessage "   - '$unresolvedGroup' (not found in tenant)" -Level WARN -Component "Validation"
            }
            Write-LogMessage "   Application will be provisioned, but group assignments may fail" -Level WARN -Component "Validation"
        }
        
        if ($skipApp) {
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
            # Application has connector groups resolved (Entra groups are optional)
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
        [string]$ConnectorGroupName,
        
        [Parameter(Mandatory=$false)]
        [bool]$SkipExisting = $true
    )
    
    Write-LogMessage "Processing Private Access application: $AppName" -Level INFO -Component "AppProvisioning"
    
    try {
        # Check if application already exists
        $checkAppParams = @{
            ApplicationName = $AppName
            ErrorAction = 'SilentlyContinue'
        }
        if ($DebugPreference -eq 'Continue') {
            $checkAppParams['Debug'] = $true
        }
        $existingApp = Get-IntPrivateAccessApp @checkAppParams
        
        if ($existingApp) {
            # Handle case where multiple apps with same name exist - select the most recent one
            if ($existingApp -is [array]) {
                Write-LogMessage "Multiple applications found with name '$AppName' ($($existingApp.Count) apps). Selecting most recent." -Level WARN -Component "AppProvisioning"
                $existingApp = $existingApp | Sort-Object createdDateTime -Descending | Select-Object -First 1
            }
            
            if ($SkipExisting) {
                Write-LogMessage "Application '$AppName' already exists. Skipping segment creation (SkipExistingApps enabled)." -Level WARN -Component "AppProvisioning"
                return @{ Success = $true; AppId = $existingApp.appId; AppObjectId = $existingApp.id; Action = "SkippedExisting" }
            } else {
                Write-LogMessage "Application '$AppName' already exists. Will add segments to existing app." -Level INFO -Component "AppProvisioning"
                return @{ Success = $true; AppId = $existingApp.appId; AppObjectId = $existingApp.id; Action = "ExistingApp" }
            }
        }
        
        # Get connector group ID
        $connectorGroupId = $Global:ConnectorGroupCache[$ConnectorGroupName]
        if (-not $connectorGroupId) {
            throw "Connector group '$ConnectorGroupName' not found"
        }
        
        if ($WhatIfPreference) {
            Write-LogMessage "[WHATIF] Would create Private Access application: $AppName" -Level INFO -Component "AppProvisioning"
            return @{ Success = $true; AppId = "whatif-app-id"; Action = "WhatIf" }
        }
        
        # Create new application using internal function
        $appParams = @{
            ApplicationName = $AppName
            ConnectorGroupId = $connectorGroupId
        }
        
        # Add Debug parameter if script was called with -Debug
        if ($DebugPreference -eq 'Continue') {
            $appParams['Debug'] = $true
        }
        
        # Create the application and get the result object
        $createResult = New-IntPrivateAccessApp @appParams
        
        if (-not $createResult.Success) {
            throw "Failed to create application: $($createResult.Error)"
        }
        
        Write-LogMessage $createResult.Message -Level SUCCESS -Component "AppProvisioning"
        
        # The application was created, but we still need to retrieve it using the Get cmdlet
        # to ensure we have the full object with all properties needed downstream
        # Retry logic to retrieve the created application with exponential backoff
        $maxRetries = 6
        $baseDelay = 2  # seconds
        $newApp = $null
        
        for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
            try {
                Write-LogMessage "Attempting to retrieve created application '$AppName' (attempt $attempt/$maxRetries)" -Level INFO -Component "AppProvisioning"
                
                $getAppParams = @{
                    ApplicationName = $AppName
                    ErrorAction = 'Stop'
                }
                if ($DebugPreference -eq 'Continue') {
                    $getAppParams['Debug'] = $true
                }
                $newApp = Get-IntPrivateAccessApp @getAppParams
                
                if ($newApp) {
                    # Handle case where multiple apps with same name exist - select the most recent one
                    if ($newApp -is [array]) {
                        Write-LogMessage "Multiple applications found with name '$AppName' ($($newApp.Count) apps). Selecting most recent." -Level WARN -Component "AppProvisioning"
                        $newApp = $newApp | Sort-Object createdDateTime -Descending | Select-Object -First 1
                    }
                    Write-LogMessage "Successfully retrieved created application '$AppName' on attempt $attempt" -Level SUCCESS -Component "AppProvisioning"
                    break
                }
                
                # If no app found and not the last attempt, wait before retrying
                if ($attempt -lt $maxRetries) {
                    $delay = $baseDelay * [math]::Pow(2, $attempt - 1)  # Exponential backoff: 2, 4, 8, 16 seconds
                    Write-LogMessage "Application '$AppName' not found on attempt $attempt. Retrying in $delay seconds..." -Level WARN -Component "AppProvisioning"
                    Start-Sleep -Seconds $delay
                }
            }
            catch {
                $delay = $baseDelay * [math]::Pow(2, $attempt - 1)  # Exponential backoff: 2, 4, 8, 16 seconds
                
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
        
        Write-LogMessage "Successfully created Private Access application: $AppName (ID: $($newApp.id))" -Level SUCCESS -Component "AppProvisioning"
        
        return @{ Success = $true; AppId = $newApp.appId; AppObjectId = $newApp.id; Action = "Created" }
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
        
        if ($WhatIfPreference) {
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
            ErrorAction = 'Stop'
        }
        
        # Add Debug parameter if script was called with -Debug
        if ($DebugPreference -eq 'Continue') {
            $segmentParams['Debug'] = $true
        }
        
        # Create the segment using internal function
        $newSegment = New-IntPrivateAccessAppSegment @segmentParams
        
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
        Assigns multiple Entra ID groups to Private Access applications.
    
    .DESCRIPTION
        Assigns one or more Entra ID groups to a Private Access application. The function processes
        each group individually, includes duplicate assignment checking, and returns a summary of
        successful, already assigned, and failed assignments. The application provisioning is not
        considered failed even if group assignments fail.
    
    .PARAMETER AppId
        The application ID of the Private Access application.
    
    .PARAMETER GroupNames
        Array of Entra ID group display names to assign to the application.
    
    .OUTPUTS
        Returns a hashtable with:
        - TotalGroups: Total number of groups to assign
        - Succeeded: Number of successfully assigned groups
        - AlreadyAssigned: Number of groups already assigned
        - Failed: Number of failed group assignments
        - FailedGroups: Array of group names that failed
    
    .EXAMPLE
        Set-ApplicationGroupAssignments -AppId "app-123" -GroupNames @("Group1", "Group2")
        Assigns multiple groups to application "app-123".
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$AppId,
        
        [Parameter(Mandatory=$true)]
        [string[]]$GroupNames
    )
    
    # Initialize result tracking
    $result = @{
        TotalGroups = $GroupNames.Count
        Succeeded = 0
        AlreadyAssigned = 0
        Failed = 0
        FailedGroups = @()
    }
    
    if ($GroupNames.Count -eq 0) {
        Write-LogMessage "No groups to assign" -Level INFO -Component "GroupAssignment"
        return $result
    }
    
    Write-LogMessage "Assigning $($GroupNames.Count) groups to application" -Level INFO -Component "GroupAssignment"
    
    # Get the service principal once for all assignments (if not WhatIf)
    $servicePrincipal = $null
    $appRoleId = $null
    
    if (-not $WhatIfPreference) {
        try {
            # Get the service principal for the application with retry logic
            # Service principals may not be immediately available after application creation
            $maxRetries = 6
            $baseDelay = 2  # seconds
            $servicePrincipal = $null
            
            for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
                try {
                    Write-LogMessage "Attempting to retrieve service principal for application (attempt $attempt/$maxRetries)" -Level INFO -Component "GroupAssignment"
                    
                    $servicePrincipal = Get-IntServicePrincipal -Filter "appId eq '$AppId'"
                    
                    if ($servicePrincipal) {
                        Write-LogMessage "Successfully retrieved service principal on attempt $attempt" -Level SUCCESS -Component "GroupAssignment"
                        break
                    }
                    
                    # If no service principal found and not the last attempt, wait before retrying
                    if ($attempt -lt $maxRetries) {
                        $delay = $baseDelay * [math]::Pow(2, $attempt - 1)  # Exponential backoff: 2, 4, 8, 16 seconds
                        Write-LogMessage "Service principal not found on attempt $attempt. Retrying in $delay seconds..." -Level WARN -Component "GroupAssignment"
                        Start-Sleep -Seconds $delay
                    }
                }
                catch {
                    $delay = $baseDelay * [math]::Pow(2, $attempt - 1)  # Exponential backoff: 2, 4, 8, 16 seconds
                    
                    if ($attempt -eq $maxRetries) {
                        Write-LogMessage "Failed to retrieve service principal after $maxRetries attempts. Final error: $_" -Level ERROR -Component "GroupAssignment"
                        throw "Failed to retrieve service principal for application ID '$AppId' after $maxRetries retry attempts"
                    }
                    
                    Write-LogMessage "Failed to retrieve service principal on attempt $attempt. Retrying in $delay seconds... Error: $_" -Level WARN -Component "GroupAssignment"
                    Start-Sleep -Seconds $delay
                }
            }
            
            if (-not $servicePrincipal) {
                Write-LogMessage "Service principal not found for application ID: $AppId after $maxRetries retry attempts" -Level ERROR -Component "GroupAssignment"
                $result.Failed = $GroupNames.Count
                $result.FailedGroups = $GroupNames
                return $result
            }
            
            # Find the User app role from the service principal's app roles
            $userAppRole = $servicePrincipal.AppRoles | Where-Object { $_.DisplayName -eq "User" -and $_.IsEnabled -eq $true }
            
            if (-not $userAppRole) {
                # Fallback to default role if User role not found
                Write-LogMessage "User app role not found for application, using default role" -Level WARN -Component "GroupAssignment"
                $appRoleId = "00000000-0000-0000-0000-000000000000"
            } else {
                $appRoleId = $userAppRole.Id
            }
        }
        catch {
            Write-LogMessage "Failed to retrieve service principal: $_" -Level ERROR -Component "GroupAssignment"
            $result.Failed = $GroupNames.Count
            $result.FailedGroups = $GroupNames
            return $result
        }
    }
    
    # Process each group individually
    foreach ($groupName in $GroupNames) {
        try {
            # Skip placeholders
            if ($groupName -match '_Replace_Me' -or [string]::IsNullOrWhiteSpace($groupName)) {
                Write-LogMessage "Skipping placeholder group: '$groupName'" -Level INFO -Component "GroupAssignment"
                continue
            }
            
            Write-LogMessage "Assigning group '$groupName' to application" -Level INFO -Component "GroupAssignment"
            
            # Check if group was resolved
            $groupId = $Global:EntraGroupCache[$groupName]
            if (-not $groupId) {
                Write-LogMessage "Group '$groupName' not found or not resolved" -Level WARN -Component "GroupAssignment"
                $result.Failed++
                $result.FailedGroups += $groupName
                continue
            }
            
            if ($WhatIfPreference) {
                Write-LogMessage "[WHATIF] Would assign group '$groupName' to application" -Level INFO -Component "GroupAssignment"
                $result.Succeeded++
                continue
            }
            
            # Check if the group is already assigned to the application with this role
            try {
                $assignmentCheckParams = @{
                    ServicePrincipalId = $servicePrincipal.Id
                    ErrorAction = 'Stop'
                }
                if ($DebugPreference -eq 'Continue') {
                    $assignmentCheckParams['Debug'] = $true
                }
                $existingAssignments = Get-IntServicePrincipalAppRoleAssignedTo @assignmentCheckParams
                
                $existingAssignment = $existingAssignments | Where-Object { 
                    $_.PrincipalId -eq $groupId -and $_.AppRoleId -eq $appRoleId 
                }
                
                if ($existingAssignment) {
                    Write-LogMessage "Group '$groupName' is already assigned to application" -Level INFO -Component "GroupAssignment"
                    $result.AlreadyAssigned++
                    continue
                }
            }
            catch {
                Write-LogMessage "Warning: Could not check existing assignments for group '$groupName': $_" -Level WARN -Component "GroupAssignment"
            }

            # Create app role assignment
            $assignmentParams = @{
                GroupId = $groupId
                PrincipalId = $groupId
                ResourceId = $servicePrincipal.Id
                AppRoleId = $appRoleId
                ErrorAction = 'Stop'
            }
            
            if ($DebugPreference -eq 'Continue') {
                $assignmentParams['Debug'] = $true
            }
            
            New-IntGroupAppRoleAssignment @assignmentParams
            
            Write-LogMessage "Successfully assigned group '$groupName' to application" -Level SUCCESS -Component "GroupAssignment"
            $result.Succeeded++
        }
        catch {
            Write-LogMessage "Failed to assign group '$groupName' to application: $_" -Level ERROR -Component "GroupAssignment"
            $result.Failed++
            $result.FailedGroups += $groupName
        }
    }
    
    # Log summary
    if ($result.Failed -gt 0) {
        Write-LogMessage "Group assignment summary: $($result.Succeeded) succeeded, $($result.AlreadyAssigned) already assigned, $($result.Failed) failed" -Level WARN -Component "GroupAssignment"
    } else {
        Write-LogMessage "Group assignment summary: $($result.Succeeded) succeeded, $($result.AlreadyAssigned) already assigned" -Level SUCCESS -Component "GroupAssignment"
    }
    
    return $result
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
        Write-LogMessage "WhatIf Mode: $WhatIfPreference" -Level INFO -Component "Main"
        
        # Validate required PowerShell modules are installed
        Test-RequiredModules
        
        # Validate Entra authentication
        Test-EntraConnection
        
        # Check tenant
        $null = Invoke-InternalGraphRequest -Uri "/beta/networkAccess/tenantStatus"

        # Import and validate configuration
        $configData = Import-ProvisioningConfig -ConfigPath $ProvisioningConfigPath -AppFilter $AppNamePrefix -ConnectorFilter $ConnectorGroupFilter
        
        if ($configData.Count -eq 0) {
            Write-LogMessage "No records to process after filtering" -Level WARN -Component "Main"
            return
        }
        
        # Show provisioning plan
        Show-ProvisioningPlan -ConfigData $configData
        
        # Confirm execution unless Force is specified
        if (-not $Force -and -not $WhatIfPreference) {
            $confirmation = Read-Host "Proceed with provisioning? (y/N)"
            if ($confirmation -notmatch '^[Yy]') {
                Write-LogMessage "Provisioning cancelled by user" -Level INFO -Component "Main"
                return
            }
        }
        
        # Resolve dependencies
        Resolve-ConnectorGroups -ConfigData $configData
        Resolve-EntraGroups -ConfigData $configData
        
        # Validate that all required groups and users exist in Entra ID
        # This will throw an error and stop execution if any are missing
        Test-MissingGroupsAndUsers -ConfigData $configData
        
        # Validate dependencies and filter out applications with unresolved dependencies
        $validConfigData = Test-ApplicationDependencies -ConfigData $configData
        
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
            
            # Get connector group for first segment (assuming all segments for an app use same connector group)
            $connectorGroupName = $segments[0].ConnectorGroup
            
            # Get aggregated Entra groups from all segments
            $aggregatedGroups = Get-AggregatedEntraGroups -Segments $segments
            
            # Add visual separator and enhanced app header
            Write-LogMessage " " -Level INFO -Component "Main"
            Write-LogMessage "╔═══════════════════════════════════════════════════════════════════════════════════════" -Level SUMMARY -Component "Main"
            Write-LogMessage "║ 📱 APPLICATION [$currentAppNumber/$($appGroups.Count)]: $appName" -Level SUMMARY -Component "Main"
            if ($aggregatedGroups.Count -gt 0) {
                Write-LogMessage "║ 🔗 Segments: $($segments.Count) | Connector: $connectorGroupName | Groups: $($aggregatedGroups.Count)" -Level SUMMARY -Component "Main"
            } else {
                Write-LogMessage "║ 🔗 Segments: $($segments.Count) | Connector: $connectorGroupName | Groups: None" -Level SUMMARY -Component "Main"
            }
            Write-LogMessage "╚═══════════════════════════════════════════════════════════════════════════════════════" -Level SUMMARY -Component "Main"
            
            # Create or get application
            $appResult = New-PrivateAccessApplication -AppName $appName -ConnectorGroupName $connectorGroupName -SkipExisting $SkipExistingApps
            
            if ($appResult.Success) {
                # Handle skipped existing apps
                if ($appResult.Action -eq "SkippedExisting") {
                    Write-LogMessage "⏭️  Skipping all segments and group assignments for existing application '$appName'" -Level WARN -Component "Main"
                    
                    # Mark all segments as skipped
                    foreach ($segment in $segments) {
                        $resultRecord = $Global:RecordLookup[$segment.UniqueRecordId]
                        if ($resultRecord) {
                            $resultRecord.ProvisioningResult = "Skipped: Application already exists (SkipExistingApps enabled)"
                            $resultRecord.Provision = "No"
                        }
                        $Global:ProvisioningStats.ProcessedRecords++
                    }
                    
                    Write-LogMessage "⏭️  Application '$appName' skipped: $($segments.Count) segments not created" -Level WARN -Component "Main"
                    continue
                }
                
                if ($appResult.Action -eq "Created") {
                    $Global:ProvisioningStats.SuccessfulApps++
                }
                
                # Assign aggregated groups to the application
                if ($aggregatedGroups.Count -gt 0) {
                    $assignmentResult = Set-ApplicationGroupAssignments -AppId $appResult.AppId -GroupNames $aggregatedGroups
                    
                    # Update provisioning result based on group assignment outcomes
                    $groupAssignmentStatus = ""
                    if ($assignmentResult.Failed -eq 1) {
                        $groupAssignmentStatus = " (Warning: 1 group failed assignment)"
                    } elseif ($assignmentResult.Failed -gt 1) {
                        $groupAssignmentStatus = " (Warning: Multiple groups failed assignment, check the log)"
                    } elseif ($assignmentResult.Failed -eq $assignmentResult.TotalGroups -and $assignmentResult.TotalGroups -gt 0) {
                        $groupAssignmentStatus = " (Warning: All groups failed assignment, check the log)"
                    }
                    
                    # Store for later use in result tracking
                    $Global:CurrentAppGroupAssignmentStatus = $groupAssignmentStatus
                } else {
                    $Global:CurrentAppGroupAssignmentStatus = ""
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
                                $resultRecord.ProvisioningResult = "AlreadyExists$($Global:CurrentAppGroupAssignmentStatus)"
                                $resultRecord.Provision = "No"  # Mark as completed since segment already exists
                            } elseif ($appResult.Action -eq "ExistingApp") {
                                $resultRecord.ProvisioningResult = "AddedToExisting$($Global:CurrentAppGroupAssignmentStatus)"
                                $resultRecord.Provision = "No"  # Mark as completed
                            } else {
                                $resultRecord.ProvisioningResult = "Provisioned$($Global:CurrentAppGroupAssignmentStatus)"
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
        Write-LogMessage "Log file written to: $LogPath" -Level INFO -Component "Main"
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
        throw
    }
}
#endregion
