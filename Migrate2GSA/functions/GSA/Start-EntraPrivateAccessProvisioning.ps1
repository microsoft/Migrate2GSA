<#
.SYNOPSIS
    Provisions Microsoft Entra Private Access applications from CSV or JSON configuration data.

.DESCRIPTION
    This script reads CSV or JSON configuration files containing Entra Private Access application details
    and provisions them automatically. It provides comprehensive logging, error handling, and
    supports retry scenarios through output CSV generation.
    
    JSON format provides enhanced flexibility with nested structures and better integration with
    discovery tools, while CSV format maintains compatibility with existing workflows.
    
    The script supports assigning multiple Entra ID groups per Enterprise Application using
    semicolon-separated values in the EntraGroups column. Groups are aggregated across all
    segments of an application, deduplicated, and assigned at the application level.

.PARAMETER ProvisioningConfigPath
    Path to the CSV or JSON provisioning configuration file.

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
    Start-EntraPrivateAccessProvisioning -ProvisioningConfigPath ".\config.json"

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
        [Parameter(Mandatory=$true, HelpMessage="Path to CSV or JSON provisioning config file")]
        [ValidateScript({
            if (-not (Test-Path $_ -PathType Leaf)) {
                throw "File not found: $_"
            }
            $extension = [System.IO.Path]::GetExtension($_).ToLower()
            if ($extension -notin @('.csv', '.json')) {
                throw "Unsupported file format. Only .csv and .json files are supported."
            }
            return $true
        })]
        [string]$ProvisioningConfigPath,
           
        [Parameter(HelpMessage="Application name filter")]
        [string]$AppNamePrefix = "",
        
        [Parameter(HelpMessage="Connector group filter")]
        [string]$ConnectorGroupFilter = "",
         
        [Parameter(HelpMessage="Log file path")]
        [string]$LogPath = ".\Provision-EntraPrivateAccessConfig.log",
        
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

#region Authentication Functions
function Test-RequiredModules {
    <#
    .SYNOPSIS
        Validates that all required PowerShell modules are installed and loads them properly.
        
    .DESCRIPTION
        Checks for required Microsoft Entra and Graph modules, handles dependencies,
        and imports modules in the correct order to avoid dependency conflicts.
    #>
    [CmdletBinding()]
    param()
    
    Write-LogMessage "Validating required PowerShell modules..." -Level INFO -Component "ModuleCheck"
    
    # Define modules in dependency order (Graph modules must be loaded before Entra modules)
    $requiredModules = @(
        @{ Name = 'Microsoft.Graph.Authentication'; Description = 'Microsoft Graph Authentication (required for all Graph modules)' },
        @{ Name = 'Microsoft.Graph.Beta.Groups'; Description = 'Microsoft Graph Beta Groups (required for Entra Groups module)' },
        @{ Name = 'Microsoft.Graph.Beta.Applications'; Description = 'Microsoft Graph Beta Applications (required for Entra modules)' },
        @{ Name = 'Microsoft.Graph.Beta.Identity.DirectoryManagement'; Description = 'Microsoft Graph Beta Directory Management (required for Entra modules)' },
        @{ Name = 'Microsoft.Entra.Beta.Groups'; Description = 'Microsoft Entra Beta Groups' },
        @{ Name = 'Microsoft.Entra.Beta.Authentication'; Description = 'Microsoft Entra Beta Authentication' },
        @{ Name = 'Microsoft.Entra.Beta.NetworkAccess'; Description = 'Microsoft Entra Beta Network Access' }
    )
    
    $missingModules = @()
    $installedModules = @()
    
    # First, check if all required modules are available
    foreach ($moduleInfo in $requiredModules) {
        $moduleName = $moduleInfo.Name
        try {
            $module = Get-Module -Name $moduleName -ListAvailable -ErrorAction Stop
            if ($module) {
                $installedModules += $moduleInfo
                $latestVersion = ($module | Sort-Object Version -Descending | Select-Object -First 1).Version
                Write-LogMessage "✅ $moduleName (v$latestVersion) - Available" -Level SUCCESS -Component "ModuleCheck"
            } else {
                $missingModules += $moduleInfo
            }
        }
        catch {
            $missingModules += $moduleInfo
        }
    }
    
    if ($missingModules.Count -gt 0) {
        Write-LogMessage "❌ Missing required PowerShell modules:" -Level ERROR -Component "ModuleCheck"
        foreach ($moduleInfo in $missingModules) {
            Write-LogMessage "   - $($moduleInfo.Name): $($moduleInfo.Description)" -Level ERROR -Component "ModuleCheck"
        }
        
        Write-LogMessage "Please install missing modules using the following commands:" -Level INFO -Component "ModuleCheck"
        Write-LogMessage "Install-Module -Name Microsoft.Graph -Force -AllowClobber" -Level INFO -Component "ModuleCheck"
        Write-LogMessage "Install-Module -Name Microsoft.Graph.Beta -Force -AllowClobber" -Level INFO -Component "ModuleCheck"
        Write-LogMessage "Install-Module -Name Microsoft.Entra.Beta -Force -AllowClobber" -Level INFO -Component "ModuleCheck"
        
        throw "Required PowerShell modules are missing: $($missingModules.Name -join ', ')"
    }
    
    Write-LogMessage "All required PowerShell modules are available" -Level SUCCESS -Component "ModuleCheck"
    
    # Now import modules in dependency order
    Write-LogMessage "Importing required modules in dependency order..." -Level INFO -Component "ModuleCheck"
    
    foreach ($moduleInfo in $installedModules) {
        $moduleName = $moduleInfo.Name
        try {
            # Check if module is already imported
            $importedModule = Get-Module -Name $moduleName -ErrorAction SilentlyContinue
            if ($importedModule) {
                Write-LogMessage "✅ $moduleName - Already imported (v$($importedModule.Version))" -Level INFO -Component "ModuleCheck"
            } else {
                Write-LogMessage "Importing module: $moduleName..." -Level INFO -Component "ModuleCheck"
                
                # Special handling for Entra modules that have strict version dependencies
                if ($moduleName.StartsWith('Microsoft.Entra.Beta.')) {
                    Write-LogMessage "Checking version dependencies for $moduleName..." -Level INFO -Component "ModuleCheck"
                    
                    # Check the module manifest for required versions
                    $availableModules = Get-Module -Name $moduleName -ListAvailable
                    $latestEntraModule = $availableModules | Sort-Object Version -Descending | Select-Object -First 1
                    
                    if ($latestEntraModule -and $latestEntraModule.Path) {
                        $manifestPath = $latestEntraModule.Path
                        Write-LogMessage "Checking manifest at: $manifestPath" -Level INFO -Component "ModuleCheck"
                        
                        try {
                            # Read the manifest to get exact version requirements
                            $manifestContent = Get-Content $manifestPath -Raw
                            
                            # Check for Graph.Beta.Groups dependency
                            if ($manifestContent -match "Microsoft\.Graph\.Beta\.Groups.*RequiredVersion.*?'([^']+)'") {
                                $requiredGraphVersion = $matches[1]
                                Write-LogMessage "Found required Graph.Beta.Groups version: $requiredGraphVersion" -Level INFO -Component "ModuleCheck"
                                
                                # Import the specific version of Graph module
                                $graphModule = Get-Module -Name 'Microsoft.Graph.Beta.Groups' -ListAvailable | Where-Object { $_.Version -eq $requiredGraphVersion }
                                if ($graphModule) {
                                    Write-LogMessage "Importing Microsoft.Graph.Beta.Groups version $requiredGraphVersion..." -Level INFO -Component "ModuleCheck"
                                    Import-Module -Name 'Microsoft.Graph.Beta.Groups' -RequiredVersion $requiredGraphVersion -Force -Global -ErrorAction Stop
                                } else {
                                    Write-LogMessage "Required version $requiredGraphVersion of Microsoft.Graph.Beta.Groups not found. Available versions:" -Level WARN -Component "ModuleCheck"
                                    $availableGraphVersions = Get-Module -Name 'Microsoft.Graph.Beta.Groups' -ListAvailable | ForEach-Object { $_.Version }
                                    Write-LogMessage "Available: $($availableGraphVersions -join ', ')" -Level INFO -Component "ModuleCheck"
                                    
                                    # Try with the closest available version
                                    $closestVersion = $availableGraphVersions | Sort-Object | Where-Object { $_ -ge [version]$requiredGraphVersion } | Select-Object -First 1
                                    if (-not $closestVersion) {
                                        $closestVersion = $availableGraphVersions | Sort-Object -Descending | Select-Object -First 1
                                    }
                                    
                                    Write-LogMessage "Attempting with closest version: $closestVersion" -Level INFO -Component "ModuleCheck"
                                    Import-Module -Name 'Microsoft.Graph.Beta.Groups' -RequiredVersion $closestVersion -Force -Global -ErrorAction Stop
                                }
                            }
                        }
                        catch {
                            Write-LogMessage "Could not parse manifest for version requirements: $($_.Exception.Message)" -Level WARN -Component "ModuleCheck"
                            # Fallback to loading latest Graph modules
                            Import-Module -Name 'Microsoft.Graph.Beta.Groups' -Force -Global -ErrorAction SilentlyContinue
                        }
                    }
                    
                    # Now try to import the Entra module
                    Import-Module -Name $moduleName -Force -Global -ErrorAction Stop
                } else {
                    # Standard import for Graph modules
                    Import-Module -Name $moduleName -Force -Global -ErrorAction Stop
                }
                
                $importedModule = Get-Module -Name $moduleName
                Write-LogMessage "✅ $moduleName - Imported successfully (v$($importedModule.Version))" -Level SUCCESS -Component "ModuleCheck"
            }
        }
        catch {
            Write-LogMessage "❌ Failed to import module $moduleName : $($_.Exception.Message)" -Level ERROR -Component "ModuleCheck"
            
            # For Entra modules, provide specific guidance about version conflicts
            if ($moduleName.StartsWith('Microsoft.Entra.Beta.')) {
                Write-LogMessage "This appears to be a version compatibility issue with Microsoft Graph modules." -Level ERROR -Component "ModuleCheck"
                Write-LogMessage "The Entra module requires specific versions of Graph modules that may not match your installed versions." -Level ERROR -Component "ModuleCheck"
                Write-LogMessage "Consider installing compatible versions:" -Level INFO -Component "ModuleCheck"
                Write-LogMessage "Install-Module Microsoft.Graph.Beta -RequiredVersion 2.25.0 -Force -AllowClobber" -Level INFO -Component "ModuleCheck"
                Write-LogMessage "Install-Module Microsoft.Entra.Beta -Force -AllowClobber" -Level INFO -Component "ModuleCheck"
            }
            
            throw "Failed to import required module: $moduleName"
        }
    }
    
    Write-LogMessage "All required PowerShell modules imported successfully" -Level SUCCESS -Component "ModuleCheck"
    
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
        
    .DESCRIPTION
        Checks if Entra PowerShell is connected with proper authentication context
        and validates that all required scopes are available for the provisioning operations.
    #>
    [CmdletBinding()]
    param()
    
    Write-LogMessage "Validating Entra PowerShell connection..." -Level INFO -Component "Auth"
    
    try {
        # Ensure authentication module is properly loaded
        try {
            $authModule = Get-Module -Name 'Microsoft.Entra.Beta.Authentication' -ErrorAction Stop
            if (-not $authModule) {
                Write-LogMessage "Authentication module not loaded, attempting import..." -Level INFO -Component "Auth"
                Import-Module -Name 'Microsoft.Entra.Beta.Authentication' -Force -ErrorAction Stop
            }
        }
        catch {
            Write-LogMessage "Failed to load authentication module: $($_.Exception.Message)" -Level ERROR -Component "Auth"
            Write-LogMessage "Please ensure Microsoft.Entra.Beta.Authentication module is properly installed" -Level ERROR -Component "Auth"
            throw "Authentication module unavailable: $_"
        }
        
        # Check if already connected
        $context = $null
        try {
            $context = Get-EntraContext -ErrorAction Stop
        }
        catch {
            Write-LogMessage "Error checking Entra context: $($_.Exception.Message)" -Level WARN -Component "Auth"
        }
        
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
function ConvertFrom-JsonToConfigArray {
    <#
    .SYNOPSIS
        Converts JSON configuration data to CSV-compatible array format.
    
    .DESCRIPTION
        Dynamically transforms JSON data to match the exact CSV structure without
        hardcoded mappings. Preserves all column names and data formats exactly.
        Supports both flat JSON arrays and nested application structures with segments.
        
    .PARAMETER JsonData
        The parsed JSON object from ConvertFrom-Json. Can be a flat array of configuration
        objects, a nested structure with an 'applications' property, or a single application object.
        
    .OUTPUTS
        System.Object[]
        Array of configuration objects matching CSV format with proper column structure.
        
    .EXAMPLE
        $jsonContent = Get-Content "config.json" -Raw | ConvertFrom-Json
        $csvData = ConvertFrom-JsonToConfigArray -JsonData $jsonContent
        
        Converts JSON configuration data to CSV-compatible format.
        
    .EXAMPLE
        $flatArray = @(
            @{ EnterpriseAppName = "GSA-App1"; SegmentId = "Seg1"; destinationHost = "app1.local" }
            @{ EnterpriseAppName = "GSA-App2"; SegmentId = "Seg2"; destinationHost = "app2.local" }
        )
        $csvData = ConvertFrom-JsonToConfigArray -JsonData $flatArray
        
        Converts a flat array of PowerShell objects to CSV format.
        
    .NOTES
        Author: Michael Morten Sonne
        This function is part of the Migrate2GSA toolkit for Entra Private Access provisioning.
        The function automatically detects JSON structure and handles conversion appropriately.
        All array properties are converted to appropriate string formats based on naming conventions.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [PSObject]$JsonData
    )
    
    begin {
        Write-Verbose "Starting JSON to CSV conversion process"
        $configArray = @()
    }
    
    process {
        try {
            Write-LogMessage "Converting JSON data to CSV format..." -Level INFO -Component "Config"
            
            # Detect JSON structure format
            if ($JsonData.PSObject.Properties.Name -contains 'applications') {
                Write-LogMessage "Processing nested JSON format with applications array" -Level INFO -Component "Config"
                foreach ($app in $JsonData.applications) {
                    $configArray += ConvertFrom-JsonApplication -Application $app
                }
            }
            elseif ($JsonData -is [Array]) {
                Write-LogMessage "Processing flat JSON array format" -Level INFO -Component "Config"
                foreach ($item in $JsonData) {
                    $configArray += ConvertFrom-JsonRecord -Record $item
                }
            }
            else {
                Write-LogMessage "Processing single application JSON format" -Level INFO -Component "Config"
                $configArray += ConvertFrom-JsonApplication -Application $JsonData
            }
            
            Write-LogMessage "Converted $($configArray.Count) records from JSON format" -Level SUCCESS -Component "Config"
        }
        catch {
            $errorMessage = "Failed to convert JSON data: $($_.Exception.Message)"
            Write-LogMessage $errorMessage -Level ERROR -Component "Config"
            Write-Error $errorMessage -ErrorAction Stop
        }
    }
    
    end {
        Write-Verbose "JSON to CSV conversion completed. Converted $($configArray.Count) records"
        return $configArray
    }
}

function ConvertFrom-JsonApplication {
    <#
    .SYNOPSIS
        Converts JSON application to CSV records without hardcoded assumptions.
        
    .DESCRIPTION
        Processes an application object with nested segments and converts to flat
        configuration records matching the exact CSV structure. Handles group aggregation
        and applies application-level defaults to segments. Supports flexible property mapping.
        
    .PARAMETER Application
        The JSON application object to convert. Must contain application name and can include
        segments array. If no segments are provided, treats the application object as a single segment.
        
    .OUTPUTS
        System.Object[]
        Array of configuration records matching CSV format, one record per segment.
        
    .EXAMPLE
        $app = @{
            name = "GSA-WebApp"
            connectorGroup = "Default"
            segments = @(
                @{ segmentId = "Web"; destinationHost = "web.local"; ports = @(80, 443) }
                @{ segmentId = "API"; destinationHost = "api.local"; ports = "8080" }
            )
        }
        $records = ConvertFrom-JsonApplication -Application $app
        
        Converts a nested application object with multiple segments to CSV records.
        
    .EXAMPLE
        $singleApp = @{
            EnterpriseAppName = "GSA-Simple"
            destinationHost = "simple.local"
            Protocol = "tcp"
            Ports = "443"
        }
        $records = ConvertFrom-JsonApplication -Application $singleApp
        
        Converts a single application object (no nested segments) to a CSV record.
        
    .NOTES
        Author: Michael Morten Sonne
        This function handles dynamic property mapping and array-to-string conversions.
        Groups use semicolon separators, ports with multiple values get quoted.
        Application-level properties serve as defaults for all segments.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [PSObject]$Application
    )
    
    begin {
        Write-Verbose "Starting application conversion process"
        $records = @()
    }
    
    process {
        try {
            # Get application name from any reasonable property
            $appName = Get-PropertyValue -Object $Application -PropertyNames @('EnterpriseAppName', 'name', 'applicationName')
            if (-not $appName) {
                $errorMessage = "Application name is required but not found in properties: EnterpriseAppName, name, or applicationName"
                Write-Error $errorMessage -ErrorAction Stop
            }
            
            Write-Verbose "Processing application: $appName"
            
            # Get application-level defaults
            $appDefaults = @{}
            foreach ($prop in $Application.PSObject.Properties) {
                if ($prop.Name -notin @('segments', 'name', 'EnterpriseAppName')) {
                    $appDefaults[$prop.Name] = $prop.Value
                }
            }
            
            Write-Verbose "Found $($appDefaults.Count) application-level default properties"
            
            # Process segments
            $segments = $Application.segments
            if (-not $segments) {
                Write-Verbose "No segments array found, treating application object as single segment"
                $segments = @($Application)
            }
            
            $segmentIndex = 1
            foreach ($segment in $segments) {
                Write-Verbose "Processing segment $segmentIndex of $($segments.Count)"
                
                $record = [PSCustomObject]@{}
                
                # Start with application defaults
                foreach ($key in $appDefaults.Keys) {
                    $record | Add-Member -NotePropertyName $key -NotePropertyValue $appDefaults[$key] -Force
                }
                
                # Override with segment-specific values
                foreach ($prop in $segment.PSObject.Properties) {
                    if ($prop.Name -ne 'segments') {
                        $value = $prop.Value
                        
                        # Convert arrays to appropriate string format based on property name
                        if ($value -is [Array]) {
                            if ($prop.Name -match 'group|Group') {
                                $value = $value -join ';'
                            }
                            elseif ($prop.Name -match 'port|Port') {
                                # Convert port arrays to proper CSV format
                                if ($value.Count -eq 1) {
                                    # Single port, no quotes needed
                                    $value = $value[0].ToString()
                                } else {
                                    # Multiple ports, use quotes around comma-separated values
                                    $portString = ($value | ForEach-Object { $_.ToString() }) -join ','
                                    $value = '"' + $portString + '"'
                                }
                            }
                            else {
                                $value = $value -join ','
                            }
                        }
                        
                        $record | Add-Member -NotePropertyName $prop.Name -NotePropertyValue $value -Force
                    }
                }
                
                # Ensure required properties exist
                if (-not $record.EnterpriseAppName) {
                    $record | Add-Member -NotePropertyName 'EnterpriseAppName' -NotePropertyValue $appName -Force
                }
                
                if (-not $record.SegmentId) {
                    $segmentId = "Segment-$segmentIndex"
                    $record | Add-Member -NotePropertyName 'SegmentId' -NotePropertyValue $segmentId -Force
                    Write-Verbose "Auto-generated SegmentId: $segmentId"
                }
                
                $records += $record
                $segmentIndex++
            }
        }
        catch {
            $errorMessage = "Failed to convert application '$($Application.name -or 'Unknown')': $($_.Exception.Message)"
            Write-LogMessage $errorMessage -Level ERROR -Component "Config"
            Write-Error $errorMessage -ErrorAction Stop
        }
    }
    
    end {
        Write-Verbose "Application conversion completed. Generated $($records.Count) records"
        return $records
    }
}

function ConvertFrom-JsonRecord {
    <#
    .SYNOPSIS
        Converts flat JSON record with dynamic property mapping.
        
    .DESCRIPTION
        Normalizes property names and formats values to match the exact CSV structure
        used by the provisioning engine. Handles array-to-string conversions based on
        property naming conventions and preserves all original properties.
        
    .PARAMETER Record
        The JSON record object to convert. Can contain any properties that will be
        dynamically mapped to the CSV structure.
        
    .OUTPUTS
        System.Management.Automation.PSCustomObject
        Configuration object matching CSV format with proper property formatting.
        
    .EXAMPLE
        $record = @{
            EnterpriseAppName = "GSA-App"
            destinationHost = "app.local"
            EntraGroups = @("Group1", "Group2")
            Ports = @(80, 443)
        }
        $csvRecord = ConvertFrom-JsonRecord -Record $record
        
        Converts a flat JSON record, formatting arrays appropriately (groups with semicolons, ports with commas).
        
    .EXAMPLE
        $simpleRecord = @{
            name = "Simple-App"
            host = "simple.local"
            protocol = "tcp"
        }
        $csvRecord = ConvertFrom-JsonRecord -Record $simpleRecord
        
        Converts a simple record with basic properties.
        
    .NOTES
        Author: Michael Morten Sonne
        Array conversion rules:
        - Properties containing 'group' or 'Group' use semicolon separators
        - Properties containing 'port' or 'Port' use comma separators with quotes for multiple values
        - Other arrays use comma separators
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [PSObject]$Record
    )
    
    begin {
        Write-Verbose "Starting flat JSON record conversion"
    }
    
    process {
        try {
            $convertedRecord = [PSCustomObject]@{}
            $propertyCount = ($Record.PSObject.Properties | Measure-Object).Count
            Write-Verbose "Processing record with $propertyCount properties"
            
            foreach ($prop in $Record.PSObject.Properties) {
                $value = $prop.Value
                
                # Convert arrays to appropriate string format based on property name
                if ($value -is [Array]) {
                    Write-Verbose "Converting array property '$($prop.Name)' with $($value.Count) items"
                    
                    if ($prop.Name -match 'group|Group') {
                        $value = $value -join ';'
                        Write-Verbose "Applied semicolon separator for groups: $value"
                    }
                    elseif ($prop.Name -match 'port|Port') {
                        # Convert port arrays to proper CSV format
                        if ($value.Count -eq 1) {
                            # Single port, no quotes needed
                            $value = $value[0].ToString()
                            Write-Verbose "Single port converted: $value"
                        } else {
                            # Multiple ports, use quotes around comma-separated values
                            $portString = ($value | ForEach-Object { $_.ToString() }) -join ','
                            $value = '"' + $portString + '"'
                            Write-Verbose "Multiple ports converted with quotes: $value"
                        }
                    }
                    else {
                        $value = $value -join ','
                        Write-Verbose "Applied comma separator for array: $value"
                    }
                }
                
                $convertedRecord | Add-Member -NotePropertyName $prop.Name -NotePropertyValue $value -Force
            }
            
            Write-Verbose "Record conversion completed successfully"
            return $convertedRecord
        }
        catch {
            $errorMessage = "Failed to convert JSON record: $($_.Exception.Message)"
            Write-LogMessage $errorMessage -Level ERROR -Component "Config"
            Write-Error $errorMessage -ErrorAction Stop
        }
    }
    
    end {
        Write-Verbose "Flat JSON record conversion process completed"
    }
}

function Get-PropertyValue {
    <#
    .SYNOPSIS
        Gets property value from object using multiple possible property names.
        
    .DESCRIPTION
        Searches an object for properties using a list of potential property names,
        returning the value of the first property found. This enables flexible
        property mapping when objects may use different naming conventions.
        
    .PARAMETER Object
        The object to search for properties. Must be a PowerShell object with properties.
        
    .PARAMETER PropertyNames
        Array of property names to try in order of preference. The function will return
        the value of the first property name that exists on the object.
        
    .OUTPUTS
        System.Object
        The first property value found, or $null if none of the specified properties exist.
        
    .EXAMPLE
        $user = @{ UserName = "jdoe"; Email = "jdoe@company.com" }
        $name = Get-PropertyValue -Object $user -PropertyNames @('Name', 'UserName', 'LoginName')
        
        Returns "jdoe" because UserName is the first matching property from the list.
        
    .EXAMPLE
        $app = @{ name = "MyApp"; displayName = "My Application" }
        $appName = Get-PropertyValue -Object $app -PropertyNames @('EnterpriseAppName', 'name', 'applicationName')
        
        Returns "MyApp" because 'name' is found (EnterpriseAppName doesn't exist).
        
    .EXAMPLE
        $emptyObj = @{ SomeOtherProp = "value" }
        $result = Get-PropertyValue -Object $emptyObj -PropertyNames @('Name', 'Title')
        
        Returns $null because neither Name nor Title properties exist.
        
    .NOTES
        Author: Michael Morten Sonne
        This function is particularly useful for handling objects from different sources
        that may use varying property naming conventions (e.g., JSON APIs vs PowerShell objects).
        Property names are case-sensitive and must match exactly.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [PSObject]$Object,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$PropertyNames
    )
    
    begin {
        Write-Verbose "Starting property value search for $($PropertyNames.Count) potential property names"
    }
    
    process {
        try {
            foreach ($propName in $PropertyNames) {
                Write-Verbose "Checking for property: $propName"
                
                if ($Object.PSObject.Properties[$propName]) {
                    $value = $Object.$propName
                    Write-Verbose "Found property '$propName' with value: $value"
                    return $value
                }
            }
            
            Write-Verbose "No matching properties found from the specified list: $($PropertyNames -join ', ')"
            return $null
        }
        catch {
            $errorMessage = "Failed to get property value: $($_.Exception.Message)"
            Write-Verbose $errorMessage
            Write-Error $errorMessage -ErrorAction Stop
        }
    }
    
    end {
        Write-Verbose "Property value search completed"
    }
}

function Import-ProvisioningConfig {
    <#
    .SYNOPSIS
        Loads and validates CSV or JSON provisioning configuration.
        
    .DESCRIPTION
        Imports configuration data from either CSV or JSON format. JSON format supports
        richer data structures and better integration with discovery tools. The function
        automatically detects the file format based on extension.
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
        $fileExtension = [System.IO.Path]::GetExtension($ConfigPath).ToLower()
        $configData = @()
        
        # Load data based on file extension
        switch ($fileExtension) {
            '.csv' {
                Write-LogMessage "Detected CSV format" -Level INFO -Component "Config"
                $configData = Import-Csv -Path $ConfigPath
            }
            '.json' {
                Write-LogMessage "Detected JSON format" -Level INFO -Component "Config"
                $jsonContent = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
                $configData = ConvertFrom-JsonToConfigArray -JsonData $jsonContent
            }
            default {
                throw "Unsupported file format: $fileExtension. Only .csv and .json are supported."
            }
        }
        
        if (-not $configData -or $configData.Count -eq 0) {
            throw "No data found in configuration file"
        }
        
        Write-LogMessage "Loaded $($configData.Count) configuration records from $fileExtension file" -Level INFO -Component "Config"
        
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
        $allConnectorGroups = Get-EntraBetaApplicationProxyConnectorGroup @connectorGroupParams
        
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
                $group = Get-EntraBetaGroup @groupParams
                
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
        [string]$ConnectorGroupName
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
        $existingApp = Get-EntraBetaPrivateAccessApplication @checkAppParams
        
        if ($existingApp) {
            Write-LogMessage "Application '$AppName' already exists. Will add segments to existing app." -Level INFO -Component "AppProvisioning"
            return @{ Success = $true; AppId = $existingApp.AppId; AppObjectId = $existingApp.Id; Action = "ExistingApp" }
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
        
        # Create new application
        $appParams = @{
            ApplicationName = $AppName
            ConnectorGroupId = $connectorGroupId
            # Add other required parameters for Private Access application
        }
        
        # Add Debug parameter if script was called with -Debug
        if ($DebugPreference -eq 'Continue') {
            $appParams['Debug'] = $true
        }
        
        New-EntraBetaPrivateAccessApplication @appParams
        
        # Retry logic to retrieve the created application with exponential backoff
        $maxRetries = 5
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
                $newApp = Get-EntraBetaPrivateAccessApplication @getAppParams
                
                if ($newApp) {
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
        
        # Remove surrounding quotes if present (for CSV format compatibility)
        $portString = $portString -replace '^"', '' -replace '"$', ''
        
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
        
        # Create the segment
        $newSegment = New-EntraBetaPrivateAccessApplicationSegment @segmentParams
        
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
            # Get the service principal for the application
            $servicePrincipalParams = @{
                Filter = "appId eq '$AppId'"
                ErrorAction = 'Stop'
            }
            if ($DebugPreference -eq 'Continue') {
                $servicePrincipalParams['Debug'] = $true
            }
            $servicePrincipal = Get-EntraBetaServicePrincipal @servicePrincipalParams
            
            if (-not $servicePrincipal) {
                Write-LogMessage "Service principal not found for application ID: $AppId" -Level ERROR -Component "GroupAssignment"
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
                $existingAssignments = Get-EntraBetaServicePrincipalAppRoleAssignedTo @assignmentCheckParams
                
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
            
            New-EntraBetaGroupAppRoleAssignment @assignmentParams
            
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
            $appResult = New-PrivateAccessApplication -AppName $appName -ConnectorGroupName $connectorGroupName
            
            if ($appResult.Success) {
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
