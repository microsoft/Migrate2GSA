function Convert-NPA2EPA {
    <#
    .SYNOPSIS
        Converts Netskope Private Access (NPA) configuration to Microsoft Entra Private Access (EPA) format.

    .DESCRIPTION
        This function converts Netskope Private Access (NPA) private applications and access policies 
        to Microsoft Global Secure Access (GSA) Enterprise Application format compatible with 
        Start-EntraPrivateAccessProvisioning.
        
        The function processes:
        - Private applications with hosts, protocols, and ports
        - Access policies with user and group assignments
        - Conflict detection for overlapping IP ranges, FQDNs, protocols, and ports
        - Policy aggregation for comprehensive access assignments

    .PARAMETER PrivateAppsPath
        Path to NPA Private Apps JSON export file. Required.

    .PARAMETER PoliciesPath
        Path to NPA Policies JSON export file. Optional. If not provided, apps will have 
        placeholder access assignments.

    .PARAMETER OutputBasePath
        Base directory for output files. Defaults to current working directory.

    .PARAMETER TargetAppName
        Specific app name for exact match processing. When specified, only processes 
        this specific application.

    .PARAMETER AppNamePattern
        Wildcard pattern for app name matching. Supports * and ? wildcards.

    .PARAMETER SkipAppName
        Comma-separated list of specific app names to skip (exact match).

    .PARAMETER SkipAppNamePattern
        Comma-separated list of wildcard patterns for app names to skip.

    .PARAMETER EnableDebugLogging
        Enable verbose debug logging for detailed troubleshooting.

    .PARAMETER PassThru
        Return results to pipeline instead of just saving to file. When specified, 
        the function returns the processed data objects for further processing.

    .EXAMPLE
        Convert-NPA2EPA -PrivateAppsPath "C:\Export\private_apps.json" -PoliciesPath "C:\Export\npa_policies.json" -OutputBasePath "C:\Output"
        
        Converts all private apps and integrates access policies from the specified files.

    .EXAMPLE
        Convert-NPA2EPA -PrivateAppsPath ".\private_apps.json" -TargetAppName "Finance Portal"
        
        Processes only the "Finance Portal" app from the specified file.

    .EXAMPLE
        Convert-NPA2EPA -PrivateAppsPath ".\private_apps.json" -AppNamePattern "HR*" -SkipAppName "Test,Development"
        
        Processes all apps matching "HR*" pattern while skipping "Test" and "Development" apps.

    .EXAMPLE
        $results = Convert-NPA2EPA -PrivateAppsPath ".\private_apps.json" -PoliciesPath ".\npa_policies.json" -PassThru
        
        Processes apps and returns the results for further processing instead of just saving to file.

    .OUTPUTS
        System.Management.Automation.PSCustomObject[]
        Returns an array of transformed GSA Enterprise Application configuration objects.

    .NOTES
        - Requires PowerShell 5.1 or later
        - Input files must be valid JSON format
        - Output includes conflict detection and resolution recommendations
        - Reuses core logic from Convert-ZPA2EPA for consistency
    #>
    
    [CmdletBinding(SupportsShouldProcess = $false)]
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Path to NPA Private Apps JSON export")]
        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [string]$PrivateAppsPath,
        
        [Parameter(Mandatory = $false, HelpMessage = "Path to NPA Policies JSON export")]
        [ValidateScript({
            if ([string]::IsNullOrEmpty($_)) { return $true }
            if (Test-Path $_ -PathType Leaf) { return $true }
            else { throw "File not found: $_" }
        })]
        [string]$PoliciesPath,
        
        [Parameter(Mandatory = $false, HelpMessage = "Base directory for output files")]
        [ValidateScript({Test-Path $_ -PathType Container})]
        [string]$OutputBasePath = $PWD,
        
        [Parameter(HelpMessage = "Specific app name for exact match processing")]
        [string]$TargetAppName,
        
        [Parameter(HelpMessage = "Wildcard pattern for app name matching")]
        [string]$AppNamePattern,
        
        [Parameter(HelpMessage = "Comma-separated list of app names to skip (exact match)")]
        [string]$SkipAppName,
        
        [Parameter(HelpMessage = "Comma-separated list of wildcard patterns for app names to skip")]
        [string]$SkipAppNamePattern,
        
        [Parameter(HelpMessage = "Enable verbose debug logging")]
        [switch]$EnableDebugLogging,
        
        [Parameter(HelpMessage = "Return results to pipeline (suppresses automatic console output)")]
        [switch]$PassThru
    )

    # Set strict mode for better error handling
    Set-StrictMode -Version Latest

    # Establish shared timestamp and log destination
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $LogPath = Join-Path -Path $OutputBasePath -ChildPath "${timestamp}_Convert-NPA2EPA.log"

#region Helper Functions (Reused from Convert-ZPA2EPA)

function Convert-CIDRToRange {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CIDR
    )
    
    try {
        # Validate CIDR format
        if ($CIDR -notmatch '^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$') {
            Write-LogMessage "Invalid CIDR format: $CIDR" -Level "ERROR" -Component 'ConvertCIDR'
            return $null
        }
        
        $parts = $CIDR.Split('/')
        $ipAddress = $parts[0]
        $prefixLength = [int]$parts[1]
        
        # Validate prefix length
        if ($prefixLength -lt 0 -or $prefixLength -gt 32) {
            Write-LogMessage "Invalid prefix length in CIDR: $CIDR" -Level "ERROR" -Component 'ConvertCIDR'
            return $null
        }
        
        # Convert IP to integer
        $ipInteger = Convert-IPToInteger -IPAddress $ipAddress
        if ($null -eq $ipInteger) {
            return $null
        }
        
        # Calculate subnet mask
        $subnetMask = [uint32]([math]::Pow(2, 32) - [math]::Pow(2, 32 - $prefixLength))
        
        # Calculate network and broadcast addresses
        $networkAddress = $ipInteger -band $subnetMask
        $broadcastAddress = $networkAddress -bor (-bnot $subnetMask -band 0xFFFFFFFF)
        
        return @{
            Start = $networkAddress
            End = $broadcastAddress
        }
    }
    catch {
        Write-LogMessage "Error converting CIDR $CIDR to range: $_" -Level "ERROR" -Component 'ConvertCIDR'
        return $null
    }
}

function Convert-IPToInteger {
    param(
        [Parameter(Mandatory = $true)]
        [string]$IPAddress
    )
    
    try {
        # Validate IP address format
        if ($IPAddress -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
            Write-LogMessage "Invalid IP address format: $IPAddress" -Level "ERROR" -Component 'ConvertIP'
            return $null
        }
        
        $octets = $IPAddress.Split('.')
        
        # Validate each octet
        foreach ($octet in $octets) {
            $octetInt = [int]$octet
            if ($octetInt -lt 0 -or $octetInt -gt 255) {
                Write-LogMessage "Invalid octet value in IP address: $IPAddress" -Level "ERROR" -Component 'ConvertIP'
                return $null
            }
        }
        
        # Convert to 32-bit unsigned integer
        $result = [uint32]([int]$octets[0] * 16777216 + [int]$octets[1] * 65536 + [int]$octets[2] * 256 + [int]$octets[3])
        return $result
    }
    catch {
        Write-LogMessage "Error converting IP $IPAddress to integer: $_" -Level "ERROR" -Component 'ConvertIP'
        return $null
    }
}

function Test-IntervalOverlap {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Range1,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Range2
    )
    
    try {
        # Check if two ranges overlap
        # Overlap occurs if: max(start1, start2) <= min(end1, end2)
        $maxStart = [Math]::Max($Range1.Start, $Range2.Start)
        $minEnd = [Math]::Min($Range1.End, $Range2.End)
        
        return $maxStart -le $minEnd
    }
    catch {
        Write-LogMessage "Error checking interval overlap: $_" -Level "ERROR" -Component 'Conflicts'
        return $false
    }
}

function Test-PortRangeOverlap {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PortRange1,
        
        [Parameter(Mandatory = $true)]
        [string]$PortRange2
    )
    
    try {
        # Parse port ranges (comma-separated or range)
        $ports1List = $PortRange1 -split ',' | ForEach-Object { $_.Trim() }
        $ports2List = $PortRange2 -split ',' | ForEach-Object { $_.Trim() }
        
        foreach ($port1 in $ports1List) {
            $range1 = if ($port1.Contains('-')) {
                $parts = $port1.Split('-')
                @{ Start = [int]$parts[0]; End = [int]$parts[1] }
            } else {
                @{ Start = [int]$port1; End = [int]$port1 }
            }
            
            foreach ($port2 in $ports2List) {
                $range2 = if ($port2.Contains('-')) {
                    $parts = $port2.Split('-')
                    @{ Start = [int]$parts[0]; End = [int]$parts[1] }
                } else {
                    @{ Start = [int]$port2; End = [int]$port2 }
                }
                
                if (Test-IntervalOverlap -Range1 $range1 -Range2 $range2) {
                    return $true
                }
            }
        }
        
        return $false
    }
    catch {
        Write-LogMessage "Error checking port range overlap: $_" -Level "ERROR" -Component 'Conflicts'
        return $false
    }
}

function Get-DestinationType {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Destination
    )
    
    # Check if it's an IP address
    if ($Destination -match '^\d{1,3}(\.\d{1,3}){3}$') {
        return "ipAddress"
    }
    
    # Check if it's a CIDR notation
    if ($Destination -match '^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$') {
        return "ipRangeCidr"
    }
    
    # Otherwise, it's an FQDN
    return "fqdn"
}

function Clear-Domain {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain
    )
    
    try {
        # Remove Unicode zero-width characters and trim whitespace
        $cleanDomain = $Domain -replace '[\u200B-\u200D\uFEFF]', ''
        $cleanDomain = $cleanDomain.Trim()
        return $cleanDomain
    }
    catch {
        Write-LogMessage "Error cleaning domain $Domain : $_" -Level "ERROR" -Component 'Parse'
        return $Domain
    }
}

#endregion

#region NPA-Specific Helper Functions

function Get-GroupNameFromX500 {
    <#
    .SYNOPSIS
        Extracts group name from X500 path.
    
    .DESCRIPTION
        Parses X500 AD-style paths to extract the final group name segment.
        Example: "fabrikam.com/Groups/Finance/APP Finance Users" -> "APP Finance Users"
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$X500Path
    )
    
    try {
        if ([string]::IsNullOrWhiteSpace($X500Path)) {
            return $null
        }
        
        # Split by / and take last segment
        $segments = $X500Path -split '/'
        $lastSegment = $segments[-1].Trim()
        
        if ([string]::IsNullOrWhiteSpace($lastSegment)) {
            Write-LogMessage "Empty group name after parsing X500 path: $X500Path" -Level "WARN" -Component 'ParseGroup'
            return $null
        }
        
        return $lastSegment
    }
    catch {
        Write-LogMessage "Error parsing X500 path '$X500Path': $_" -Level "WARN" -Component 'ParseGroup'
        return $null
    }
}

function Test-ValidNPAPolicy {
    <#
    .SYNOPSIS
        Validates NPA policy meets processing requirements.
    
    .DESCRIPTION
        Checks if a policy is enabled, has allow action, and has required fields.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [object]$Policy
    )
    
    try {
        # Check if enabled
        if ($Policy.PSObject.Properties.Name -notcontains 'enabled' -or $Policy.enabled -ne "1") {
            return $false
        }
        
        # Check has rule_data
        if ($Policy.PSObject.Properties.Name -notcontains 'rule_data' -or $null -eq $Policy.rule_data) {
            return $false
        }
        
        # Check action is allow
        if ($Policy.rule_data.PSObject.Properties.Name -notcontains 'match_criteria_action' -or 
            $null -eq $Policy.rule_data.match_criteria_action -or
            $Policy.rule_data.match_criteria_action.PSObject.Properties.Name -notcontains 'action_name' -or
            $Policy.rule_data.match_criteria_action.action_name -ne "allow") {
            return $false
        }
        
        # Check has privateApps
        if ($Policy.rule_data.PSObject.Properties.Name -notcontains 'privateApps' -or 
            $null -eq $Policy.rule_data.privateApps) {
            return $false
        }
        
        # Ensure privateApps is an array and has items
        $privateAppsArray = @($Policy.rule_data.privateApps)
        if ($privateAppsArray.Count -eq 0) {
            return $false
        }
        
        return $true
    }
    catch {
        Write-LogMessage "Error validating policy: $_" -Level "WARN" -Component 'Policies'
        return $false
    }
}

function Build-AppToAccessLookup {
    <#
    .SYNOPSIS
        Builds lookup table mapping app names to access assignments.
    
    .DESCRIPTION
        Aggregates users and groups from all policies referencing each app.
        Handles X500 path parsing and deduplication.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [array]$Policies
    )
    
    try {
        $lookup = @{}
        $processedPolicies = 0
        $skippedPolicies = 0
        $totalGroups = 0
        $totalUsers = 0
        
        foreach ($policy in $Policies) {
            if (-not (Test-ValidNPAPolicy -Policy $policy)) {
                $skippedPolicies++
                continue
            }
            
            $processedPolicies++
            $policyName = if ($policy.PSObject.Properties.Name -contains 'rule_name') { $policy.rule_name } else { "Unknown" }
            
            Write-LogMessage "  Processing policy: $policyName" -Level "DEBUG" -Component 'Policies'
            
            # Get app names from policy (ensure it's an array)
            $privateApps = @($policy.rule_data.privateApps)
            
            # Extract groups
            $groups = @()
            if ($policy.rule_data.PSObject.Properties.Name -contains 'userGroups' -and $policy.rule_data.userGroups) {
                foreach ($x500Path in $policy.rule_data.userGroups) {
                    $groupName = Get-GroupNameFromX500 -X500Path $x500Path
                    if ($null -ne $groupName) {
                        $groups += $groupName
                    }
                }
            }
            
            # Extract users
            $users = @()
            if ($policy.rule_data.PSObject.Properties.Name -contains 'users' -and $policy.rule_data.users) {
                $users = @($policy.rule_data.users | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            }
            
            $totalGroups += $groups.Count
            $totalUsers += $users.Count
            
            # Map to apps
            foreach ($appName in $privateApps) {
                # Strip brackets for matching
                $cleanAppName = $appName -replace '^\[|\]$', ''
                $cleanAppName = $cleanAppName.Trim()
                
                if ([string]::IsNullOrWhiteSpace($cleanAppName)) {
                    continue
                }
                
                if (-not $lookup.ContainsKey($cleanAppName)) {
                    $lookup[$cleanAppName] = @{
                        Groups = @()
                        Users = @()
                    }
                }
                
                if ($groups.Count -gt 0) {
                    $lookup[$cleanAppName].Groups += $groups
                }
                
                if ($users.Count -gt 0) {
                    $lookup[$cleanAppName].Users += $users
                }
            }
        }
        
        # Deduplicate groups and users for each app
        $appsWithAccess = 0
        $appsWithGroups = 0
        $appsWithUsers = 0
        $appsWithBoth = 0
        $uniqueUsersGlobal = @{}
        
        foreach ($appName in $lookup.Keys) {
            # Deduplicate groups (case-insensitive)
            $uniqueGroups = @{}
            foreach ($group in $lookup[$appName].Groups) {
                $key = $group.ToLowerInvariant()
                if (-not $uniqueGroups.ContainsKey($key)) {
                    $uniqueGroups[$key] = $group
                }
            }
            $lookup[$appName].Groups = @($uniqueGroups.Values | Sort-Object)
            
            # Deduplicate users (case-sensitive)
            $uniqueUsers = @{}
            foreach ($user in $lookup[$appName].Users) {
                $key = $user.ToLowerInvariant()
                if (-not $uniqueUsers.ContainsKey($key)) {
                    $uniqueUsers[$key] = $user
                    if (-not $uniqueUsersGlobal.ContainsKey($key)) {
                        $uniqueUsersGlobal[$key] = $user
                    }
                }
            }
            $lookup[$appName].Users = @($uniqueUsers.Values | Sort-Object)
            
            # Track stats
            $appsWithAccess++
            $hasGroups = $lookup[$appName].Groups.Count -gt 0
            $hasUsers = $lookup[$appName].Users.Count -gt 0
            
            if ($hasGroups) { $appsWithGroups++ }
            if ($hasUsers) { $appsWithUsers++ }
            if ($hasGroups -and $hasUsers) { $appsWithBoth++ }
        }
        
        Write-LogMessage "  Valid policies processed: $processedPolicies" -Level "INFO" -Component 'Policies'
        Write-LogMessage "  Policies skipped (disabled/deny/invalid): $skippedPolicies" -Level "INFO" -Component 'Policies'
        Write-LogMessage "  Apps with policy assignments: $appsWithAccess" -Level "INFO" -Component 'Policies'
        Write-LogMessage "  Apps with group-based access: $appsWithGroups" -Level "INFO" -Component 'Policies'
        Write-LogMessage "  Apps with user-based access: $appsWithUsers" -Level "INFO" -Component 'Policies'
        Write-LogMessage "  Apps with both groups and users: $appsWithBoth" -Level "INFO" -Component 'Policies'
        Write-LogMessage "  Total unique users: $($uniqueUsersGlobal.Count)" -Level "INFO" -Component 'Policies'
        
        return @{
            Lookup = $lookup
            Stats = @{
                ProcessedPolicies = $processedPolicies
                SkippedPolicies = $skippedPolicies
                AppsWithAccess = $appsWithAccess
                AppsWithGroups = $appsWithGroups
                AppsWithUsers = $appsWithUsers
                AppsWithBoth = $appsWithBoth
                TotalUniqueUsers = $uniqueUsersGlobal.Count
            }
        }
    }
    catch {
        Write-LogMessage "Error building app-to-access lookup: $_" -Level "ERROR" -Component 'Policies'
        return @{
            Lookup = @{}
            Stats = @{
                ProcessedPolicies = 0
                SkippedPolicies = 0
                AppsWithAccess = 0
                AppsWithGroups = 0
                AppsWithUsers = 0
                AppsWithBoth = 0
                TotalUniqueUsers = 0
            }
        }
    }
}

#endregion

#region Main Script Logic

try {
    Write-LogMessage "Starting NPA to EPA conversion function" -Level "INFO" -Component 'Main'
    Write-LogMessage "Function version: 1.0" -Level "INFO" -Component 'Main'
    Write-LogMessage "Parameters:" -Level "INFO" -Component 'Main'
    Write-LogMessage "  PrivateAppsPath: $PrivateAppsPath" -Level "INFO" -Component 'Main'
    Write-LogMessage "  PoliciesPath: $PoliciesPath" -Level "INFO" -Component 'Main'
    Write-LogMessage "  OutputBasePath: $OutputBasePath" -Level "INFO" -Component 'Main'
    
    if ($EnableDebugLogging) {
        Write-LogMessage "  EnableDebugLogging: True" -Level "INFO" -Component 'Main'
    }
    
    if ($TargetAppName) {
        Write-LogMessage "Target app name: $TargetAppName" -Level "INFO" -Component 'Main'
    }
    
    if ($AppNamePattern) {
        Write-LogMessage "App name pattern: $AppNamePattern" -Level "INFO" -Component 'Main'
    }
    
    if ($SkipAppName) {
        Write-LogMessage "Skip app names: $SkipAppName" -Level "INFO" -Component 'Main'
    }
    
    if ($SkipAppNamePattern) {
        Write-LogMessage "Skip app patterns: $SkipAppNamePattern" -Level "INFO" -Component 'Main'
    }
    
    $startTime = Get-Date
    
    #region Data Loading Phase
    Write-LogMessage "" -Level "INFO"
    Write-LogMessage "=== LOADING PRIVATE APPS ===" -Level "INFO" -Component 'Load'
    
    # Load private apps
    Write-LogMessage "Loading NPA private apps from: $PrivateAppsPath" -Level "INFO" -Component 'Load'
    
    try {
        $privateAppsJson = Get-Content -Path $PrivateAppsPath -Raw -Encoding UTF8
        $privateAppsData = $privateAppsJson | ConvertFrom-Json
        
        # Handle different JSON structures
        if ($privateAppsData.PSObject.Properties.Name -contains 'data' -and 
            $privateAppsData.data.PSObject.Properties.Name -contains 'private_apps') {
            $privateApps = @($privateAppsData.data.private_apps)
            Write-LogMessage "Detected nested data.private_apps structure" -Level "DEBUG" -Component 'Load'
        } elseif ($privateAppsData -is [array]) {
            $privateApps = @($privateAppsData)
            Write-LogMessage "Detected direct array structure" -Level "DEBUG" -Component 'Load'
        } else {
            throw "Unexpected JSON structure in private apps file. Expected array or data.private_apps property."
        }
        
        if ($null -eq $privateApps -or $privateApps.Count -eq 0) {
            throw "No private apps found in the JSON data"
        }
        
        Write-LogMessage "Loaded $($privateApps.Count) private apps" -Level "INFO" -Component 'Load'
    }
    catch {
        Write-LogMessage "Error loading private apps: $_" -Level "ERROR" -Component 'Load'
        throw
    }
    
    # Load policies if provided
    $appToAccessLookup = $null
    $policyStats = @{
        FilesProvided = $false
        ProcessedPolicies = 0
        SkippedPolicies = 0
        AppsWithAccess = 0
        AppsWithGroups = 0
        AppsWithUsers = 0
        AppsWithBoth = 0
        AppsWithoutPolicies = 0
        TotalUniqueUsers = 0
    }
    
    if (-not [string]::IsNullOrEmpty($PoliciesPath)) {
        Write-LogMessage "" -Level "INFO"
        Write-LogMessage "=== LOADING ACCESS POLICIES ===" -Level "INFO" -Component 'Policies'
        Write-LogMessage "Loading NPA policies from: $PoliciesPath" -Level "INFO" -Component 'Policies'
        
        try {
            $policiesJson = Get-Content -Path $PoliciesPath -Raw -Encoding UTF8
            $policies = @($policiesJson | ConvertFrom-Json)
            
            if ($null -eq $policies -or $policies.Count -eq 0) {
                Write-LogMessage "No policies found in file. Using placeholder values." -Level "WARN" -Component 'Policies'
            } else {
                Write-LogMessage "Loaded $($policies.Count) policies" -Level "INFO" -Component 'Policies'
                
                # Build app-to-access lookup
                $lookupResult = Build-AppToAccessLookup -Policies $policies
                $appToAccessLookup = $lookupResult.Lookup
                $policyStats = $lookupResult.Stats
                $policyStats.FilesProvided = $true
            }
        }
        catch {
            Write-LogMessage "Error loading policies: $_" -Level "WARN" -Component 'Policies'
            Write-LogMessage "Continuing with placeholder values for access assignments" -Level "INFO" -Component 'Policies'
        }
    } else {
        Write-LogMessage "" -Level "INFO"
        Write-LogMessage "No policies file provided. Using placeholder values for EntraGroups and EntraUsers." -Level "INFO" -Component 'Policies'
    }
    #endregion
    
    #region App Filtering Phase
    Write-LogMessage "" -Level "INFO"
    Write-LogMessage "=== FILTERING PRIVATE APPS ===" -Level "INFO" -Component 'Filter'
    
    $originalCount = $privateApps.Count
    $filteredApps = $privateApps
    
    # Apply skip filters first (exact name)
    if ($SkipAppName) {
        Write-LogMessage "Applying skip exact name filter: $SkipAppName" -Level "INFO" -Component 'Filter'
        $skipNames = $SkipAppName.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
        $beforeSkipCount = $filteredApps.Count
        $filteredApps = $filteredApps | Where-Object { 
            $appName = $_.app_name -replace '^\[|\]$', ''
            $shouldSkip = $false
            foreach ($skipName in $skipNames) {
                if ($appName -eq $skipName) {
                    $shouldSkip = $true
                    Write-LogMessage "  Skipping app: $appName (exact match: $skipName)" -Level "DEBUG" -Component 'Filter'
                    break
                }
            }
            return -not $shouldSkip
        }
        $skippedCount = $beforeSkipCount - $filteredApps.Count
        Write-LogMessage "Apps after skip exact name filter: $($filteredApps.Count) (skipped: $skippedCount)" -Level "INFO" -Component 'Filter'
    }
    
    # Apply skip filters (pattern)
    if ($SkipAppNamePattern) {
        Write-LogMessage "Applying skip pattern filter: $SkipAppNamePattern" -Level "INFO" -Component 'Filter'
        $skipPatterns = $SkipAppNamePattern.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
        $beforeSkipCount = $filteredApps.Count
        $filteredApps = $filteredApps | Where-Object { 
            $appName = $_.app_name -replace '^\[|\]$', ''
            $shouldSkip = $false
            foreach ($skipPattern in $skipPatterns) {
                if (Test-WildcardMatch -Pattern $skipPattern -Text $appName) {
                    $shouldSkip = $true
                    Write-LogMessage "  Skipping app: $appName (pattern match: $skipPattern)" -Level "DEBUG" -Component 'Filter'
                    break
                }
            }
            return -not $shouldSkip
        }
        $skippedCount = $beforeSkipCount - $filteredApps.Count
        Write-LogMessage "Apps after skip pattern filter: $($filteredApps.Count) (skipped: $skippedCount)" -Level "INFO" -Component 'Filter'
    }
    
    # Apply exact name filter
    if ($TargetAppName) {
        Write-LogMessage "Applying exact name filter: $TargetAppName" -Level "INFO" -Component 'Filter'
        $filteredApps = $filteredApps | Where-Object { 
            $appName = $_.app_name -replace '^\[|\]$', ''
            $appName -eq $TargetAppName
        }
        Write-LogMessage "Apps after exact name filter: $($filteredApps.Count)" -Level "INFO" -Component 'Filter'
    }
    
    # Apply pattern filter
    if ($AppNamePattern) {
        Write-LogMessage "Applying pattern filter: $AppNamePattern" -Level "INFO" -Component 'Filter'
        $filteredApps = $filteredApps | Where-Object { 
            $appName = $_.app_name -replace '^\[|\]$', ''
            Test-WildcardMatch -Pattern $AppNamePattern -Text $appName
        }
        Write-LogMessage "Apps after pattern filter: $($filteredApps.Count)" -Level "INFO" -Component 'Filter'
    }
    
    Write-LogMessage "Processing $($filteredApps.Count) of $originalCount total apps" -Level "INFO" -Component 'Filter'
    
    if ($filteredApps.Count -eq 0) {
        Write-LogMessage "No apps remain after filtering. Returning empty result." -Level "WARN" -Component 'Filter'
        return @()
    }
    #endregion
    
    #region Initialize Conflict Detection Data Structures
    Write-LogMessage "" -Level "INFO"
    Write-LogMessage "=== INITIALIZING CONFLICT DETECTION ===" -Level "INFO" -Component 'Main'
    
    $ipRangeToProtocolToPorts = @{}      # IP ranges -> protocols -> ports -> app info
    $hostToProtocolToPorts = @{}         # FQDNs -> protocols -> ports -> app info
    $dnsSuffixes = @{}                   # Wildcard domains -> protocols -> ports -> app info
    $allResults = @()
    $conflictCount = 0
    $processedCount = 0
    $skippedCount = 0
    $totalSegments = 0
    #endregion
    
    #region Main Processing Phase
    Write-LogMessage "" -Level "INFO"
    Write-LogMessage "=== PROCESSING PRIVATE APPS ===" -Level "INFO" -Component 'Process'
    
    foreach ($app in $filteredApps) {
        $processedCount++
        
        # Show progress
        Write-ProgressUpdate -Current $processedCount -Total $filteredApps.Count -Activity "Converting NPA applications to EPA" -Status "Processing app: $($app.app_name)" -StartTime $startTime
        
        try {
            # Clean app name (strip brackets)
            $appName = $app.app_name -replace '^\[|\]$', ''
            $appName = $appName.Trim()
            
            Write-LogMessage "Processing app: $appName" -Level "DEBUG" -Component 'Process'
            
            # Ensure Enterprise App names carry the required GSA- prefix
            $enterpriseAppName = if ($appName -like 'GSA-*') {
                $appName
            } else {
                "GSA-$appName"
            }

            # Skip if no protocols
            if ($app.PSObject.Properties.Name -notcontains 'protocols' -or 
                $null -eq $app.protocols) {
                Write-LogMessage "Private app '$appName' has no protocols defined. Skipping." -Level "WARN" -Component 'Process'
                $skippedCount++
                continue
            }
            
            # Ensure protocols is an array and check count
            $protocolsArray = @($app.protocols)
            if ($protocolsArray.Count -eq 0) {
                Write-LogMessage "Private app '$appName' has empty protocols array. Skipping." -Level "WARN" -Component 'Process'
                $skippedCount++
                continue
            }
            
            # Skip if no hosts
            if ($app.PSObject.Properties.Name -notcontains 'host' -or 
                [string]::IsNullOrWhiteSpace($app.host)) {
                Write-LogMessage "Private app '$appName' has no hosts defined. Skipping." -Level "WARN" -Component 'Process'
                $skippedCount++
                continue
            }
            
            # Parse hosts (comma-separated)
            $destinationHosts = @($app.host -split ',' | ForEach-Object { Clear-Domain -Domain $_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            
            if ($destinationHosts.Count -eq 0) {
                Write-LogMessage "Private app '$appName' has no valid hosts after parsing. Skipping." -Level "WARN" -Component 'Process'
                $skippedCount++
                continue
            }
            
            Write-LogMessage "  App has $($destinationHosts.Count) host(s) and $($protocolsArray.Count) protocol(s)" -Level "DEBUG" -Component 'Process'
            
            # Group protocols by transport
            $protocolsByTransport = $protocolsArray | Group-Object -Property transport
            
            # Get access assignments
            $entraGroups = ""
            $entraUsers = ""
            
            if ($null -ne $appToAccessLookup -and $appToAccessLookup.ContainsKey($appName)) {
                $accessInfo = $appToAccessLookup[$appName]
                
                if ($accessInfo.Groups.Count -gt 0) {
                    $entraGroups = ($accessInfo.Groups -join ";")
                }
                
                if ($accessInfo.Users.Count -gt 0) {
                    $entraUsers = ($accessInfo.Users -join ";")
                }
            }
            
            # If no access info found, use placeholder
            if ([string]::IsNullOrWhiteSpace($entraGroups) -and [string]::IsNullOrWhiteSpace($entraUsers)) {
                # No access policy - leave empty to allow manual assignment later
            }
            
            # Generate segments for each host x protocol combination
            $segmentCounter = 1
            
            foreach ($destinationHost in $destinationHosts) {
                $destType = Get-DestinationType -Destination $destinationHost
                
                # Validate CIDR if applicable
                if ($destType -eq "ipRangeCidr") {
                    $cidrRange = Convert-CIDRToRange -CIDR $destinationHost
                    if ($null -eq $cidrRange) {
                        Write-LogMessage "Invalid CIDR format in app '$appName': $destinationHost. Skipping this host." -Level "ERROR" -Component 'Process'
                        continue
                    }
                }
                
                foreach ($transportGroup in $protocolsByTransport) {
                    $transport = $transportGroup.Name.ToLower()
                    
                    # Combine all ports for this transport
                    $ports = ($transportGroup.Group | Select-Object -ExpandProperty port) -join ','
                    
                    # Create segment ID
                    $segmentId = "$appName-Segment-{0:D3}" -f $segmentCounter
                    
                    # Check for conflicts
                    $hasConflict = $false
                    $conflictingApps = @()
                    
                    # Create current app info for tracking
                    $currentAppInfo = @{
                        Name = $enterpriseAppName
                        SegmentId = $segmentId
                    }
                    
                    # Conflict detection logic (adapted from ZPA)
                    if ($destType -eq "ipAddress" -or $destType -eq "ipRangeCidr") {
                        # Convert to IP range for comparison
                        $currentRange = if ($destType -eq "ipAddress") {
                            $ipInt = Convert-IPToInteger -IPAddress $destinationHost
                            if ($null -ne $ipInt) {
                                @{ Start = $ipInt; End = $ipInt }
                            } else {
                                $null
                            }
                        } else {
                            Convert-CIDRToRange -CIDR $destinationHost
                        }
                        
                        if ($null -ne $currentRange) {
                            # Check against existing IP ranges
                            foreach ($existingRangeKey in $ipRangeToProtocolToPorts.Keys) {
                                if (Test-IntervalOverlap -Range1 $currentRange -Range2 $existingRangeKey) {
                                    $protocolData = $ipRangeToProtocolToPorts[$existingRangeKey]
                                    if ($protocolData.ContainsKey($transport)) {
                                        foreach ($existingPort in $protocolData[$transport].Keys) {
                                            if (Test-PortRangeOverlap -PortRange1 $ports -PortRange2 $existingPort) {
                                                $hasConflict = $true
                                                $existingAppInfo = $protocolData[$transport][$existingPort]
                                                $conflictingApps += $existingAppInfo.SegmentId
                                                Write-LogMessage "Conflict detected: ${destinationHost}:${ports}:${transport} conflicts with $($existingAppInfo.SegmentId)" -Level "WARN" -Component 'Conflicts'
                                            }
                                        }
                                    }
                                }
                            }
                            
                            # Add to tracking structures
                            if (-not $ipRangeToProtocolToPorts.ContainsKey($currentRange)) {
                                $ipRangeToProtocolToPorts[$currentRange] = @{}
                            }
                            if (-not $ipRangeToProtocolToPorts[$currentRange].ContainsKey($transport)) {
                                $ipRangeToProtocolToPorts[$currentRange][$transport] = @{}
                            }
                            $ipRangeToProtocolToPorts[$currentRange][$transport][$ports] = $currentAppInfo
                        }
                    } else {
                        # FQDN conflict detection
                        $hostKey = $destinationHost.ToLowerInvariant()
                        
                        if ($hostToProtocolToPorts.ContainsKey($hostKey)) {
                            if ($hostToProtocolToPorts[$hostKey].ContainsKey($transport)) {
                                foreach ($existingPort in $hostToProtocolToPorts[$hostKey][$transport].Keys) {
                                    if (Test-PortRangeOverlap -PortRange1 $ports -PortRange2 $existingPort) {
                                        $hasConflict = $true
                                        $existingAppInfo = $hostToProtocolToPorts[$hostKey][$transport][$existingPort]
                                        $conflictingApps += $existingAppInfo.SegmentId
                                        Write-LogMessage "Conflict detected: ${destinationHost}:${ports}:${transport} conflicts with $($existingAppInfo.SegmentId)" -Level "WARN" -Component 'Conflicts'
                                    }
                                }
                            }
                        }
                        
                        # Check wildcard DNS suffixes
                        if ($destinationHost.StartsWith('*.')) {
                            $suffix = $destinationHost.Substring(1)  # Remove leading *
                            foreach ($existingSuffix in $dnsSuffixes.Keys) {
                                if ($suffix.EndsWith($existingSuffix) -or $existingSuffix.EndsWith($suffix)) {
                                    $suffixData = $dnsSuffixes[$existingSuffix]
                                    if ($suffixData.ContainsKey($transport)) {
                                        foreach ($existingPort in $suffixData[$transport].Keys) {
                                            if (Test-PortRangeOverlap -PortRange1 $ports -PortRange2 $existingPort) {
                                                $hasConflict = $true
                                                $existingAppInfo = $suffixData[$transport][$existingPort]
                                                $conflictingApps += $existingAppInfo.SegmentId
                                                Write-LogMessage "Conflict detected: ${destinationHost}:${ports}:${transport} conflicts with wildcard $($existingAppInfo.SegmentId)" -Level "WARN" -Component 'Conflicts'
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            # Check if current host matches any existing wildcard
                            foreach ($existingSuffix in $dnsSuffixes.Keys) {
                                if ($destinationHost.EndsWith($existingSuffix)) {
                                    $suffixData = $dnsSuffixes[$existingSuffix]
                                    if ($suffixData.ContainsKey($transport)) {
                                        foreach ($existingPort in $suffixData[$transport].Keys) {
                                            if (Test-PortRangeOverlap -PortRange1 $ports -PortRange2 $existingPort) {
                                                $hasConflict = $true
                                                $existingAppInfo = $suffixData[$transport][$existingPort]
                                                $conflictingApps += $existingAppInfo.SegmentId
                                                Write-LogMessage "Conflict detected: ${destinationHost}:${ports}:${transport} matches wildcard $($existingAppInfo.SegmentId)" -Level "WARN" -Component 'Conflicts'
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        
                        # Add to tracking structures
                        if (-not $hostToProtocolToPorts.ContainsKey($hostKey)) {
                            $hostToProtocolToPorts[$hostKey] = @{}
                        }
                        if (-not $hostToProtocolToPorts[$hostKey].ContainsKey($transport)) {
                            $hostToProtocolToPorts[$hostKey][$transport] = @{}
                        }
                        $hostToProtocolToPorts[$hostKey][$transport][$ports] = $currentAppInfo
                        
                        # Track wildcard domains
                        if ($destinationHost.StartsWith('*.')) {
                            $suffix = $destinationHost.Substring(1)
                            if (-not $dnsSuffixes.ContainsKey($suffix)) {
                                $dnsSuffixes[$suffix] = @{}
                            }
                            if (-not $dnsSuffixes[$suffix].ContainsKey($transport)) {
                                $dnsSuffixes[$suffix][$transport] = @{}
                            }
                            $dnsSuffixes[$suffix][$transport][$ports] = $currentAppInfo
                        }
                    }
                    
                    if ($hasConflict) {
                        $conflictCount++
                    }
                    
                    # Create result object
                    $resultObj = [PSCustomObject]@{
                        EnterpriseAppName = $enterpriseAppName
                        SegmentId = $segmentId
                        destinationHost = $destinationHost
                        DestinationType = $destType
                        Protocol = $transport
                        Ports = $ports
                        ConnectorGroup = "Placeholder_Replace_Me"
                        Provision = "Yes"
                        EntraGroups = $entraGroups
                        EntraUsers = $entraUsers
                        Conflict = if ($hasConflict) { "Yes" } else { "No" }
                        ConflictingEnterpriseApp = if (@($conflictingApps).Count -gt 0) { ($conflictingApps -join ", ") } else { "" }
                    }
                    
                    $allResults += $resultObj
                    $totalSegments++
                    $segmentCounter++
                }
            }
        }
        catch {
            Write-LogMessage "Error processing app '$($app.app_name)': $_" -Level "ERROR" -Component 'Process'
            continue
        }
    }
    
    Write-Progress -Activity "Converting NPA applications to EPA" -Completed
    #endregion
    
    #region Data Grouping and Deduplication
    Write-LogMessage "" -Level "INFO"
    Write-LogMessage "=== GROUPING AND DEDUPLICATION ===" -Level "INFO" -Component 'Export'
    
    # Group results by key fields to consolidate duplicate segments
    $groupedResults = $allResults | Group-Object -Property EnterpriseAppName, destinationHost, DestinationType, Protocol, Conflict, ConflictingEnterpriseApp | ForEach-Object {
        $group = $_.Group
        $firstItem = $group[0]
        
        # Consolidate ports within groups (already comma-separated from protocol grouping)
        # Keep unique ports if somehow duplicated
        $allPorts = ($group | ForEach-Object { $_.Ports -split ',' | ForEach-Object { $_.Trim() } }) | Sort-Object -Unique
        $consolidatedPorts = $allPorts -join ','
        
        [PSCustomObject]@{
            EnterpriseAppName = $firstItem.EnterpriseAppName
            SegmentId = $firstItem.SegmentId
            destinationHost = $firstItem.destinationHost
            DestinationType = $firstItem.DestinationType
            Protocol = $firstItem.Protocol
            Ports = $consolidatedPorts
            ConnectorGroup = $firstItem.ConnectorGroup
            Provision = $firstItem.Provision
            EntraGroups = $firstItem.EntraGroups
            EntraUsers = $firstItem.EntraUsers
            Conflict = $firstItem.Conflict
            ConflictingEnterpriseApp = $firstItem.ConflictingEnterpriseApp
        }
    }
    
    Write-LogMessage "Grouped $($allResults.Count) records into $($groupedResults.Count) unique segments" -Level "INFO" -Component 'Export'
    #endregion
    
    #region Export Results
    Write-LogMessage "" -Level "INFO"
    Write-LogMessage "=== EXPORTING RESULTS ===" -Level "INFO" -Component 'Export'
    
    $outputFileName = "${timestamp}_GSA_EnterpriseApps_NPA.csv"
    $outputFilePath = Join-Path $OutputBasePath $outputFileName
    
    # Export with UTF-8 BOM for better compatibility with Excel
    $groupedResults | Export-Csv -Path $outputFilePath -NoTypeInformation -Encoding utf8BOM
    
    $exportSuccess = Test-Path $outputFilePath
    
    if ($exportSuccess) {
        Write-LogMessage "Results exported successfully to: $outputFilePath" -Level "SUCCESS" -Component 'Export'
    } else {
        Write-LogMessage "Failed to export results" -Level "ERROR" -Component 'Export'
    }
    #endregion
    
    #region Statistics and Summary
    Write-LogMessage "" -Level "INFO"
    Write-LogMessage "=== CONVERSION SUMMARY ===" -Level "SUMMARY" -Component 'Summary'
    Write-LogMessage "Total private apps loaded: $originalCount" -Level "SUMMARY" -Component 'Summary'
    Write-LogMessage "Apps processed: $processedCount" -Level "SUMMARY" -Component 'Summary'
    Write-LogMessage "Apps skipped (no protocols): $skippedCount" -Level "SUMMARY" -Component 'Summary'
    Write-LogMessage "Total segments generated: $totalSegments" -Level "SUMMARY" -Component 'Summary'
    Write-LogMessage "Grouped result records: $($groupedResults.Count)" -Level "SUMMARY" -Component 'Summary'
    Write-LogMessage "Conflicts detected: $conflictCount" -Level "SUMMARY" -Component 'Summary'
    Write-LogMessage "" -Level "INFO"
    
    # Policy Integration Summary
    if ($policyStats.FilesProvided) {
        Write-LogMessage "=== POLICY INTEGRATION SUMMARY ===" -Level "SUMMARY" -Component 'Summary'
        Write-LogMessage "Total policies loaded: $($policyStats.ProcessedPolicies + $policyStats.SkippedPolicies)" -Level "SUMMARY" -Component 'Summary'
        Write-LogMessage "Valid policies processed: $($policyStats.ProcessedPolicies)" -Level "SUMMARY" -Component 'Summary'
        Write-LogMessage "Policies skipped (disabled/deny/invalid): $($policyStats.SkippedPolicies)" -Level "SUMMARY" -Component 'Summary'
        Write-LogMessage "Apps with policy assignments: $($policyStats.AppsWithAccess)" -Level "SUMMARY" -Component 'Summary'
        
        # Calculate apps without policies
        $appsWithoutPolicies = $processedCount - $policyStats.AppsWithAccess
        Write-LogMessage "Apps without policy assignments: $appsWithoutPolicies" -Level "SUMMARY" -Component 'Summary'
        Write-LogMessage "Total unique groups: $($policyStats.AppsWithGroups)" -Level "SUMMARY" -Component 'Summary'
        Write-LogMessage "Total unique users: $($policyStats.TotalUniqueUsers)" -Level "SUMMARY" -Component 'Summary'
    } else {
        Write-LogMessage "=== POLICY INTEGRATION SUMMARY ===" -Level "SUMMARY" -Component 'Summary'
        Write-LogMessage "Policies file: Not provided" -Level "SUMMARY" -Component 'Summary'
        Write-LogMessage "All apps using placeholder/empty access assignments" -Level "SUMMARY" -Component 'Summary'
    }
    
    Write-LogMessage "" -Level "INFO"
    Write-LogMessage "Output file: $outputFilePath" -Level "SUMMARY" -Component 'Summary'
    Write-LogMessage "" -Level "INFO"
    
    Write-LogMessage "=== NEXT STEPS ===" -Level "INFO" -Component 'Summary'
    Write-LogMessage "1. Review the exported CSV file for accuracy" -Level "INFO" -Component 'Summary'
    Write-LogMessage "2. Replace all 'Placeholder_Replace_Me' values with actual connector group names" -Level "INFO" -Component 'Summary'
    Write-LogMessage "3. Review and assign EntraGroups/EntraUsers for apps without policy assignments" -Level "INFO" -Component 'Summary'
    Write-LogMessage "4. Review and resolve any conflicts identified in the 'Conflict' column" -Level "INFO" -Component 'Summary'
    Write-LogMessage "5. Import the completed data using Start-EntraPrivateAccessProvisioning" -Level "INFO" -Component 'Summary'
    Write-LogMessage "" -Level "INFO"
    
    if ($conflictCount -gt 0) {
        Write-LogMessage "WARNING: $conflictCount conflicts were detected. Please review the 'ConflictingEnterpriseApp' column for details." -Level "WARN" -Component 'Summary'
    }
    
    Write-LogMessage "Function completed successfully!" -Level "SUCCESS" -Component 'Main'
    #endregion
    
    # Return the grouped results only if PassThru is specified
    if ($PassThru) {
        return $groupedResults
    }
}
catch {
    Write-LogMessage "Fatal error in function execution: $_" -Level "ERROR" -Component 'Main'
    Write-LogMessage "Stack trace: $($_.ScriptStackTrace)" -Level "ERROR" -Component 'Main'
    throw
}

#endregion
}
