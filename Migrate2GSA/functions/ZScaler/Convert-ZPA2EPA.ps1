function Convert-ZPA2EPA {
    <#
    .SYNOPSIS
        Converts ZPA Application Segments to GSA Enterprise Application format.

    .DESCRIPTION
        This function converts Zscaler Private Access (ZPA) Application Segments configuration
        to Microsoft Global Secure Access (GSA) Enterprise Application format. It processes
        application segments, handles conflicts detection, and integrates access policies.

    .PARAMETER AppSegmentPath
        Path to ZPA Application Segments JSON export file. Defaults to "App_Segments.json" 
        in the script root directory.

    .PARAMETER OutputBasePath
        Base directory for output files. Defaults to current working directory.

    .PARAMETER TargetAppSegmentName
        Specific segment name for exact match processing. When specified, only processes 
        this specific segment.

    .PARAMETER AppSegmentNamePattern
        Wildcard pattern for segment name matching. Supports * and ? wildcards.

    .PARAMETER SkipAppSegmentName
        Comma-separated list of specific segment names to skip (exact match).

    .PARAMETER SkipAppSegmentNamePattern
        Comma-separated list of wildcard patterns for segment names to skip.

    .PARAMETER SegmentGroupPath
        Path to ZPA Segment Groups JSON export (optional). When provided, segments 
        from groups are merged with standalone segments.

    .PARAMETER AccessPolicyPath
        Path to ZPA Access Policies JSON export (optional). Defaults to "access_policies.json"
        in the script root directory.

    .PARAMETER ScimGroupPath
        Path to SCIM Groups JSON export (optional). Defaults to "scim_groups.json"
        in the script root directory.

    .PARAMETER EnableDebugLogging
        Enable verbose debug logging for detailed troubleshooting.

    .PARAMETER PassThru
        Return results to pipeline instead of just saving to file. When specified, 
        the function returns the processed data objects for further processing.

    .EXAMPLE
        Convert-ZPA2EPA -AppSegmentPath "C:\Export\App_Segments.json" -OutputBasePath "C:\Output"
        
        Transforms all application segments from the specified file to GSA format.

    .EXAMPLE
        Convert-ZPA2EPA -AppSegmentPath "segments.json" -TargetAppSegmentName "WebApp-Prod"
        
        Processes only the "WebApp-Prod" segment from the specified file.

    .EXAMPLE
        Convert-ZPA2EPA -AppSegmentNamePattern "Web*" -SkipAppSegmentName "Test,Dev"
        
        Processes all segments matching "Web*" pattern while skipping "Test" and "Dev" segments.

    .EXAMPLE
        $results = Convert-ZPA2EPA -AppSegmentPath "segments.json" -PassThru
        
        Processes segments and returns the results for further processing instead of just saving to file.

    .OUTPUTS
        System.Management.Automation.PSCustomObject[]
        Returns an array of transformed GSA Enterprise Application configuration objects.

    .NOTES
        - Requires PowerShell 5.1 or later
        - Input files must be valid JSON format
        - Output includes conflict detection and resolution recommendations
        - Access policies integration requires both AccessPolicyPath and ScimGroupPath
    #>
    
    [CmdletBinding(SupportsShouldProcess = $false)]
    param(
        [Parameter(HelpMessage = "Path to ZPA Application Segments JSON export")]
        [ValidateScript({
            if (Test-Path $_) { return $true }
            else { throw "File not found: $_" }
        })]
        [string]$AppSegmentPath = (Join-Path $PSScriptRoot "App_Segments.json"),
        
        [Parameter(HelpMessage = "Base directory for output files")]
        [ValidateScript({
            if (Test-Path $_ -PathType Container) { return $true }
            else { throw "Directory not found: $_" }
        })]
        [string]$OutputBasePath = $PWD,
        
        [Parameter(HelpMessage = "Specific segment name for exact match processing")]
        [string]$TargetAppSegmentName,
        
        [Parameter(HelpMessage = "Wildcard pattern for segment name matching")]
        [string]$AppSegmentNamePattern,
        
        [Parameter(HelpMessage = "Comma-separated list of specific segment names to skip (exact match)")]
        [string]$SkipAppSegmentName,
        
        [Parameter(HelpMessage = "Comma-separated list of wildcard patterns for segment names to skip")]
        [string]$SkipAppSegmentNamePattern,
        
        [Parameter(HelpMessage = "Path to ZPA Segment Groups JSON export (optional)")]
        [ValidateScript({
            if ([string]::IsNullOrEmpty($_)) { return $true }
            if (Test-Path $_) { return $true }
            else { throw "File not found: $_" }
        })]
        [string]$SegmentGroupPath,
        
        [Parameter(HelpMessage = "Path to ZPA Access Policies JSON export (optional)")]
        [string]$AccessPolicyPath = (Join-Path $PSScriptRoot "access_policies.json"),
        
        [Parameter(HelpMessage = "Path to SCIM Groups JSON export (optional)")]
        [string]$ScimGroupPath = (Join-Path $PSScriptRoot "scim_groups.json"),
        
        [Parameter(HelpMessage = "Enable verbose debug logging")]
        [switch]$EnableDebugLogging,
        
        [Parameter(HelpMessage = "Return results to pipeline (suppresses automatic console output)")]
        [switch]$PassThru
    )

    # Set strict mode for better error handling
    Set-StrictMode -Version Latest

#region Helper Functions

function Convert-CIDRToRange {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CIDR
    )
    
    try {
        # Validate CIDR format
        if ($CIDR -notmatch '^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$') {
            Write-LogMessage "Invalid CIDR format: $CIDR" -Level "ERROR"
            return $null
        }
        
        $parts = $CIDR.Split('/')
        $ipAddress = $parts[0]
        $prefixLength = [int]$parts[1]
        
        # Validate prefix length
        if ($prefixLength -lt 0 -or $prefixLength -gt 32) {
            Write-LogMessage "Invalid prefix length in CIDR: $CIDR" -Level "ERROR"
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
        Write-LogMessage "Error converting CIDR $CIDR to range: $_" -Level "ERROR"
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
            Write-LogMessage "Invalid IP address format: $IPAddress" -Level "ERROR"
            return $null
        }
        
        $octets = $IPAddress.Split('.')
        
        # Validate each octet
        foreach ($octet in $octets) {
            $octetInt = [int]$octet
            if ($octetInt -lt 0 -or $octetInt -gt 255) {
                Write-LogMessage "Invalid octet value in IP address: $IPAddress" -Level "ERROR"
                return $null
            }
        }
        
        # Convert to 32-bit unsigned integer
        $result = [uint32]([int]$octets[0] * 16777216 + [int]$octets[1] * 65536 + [int]$octets[2] * 256 + [int]$octets[3])
        return $result
    }
    catch {
        Write-LogMessage "Error converting IP $IPAddress to integer: $_" -Level "ERROR"
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
        Write-LogMessage "Error checking interval overlap: $_" -Level "ERROR"
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
        # Parse port ranges
        $ports1 = if ($PortRange1.Contains('-')) {
            $parts = $PortRange1.Split('-')
            @{ Start = [int]$parts[0]; End = [int]$parts[1] }
        } else {
            @{ Start = [int]$PortRange1; End = [int]$PortRange1 }
        }
        
        $ports2 = if ($PortRange2.Contains('-')) {
            $parts = $PortRange2.Split('-')
            @{ Start = [int]$parts[0]; End = [int]$parts[1] }
        } else {
            @{ Start = [int]$PortRange2; End = [int]$PortRange2 }
        }
        
        return Test-IntervalOverlap -Range1 $ports1 -Range2 $ports2
    }
    catch {
        Write-LogMessage "Error checking port range overlap: $_" -Level "ERROR"
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
    return "FQDN"
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
        Write-LogMessage "Error cleaning domain $Domain : $_" -Level "ERROR"
        return $Domain
    }
}

function Import-SegmentGroups {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    
    try {
        Write-LogMessage "Loading ZPA segment groups from: $FilePath" -Level "INFO"
        
        if (-not (Test-Path $FilePath)) {
            Write-LogMessage "Segment groups file not found: $FilePath" -Level "ERROR"
            return @()
        }
        
        $segmentGroupsJson = Get-Content -Path $FilePath -Raw -Encoding UTF8
        $segmentGroupsData = $segmentGroupsJson | ConvertFrom-Json
        
        if ($null -eq $segmentGroupsData) {
            Write-LogMessage "Failed to parse JSON from segment groups file: $FilePath" -Level "ERROR"
            return @()
        }
        
        # Handle different JSON formats: direct array or nested under 'list' property
        $segmentGroups = @()
        if ($segmentGroupsData.PSObject.Properties.Name -contains 'list') {
            Write-LogMessage "Detected paginated format with 'list' property in segment groups" -Level "DEBUG"
            $segmentGroups = $segmentGroupsData.list
            if ($segmentGroupsData.PSObject.Properties.Name -contains 'totalCount') {
                Write-LogMessage "Total segment groups count from API: $($segmentGroupsData.totalCount)" -Level "DEBUG"
            }
        } elseif ($segmentGroupsData -is [array]) {
            Write-LogMessage "Detected direct array format in segment groups" -Level "DEBUG"
            $segmentGroups = $segmentGroupsData
        } else {
            Write-LogMessage "Unknown JSON format in segment groups file. Expected either an array or object with 'list' property" -Level "ERROR"
            return @()
        }
        
        if ($null -eq $segmentGroups -or $segmentGroups.Count -eq 0) {
            Write-LogMessage "No segment groups found in the JSON data" -Level "WARN"
            return @()
        }
        
        Write-LogMessage "Loaded $($segmentGroups.Count) segment groups" -Level "INFO"
        
        # Extract application segments from segment groups and build membership hashtable
        $extractedSegments = @()
        $segmentGroupMembership = @{}
        $totalApplications = 0
        
        foreach ($segmentGroup in $segmentGroups) {
            if ($segmentGroup.PSObject.Properties.Name -contains 'applications' -and $segmentGroup.applications -and $segmentGroup.applications.Count -gt 0) {
                $segmentGroupName = if ($segmentGroup.PSObject.Properties.Name -contains 'name' -and $segmentGroup.name) { $segmentGroup.name } else { "Unknown" }
                $segmentGroupId = if ($segmentGroup.PSObject.Properties.Name -contains 'id' -and $segmentGroup.id) { $segmentGroup.id.ToString() } else { $null }
                
                Write-LogMessage "Processing segment group '$segmentGroupName' with $($segmentGroup.applications.Count) applications" -Level "DEBUG"
                
                # Build membership list for this APP_GROUP
                $appIds = @()
                
                foreach ($app in $segmentGroup.applications) {
                    # Add segment group name to the application segment
                    $app | Add-Member -NotePropertyName 'segmentGroupName' -NotePropertyValue $segmentGroupName -Force
                    $extractedSegments += $app
                    $totalApplications++
                    
                    # Track APP ID for membership hashtable
                    if ($app.PSObject.Properties.Name -contains 'id' -and $app.id) {
                        $appIds += $app.id.ToString()
                    }
                }
                
                # Store APP_GROUP membership
                if ($segmentGroupId -and $appIds.Count -gt 0) {
                    $segmentGroupMembership[$segmentGroupId] = $appIds
                    Write-LogMessage "  APP_GROUP '$segmentGroupId' contains $($appIds.Count) APPs" -Level "DEBUG"
                }
            } else {
                $segmentGroupName = if ($segmentGroup.PSObject.Properties.Name -contains 'name' -and $segmentGroup.name) { $segmentGroup.name } else { "Unknown" }
                Write-LogMessage "Segment group '$segmentGroupName' has no applications or applications array is empty" -Level "DEBUG"
            }
        }
        
        Write-LogMessage "Extracted $totalApplications application segments from $($segmentGroups.Count) segment groups" -Level "INFO"
        Write-LogMessage "Built membership map for $($segmentGroupMembership.Count) APP_GROUPs" -Level "DEBUG"
        
        return @{
            Segments = $extractedSegments
            Membership = $segmentGroupMembership
        }
    }
    catch {
        Write-LogMessage "Error loading segment groups: $_" -Level "ERROR"
        return @()
    }
}

function Merge-ApplicationSegments {
    param(
        [Parameter(Mandatory = $true)]
        [array]$StandaloneSegments,
        
        [Parameter(Mandatory = $false)]
        [array]$SegmentGroupSegments = @(),
        
        [Parameter(Mandatory = $false)]
        [hashtable]$SegmentGroupMembership = @{}
    )
    
    try {
        Write-LogMessage "Merging application segments and removing duplicates" -Level "INFO"
        
        # Ensure arrays are properly initialized
        if ($null -eq $StandaloneSegments) { $StandaloneSegments = @() }
        if ($null -eq $SegmentGroupSegments) { $SegmentGroupSegments = @() }
        
        # Convert to arrays if they're not already
        if ($StandaloneSegments -isnot [array]) { $StandaloneSegments = @($StandaloneSegments) }
        if ($SegmentGroupSegments -isnot [array]) { $SegmentGroupSegments = @($SegmentGroupSegments) }
        
        Write-LogMessage "Standalone segments: $($StandaloneSegments.Count)" -Level "DEBUG"
        Write-LogMessage "Segment group segments: $($SegmentGroupSegments.Count)" -Level "DEBUG"
        
        # Create hashtable with segment ID as key for deduplication
        $segmentLookup = @{}
        $duplicateCount = 0
        $uniqueFromStandalone = 0
        $uniqueFromSegmentGroups = 0
        
        # Add standalone segments first (they take priority)
        foreach ($segment in $StandaloneSegments) {
            if ($segment.PSObject.Properties.Name -contains 'id' -and $segment.id) {
                $segmentId = $segment.id.ToString()
                if (-not $segmentLookup.ContainsKey($segmentId)) {
                    $segmentLookup[$segmentId] = $segment
                    $uniqueFromStandalone++
                } else {
                    Write-LogMessage "Duplicate ID found in standalone segments: $segmentId" -Level "WARN"
                }
            } else {
                Write-LogMessage "Standalone segment missing ID property, skipping: $($segment.name)" -Level "WARN"
            }
        }
        
        # Add segment group segments only if ID doesn't already exist
        foreach ($segment in $SegmentGroupSegments) {
            if ($segment.PSObject.Properties.Name -contains 'id' -and $segment.id) {
                $segmentId = $segment.id.ToString()
                if (-not $segmentLookup.ContainsKey($segmentId)) {
                    $segmentLookup[$segmentId] = $segment
                    $uniqueFromSegmentGroups++
                } else {
                    $duplicateCount++
                    $existingSegment = $segmentLookup[$segmentId]
                    Write-LogMessage "Duplicate segment found (ID: $segmentId): '$($segment.name)' from segment group conflicts with standalone segment '$($existingSegment.name)'. Keeping standalone version." -Level "DEBUG"
                }
            } else {
                Write-LogMessage "Segment group segment missing ID property, skipping: $($segment.name)" -Level "WARN"
            }
        }
        
        # Convert hashtable values back to array
        $mergedSegments = $segmentLookup.Values | Sort-Object -Property name
        
        Write-LogMessage "Deduplication complete:" -Level "INFO"
        Write-LogMessage "  Total unique segments: $($mergedSegments.Count)" -Level "INFO"
        Write-LogMessage "  Duplicates removed: $duplicateCount" -Level "INFO"
        Write-LogMessage "  Unique segments from standalone file: $uniqueFromStandalone" -Level "INFO"
        Write-LogMessage "  Unique segments from segment groups: $uniqueFromSegmentGroups" -Level "INFO"
        Write-LogMessage "  Total segments in standalone file: $($StandaloneSegments.Count)" -Level "INFO"
        Write-LogMessage "  Total segments in segment groups: $($SegmentGroupSegments.Count)" -Level "INFO"
        
        # Return stats along with segments for use in final summary
        $result = @{
            Segments = $mergedSegments
            Stats = @{
                TotalUnique = $mergedSegments.Count
                DuplicatesRemoved = $duplicateCount
                UniqueFromStandalone = $uniqueFromStandalone
                UniqueFromSegmentGroups = $uniqueFromSegmentGroups
                TotalFromStandalone = $StandaloneSegments.Count
                TotalFromSegmentGroups = $SegmentGroupSegments.Count
            }
            SegmentGroupMembership = $SegmentGroupMembership
        }
        
        return $result
    }
    catch {
        Write-LogMessage "Error merging application segments: $_" -Level "ERROR"
        return @{
            Segments = $StandaloneSegments
            Stats = @{
                TotalUnique = $StandaloneSegments.Count
                DuplicatesRemoved = 0
                UniqueFromStandalone = $StandaloneSegments.Count
                UniqueFromSegmentGroups = 0
                TotalFromStandalone = $StandaloneSegments.Count
                TotalFromSegmentGroups = 0
            }
            SegmentGroupMembership = @{}
        }
    }
}

function Import-ApplicationSegments {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AppSegmentPath,
        
        [Parameter(Mandatory = $false)]
        [string]$SegmentGroupPath
    )
    
    try {
        # Load standalone application segments
        Write-LogMessage "Loading standalone application segments from: $AppSegmentPath" -Level "INFO"
        
        if (-not (Test-Path $AppSegmentPath)) {
            Write-LogMessage "Application segments file not found: $AppSegmentPath" -Level "ERROR"
            throw "Application segments file not found"
        }
        
        $appSegmentsJson = Get-Content -Path $AppSegmentPath -Raw -Encoding UTF8
        $appSegmentsData = $appSegmentsJson | ConvertFrom-Json
        
        if ($null -eq $appSegmentsData) {
            Write-LogMessage "Failed to parse JSON from file: $AppSegmentPath" -Level "ERROR"
            throw "Failed to parse application segments JSON"
        }
        
        # Handle different JSON formats: direct array or nested under 'list' property
        $standaloneSegments = @()
        if ($appSegmentsData.PSObject.Properties.Name -contains 'list') {
            Write-LogMessage "Detected paginated format with 'list' property" -Level "DEBUG"
            $standaloneSegments = $appSegmentsData.list
            if ($appSegmentsData.PSObject.Properties.Name -contains 'totalCount') {
                Write-LogMessage "Total count from API: $($appSegmentsData.totalCount)" -Level "DEBUG"
            }
        } elseif ($appSegmentsData -is [array]) {
            Write-LogMessage "Detected direct array format" -Level "DEBUG"
            $standaloneSegments = $appSegmentsData
        } else {
            Write-LogMessage "Unknown JSON format. Expected either an array or object with 'list' property" -Level "ERROR"
            throw "Unknown JSON format in application segments file"
        }
        
        if ($null -eq $standaloneSegments -or $standaloneSegments.Count -eq 0) {
            Write-LogMessage "No application segments found in the JSON data" -Level "ERROR"
            throw "No application segments found"
        }
        
        Write-LogMessage "Loaded $($standaloneSegments.Count) standalone application segments" -Level "INFO"
        
        # Load segment groups if provided
        $segmentGroupSegments = @()
        $segmentGroupMembership = @{}
        if (-not [string]::IsNullOrEmpty($SegmentGroupPath)) {
            $segmentGroupResult = Import-SegmentGroups -FilePath $SegmentGroupPath
            $segmentGroupSegments = $segmentGroupResult.Segments
            $segmentGroupMembership = $segmentGroupResult.Membership
        }
        
        # Merge and deduplicate
        $mergeResult = Merge-ApplicationSegments -StandaloneSegments $standaloneSegments -SegmentGroupSegments $segmentGroupSegments -SegmentGroupMembership $segmentGroupMembership
        
        return $mergeResult
    }
    catch {
        Write-LogMessage "Error loading application segments: $_" -Level "ERROR"
        throw
    }
}

function Import-AccessPolicies {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    
    try {
        Write-LogMessage "Loading ZPA access policies from: $FilePath" -Level "INFO"
        
        if (-not (Test-Path $FilePath)) {
            Write-LogMessage "Access policies file not found: $FilePath" -Level "DEBUG"
            return $null
        }
        
        $accessPoliciesJson = Get-Content -Path $FilePath -Raw -Encoding UTF8 -ErrorAction Stop
        $accessPoliciesData = $accessPoliciesJson | ConvertFrom-Json -ErrorAction Stop
        
        if ($null -eq $accessPoliciesData) {
            Write-LogMessage "Failed to parse JSON from access policies file: $FilePath" -Level "ERROR"
            throw "Failed to parse access policies JSON"
        }
        
        # Handle different JSON formats: direct array or nested under 'list' property
        $accessPolicies = @()
        if ($accessPoliciesData.PSObject.Properties.Name -contains 'list') {
            Write-LogMessage "Detected paginated format with 'list' property in access policies" -Level "DEBUG"
            $accessPolicies = $accessPoliciesData.list
            if ($accessPoliciesData.PSObject.Properties.Name -contains 'totalPages') {
                Write-LogMessage "Total pages from API: $($accessPoliciesData.totalPages)" -Level "DEBUG"
            }
        } elseif ($accessPoliciesData -is [array]) {
            Write-LogMessage "Detected direct array format in access policies" -Level "DEBUG"
            $accessPolicies = $accessPoliciesData
        } else {
            Write-LogMessage "Unknown JSON format in access policies file. Expected either an array or object with 'list' property" -Level "ERROR"
            throw "Unknown JSON format in access policies file"
        }
        
        if ($null -eq $accessPolicies -or $accessPolicies.Count -eq 0) {
            Write-LogMessage "No access policies found in the JSON data" -Level "WARN"
            return @()
        }
        
        Write-LogMessage "Loaded $($accessPolicies.Count) access policies" -Level "INFO"
        return $accessPolicies
    }
    catch {
        Write-LogMessage "Error loading access policies: $_" -Level "ERROR"
        throw
    }
}

function Import-ScimGroups {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    
    try {
        Write-LogMessage "Loading SCIM groups from: $FilePath" -Level "INFO"
        
        if (-not (Test-Path $FilePath)) {
            Write-LogMessage "SCIM groups file not found: $FilePath" -Level "DEBUG"
            return $null
        }
        
        $scimGroupsJson = Get-Content -Path $FilePath -Raw -Encoding UTF8 -ErrorAction Stop
        $scimGroupsData = $scimGroupsJson | ConvertFrom-Json -ErrorAction Stop
        
        if ($null -eq $scimGroupsData) {
            Write-LogMessage "Failed to parse JSON from SCIM groups file: $FilePath" -Level "ERROR"
            throw "Failed to parse SCIM groups JSON"
        }
        
        # Handle different JSON formats: direct array or nested under 'list' property
        $scimGroups = @()
        if ($scimGroupsData.PSObject.Properties.Name -contains 'list') {
            Write-LogMessage "Detected paginated format with 'list' property in SCIM groups" -Level "DEBUG"
            $scimGroups = $scimGroupsData.list
            if ($scimGroupsData.PSObject.Properties.Name -contains 'totalCount') {
                Write-LogMessage "Total SCIM groups count from API: $($scimGroupsData.totalCount)" -Level "DEBUG"
            }
        } elseif ($scimGroupsData -is [array]) {
            Write-LogMessage "Detected direct array format in SCIM groups" -Level "DEBUG"
            $scimGroups = $scimGroupsData
        } else {
            Write-LogMessage "Unknown JSON format in SCIM groups file. Expected either an array or object with 'list' property" -Level "ERROR"
            throw "Unknown JSON format in SCIM groups file"
        }
        
        if ($null -eq $scimGroups -or $scimGroups.Count -eq 0) {
            Write-LogMessage "No SCIM groups found in the JSON data" -Level "WARN"
            return @()
        }
        
        Write-LogMessage "Loaded $($scimGroups.Count) SCIM groups" -Level "INFO"
        return $scimGroups
    }
    catch {
        Write-LogMessage "Error loading SCIM groups: $_" -Level "ERROR"
        throw
    }
}

function Test-ValidAccessPolicy {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Policy
    )
    
    try {
        # Check policyType == "1" (Access Policy)
        if ($Policy.PSObject.Properties.Name -notcontains 'policyType' -or $Policy.policyType -ne "1") {
            Write-LogMessage "  Policy '$($Policy.name)' skipped: policyType is not '1' (got: $($Policy.policyType))" -Level "DEBUG"
            return $false
        }
        
        # Check action == "ALLOW"
        if ($Policy.PSObject.Properties.Name -notcontains 'action' -or $Policy.action -ne "ALLOW") {
            Write-LogMessage "  Policy '$($Policy.name)' skipped: action is not 'ALLOW' (got: $($Policy.action))" -Level "DEBUG"
            return $false
        }
        
        # Check root operator == "AND"
        if ($Policy.PSObject.Properties.Name -notcontains 'operator' -or $Policy.operator -ne "AND") {
            Write-LogMessage "  Policy '$($Policy.name)' skipped: root operator is not 'AND' (got: $($Policy.operator))" -Level "DEBUG"
            return $false
        }
        
        # Check has conditions
        if ($Policy.PSObject.Properties.Name -notcontains 'conditions' -or $null -eq $Policy.conditions -or $Policy.conditions.Count -eq 0) {
            Write-LogMessage "  Policy '$($Policy.name)' skipped: no conditions found" -Level "DEBUG"
            return $false
        }
        
        # Check for negated conditions
        foreach ($condition in $Policy.conditions) {
            if ($condition.PSObject.Properties.Name -contains 'negated' -and $condition.negated -eq $true) {
                Write-LogMessage "  Policy '$($Policy.name)' skipped: contains negated conditions" -Level "DEBUG"
                return $false
            }
        }
        
        # Check has at least one APP or APP_GROUP operand
        $hasAppTarget = $false
        foreach ($condition in $Policy.conditions) {
            if ($condition.PSObject.Properties.Name -contains 'operands' -and $condition.operands) {
                foreach ($operand in $condition.operands) {
                    if ($operand.PSObject.Properties.Name -contains 'objectType' -and 
                        ($operand.objectType -eq "APP" -or $operand.objectType -eq "APP_GROUP")) {
                        $hasAppTarget = $true
                        break
                    }
                }
            }
            if ($hasAppTarget) { break }
        }
        
        if (-not $hasAppTarget) {
            Write-LogMessage "  Policy '$($Policy.name)' skipped: no APP or APP_GROUP targets found" -Level "DEBUG"
            return $false
        }
        
        # Check has at least one SCIM_GROUP or SCIM username operand
        $hasScimGroup = $false
        $hasScimUser = $false
        foreach ($condition in $Policy.conditions) {
            if ($condition.PSObject.Properties.Name -contains 'operands' -and $condition.operands) {
                foreach ($operand in $condition.operands) {
                    if ($operand.PSObject.Properties.Name -contains 'objectType' -and $operand.objectType -eq "SCIM_GROUP") {
                        $hasScimGroup = $true
                        break
                    }
                    if ($operand.PSObject.Properties.Name -contains 'objectType' -and $operand.objectType -eq "SCIM") {
                        if ($operand.PSObject.Properties.Name -contains 'name' -and $operand.name -eq "userName") {
                            if ($operand.PSObject.Properties.Name -contains 'rhs' -and -not [string]::IsNullOrWhiteSpace($operand.rhs)) {
                                $hasScimUser = $true
                                break
                            }
                        }
                    }
                }
            }
            if ($hasScimGroup -and $hasScimUser) { break }
        }
        
        if (-not ($hasScimGroup -or $hasScimUser)) {
            Write-LogMessage "  Policy '$($Policy.name)' skipped: no SCIM_GROUP or SCIM username conditions found" -Level "DEBUG"
            return $false
        }
        
        return $true
    }
    catch {
        Write-LogMessage "Error validating policy '$($Policy.name)': $_" -Level "WARN"
        return $false
    }
}

function Get-AppTargetsFromPolicy {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Policy
    )
    
    try {
        $appIds = @()
        $appGroupIds = @()
        
        if ($Policy.PSObject.Properties.Name -notcontains 'conditions' -or $null -eq $Policy.conditions) {
            return @{ AppIds = @($appIds); AppGroupIds = @($appGroupIds) }
        }
        
        foreach ($condition in $Policy.conditions) {
            if ($condition.PSObject.Properties.Name -contains 'operands' -and $condition.operands) {
                # Ensure operands is treated as an array
                $operandsList = @($condition.operands)
                foreach ($operand in $operandsList) {
                    if ($operand.PSObject.Properties.Name -contains 'objectType') {
                        if ($operand.objectType -eq "APP" -and $operand.PSObject.Properties.Name -contains 'rhs') {
                            $appIds += $operand.rhs.ToString()
                            Write-LogMessage "    Found APP target: $($operand.rhs) ($($operand.name))" -Level "DEBUG"
                        }
                        elseif ($operand.objectType -eq "APP_GROUP" -and $operand.PSObject.Properties.Name -contains 'rhs') {
                            $appGroupIds += $operand.rhs.ToString()
                            Write-LogMessage "    Found APP_GROUP target: $($operand.rhs) ($($operand.name))" -Level "DEBUG"
                        }
                    }
                }
            }
        }
        
        # Ensure arrays are returned
        return @{
            AppIds = @($appIds | Select-Object -Unique)
            AppGroupIds = @($appGroupIds | Select-Object -Unique)
        }
    }
    catch {
        Write-LogMessage "Error extracting app targets from policy '$($Policy.name)': $_" -Level "WARN"
        return @{ AppIds = @(); AppGroupIds = @() }
    }
}

function Get-ScimAccessFromPolicy {
    <#
    .SYNOPSIS
        Extracts SCIM group identifiers and SCIM usernames from an access policy.

    .PARAMETER Policy
        The access policy object to process.

    .OUTPUTS
        Hashtable containing arrays of SCIM group IDs and usernames, plus an invalid username count.

    .EXAMPLE
        $access = Get-ScimAccessFromPolicy -Policy $policy
        $groupIds = $access.ScimGroupIds
        $usernames = $access.Usernames
    #>
    param(
        [Parameter(Mandatory = $true)]
        [object]$Policy
    )
    
    try {
    $scimGroupIds = @()
    $usernames = @()
    $invalidUsernameCount = 0
        
        if ($Policy.PSObject.Properties.Name -notcontains 'conditions' -or $null -eq $Policy.conditions) {
            return @{
                ScimGroupIds = @()
                Usernames = @()
                InvalidUsernameCount = 0
            }
        }
        
        foreach ($condition in $Policy.conditions) {
            if ($condition.PSObject.Properties.Name -contains 'operands' -and $condition.operands) {
                $operandsList = @($condition.operands)
                foreach ($operand in $operandsList) {
                    if ($operand.PSObject.Properties.Name -contains 'objectType') {
                        if ($operand.objectType -eq "SCIM_GROUP" -and $operand.PSObject.Properties.Name -contains 'rhs') {
                            $scimGroupIds += $operand.rhs.ToString()
                        }
                        elseif ($operand.objectType -eq "SCIM" -and $operand.PSObject.Properties.Name -contains 'name' -and $operand.name -eq "userName") {
                            if ($operand.PSObject.Properties.Name -contains 'rhs' -and -not [string]::IsNullOrWhiteSpace($operand.rhs)) {
                                $usernames += $operand.rhs.Trim()
                            }
                            else {
                                Write-LogMessage "    Found SCIM username operand with empty/null username in policy $($Policy.id)" -Level "WARN"
                                $invalidUsernameCount++
                            }
                        }
                    }
                }
            }
        }
        
        return @{
            ScimGroupIds = @($scimGroupIds)
            Usernames = @($usernames)
            InvalidUsernameCount = $invalidUsernameCount
        }
    }
    catch {
        Write-LogMessage "Error extracting SCIM access operands from policy '$($Policy.name)': $_" -Level "WARN"
        return @{
            ScimGroupIds = @()
            Usernames = @()
            InvalidUsernameCount = 0
        }
    }
}

function Expand-AppGroupToApps {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$AppGroupIds,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$SegmentGroupMembership
    )
    
    try {
        $expandedAppIds = @()
        
        foreach ($appGroupId in $AppGroupIds) {
            if ($SegmentGroupMembership.ContainsKey($appGroupId)) {
                $memberAppIds = @($SegmentGroupMembership[$appGroupId])
                $expandedAppIds += $memberAppIds
                Write-LogMessage "    Expanded APP_GROUP $appGroupId to $($memberAppIds.Count) APPs" -Level "DEBUG"
            }
            else {
                Write-LogMessage "    APP_GROUP $appGroupId not found in segment group membership" -Level "WARN"
            }
        }
        
        return @($expandedAppIds | Select-Object -Unique)
    }
    catch {
        Write-LogMessage "Error expanding APP_GROUP to APPs: $_" -Level "WARN"
        return @()
    }
}

function Build-AppToScimAccessLookup {
    <#
    .SYNOPSIS
        Builds a lookup table mapping APP IDs to SCIM groups and usernames with access.

    .PARAMETER AccessPolicyPath
        Path to ZPA Access Policies JSON file.

    .PARAMETER ScimGroupPath
        Path to SCIM Groups JSON file.

    .PARAMETER SegmentGroupMembership
        Hashtable containing APP_GROUP to APP IDs mapping (from Load-ApplicationSegments).

    .PARAMETER EnableDebugLogging
        Enable verbose debug logging.

    .OUTPUTS
        Hashtable with APP IDs as keys and hashtables containing Groups and Users arrays as values.
        Returns $null if files not found or prerequisites not met.

    .EXAMPLE
        $lookup = Build-AppToScimAccessLookup `
            -AccessPolicyPath "c:\path\to\access_policies.json" `
            -ScimGroupPath "c:\path\to\scim_groups.json" `
            -SegmentGroupMembership $loadResult.SegmentGroupMembership `
            -EnableDebugLogging:$EnableDebugLogging
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccessPolicyPath,

        [Parameter(Mandatory = $true)]
        [string]$ScimGroupPath,

        [Parameter(Mandatory = $true)]
        [hashtable]$SegmentGroupMembership,

        [Parameter(Mandatory = $false)]
        [switch]$EnableDebugLogging
    )

    try {
        Write-LogMessage "" -Level "INFO"
        Write-LogMessage "=== LOADING ACCESS POLICY DATA ===" -Level "INFO"

        $invalidUsernameCount = 0

        # Step 1: Load SCIM Groups
        $scimGroups = $null
        try {
            $scimGroups = Import-ScimGroups -FilePath $ScimGroupPath
        }
        catch {
            Write-LogMessage "Failed to load SCIM groups: $_" -Level "ERROR"
            throw
        }

        # Step 2: Load Access Policies
        $accessPolicies = $null
        try {
            $accessPolicies = Import-AccessPolicies -FilePath $AccessPolicyPath
        }
        catch {
            Write-LogMessage "Failed to load access policies: $_" -Level "ERROR"
            throw
        }

        # Step 3: Validate Prerequisites
        if ($null -eq $scimGroups -or $null -eq $accessPolicies) {
            Write-LogMessage "Access policy files not provided or not found. Using placeholder values for EntraGroups and EntraUsers." -Level "INFO"
            return $null
        }

        if ($scimGroups.Count -eq 0 -or $accessPolicies.Count -eq 0) {
            Write-LogMessage "Access policy files are empty. Using placeholder values for EntraGroups and EntraUsers." -Level "WARN"
            return $null
        }

        # Build SCIM group lookup: ID -> Name
        Write-LogMessage "" -Level "INFO"
        $scimGroupLookup = @{}
        foreach ($group in $scimGroups) {
            if ($group.PSObject.Properties.Name -contains 'id' -and $group.PSObject.Properties.Name -contains 'name') {
                $scimGroupLookup[$group.id.ToString()] = $group.name
            }
        }
        Write-LogMessage "Built SCIM group lookup with $($scimGroupLookup.Count) groups" -Level "DEBUG"

        # Step 4 & 5: Filter and Process Policies
        Write-LogMessage "" -Level "INFO"
        Write-LogMessage "=== PROCESSING ACCESS POLICIES ===" -Level "INFO"
        Write-LogMessage "Processing $($accessPolicies.Count) access policies..." -Level "INFO"

        $validPolicies = @()
        $skipReasons = @{
            'No SCIM_GROUP/SCIM username conditions' = 0
            'No APP/APP_GROUP targets' = 0
            'Negated conditions' = 0
            'Complex OR logic at root' = 0
            'Wrong policyType' = 0
            'Wrong action' = 0
            'Malformed' = 0
        }

        foreach ($policy in $accessPolicies) {
            try {
                if (Test-ValidAccessPolicy -Policy $policy) {
                    $validPolicies += $policy
                    Write-LogMessage "  Valid policy: $($policy.name) (ID: $($policy.id))" -Level "DEBUG"
                }
                else {
                    if ($policy.PSObject.Properties.Name -notcontains 'policyType' -or $policy.policyType -ne "1") {
                        $skipReasons['Wrong policyType']++
                    }
                    elseif ($policy.PSObject.Properties.Name -notcontains 'action' -or $policy.action -ne "ALLOW") {
                        $skipReasons['Wrong action']++
                    }
                    elseif ($policy.PSObject.Properties.Name -notcontains 'operator' -or $policy.operator -ne "AND") {
                        $skipReasons['Complex OR logic at root']++
                    }
                    else {
                        $hasNegated = $false
                        $hasAppTarget = $false
                        $hasScimAssignment = $false

                        if ($policy.PSObject.Properties.Name -contains 'conditions') {
                            foreach ($condition in $policy.conditions) {
                                if ($condition.PSObject.Properties.Name -contains 'negated' -and $condition.negated -eq $true) {
                                    $hasNegated = $true
                                }

                                if ($condition.PSObject.Properties.Name -contains 'operands' -and $condition.operands) {
                                    foreach ($operand in @($condition.operands)) {
                                        if ($operand.PSObject.Properties.Name -contains 'objectType') {
                                            if ($operand.objectType -eq "APP" -or $operand.objectType -eq "APP_GROUP") {
                                                $hasAppTarget = $true
                                            }
                                            elseif ($operand.objectType -eq "SCIM_GROUP") {
                                                $hasScimAssignment = $true
                                            }
                                            elseif ($operand.objectType -eq "SCIM" -and $operand.PSObject.Properties.Name -contains 'name' -and $operand.name -eq "userName" -and $operand.PSObject.Properties.Name -contains 'rhs' -and -not [string]::IsNullOrWhiteSpace($operand.rhs)) {
                                                $hasScimAssignment = $true
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        if ($hasNegated) {
                            $skipReasons['Negated conditions']++
                        }
                        elseif (-not $hasAppTarget) {
                            $skipReasons['No APP/APP_GROUP targets']++
                        }
                        elseif (-not $hasScimAssignment) {
                            $skipReasons['No SCIM_GROUP/SCIM username conditions']++
                        }
                        else {
                            $skipReasons['Malformed']++
                        }
                    }
                }
            }
            catch {
                $skipReasons['Malformed']++
                Write-LogMessage "  Malformed policy (ID: $($policy.id)): $_" -Level "DEBUG"
            }
        }

        Write-LogMessage "  Valid policies: $($validPolicies.Count)" -Level "INFO"
        Write-LogMessage "  Skipped policies: $($accessPolicies.Count - $validPolicies.Count)" -Level "INFO"
        foreach ($reason in $skipReasons.Keys | Sort-Object) {
            if ($skipReasons[$reason] -gt 0) {
                Write-LogMessage "    - ${reason}: $($skipReasons[$reason])" -Level "INFO"
            }
        }

        # Step 5b & 5c & 5d: Extract targets, expand APP_GROUPs, build mappings
        Write-LogMessage "" -Level "INFO"
        Write-LogMessage "Expanding APP_GROUP targets using segment group membership..." -Level "INFO"

        $appToScimAccessLookup = @{}
        $totalDirectApps = 0
        $totalAppGroups = 0
        $totalExpandedFromAppGroups = 0
        $appGroupsNotFound = 0
        $scimGroupsNotFound = @()

        foreach ($policy in $validPolicies) {
            try {
                Write-LogMessage "  Processing policy: $($policy.name) (ID: $($policy.id))" -Level "DEBUG"

                # Get APP and APP_GROUP targets
                $targets = Get-AppTargetsFromPolicy -Policy $policy
                $directAppIds = @($targets.AppIds)
                $appGroupIds = @($targets.AppGroupIds)

                $totalDirectApps += $directAppIds.Count
                $totalAppGroups += $appGroupIds.Count

                foreach ($appGroupId in $appGroupIds) {
                    if (-not $SegmentGroupMembership.ContainsKey($appGroupId)) {
                        $appGroupsNotFound++
                    }
                }

                # Expand APP_GROUPs to APPs
                $expandedAppIds = @()
                if ($appGroupIds.Count -gt 0) {
                    $expandedAppIds = @(Expand-AppGroupToApps -AppGroupIds $appGroupIds -SegmentGroupMembership $SegmentGroupMembership)
                    $totalExpandedFromAppGroups += $expandedAppIds.Count
                }

                # Combine direct and expanded APP IDs
                $allAppIds = @(($directAppIds + $expandedAppIds) | Select-Object -Unique)

                if ($allAppIds.Count -eq 0) {
                    Write-LogMessage "    No APP targets resolved for policy '$($policy.name)'" -Level "DEBUG"
                    continue
                }

                # Extract SCIM group IDs and usernames
                $scimAccess = Get-ScimAccessFromPolicy -Policy $policy
                $invalidUsernameCount += $scimAccess.InvalidUsernameCount

                $resolvedGroupNames = @()
                foreach ($groupId in $scimAccess.ScimGroupIds) {
                    if ($scimGroupLookup.ContainsKey($groupId)) {
                        $groupName = $scimGroupLookup[$groupId]
                        $resolvedGroupNames += $groupName
                        Write-LogMessage "    Found SCIM_GROUP: $groupId -> $groupName" -Level "DEBUG"
                    }
                    else {
                        Write-LogMessage "    SCIM_GROUP ID $groupId not found in SCIM groups lookup" -Level "WARN"
                        if ($scimGroupsNotFound -notcontains $groupId) {
                            $scimGroupsNotFound += $groupId
                        }
                    }
                }

                $usernames = @($scimAccess.Usernames)

                if ($resolvedGroupNames.Count -eq 0 -and $usernames.Count -eq 0) {
                    Write-LogMessage "    No SCIM groups or usernames extracted for policy '$($policy.name)'" -Level "DEBUG"
                    continue
                }

                foreach ($appId in $allAppIds) {
                    if (-not $appToScimAccessLookup.ContainsKey($appId)) {
                        $appToScimAccessLookup[$appId] = @{
                            Groups = @()
                            Users = @()
                        }
                    }

                    if ($resolvedGroupNames.Count -gt 0) {
                        $appToScimAccessLookup[$appId].Groups += $resolvedGroupNames
                    }

                    if ($usernames.Count -gt 0) {
                        $appToScimAccessLookup[$appId].Users += $usernames
                    }
                }
            }
            catch {
                Write-LogMessage "  Error processing policy '$($policy.name)': $_" -Level "WARN"
                continue
            }
        }

        # Step 6: Deduplication & Aggregation
        $appIds = @($appToScimAccessLookup.Keys)
        $appsWithGroupAccess = 0
        $appsWithUserAccess = 0
        $appsWithBothAccess = 0
        $globalUserLookup = @{}

        foreach ($appId in $appIds) {
            $entry = $appToScimAccessLookup[$appId]

            $groupNames = @($entry.Groups | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            $groupNames = @($groupNames | Select-Object -Unique | Sort-Object)
            $entry.Groups = $groupNames

            $dedupedUsers = @()
            $userSeen = @{}
            foreach ($user in $entry.Users) {
                if ([string]::IsNullOrWhiteSpace($user)) {
                    continue
                }

                $key = $user.ToLowerInvariant()
                if (-not $userSeen.ContainsKey($key)) {
                    $userSeen[$key] = $true
                    $dedupedUsers += $user

                    if (-not $globalUserLookup.ContainsKey($key)) {
                        $globalUserLookup[$key] = $user
                    }
                }
            }

            $entry.Users = @($dedupedUsers | Sort-Object { $_.ToLowerInvariant() })

            $hasGroups = $entry.Groups.Count -gt 0
            $hasUsers = $entry.Users.Count -gt 0

            if ($hasGroups) { $appsWithGroupAccess++ }
            if ($hasUsers) { $appsWithUserAccess++ }
            if ($hasGroups -and $hasUsers) { $appsWithBothAccess++ }
        }

        $totalUniqueUsernames = $globalUserLookup.Count

        # Step 7: Summary Logging
        Write-LogMessage "  Total APP targets (direct): $totalDirectApps" -Level "INFO"
        Write-LogMessage "  Total APP_GROUP targets: $totalAppGroups" -Level "INFO"
        Write-LogMessage "  APP_GROUPs expanded to: $totalExpandedFromAppGroups APPs" -Level "INFO"
        Write-LogMessage "  Total unique APPs with access policies: $($appToScimAccessLookup.Count)" -Level "INFO"
        Write-LogMessage "  APPs with group-based access: $appsWithGroupAccess" -Level "INFO"
        Write-LogMessage "  APPs with user-based access: $appsWithUserAccess" -Level "INFO"
        Write-LogMessage "  APPs with both groups and users: $appsWithBothAccess" -Level "INFO"
        Write-LogMessage "  Total unique usernames found: $totalUniqueUsernames" -Level "INFO"

        if ($scimGroupsNotFound.Count -gt 0 -or $appGroupsNotFound -gt 0 -or $invalidUsernameCount -gt 0) {
            Write-LogMessage "  Warnings:" -Level "INFO"

            if ($scimGroupsNotFound.Count -gt 0) {
                Write-LogMessage "    - SCIM Groups not found: $($scimGroupsNotFound.Count) (IDs logged below)" -Level "INFO"
                foreach ($missingGroupId in $scimGroupsNotFound | Sort-Object) {
                    Write-LogMessage "      Missing SCIM group ID: $missingGroupId" -Level "WARN"
                }
            }

            if ($appGroupsNotFound -gt 0) {
                Write-LogMessage "    - APP_GROUPs not found in segment groups: $appGroupsNotFound" -Level "INFO"
            }

            if ($invalidUsernameCount -gt 0) {
                Write-LogMessage "    - Invalid/empty usernames skipped: $invalidUsernameCount" -Level "INFO"
            }
        }

        Write-LogMessage "" -Level "INFO"
        Write-LogMessage "Access policy lookup built successfully" -Level "INFO"

        return $appToScimAccessLookup
    }
    catch {
        Write-LogMessage "Error building APP to SCIM access lookup: $_" -Level "ERROR"
        return $null
    }
}

#endregion

#region Main Script Logic

try {
    Write-LogMessage "Starting ZPA to GSA conversion function" -Level "INFO"
    Write-LogMessage "Function version: 1.0" -Level "INFO"
    Write-LogMessage "Parameters:" -Level "INFO"
    Write-LogMessage "  AppSegmentPath: $AppSegmentPath" -Level "INFO"
    Write-LogMessage "  OutputBasePath: $OutputBasePath" -Level "INFO"
    if (-not [string]::IsNullOrEmpty($SegmentGroupPath)) {
        Write-LogMessage "  SegmentGroupPath: $SegmentGroupPath" -Level "INFO"
    }
    Write-LogMessage "  AccessPolicyPath: $AccessPolicyPath" -Level "INFO"
    Write-LogMessage "  ScimGroupPath: $ScimGroupPath" -Level "INFO"
    
    if ($EnableDebugLogging) {
        Write-LogMessage "  EnableDebugLogging: True" -Level "INFO"
    }
    
    if ($TargetAppSegmentName) {
        Write-LogMessage "Target segment name: $TargetAppSegmentName" -Level "INFO"
    }
    
    if ($AppSegmentNamePattern) {
        Write-LogMessage "Segment name pattern: $AppSegmentNamePattern" -Level "INFO"
    }
    
    if ($SkipAppSegmentName) {
        Write-LogMessage "Skip segment names: $SkipAppSegmentName" -Level "INFO"
    }
    
    if ($SkipAppSegmentNamePattern) {
        Write-LogMessage "Skip segment patterns: $SkipAppSegmentNamePattern" -Level "INFO"
    }
    
    if ($SegmentGroupPath) {
        Write-LogMessage "Segment groups file: $SegmentGroupPath" -Level "INFO"
    }
    
    #region Data Loading Phase
    try {
        $loadResult = Import-ApplicationSegments -AppSegmentPath $AppSegmentPath -SegmentGroupPath $SegmentGroupPath
        $appSegments = $loadResult.Segments
        $loadingStats = $loadResult.Stats
        $segmentGroupMembership = $loadResult.SegmentGroupMembership
    }
    catch {
        Write-LogMessage "Error loading application segments: $_" -Level "ERROR"
        throw
    }
    
    # Build access policy lookup if files are provided
    $appToScimAccessLookup = $null
    $accessPolicyStats = @{
        FilesProvided = $false
        AppsWithGroups = 0
        AppsWithUsers = 0
        AppsWithBoth = 0
        AppsWithoutPolicies = 0
        AppsUsingPlaceholder = 0
        TotalUniqueUsers = 0
    }
    
    try {
        $appToScimAccessLookup = Build-AppToScimAccessLookup `
            -AccessPolicyPath $AccessPolicyPath `
            -ScimGroupPath $ScimGroupPath `
            -SegmentGroupMembership $segmentGroupMembership `
            -EnableDebugLogging:$EnableDebugLogging
        
        if ($null -ne $appToScimAccessLookup) {
            $accessPolicyStats.FilesProvided = $true
        }
    }
    catch {
        Write-LogMessage "Failed to build access policy lookup. Using placeholder values. Error: $_" -Level "WARN"
        $appToScimAccessLookup = $null
    }
    #endregion
    
    #region App Segment Filtering Phase
    $originalCount = $appSegments.Count
    $filteredSegments = $appSegments
    
    # Apply skip filters first (exact name)
    if ($SkipAppSegmentName) {
        Write-LogMessage "Applying skip exact name filter: $SkipAppSegmentName" -Level "INFO"
        $skipNames = $SkipAppSegmentName.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
        $beforeSkipCount = $filteredSegments.Count
        $filteredSegments = $filteredSegments | Where-Object { 
            $segmentName = $_.name
            $shouldSkip = $false
            foreach ($skipName in $skipNames) {
                if ($segmentName -eq $skipName) {
                    $shouldSkip = $true
                    Write-LogMessage "  Skipping segment: $segmentName (exact match: $skipName)" -Level "DEBUG"
                    break
                }
            }
            return -not $shouldSkip
        }
        $skippedCount = $beforeSkipCount - $filteredSegments.Count
        Write-LogMessage "Segments after skip exact name filter: $($filteredSegments.Count) (skipped: $skippedCount)" -Level "INFO"
    }
    
    # Apply skip filters (pattern)
    if ($SkipAppSegmentNamePattern) {
        Write-LogMessage "Applying skip pattern filter: $SkipAppSegmentNamePattern" -Level "INFO"
        $skipPatterns = $SkipAppSegmentNamePattern.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
        $beforeSkipCount = $filteredSegments.Count
        $filteredSegments = $filteredSegments | Where-Object { 
            $segmentName = $_.name
            $shouldSkip = $false
            foreach ($skipPattern in $skipPatterns) {
                if (Test-WildcardMatch -Pattern $skipPattern -Text $segmentName) {
                    $shouldSkip = $true
                    Write-LogMessage "  Skipping segment: $segmentName (pattern match: $skipPattern)" -Level "DEBUG"
                    break
                }
            }
            return -not $shouldSkip
        }
        $skippedCount = $beforeSkipCount - $filteredSegments.Count
        Write-LogMessage "Segments after skip pattern filter: $($filteredSegments.Count) (skipped: $skippedCount)" -Level "INFO"
    }
    
    # Apply exact name filter
    if ($TargetAppSegmentName) {
        Write-LogMessage "Applying exact name filter: $TargetAppSegmentName" -Level "INFO"
        $filteredSegments = $filteredSegments | Where-Object { $_.name -eq $TargetAppSegmentName }
        Write-LogMessage "Segments after exact name filter: $($filteredSegments.Count)" -Level "INFO"
    }
    
    # Apply pattern filter
    if ($AppSegmentNamePattern) {
        Write-LogMessage "Applying pattern filter: $AppSegmentNamePattern" -Level "INFO"
        $filteredSegments = $filteredSegments | Where-Object { Test-WildcardMatch -Pattern $AppSegmentNamePattern -Text $_.name }
        Write-LogMessage "Segments after pattern filter: $($filteredSegments.Count)" -Level "INFO"
    }
    
    Write-LogMessage "Processing $($filteredSegments.Count) of $originalCount total segments" -Level "INFO"
    
    if ($filteredSegments.Count -eq 0) {
        Write-LogMessage "No segments remain after filtering. Returning empty result." -Level "WARN"
        return @()
    }
    #endregion
    
    #region Initialize Conflict Detection Data Structures
    # GSA-style conflict detection using efficient interval-based approach
    $ipRangeToProtocolToPorts = @{}      # IP ranges (as integer tuples) -> protocols -> port ranges -> app info
    $hostToProtocolToPorts = @{}         # FQDNs -> protocols -> port ranges -> app info
    $dnsSuffixes = @{}                   # Wildcard domain suffixes -> protocols -> port ranges -> app info
    $allResults = @()
    $conflictCount = 0
    $processedCount = 0
    $segmentIdCounter = 1                # Counter for unique segment IDs
    #endregion
    
    #region Main Processing Phase
    Write-LogMessage "Starting main processing phase" -Level "INFO"
    
    foreach ($segment in $filteredSegments) {
        $processedCount++
        $progressPercent = [math]::Round(($processedCount / $filteredSegments.Count) * 100, 1)
        Write-Progress -Activity "Processing ZPA Segments" -Status "Processing segment $processedCount of $($filteredSegments.Count) ($progressPercent%)" -PercentComplete $progressPercent
        
        try {
            Write-LogMessage "Processing segment: $($segment.name) ($($segment.domainNames.Count) domains)" -Level "DEBUG"
            
            # Create enterprise app name
            $enterpriseAppName = "GSA-$($segment.name)"
            
            # Extract server groups
            $serverGroupNames = @()
            if ($segment.PSObject.Properties.Name -contains 'serverGroups' -and $segment.serverGroups -and $segment.serverGroups.Count -gt 0) {
                foreach ($serverGroup in $segment.serverGroups) {
                    if ($serverGroup.PSObject.Properties.Name -contains 'name' -and $serverGroup.name) {
                        $serverGroupNames += $serverGroup.name
                    }
                }
            }
            $serverGroupsString = if ($serverGroupNames.Count -gt 0) { ($serverGroupNames -join ", ") } else { "Unknown" }
            
            # Validate segment has required properties
            if (-not $segment.domainNames -or $segment.domainNames.Count -eq 0) {
                Write-LogMessage "Segment '$($segment.name)' has no domain names. Skipping." -Level "WARN"
                continue
            }
            
            # Extract port ranges
            $tcpPorts = @()
            $udpPorts = @()
            
            # Process TCP port ranges (only if the property exists)
            if ($segment.PSObject.Properties.Name -contains 'tcpPortRange' -and $segment.tcpPortRange -and $segment.tcpPortRange.Count -gt 0) {
                foreach ($portRange in $segment.tcpPortRange) {
                    try {
                        $fromPort = [int]$portRange.from
                        $toPort = [int]$portRange.to
                        
                        # Validate port ranges
                        if ($fromPort -lt 1 -or $fromPort -gt 65535 -or $toPort -lt 1 -or $toPort -gt 65535) {
                            Write-LogMessage "Invalid TCP port range in segment '$($segment.name)': $fromPort-$toPort" -Level "ERROR"
                            throw "Invalid port range"
                        }
                        
                        if ($fromPort -eq $toPort) {
                            $tcpPorts += $fromPort.ToString()
                        } else {
                            $tcpPorts += "$fromPort-$toPort"
                        }
                    }
                    catch {
                        Write-LogMessage "Error processing TCP port range for segment '$($segment.name)': $_" -Level "ERROR"
                        # Skip entire segment if any port is invalid
                        break
                    }
                }
            }
            
            # Process UDP port ranges (only if the property exists)
            if ($segment.PSObject.Properties.Name -contains 'udpPortRange' -and $segment.udpPortRange -and $segment.udpPortRange.Count -gt 0) {
                foreach ($portRange in $segment.udpPortRange) {
                    try {
                        $fromPort = [int]$portRange.from
                        $toPort = [int]$portRange.to
                        
                        # Validate port ranges
                        if ($fromPort -lt 1 -or $fromPort -gt 65535 -or $toPort -lt 1 -or $toPort -gt 65535) {
                            Write-LogMessage "Invalid UDP port range in segment '$($segment.name)': $fromPort-$toPort" -Level "ERROR"
                            throw "Invalid port range"
                        }
                        
                        if ($fromPort -eq $toPort) {
                            $udpPorts += $fromPort.ToString()
                        } else {
                            $udpPorts += "$fromPort-$toPort"
                        }
                    }
                    catch {
                        Write-LogMessage "Error processing UDP port range for segment '$($segment.name)': $_" -Level "ERROR"
                        # Skip entire segment if any port is invalid
                        break
                    }
                }
            }
            
            # Skip segment if no port configuration
            if ($tcpPorts.Count -eq 0 -and $udpPorts.Count -eq 0) {
                Write-LogMessage "Segment '$($segment.name)' has no valid port configuration. Skipping." -Level "WARN"
                continue
            }
            
            Write-LogMessage "Processing $($segment.domainNames.Count) domains with $($tcpPorts.Count) TCP and $($udpPorts.Count) UDP port ranges" -Level "DEBUG"
            
            # Process each domain
            $domainCount = 0
            foreach ($domain in $segment.domainNames) {
                $domainCount++
                
                # Show progress for segments with many domains (>10)
                if ($segment.domainNames.Count -gt 10 -and $domainCount % 5 -eq 0) {
                    Write-LogMessage "  Processed $domainCount/$($segment.domainNames.Count) domains in segment '$($segment.name)'" -Level "DEBUG"
                }
                
                try {
                    $cleanDomain = Clear-Domain -Domain $domain
                    $destinationType = Get-DestinationType -Destination $cleanDomain
                    
                    # Validate CIDR if it's a subnet
                    if ($destinationType -eq "ipRangeCidr") {
                        $cidrRange = Convert-CIDRToRange -CIDR $cleanDomain
                        if ($null -eq $cidrRange) {
                            Write-LogMessage "Invalid CIDR format in segment '$($segment.name)': $cleanDomain. Skipping entire segment." -Level "ERROR"
                            break
                        }
                    }
                    
                    # Process protocols and ports
                    $protocolPortCombos = @()
                    
                    if ($tcpPorts.Count -gt 0) {
                        foreach ($port in $tcpPorts) {
                            $protocolPortCombos += @{
                                Protocol = "TCP"
                                Port = $port
                            }
                        }
                    }
                    
                    if ($udpPorts.Count -gt 0) {
                        foreach ($port in $udpPorts) {
                            $protocolPortCombos += @{
                                Protocol = "UDP"
                                Port = $port
                            }
                        }
                    }
                    
                    # Create result objects for each protocol/port combination
                    $totalCombos = $protocolPortCombos.Count
                    $comboCount = 0
                    
                    foreach ($combo in $protocolPortCombos) {
                        $comboCount++
                        
                        # Show progress for domains with many port combinations (>20)
                        if ($totalCombos -gt 20 -and $comboCount % 10 -eq 0) {
                            Write-LogMessage "    Processing combo $comboCount/$totalCombos for domain '$cleanDomain'" -Level "DEBUG"
                        }
                        
                        # Check for conflicts using GSA-style detection
                        $hasConflict = $false
                        $conflictingApps = @()
                        
                        # Create app info object for tracking
                        $currentAppInfo = @{
                            Name = $enterpriseAppName
                            SegmentId = "SEG-{0:D6}" -f $segmentIdCounter
                        }
                        
                        # Conflict detection logic
                        if ($destinationType -eq "ipAddress" -or $destinationType -eq "ipRangeCidr") {
                            # Convert to IP range for comparison
                            $currentRange = if ($destinationType -eq "ipAddress") {
                                $ipInt = Convert-IPToInteger -IPAddress $cleanDomain
                                @{ Start = $ipInt; End = $ipInt }
                            } else {
                                Convert-CIDRToRange -CIDR $cleanDomain
                            }
                            
                            if ($null -ne $currentRange) {
                                # Check against existing IP ranges
                                foreach ($existingRangeKey in $ipRangeToProtocolToPorts.Keys) {
                                    $existingRange = $existingRangeKey
                                    if (Test-IntervalOverlap -Range1 $currentRange -Range2 $existingRange) {
                                        $protocolData = $ipRangeToProtocolToPorts[$existingRangeKey]
                                        if ($protocolData.ContainsKey($combo.Protocol)) {
                                            foreach ($existingPort in $protocolData[$combo.Protocol].Keys) {
                                                if (Test-PortRangeOverlap -PortRange1 $combo.Port -PortRange2 $existingPort) {
                                                    $hasConflict = $true
                                                    $existingAppInfo = $protocolData[$combo.Protocol][$existingPort]
                                                    $conflictReference = "$($existingAppInfo.Name):$($existingAppInfo.SegmentId)"
                                                    $conflictingApps += $conflictReference
                                                    Write-LogMessage "Conflict detected: ${cleanDomain}:$($combo.Port):$($combo.Protocol) conflicts with existing app: $conflictReference" -Level "WARN"
                                                }
                                            }
                                        }
                                    }
                                }
                                
                                # Add to tracking structures
                                if (-not $ipRangeToProtocolToPorts.ContainsKey($currentRange)) {
                                    $ipRangeToProtocolToPorts[$currentRange] = @{}
                                }
                                if (-not $ipRangeToProtocolToPorts[$currentRange].ContainsKey($combo.Protocol)) {
                                    $ipRangeToProtocolToPorts[$currentRange][$combo.Protocol] = @{}
                                }
                                $ipRangeToProtocolToPorts[$currentRange][$combo.Protocol][$combo.Port] = $currentAppInfo
                            }
                        } else {
                            # FQDN conflict detection
                            if ($hostToProtocolToPorts.ContainsKey($cleanDomain)) {
                                if ($hostToProtocolToPorts[$cleanDomain].ContainsKey($combo.Protocol)) {
                                    foreach ($existingPort in $hostToProtocolToPorts[$cleanDomain][$combo.Protocol].Keys) {
                                        if (Test-PortRangeOverlap -PortRange1 $combo.Port -PortRange2 $existingPort) {
                                            $hasConflict = $true
                                            $existingAppInfo = $hostToProtocolToPorts[$cleanDomain][$combo.Protocol][$existingPort]
                                            $conflictReference = "$($existingAppInfo.Name):$($existingAppInfo.SegmentId)"
                                            $conflictingApps += $conflictReference
                                            Write-LogMessage "Conflict detected: ${cleanDomain}:$($combo.Port):$($combo.Protocol) conflicts with existing app: $conflictReference" -Level "WARN"
                                        }
                                    }
                                }
                            }
                            
                            # Check wildcard DNS suffixes
                            foreach ($suffix in $dnsSuffixes.Keys) {
                                if ($cleanDomain.EndsWith($suffix.TrimStart('*'))) {
                                    $suffixData = $dnsSuffixes[$suffix]
                                    if ($suffixData.ContainsKey($combo.Protocol)) {
                                        foreach ($existingPort in $suffixData[$combo.Protocol].Keys) {
                                            if (Test-PortRangeOverlap -PortRange1 $combo.Port -PortRange2 $existingPort) {
                                                $hasConflict = $true
                                                $existingAppInfo = $suffixData[$combo.Protocol][$existingPort]
                                                $conflictReference = "$($existingAppInfo.Name):$($existingAppInfo.SegmentId)"
                                                $conflictingApps += $conflictReference
                                                Write-LogMessage "Conflict detected: ${cleanDomain}:$($combo.Port):$($combo.Protocol) conflicts with wildcard app: $conflictReference (pattern: $suffix)" -Level "WARN"
                                            }
                                        }
                                    }
                                }
                            }
                            
                            # Add to tracking structures
                            if (-not $hostToProtocolToPorts.ContainsKey($cleanDomain)) {
                                $hostToProtocolToPorts[$cleanDomain] = @{}
                            }
                            if (-not $hostToProtocolToPorts[$cleanDomain].ContainsKey($combo.Protocol)) {
                                $hostToProtocolToPorts[$cleanDomain][$combo.Protocol] = @{}
                            }
                            $hostToProtocolToPorts[$cleanDomain][$combo.Protocol][$combo.Port] = $currentAppInfo
                            
                            # Handle wildcard domains
                            if ($cleanDomain.StartsWith('*.')) {
                                if (-not $dnsSuffixes.ContainsKey($cleanDomain)) {
                                    $dnsSuffixes[$cleanDomain] = @{}
                                }
                                if (-not $dnsSuffixes[$cleanDomain].ContainsKey($combo.Protocol)) {
                                    $dnsSuffixes[$cleanDomain][$combo.Protocol] = @{}
                                }
                                $dnsSuffixes[$cleanDomain][$combo.Protocol][$combo.Port] = $currentAppInfo
                            }
                        }
                        
                        if ($hasConflict) {
                            $conflictCount++
                        }
                        
                        # Determine EntraGroups and EntraUsers values
                        $entraGroupValue = "Placeholder_Replace_Me"
                        $entraUsersValue = ""

                        if ($null -ne $appToScimAccessLookup) {
                            $appId = $segment.id.ToString()

                            if ($appToScimAccessLookup.ContainsKey($appId)) {
                                $accessInfo = $appToScimAccessLookup[$appId]

                                if ($accessInfo.Groups -and $accessInfo.Groups.Count -gt 0) {
                                    $entraGroupValue = ($accessInfo.Groups -join "; ")
                                } else {
                                    $entraGroupValue = "No_Access_Policy_Found_Replace_Me"
                                }

                                if ($accessInfo.Users -and $accessInfo.Users.Count -gt 0) {
                                    $entraUsersValue = ($accessInfo.Users -join "; ")
                                }
                            } else {
                                $entraGroupValue = "No_Access_Policy_Found_Replace_Me"
                            }
                        }
                        
                        # Create result object
                        $resultObj = [PSCustomObject]@{
                            SegmentId = "SEG-{0:D6}" -f $segmentIdCounter
                            OriginalAppName = $segment.name
                            EnterpriseAppName = $enterpriseAppName
                            destinationHost = $cleanDomain
                            DestinationType = $destinationType
                            Protocol = $combo.Protocol
                            Ports = $combo.Port
                            SegmentGroup = if ($segment.segmentGroupName) { $segment.segmentGroupName } else { "Unknown" }
                            ServerGroups = $serverGroupsString
                            EntraGroups = $entraGroupValue
                            EntraUsers = $entraUsersValue
                            ConnectorGroup = "Placeholder_Replace_Me"
                            Conflict = if ($hasConflict) { "Yes" } else { "No" }
                            ConflictingEnterpriseApp = if ($conflictingApps.Count -gt 0) { ($conflictingApps | Sort-Object -Unique) -join ", " } else { "" }
                            Provision = if ($hasConflict) { "No" } else { "Yes" }
                        }
                        
                        $allResults += $resultObj
                        $segmentIdCounter++
                    }
                }
                catch {
                    Write-LogMessage "Error processing domain '$domain' in segment '$($segment.name)': $_" -Level "ERROR"
                    continue
                }
            }
        }
        catch {
            Write-LogMessage "Error processing segment '$($segment.name)': $_" -Level "ERROR"
            continue
        }
        
        # Log completion for segments with many results
        $segmentResults = $allResults | Where-Object { $_.OriginalAppName -eq $segment.name }
        if ($segmentResults.Count -gt 50) {
            Write-LogMessage "Completed segment '$($segment.name)' - generated $($segmentResults.Count) result records" -Level "DEBUG"
        }
    }
    
    Write-Progress -Activity "Processing ZPA Segments" -Completed
    
    # Calculate access policy statistics
    if ($null -ne $appToScimAccessLookup) {
        $appsWithGroupsCount = 0
        $appsWithUsersCount = 0
        $appsWithBothCount = 0
        $uniqueUsersAcrossSegments = @{}

        foreach ($segment in $filteredSegments) {
            $appId = $segment.id.ToString()
            if ($appToScimAccessLookup.ContainsKey($appId)) {
                $accessInfo = $appToScimAccessLookup[$appId]
                $hasGroups = $accessInfo.Groups -and $accessInfo.Groups.Count -gt 0
                $hasUsers = $accessInfo.Users -and $accessInfo.Users.Count -gt 0

                if ($hasGroups) { $appsWithGroupsCount++ }
                if ($hasUsers) {
                    $appsWithUsersCount++
                    foreach ($user in $accessInfo.Users) {
                        if (-not [string]::IsNullOrWhiteSpace($user)) {
                            $userKey = $user.ToLowerInvariant()
                            if (-not $uniqueUsersAcrossSegments.ContainsKey($userKey)) {
                                $uniqueUsersAcrossSegments[$userKey] = $user
                            }
                        }
                    }
                }
                if ($hasGroups -and $hasUsers) { $appsWithBothCount++ }

                if (-not $hasGroups -and -not $hasUsers) {
                    $accessPolicyStats.AppsWithoutPolicies++
                }
            }
            else {
                $accessPolicyStats.AppsWithoutPolicies++
            }
        }

        $accessPolicyStats.AppsWithGroups = $appsWithGroupsCount
        $accessPolicyStats.AppsWithUsers = $appsWithUsersCount
        $accessPolicyStats.AppsWithBoth = $appsWithBothCount
        $accessPolicyStats.TotalUniqueUsers = $uniqueUsersAcrossSegments.Count
    } else {
        $accessPolicyStats.AppsUsingPlaceholder = $filteredSegments.Count
    }
    #endregion
    
    #region Data Grouping and Deduplication
    Write-LogMessage "Performing data grouping and deduplication" -Level "INFO"
    
    $groupedResults = $allResults | Group-Object -Property EnterpriseAppName, destinationHost, DestinationType, Protocol, SegmentGroup, ServerGroups, Conflict, ConflictingEnterpriseApp | ForEach-Object {
        $group = $_.Group
        $firstItem = $group[0]
        
        # Consolidate ports within groups
        $uniquePorts = ($group | ForEach-Object { $_.Ports } | Sort-Object -Unique) -join ", "
        
        [PSCustomObject]@{
            SegmentId = $firstItem.SegmentId
            OriginalAppName = $firstItem.OriginalAppName
            EnterpriseAppName = $firstItem.EnterpriseAppName
            destinationHost = $firstItem.destinationHost
            DestinationType = $firstItem.DestinationType
            Protocol = $firstItem.Protocol
            Ports = $uniquePorts
            SegmentGroup = $firstItem.SegmentGroup
            ServerGroups = $firstItem.ServerGroups
            EntraGroups = $firstItem.EntraGroups
            EntraUsers = $firstItem.EntraUsers
            ConnectorGroup = $firstItem.ConnectorGroup
            Conflict = $firstItem.Conflict
            ConflictingEnterpriseApp = $firstItem.ConflictingEnterpriseApp
            Provision = $firstItem.Provision
        }
    }
    #endregion
    
    #region Export Results
    Write-LogMessage "Exporting results to CSV file" -Level "INFO"
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $outputFileName = "${timestamp}_GSA_EnterpriseApps_All.csv"
    $outputFilePath = Join-Path $OutputBasePath $outputFileName
    
    # Export with UTF-8 BOM for better compatibility with Excel and other applications
    $groupedResults | Export-Csv -Path $outputFilePath -NoTypeInformation -Encoding utf8BOM
    $exportSuccess = Test-Path $outputFilePath
    
    if ($exportSuccess) {
        Write-LogMessage "Results exported successfully to: $outputFilePath" -Level "INFO"
    } else {
        Write-LogMessage "Failed to export results" -Level "ERROR"
    }
    #endregion
    
    #region Statistics and Summary
    Write-LogMessage "" -Level "INFO"
    Write-LogMessage "=== CONVERSION SUMMARY ===" -Level "INFO"
    Write-LogMessage "Total segments loaded: $originalCount" -Level "INFO"
    if (-not [string]::IsNullOrEmpty($SegmentGroupPath)) {
        Write-LogMessage "  Standalone segments file: $($loadingStats.TotalFromStandalone) segments" -Level "INFO"
        Write-LogMessage "  Segment groups file: $($loadingStats.TotalFromSegmentGroups) segments" -Level "INFO"
        Write-LogMessage "  Unique from standalone: $($loadingStats.UniqueFromStandalone)" -Level "INFO"
        Write-LogMessage "  Unique from segment groups: $($loadingStats.UniqueFromSegmentGroups)" -Level "INFO"
        Write-LogMessage "  Duplicates removed: $($loadingStats.DuplicatesRemoved)" -Level "INFO"
    }
    Write-LogMessage "Segments processed: $($filteredSegments.Count)" -Level "INFO"
    Write-LogMessage "Total result records: $($allResults.Count)" -Level "INFO"
    Write-LogMessage "Grouped result records: $($groupedResults.Count)" -Level "INFO"
    Write-LogMessage "Conflicts detected: $conflictCount" -Level "INFO"
    Write-LogMessage "" -Level "INFO"
    
    # Access Policy Integration Summary
    if ($accessPolicyStats.FilesProvided) {
        Write-LogMessage "Access Policy Integration:" -Level "INFO"
        Write-LogMessage "  Access policy files: Provided" -Level "INFO"
        Write-LogMessage "  APPs with assigned groups: $($accessPolicyStats.AppsWithGroups) ($(if ($filteredSegments.Count -gt 0) { [math]::Round(($accessPolicyStats.AppsWithGroups / $filteredSegments.Count) * 100, 1) } else { 0 })%)" -Level "INFO"
        Write-LogMessage "  APPs with assigned users: $($accessPolicyStats.AppsWithUsers) ($(if ($filteredSegments.Count -gt 0) { [math]::Round(($accessPolicyStats.AppsWithUsers / $filteredSegments.Count) * 100, 1) } else { 0 })%)" -Level "INFO"
        Write-LogMessage "  APPs with both groups and users: $($accessPolicyStats.AppsWithBoth) ($(if ($filteredSegments.Count -gt 0) { [math]::Round(($accessPolicyStats.AppsWithBoth / $filteredSegments.Count) * 100, 1) } else { 0 })%)" -Level "INFO"
        Write-LogMessage "  APPs without access policies: $($accessPolicyStats.AppsWithoutPolicies) ($(if ($filteredSegments.Count -gt 0) { [math]::Round(($accessPolicyStats.AppsWithoutPolicies / $filteredSegments.Count) * 100, 1) } else { 0 })%)" -Level "INFO"
        Write-LogMessage "  APPs using placeholder: 0 (0.0%)" -Level "INFO"
        Write-LogMessage "  Total unique users across all policies: $($accessPolicyStats.TotalUniqueUsers)" -Level "INFO"
    } else {
        Write-LogMessage "Access Policy Integration:" -Level "INFO"
        Write-LogMessage "  Access policy files: Not provided" -Level "INFO"
        Write-LogMessage "  All APPs using placeholder: $($accessPolicyStats.AppsUsingPlaceholder) (100.0%)" -Level "INFO"
        Write-LogMessage "  No user assignments: $($accessPolicyStats.AppsUsingPlaceholder) (100.0%)" -Level "INFO"
    }
    Write-LogMessage "" -Level "INFO"
    Write-LogMessage "Output file: $outputFilePath" -Level "INFO"
    Write-LogMessage "" -Level "INFO"
    Write-LogMessage "=== NEXT STEPS ===" -Level "INFO"
    Write-LogMessage "1. Review the exported CSV file for accuracy" -Level "INFO"
    Write-LogMessage "2. Replace all 'Placeholder_Replace_Me' values with actual values:" -Level "INFO"
    Write-LogMessage "   - EntraGroups: Set appropriate Entra ID group names (if not auto-populated)" -Level "INFO"
    Write-LogMessage "   - ConnectorGroup: Set appropriate connector group names" -Level "INFO"
    Write-LogMessage "3. Review and resolve any conflicts identified in the 'Conflict' column" -Level "INFO"
    Write-LogMessage "4. Import the completed data into Global Secure Access" -Level "INFO"
    Write-LogMessage "" -Level "INFO"
    
    if ($conflictCount -gt 0) {
        Write-LogMessage "WARNING: $conflictCount conflicts were detected. Please review the 'ConflictingEnterpriseApp' column for details." -Level "WARN"
    }
    
    Write-LogMessage "Function completed successfully!" -Level "INFO"
    #endregion
    
    # Return the grouped results only if PassThru is specified
    if ($PassThru) {
        return $groupedResults
    }
}
catch {
    Write-LogMessage "Fatal error in function execution: $_" -Level "ERROR"
    Write-LogMessage "Stack trace: $($_.ScriptStackTrace)" -Level "ERROR"
    throw
}

#endregion
}
