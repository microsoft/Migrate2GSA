[CmdletBinding()]
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
    [switch]$EnableDebugLogging
)

# Set strict mode for better error handling
Set-StrictMode -Version Latest

#region Helper Functions

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("INFO", "WARN", "ERROR", "DEBUG")]
        [string]$Level = "INFO"
    )
    
    try {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        
        # Handle empty messages for spacing
        if ([string]::IsNullOrEmpty($Message)) {
            $logMessage = ""
        } else {
            $logMessage = "[$timestamp] [$Level] $Message"
        }
        
        # Color coding for console output
        if ([string]::IsNullOrEmpty($Message)) {
            Write-Host ""
        } else {
            # Skip DEBUG messages unless debug logging is enabled
            if ($Level -eq "DEBUG" -and -not $EnableDebugLogging) {
                return
            }
            
            switch ($Level) {
                "INFO" { Write-Host $logMessage -ForegroundColor Green }
                "WARN" { Write-Host $logMessage -ForegroundColor Yellow }
                "ERROR" { Write-Host $logMessage -ForegroundColor Red }
                "DEBUG" { Write-Host $logMessage -ForegroundColor Cyan }
            }
        }
        
        # Write to log file
        $logFilePath = Join-Path $OutputBasePath "Transform-ZPA2EPA.log"
        try {
            if ([string]::IsNullOrEmpty($Message)) {
                "" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
            } else {
                # Skip DEBUG messages in log file unless debug logging is enabled
                if ($Level -eq "DEBUG" -and -not $EnableDebugLogging) {
                    return
                }
                $logMessage | Out-File -FilePath $logFilePath -Append -Encoding UTF8
            }
        }
        catch {
            # Don't let log file issues interrupt the script
            Write-Warning "Failed to write to log file: $_"
        }
    }
    catch {
        # Fallback to basic Write-Host if logging fails
        Write-Host "[$Level] $Message"
    }
}

function Convert-CIDRToRange {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CIDR
    )
    
    try {
        # Validate CIDR format
        if ($CIDR -notmatch '^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$') {
            Write-Log "Invalid CIDR format: $CIDR" -Level "ERROR"
            return $null
        }
        
        $parts = $CIDR.Split('/')
        $ipAddress = $parts[0]
        $prefixLength = [int]$parts[1]
        
        # Validate prefix length
        if ($prefixLength -lt 0 -or $prefixLength -gt 32) {
            Write-Log "Invalid prefix length in CIDR: $CIDR" -Level "ERROR"
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
        Write-Log "Error converting CIDR $CIDR to range: $_" -Level "ERROR"
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
            Write-Log "Invalid IP address format: $IPAddress" -Level "ERROR"
            return $null
        }
        
        $octets = $IPAddress.Split('.')
        
        # Validate each octet
        foreach ($octet in $octets) {
            $octetInt = [int]$octet
            if ($octetInt -lt 0 -or $octetInt -gt 255) {
                Write-Log "Invalid octet value in IP address: $IPAddress" -Level "ERROR"
                return $null
            }
        }
        
        # Convert to 32-bit unsigned integer
        $result = [uint32]([int]$octets[0] * 16777216 + [int]$octets[1] * 65536 + [int]$octets[2] * 256 + [int]$octets[3])
        return $result
    }
    catch {
        Write-Log "Error converting IP $IPAddress to integer: $_" -Level "ERROR"
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
        Write-Log "Error checking interval overlap: $_" -Level "ERROR"
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
        Write-Log "Error checking port range overlap: $_" -Level "ERROR"
        return $false
    }
}

function Export-DataToFile {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Data,
        
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("JSON", "CSV")]
        [string]$Format
    )
    
    try {
        # Create output directory if it doesn't exist
        $outputDir = Split-Path $FilePath -Parent
        if (-not (Test-Path $outputDir)) {
            New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
            Write-Log "Created output directory: $outputDir" -Level "INFO"
        }
        
        # Handle empty datasets
        if ($null -eq $Data -or $Data.Count -eq 0) {
            Write-Log "No data to export to $FilePath" -Level "WARN"
            return $false
        }
        
        # Export data based on format
        switch ($Format) {
            "JSON" {
                $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $FilePath -Encoding UTF8
            }
            "CSV" {
                $Data | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
            }
        }
        
        Write-Log "Successfully exported $($Data.Count) records to $FilePath" -Level "INFO"
        return $true
    }
    catch {
        Write-Log "Failed to export data to $FilePath : $_" -Level "ERROR"
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

function Test-WildcardMatch {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Pattern,
        
        [Parameter(Mandatory = $true)]
        [string]$Text
    )
    
    try {
        # Convert wildcard pattern to regex
        $regexPattern = $Pattern.Replace('*', '.*').Replace('?', '.')
        return $Text -match "^$regexPattern$"
    }
    catch {
        Write-Log "Error in wildcard matching: $_" -Level "ERROR"
        return $false
    }
}

function Clean-Domain {
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
        Write-Log "Error cleaning domain $Domain : $_" -Level "ERROR"
        return $Domain
    }
}

function Load-SegmentGroups {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    
    try {
        Write-Log "Loading ZPA segment groups from: $FilePath" -Level "INFO"
        
        if (-not (Test-Path $FilePath)) {
            Write-Log "Segment groups file not found: $FilePath" -Level "ERROR"
            return @()
        }
        
        $segmentGroupsJson = Get-Content -Path $FilePath -Raw -Encoding UTF8
        $segmentGroupsData = $segmentGroupsJson | ConvertFrom-Json
        
        if ($null -eq $segmentGroupsData) {
            Write-Log "Failed to parse JSON from segment groups file: $FilePath" -Level "ERROR"
            return @()
        }
        
        # Handle different JSON formats: direct array or nested under 'list' property
        $segmentGroups = @()
        if ($segmentGroupsData.PSObject.Properties.Name -contains 'list') {
            Write-Log "Detected paginated format with 'list' property in segment groups" -Level "DEBUG"
            $segmentGroups = $segmentGroupsData.list
            if ($segmentGroupsData.PSObject.Properties.Name -contains 'totalCount') {
                Write-Log "Total segment groups count from API: $($segmentGroupsData.totalCount)" -Level "DEBUG"
            }
        } elseif ($segmentGroupsData -is [array]) {
            Write-Log "Detected direct array format in segment groups" -Level "DEBUG"
            $segmentGroups = $segmentGroupsData
        } else {
            Write-Log "Unknown JSON format in segment groups file. Expected either an array or object with 'list' property" -Level "ERROR"
            return @()
        }
        
        if ($null -eq $segmentGroups -or $segmentGroups.Count -eq 0) {
            Write-Log "No segment groups found in the JSON data" -Level "WARN"
            return @()
        }
        
        Write-Log "Loaded $($segmentGroups.Count) segment groups" -Level "INFO"
        
        # Extract application segments from segment groups and build membership hashtable
        $extractedSegments = @()
        $segmentGroupMembership = @{}
        $totalApplications = 0
        
        foreach ($segmentGroup in $segmentGroups) {
            if ($segmentGroup.PSObject.Properties.Name -contains 'applications' -and $segmentGroup.applications -and $segmentGroup.applications.Count -gt 0) {
                $segmentGroupName = if ($segmentGroup.PSObject.Properties.Name -contains 'name' -and $segmentGroup.name) { $segmentGroup.name } else { "Unknown" }
                $segmentGroupId = if ($segmentGroup.PSObject.Properties.Name -contains 'id' -and $segmentGroup.id) { $segmentGroup.id.ToString() } else { $null }
                
                Write-Log "Processing segment group '$segmentGroupName' with $($segmentGroup.applications.Count) applications" -Level "DEBUG"
                
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
                    Write-Log "  APP_GROUP '$segmentGroupId' contains $($appIds.Count) APPs" -Level "DEBUG"
                }
            } else {
                $segmentGroupName = if ($segmentGroup.PSObject.Properties.Name -contains 'name' -and $segmentGroup.name) { $segmentGroup.name } else { "Unknown" }
                Write-Log "Segment group '$segmentGroupName' has no applications or applications array is empty" -Level "DEBUG"
            }
        }
        
        Write-Log "Extracted $totalApplications application segments from $($segmentGroups.Count) segment groups" -Level "INFO"
        Write-Log "Built membership map for $($segmentGroupMembership.Count) APP_GROUPs" -Level "DEBUG"
        
        return @{
            Segments = $extractedSegments
            Membership = $segmentGroupMembership
        }
    }
    catch {
        Write-Log "Error loading segment groups: $_" -Level "ERROR"
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
        Write-Log "Merging application segments and removing duplicates" -Level "INFO"
        
        # Ensure arrays are properly initialized
        if ($null -eq $StandaloneSegments) { $StandaloneSegments = @() }
        if ($null -eq $SegmentGroupSegments) { $SegmentGroupSegments = @() }
        
        # Convert to arrays if they're not already
        if ($StandaloneSegments -isnot [array]) { $StandaloneSegments = @($StandaloneSegments) }
        if ($SegmentGroupSegments -isnot [array]) { $SegmentGroupSegments = @($SegmentGroupSegments) }
        
        Write-Log "Standalone segments: $($StandaloneSegments.Count)" -Level "DEBUG"
        Write-Log "Segment group segments: $($SegmentGroupSegments.Count)" -Level "DEBUG"
        
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
                    Write-Log "Duplicate ID found in standalone segments: $segmentId" -Level "WARN"
                }
            } else {
                Write-Log "Standalone segment missing ID property, skipping: $($segment.name)" -Level "WARN"
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
                    Write-Log "Duplicate segment found (ID: $segmentId): '$($segment.name)' from segment group conflicts with standalone segment '$($existingSegment.name)'. Keeping standalone version." -Level "DEBUG"
                }
            } else {
                Write-Log "Segment group segment missing ID property, skipping: $($segment.name)" -Level "WARN"
            }
        }
        
        # Convert hashtable values back to array
        $mergedSegments = $segmentLookup.Values | Sort-Object -Property name
        
        Write-Log "Deduplication complete:" -Level "INFO"
        Write-Log "  Total unique segments: $($mergedSegments.Count)" -Level "INFO"
        Write-Log "  Duplicates removed: $duplicateCount" -Level "INFO"
        Write-Log "  Unique segments from standalone file: $uniqueFromStandalone" -Level "INFO"
        Write-Log "  Unique segments from segment groups: $uniqueFromSegmentGroups" -Level "INFO"
        Write-Log "  Total segments in standalone file: $($StandaloneSegments.Count)" -Level "INFO"
        Write-Log "  Total segments in segment groups: $($SegmentGroupSegments.Count)" -Level "INFO"
        
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
        Write-Log "Error merging application segments: $_" -Level "ERROR"
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

function Load-ApplicationSegments {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AppSegmentPath,
        
        [Parameter(Mandatory = $false)]
        [string]$SegmentGroupPath
    )
    
    try {
        # Load standalone application segments
        Write-Log "Loading standalone application segments from: $AppSegmentPath" -Level "INFO"
        
        if (-not (Test-Path $AppSegmentPath)) {
            Write-Log "Application segments file not found: $AppSegmentPath" -Level "ERROR"
            throw "Application segments file not found"
        }
        
        $appSegmentsJson = Get-Content -Path $AppSegmentPath -Raw -Encoding UTF8
        $appSegmentsData = $appSegmentsJson | ConvertFrom-Json
        
        if ($null -eq $appSegmentsData) {
            Write-Log "Failed to parse JSON from file: $AppSegmentPath" -Level "ERROR"
            throw "Failed to parse application segments JSON"
        }
        
        # Handle different JSON formats: direct array or nested under 'list' property
        $standaloneSegments = @()
        if ($appSegmentsData.PSObject.Properties.Name -contains 'list') {
            Write-Log "Detected paginated format with 'list' property" -Level "DEBUG"
            $standaloneSegments = $appSegmentsData.list
            if ($appSegmentsData.PSObject.Properties.Name -contains 'totalCount') {
                Write-Log "Total count from API: $($appSegmentsData.totalCount)" -Level "DEBUG"
            }
        } elseif ($appSegmentsData -is [array]) {
            Write-Log "Detected direct array format" -Level "DEBUG"
            $standaloneSegments = $appSegmentsData
        } else {
            Write-Log "Unknown JSON format. Expected either an array or object with 'list' property" -Level "ERROR"
            throw "Unknown JSON format in application segments file"
        }
        
        if ($null -eq $standaloneSegments -or $standaloneSegments.Count -eq 0) {
            Write-Log "No application segments found in the JSON data" -Level "ERROR"
            throw "No application segments found"
        }
        
        Write-Log "Loaded $($standaloneSegments.Count) standalone application segments" -Level "INFO"
        
        # Load segment groups if provided
        $segmentGroupSegments = @()
        $segmentGroupMembership = @{}
        if (-not [string]::IsNullOrEmpty($SegmentGroupPath)) {
            $segmentGroupResult = Load-SegmentGroups -FilePath $SegmentGroupPath
            $segmentGroupSegments = $segmentGroupResult.Segments
            $segmentGroupMembership = $segmentGroupResult.Membership
        }
        
        # Merge and deduplicate
        $mergeResult = Merge-ApplicationSegments -StandaloneSegments $standaloneSegments -SegmentGroupSegments $segmentGroupSegments -SegmentGroupMembership $segmentGroupMembership
        
        return $mergeResult
    }
    catch {
        Write-Log "Error loading application segments: $_" -Level "ERROR"
        throw
    }
}

function Load-AccessPolicies {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    
    try {
        Write-Log "Loading ZPA access policies from: $FilePath" -Level "INFO"
        
        if (-not (Test-Path $FilePath)) {
            Write-Log "Access policies file not found: $FilePath" -Level "DEBUG"
            return $null
        }
        
        $accessPoliciesJson = Get-Content -Path $FilePath -Raw -Encoding UTF8 -ErrorAction Stop
        $accessPoliciesData = $accessPoliciesJson | ConvertFrom-Json -ErrorAction Stop
        
        if ($null -eq $accessPoliciesData) {
            Write-Log "Failed to parse JSON from access policies file: $FilePath" -Level "ERROR"
            throw "Failed to parse access policies JSON"
        }
        
        # Handle different JSON formats: direct array or nested under 'list' property
        $accessPolicies = @()
        if ($accessPoliciesData.PSObject.Properties.Name -contains 'list') {
            Write-Log "Detected paginated format with 'list' property in access policies" -Level "DEBUG"
            $accessPolicies = $accessPoliciesData.list
            if ($accessPoliciesData.PSObject.Properties.Name -contains 'totalPages') {
                Write-Log "Total pages from API: $($accessPoliciesData.totalPages)" -Level "DEBUG"
            }
        } elseif ($accessPoliciesData -is [array]) {
            Write-Log "Detected direct array format in access policies" -Level "DEBUG"
            $accessPolicies = $accessPoliciesData
        } else {
            Write-Log "Unknown JSON format in access policies file. Expected either an array or object with 'list' property" -Level "ERROR"
            throw "Unknown JSON format in access policies file"
        }
        
        if ($null -eq $accessPolicies -or $accessPolicies.Count -eq 0) {
            Write-Log "No access policies found in the JSON data" -Level "WARN"
            return @()
        }
        
        Write-Log "Loaded $($accessPolicies.Count) access policies" -Level "INFO"
        return $accessPolicies
    }
    catch {
        Write-Log "Error loading access policies: $_" -Level "ERROR"
        throw
    }
}

function Load-ScimGroups {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    
    try {
        Write-Log "Loading SCIM groups from: $FilePath" -Level "INFO"
        
        if (-not (Test-Path $FilePath)) {
            Write-Log "SCIM groups file not found: $FilePath" -Level "DEBUG"
            return $null
        }
        
        $scimGroupsJson = Get-Content -Path $FilePath -Raw -Encoding UTF8 -ErrorAction Stop
        $scimGroupsData = $scimGroupsJson | ConvertFrom-Json -ErrorAction Stop
        
        if ($null -eq $scimGroupsData) {
            Write-Log "Failed to parse JSON from SCIM groups file: $FilePath" -Level "ERROR"
            throw "Failed to parse SCIM groups JSON"
        }
        
        # Handle different JSON formats: direct array or nested under 'list' property
        $scimGroups = @()
        if ($scimGroupsData.PSObject.Properties.Name -contains 'list') {
            Write-Log "Detected paginated format with 'list' property in SCIM groups" -Level "DEBUG"
            $scimGroups = $scimGroupsData.list
            if ($scimGroupsData.PSObject.Properties.Name -contains 'totalCount') {
                Write-Log "Total SCIM groups count from API: $($scimGroupsData.totalCount)" -Level "DEBUG"
            }
        } elseif ($scimGroupsData -is [array]) {
            Write-Log "Detected direct array format in SCIM groups" -Level "DEBUG"
            $scimGroups = $scimGroupsData
        } else {
            Write-Log "Unknown JSON format in SCIM groups file. Expected either an array or object with 'list' property" -Level "ERROR"
            throw "Unknown JSON format in SCIM groups file"
        }
        
        if ($null -eq $scimGroups -or $scimGroups.Count -eq 0) {
            Write-Log "No SCIM groups found in the JSON data" -Level "WARN"
            return @()
        }
        
        Write-Log "Loaded $($scimGroups.Count) SCIM groups" -Level "INFO"
        return $scimGroups
    }
    catch {
        Write-Log "Error loading SCIM groups: $_" -Level "ERROR"
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
            Write-Log "  Policy '$($Policy.name)' skipped: policyType is not '1' (got: $($Policy.policyType))" -Level "DEBUG"
            return $false
        }
        
        # Check action == "ALLOW"
        if ($Policy.PSObject.Properties.Name -notcontains 'action' -or $Policy.action -ne "ALLOW") {
            Write-Log "  Policy '$($Policy.name)' skipped: action is not 'ALLOW' (got: $($Policy.action))" -Level "DEBUG"
            return $false
        }
        
        # Check root operator == "AND"
        if ($Policy.PSObject.Properties.Name -notcontains 'operator' -or $Policy.operator -ne "AND") {
            Write-Log "  Policy '$($Policy.name)' skipped: root operator is not 'AND' (got: $($Policy.operator))" -Level "DEBUG"
            return $false
        }
        
        # Check has conditions
        if ($Policy.PSObject.Properties.Name -notcontains 'conditions' -or $null -eq $Policy.conditions -or $Policy.conditions.Count -eq 0) {
            Write-Log "  Policy '$($Policy.name)' skipped: no conditions found" -Level "DEBUG"
            return $false
        }
        
        # Check for negated conditions
        foreach ($condition in $Policy.conditions) {
            if ($condition.PSObject.Properties.Name -contains 'negated' -and $condition.negated -eq $true) {
                Write-Log "  Policy '$($Policy.name)' skipped: contains negated conditions" -Level "DEBUG"
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
            Write-Log "  Policy '$($Policy.name)' skipped: no APP or APP_GROUP targets found" -Level "DEBUG"
            return $false
        }
        
        # Check has at least one SCIM_GROUP operand
        $hasScimGroup = $false
        foreach ($condition in $Policy.conditions) {
            if ($condition.PSObject.Properties.Name -contains 'operands' -and $condition.operands) {
                foreach ($operand in $condition.operands) {
                    if ($operand.PSObject.Properties.Name -contains 'objectType' -and $operand.objectType -eq "SCIM_GROUP") {
                        $hasScimGroup = $true
                        break
                    }
                }
            }
            if ($hasScimGroup) { break }
        }
        
        if (-not $hasScimGroup) {
            Write-Log "  Policy '$($Policy.name)' skipped: no SCIM_GROUP conditions found" -Level "DEBUG"
            return $false
        }
        
        return $true
    }
    catch {
        Write-Log "Error validating policy '$($Policy.name)': $_" -Level "WARN"
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
                            Write-Log "    Found APP target: $($operand.rhs) ($($operand.name))" -Level "DEBUG"
                        }
                        elseif ($operand.objectType -eq "APP_GROUP" -and $operand.PSObject.Properties.Name -contains 'rhs') {
                            $appGroupIds += $operand.rhs.ToString()
                            Write-Log "    Found APP_GROUP target: $($operand.rhs) ($($operand.name))" -Level "DEBUG"
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
        Write-Log "Error extracting app targets from policy '$($Policy.name)': $_" -Level "WARN"
        return @{ AppIds = @(); AppGroupIds = @() }
    }
}

function Get-ScimGroupsFromPolicy {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Policy,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$ScimGroupLookup
    )
    
    try {
        $scimGroupNames = @()
        
        if ($Policy.PSObject.Properties.Name -notcontains 'conditions' -or $null -eq $Policy.conditions) {
            return @($scimGroupNames)
        }
        
        foreach ($condition in $Policy.conditions) {
            if ($condition.PSObject.Properties.Name -contains 'operands' -and $condition.operands) {
                # Ensure operands is treated as an array
                $operandsList = @($condition.operands)
                foreach ($operand in $operandsList) {
                    if ($operand.PSObject.Properties.Name -contains 'objectType' -and $operand.objectType -eq "SCIM_GROUP") {
                        if ($operand.PSObject.Properties.Name -contains 'rhs') {
                            $scimGroupId = $operand.rhs.ToString()
                            
                            if ($ScimGroupLookup.ContainsKey($scimGroupId)) {
                                $groupName = $ScimGroupLookup[$scimGroupId]
                                $scimGroupNames += $groupName
                                Write-Log "    Found SCIM_GROUP: $scimGroupId -> $groupName" -Level "DEBUG"
                            }
                            else {
                                Write-Log "    SCIM_GROUP ID $scimGroupId not found in SCIM groups lookup" -Level "WARN"
                            }
                        }
                    }
                }
            }
        }
        
        return @($scimGroupNames | Select-Object -Unique)
    }
    catch {
        Write-Log "Error extracting SCIM groups from policy '$($Policy.name)': $_" -Level "WARN"
        return @()
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
                Write-Log "    Expanded APP_GROUP $appGroupId to $($memberAppIds.Count) APPs" -Level "DEBUG"
            }
            else {
                Write-Log "    APP_GROUP $appGroupId not found in segment group membership" -Level "WARN"
            }
        }
        
        return @($expandedAppIds | Select-Object -Unique)
    }
    catch {
        Write-Log "Error expanding APP_GROUP to APPs: $_" -Level "WARN"
        return @()
    }
}

function Build-AppToScimGroupLookup {
    <#
    .SYNOPSIS
        Builds a lookup table mapping APP IDs to SCIM groups with access.
    
    .PARAMETER AccessPolicyPath
        Path to ZPA Access Policies JSON file.
    
    .PARAMETER ScimGroupPath
        Path to SCIM Groups JSON file.
    
    .PARAMETER SegmentGroupMembership
        Hashtable containing APP_GROUP to APP IDs mapping (from Load-ApplicationSegments).
    
    .PARAMETER EnableDebugLogging
        Enable verbose debug logging.
    
    .OUTPUTS
        Hashtable with APP IDs as keys and arrays of SCIM group names as values.
        Returns $null if files not found or prerequisites not met.
    
    .EXAMPLE
        $lookup = Build-AppToScimGroupLookup `
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
        Write-Log "" -Level "INFO"
        Write-Log "=== LOADING ACCESS POLICY DATA ===" -Level "INFO"
        
        # Step 1: Load SCIM Groups
        $scimGroups = $null
        try {
            $scimGroups = Load-ScimGroups -FilePath $ScimGroupPath
        }
        catch {
            Write-Log "Failed to load SCIM groups: $_" -Level "ERROR"
            throw
        }
        
        # Step 2: Load Access Policies
        $accessPolicies = $null
        try {
            $accessPolicies = Load-AccessPolicies -FilePath $AccessPolicyPath
        }
        catch {
            Write-Log "Failed to load access policies: $_" -Level "ERROR"
            throw
        }
        
        # Step 3: Validate Prerequisites
        if ($null -eq $scimGroups -or $null -eq $accessPolicies) {
            Write-Log "Access policy files not provided or not found. Using placeholder values for EntraGroups." -Level "INFO"
            return $null
        }
        
        if ($scimGroups.Count -eq 0 -or $accessPolicies.Count -eq 0) {
            Write-Log "Access policy files are empty. Using placeholder values for EntraGroups." -Level "WARN"
            return $null
        }
        
        # Build SCIM group lookup: ID -> Name
        Write-Log "" -Level "INFO"
        $scimGroupLookup = @{}
        foreach ($group in $scimGroups) {
            if ($group.PSObject.Properties.Name -contains 'id' -and $group.PSObject.Properties.Name -contains 'name') {
                $scimGroupLookup[$group.id.ToString()] = $group.name
            }
        }
        Write-Log "Built SCIM group lookup with $($scimGroupLookup.Count) groups" -Level "DEBUG"
        
        # Step 4 & 5: Filter and Process Policies
        Write-Log "" -Level "INFO"
        Write-Log "=== PROCESSING ACCESS POLICIES ===" -Level "INFO"
        Write-Log "Processing $($accessPolicies.Count) access policies..." -Level "INFO"
        
        $validPolicies = @()
        $skipReasons = @{
            'No SCIM_GROUP conditions' = 0
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
                    Write-Log "  Valid policy: $($policy.name) (ID: $($policy.id))" -Level "DEBUG"
                }
                else {
                    # Count skip reasons (basic categorization)
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
                        # Check if negated
                        $hasNegated = $false
                        if ($policy.PSObject.Properties.Name -contains 'conditions') {
                            foreach ($condition in $policy.conditions) {
                                if ($condition.PSObject.Properties.Name -contains 'negated' -and $condition.negated -eq $true) {
                                    $hasNegated = $true
                                    break
                                }
                            }
                        }
                        
                        if ($hasNegated) {
                            $skipReasons['Negated conditions']++
                        }
                        else {
                            # Must be missing targets or groups
                            $skipReasons['No SCIM_GROUP conditions']++
                        }
                    }
                }
            }
            catch {
                $skipReasons['Malformed']++
                Write-Log "  Malformed policy (ID: $($policy.id)): $_" -Level "DEBUG"
            }
        }
        
        Write-Log "  Valid policies: $($validPolicies.Count)" -Level "INFO"
        Write-Log "  Skipped policies: $($accessPolicies.Count - $validPolicies.Count)" -Level "INFO"
        foreach ($reason in $skipReasons.Keys | Sort-Object) {
            if ($skipReasons[$reason] -gt 0) {
                Write-Log "    - ${reason}: $($skipReasons[$reason])" -Level "INFO"
            }
        }
        
        # Step 5b & 5c & 5d: Extract targets, expand APP_GROUPs, build mappings
        Write-Log "" -Level "INFO"
        Write-Log "Expanding APP_GROUP targets using segment group membership..." -Level "INFO"
        
        $appToScimGroupsLookup = @{}
        $totalDirectApps = 0
        $totalAppGroups = 0
        $totalExpandedFromAppGroups = 0
        $scimGroupsNotFound = @()
        
        foreach ($policy in $validPolicies) {
            try {
                Write-Log "  Processing policy: $($policy.name) (ID: $($policy.id))" -Level "DEBUG"
                
                # Get APP and APP_GROUP targets
                $targets = Get-AppTargetsFromPolicy -Policy $policy
                $directAppIds = @($targets.AppIds)
                $appGroupIds = @($targets.AppGroupIds)
                
                $totalDirectApps += $directAppIds.Count
                $totalAppGroups += $appGroupIds.Count
                
                # Expand APP_GROUPs to APPs
                $expandedAppIds = @()
                if ($appGroupIds.Count -gt 0) {
                    $expandedAppIds = @(Expand-AppGroupToApps -AppGroupIds $appGroupIds -SegmentGroupMembership $SegmentGroupMembership)
                    $totalExpandedFromAppGroups += $expandedAppIds.Count
                }
                
                # Combine direct and expanded APP IDs
                $allAppIds = @(($directAppIds + $expandedAppIds) | Select-Object -Unique)
                
                # Get SCIM groups
                $scimGroupNames = @(Get-ScimGroupsFromPolicy -Policy $policy -ScimGroupLookup $scimGroupLookup)
                
                if ($scimGroupNames.Count -eq 0) {
                    Write-Log "    No valid SCIM groups found for policy '$($policy.name)'" -Level "DEBUG"
                    continue
                }
                
                # Build mappings
                foreach ($appId in $allAppIds) {
                    if (-not $appToScimGroupsLookup.ContainsKey($appId)) {
                        $appToScimGroupsLookup[$appId] = @()
                    }
                    
                    foreach ($groupName in $scimGroupNames) {
                        if ($appToScimGroupsLookup[$appId] -notcontains $groupName) {
                            $appToScimGroupsLookup[$appId] += $groupName
                        }
                    }
                }
            }
            catch {
                Write-Log "  Error processing policy '$($policy.name)': $_" -Level "WARN"
                continue
            }
        }
        
        # Step 6: Deduplication & Aggregation (already done in step 5d)
        # Sort group names alphabetically for each APP
        # Create a copy of keys to avoid collection modification during enumeration
        $appIds = @($appToScimGroupsLookup.Keys)
        foreach ($appId in $appIds) {
            $appToScimGroupsLookup[$appId] = @($appToScimGroupsLookup[$appId] | Sort-Object)
        }
        
        # Step 7: Summary Logging
        Write-Log "  Total APP targets (direct): $totalDirectApps" -Level "INFO"
        Write-Log "  Total APP_GROUP targets: $totalAppGroups" -Level "INFO"
        Write-Log "  APP_GROUPs expanded to: $totalExpandedFromAppGroups APPs" -Level "INFO"
        Write-Log "  Total unique APPs with access policies: $($appToScimGroupsLookup.Count)" -Level "INFO"
        
        if ($scimGroupsNotFound.Count -gt 0) {
            Write-Log "  Warnings:" -Level "INFO"
            Write-Log "    - SCIM Groups not found: $($scimGroupsNotFound.Count)" -Level "INFO"
        }
        
        Write-Log "" -Level "INFO"
        Write-Log "Access policy lookup built successfully" -Level "INFO"
        
        return $appToScimGroupsLookup
    }
    catch {
        Write-Log "Error building APP to SCIM group lookup: $_" -Level "ERROR"
        return $null
    }
}

#endregion

#region Main Script Logic

try {
    Write-Log "Starting ZPA to GSA transformation script" -Level "INFO"
    Write-Log "Script version: 1.0" -Level "INFO"
    Write-Log "Parameters:" -Level "INFO"
    Write-Log "  AppSegmentPath: $AppSegmentPath" -Level "INFO"
    Write-Log "  OutputBasePath: $OutputBasePath" -Level "INFO"
    if (-not [string]::IsNullOrEmpty($SegmentGroupPath)) {
        Write-Log "  SegmentGroupPath: $SegmentGroupPath" -Level "INFO"
    }
    Write-Log "  AccessPolicyPath: $AccessPolicyPath" -Level "INFO"
    Write-Log "  ScimGroupPath: $ScimGroupPath" -Level "INFO"
    
    if ($EnableDebugLogging) {
        Write-Log "  EnableDebugLogging: True" -Level "INFO"
    }
    
    if ($TargetAppSegmentName) {
        Write-Log "Target segment name: $TargetAppSegmentName" -Level "INFO"
    }
    
    if ($AppSegmentNamePattern) {
        Write-Log "Segment name pattern: $AppSegmentNamePattern" -Level "INFO"
    }
    
    if ($SkipAppSegmentName) {
        Write-Log "Skip segment names: $SkipAppSegmentName" -Level "INFO"
    }
    
    if ($SkipAppSegmentNamePattern) {
        Write-Log "Skip segment patterns: $SkipAppSegmentNamePattern" -Level "INFO"
    }
    
    if ($SegmentGroupPath) {
        Write-Log "Segment groups file: $SegmentGroupPath" -Level "INFO"
    }
    
    #region Data Loading Phase
    try {
        $loadResult = Load-ApplicationSegments -AppSegmentPath $AppSegmentPath -SegmentGroupPath $SegmentGroupPath
        $appSegments = $loadResult.Segments
        $loadingStats = $loadResult.Stats
        $segmentGroupMembership = $loadResult.SegmentGroupMembership
    }
    catch {
        Write-Log "Error loading application segments: $_" -Level "ERROR"
        exit 1
    }
    
    # Build access policy lookup if files are provided
    $appToScimGroupLookup = $null
    $accessPolicyStats = @{
        FilesProvided = $false
        AppsWithGroups = 0
        AppsWithoutPolicies = 0
        AppsUsingPlaceholder = 0
    }
    
    try {
        $appToScimGroupLookup = Build-AppToScimGroupLookup `
            -AccessPolicyPath $AccessPolicyPath `
            -ScimGroupPath $ScimGroupPath `
            -SegmentGroupMembership $segmentGroupMembership `
            -EnableDebugLogging:$EnableDebugLogging
        
        if ($null -ne $appToScimGroupLookup) {
            $accessPolicyStats.FilesProvided = $true
        }
    }
    catch {
        Write-Log "Failed to build access policy lookup. Using placeholder values. Error: $_" -Level "WARN"
        $appToScimGroupLookup = $null
    }
    #endregion
    
    #region App Segment Filtering Phase
    $originalCount = $appSegments.Count
    $filteredSegments = $appSegments
    
    # Apply skip filters first (exact name)
    if ($SkipAppSegmentName) {
        Write-Log "Applying skip exact name filter: $SkipAppSegmentName" -Level "INFO"
        $skipNames = $SkipAppSegmentName.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
        $beforeSkipCount = $filteredSegments.Count
        $filteredSegments = $filteredSegments | Where-Object { 
            $segmentName = $_.name
            $shouldSkip = $false
            foreach ($skipName in $skipNames) {
                if ($segmentName -eq $skipName) {
                    $shouldSkip = $true
                    Write-Log "  Skipping segment: $segmentName (exact match: $skipName)" -Level "DEBUG"
                    break
                }
            }
            return -not $shouldSkip
        }
        $skippedCount = $beforeSkipCount - $filteredSegments.Count
        Write-Log "Segments after skip exact name filter: $($filteredSegments.Count) (skipped: $skippedCount)" -Level "INFO"
    }
    
    # Apply skip filters (pattern)
    if ($SkipAppSegmentNamePattern) {
        Write-Log "Applying skip pattern filter: $SkipAppSegmentNamePattern" -Level "INFO"
        $skipPatterns = $SkipAppSegmentNamePattern.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
        $beforeSkipCount = $filteredSegments.Count
        $filteredSegments = $filteredSegments | Where-Object { 
            $segmentName = $_.name
            $shouldSkip = $false
            foreach ($skipPattern in $skipPatterns) {
                if (Test-WildcardMatch -Pattern $skipPattern -Text $segmentName) {
                    $shouldSkip = $true
                    Write-Log "  Skipping segment: $segmentName (pattern match: $skipPattern)" -Level "DEBUG"
                    break
                }
            }
            return -not $shouldSkip
        }
        $skippedCount = $beforeSkipCount - $filteredSegments.Count
        Write-Log "Segments after skip pattern filter: $($filteredSegments.Count) (skipped: $skippedCount)" -Level "INFO"
    }
    
    # Apply exact name filter
    if ($TargetAppSegmentName) {
        Write-Log "Applying exact name filter: $TargetAppSegmentName" -Level "INFO"
        $filteredSegments = $filteredSegments | Where-Object { $_.name -eq $TargetAppSegmentName }
        Write-Log "Segments after exact name filter: $($filteredSegments.Count)" -Level "INFO"
    }
    
    # Apply pattern filter
    if ($AppSegmentNamePattern) {
        Write-Log "Applying pattern filter: $AppSegmentNamePattern" -Level "INFO"
        $filteredSegments = $filteredSegments | Where-Object { Test-WildcardMatch -Pattern $AppSegmentNamePattern -Text $_.name }
        Write-Log "Segments after pattern filter: $($filteredSegments.Count)" -Level "INFO"
    }
    
    Write-Log "Processing $($filteredSegments.Count) of $originalCount total segments" -Level "INFO"
    
    if ($filteredSegments.Count -eq 0) {
        Write-Log "No segments remain after filtering. Exiting." -Level "WARN"
        exit 0
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
    Write-Log "Starting main processing phase" -Level "INFO"
    
    foreach ($segment in $filteredSegments) {
        $processedCount++
        $progressPercent = [math]::Round(($processedCount / $filteredSegments.Count) * 100, 1)
        Write-Progress -Activity "Processing ZPA Segments" -Status "Processing segment $processedCount of $($filteredSegments.Count) ($progressPercent%)" -PercentComplete $progressPercent
        
        try {
            Write-Log "Processing segment: $($segment.name) ($($segment.domainNames.Count) domains)" -Level "DEBUG"
            
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
                Write-Log "Segment '$($segment.name)' has no domain names. Skipping." -Level "WARN"
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
                            Write-Log "Invalid TCP port range in segment '$($segment.name)': $fromPort-$toPort" -Level "ERROR"
                            throw "Invalid port range"
                        }
                        
                        if ($fromPort -eq $toPort) {
                            $tcpPorts += $fromPort.ToString()
                        } else {
                            $tcpPorts += "$fromPort-$toPort"
                        }
                    }
                    catch {
                        Write-Log "Error processing TCP port range for segment '$($segment.name)': $_" -Level "ERROR"
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
                            Write-Log "Invalid UDP port range in segment '$($segment.name)': $fromPort-$toPort" -Level "ERROR"
                            throw "Invalid port range"
                        }
                        
                        if ($fromPort -eq $toPort) {
                            $udpPorts += $fromPort.ToString()
                        } else {
                            $udpPorts += "$fromPort-$toPort"
                        }
                    }
                    catch {
                        Write-Log "Error processing UDP port range for segment '$($segment.name)': $_" -Level "ERROR"
                        # Skip entire segment if any port is invalid
                        break
                    }
                }
            }
            
            # Skip segment if no port configuration
            if ($tcpPorts.Count -eq 0 -and $udpPorts.Count -eq 0) {
                Write-Log "Segment '$($segment.name)' has no valid port configuration. Skipping." -Level "WARN"
                continue
            }
            
            Write-Log "Processing $($segment.domainNames.Count) domains with $($tcpPorts.Count) TCP and $($udpPorts.Count) UDP port ranges" -Level "DEBUG"
            
            # Process each domain
            $domainCount = 0
            foreach ($domain in $segment.domainNames) {
                $domainCount++
                
                # Show progress for segments with many domains (>10)
                if ($segment.domainNames.Count -gt 10 -and $domainCount % 5 -eq 0) {
                    Write-Log "  Processed $domainCount/$($segment.domainNames.Count) domains in segment '$($segment.name)'" -Level "DEBUG"
                }
                
                try {
                    $cleanDomain = Clean-Domain -Domain $domain
                    $destinationType = Get-DestinationType -Destination $cleanDomain
                    
                    # Validate CIDR if it's a subnet
                    if ($destinationType -eq "ipRangeCidr") {
                        $cidrRange = Convert-CIDRToRange -CIDR $cleanDomain
                        if ($null -eq $cidrRange) {
                            Write-Log "Invalid CIDR format in segment '$($segment.name)': $cleanDomain. Skipping entire segment." -Level "ERROR"
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
                            Write-Log "    Processing combo $comboCount/$totalCombos for domain '$cleanDomain'" -Level "DEBUG"
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
                                                    Write-Log "Conflict detected: ${cleanDomain}:$($combo.Port):$($combo.Protocol) conflicts with existing app: $conflictReference" -Level "WARN"
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
                                            Write-Log "Conflict detected: ${cleanDomain}:$($combo.Port):$($combo.Protocol) conflicts with existing app: $conflictReference" -Level "WARN"
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
                                                Write-Log "Conflict detected: ${cleanDomain}:$($combo.Port):$($combo.Protocol) conflicts with wildcard app: $conflictReference (pattern: $suffix)" -Level "WARN"
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
                        
                        # Determine EntraGroups value
                        $entraGroupValue = "Placeholder_Replace_Me"
                        
                        if ($null -ne $appToScimGroupLookup) {
                            $appId = $segment.id.ToString()
                            
                            if ($appToScimGroupLookup.ContainsKey($appId)) {
                                $groupNames = $appToScimGroupLookup[$appId]
                                if ($groupNames -and $groupNames.Count -gt 0) {
                                    $entraGroupValue = ($groupNames -join "; ")
                                } else {
                                    $entraGroupValue = "No_Access_Policy_Found_Replace_Me"
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
                    Write-Log "Error processing domain '$domain' in segment '$($segment.name)': $_" -Level "ERROR"
                    continue
                }
            }
        }
        catch {
            Write-Log "Error processing segment '$($segment.name)': $_" -Level "ERROR"
            continue
        }
        
        # Log completion for segments with many results
        $segmentResults = $allResults | Where-Object { $_.OriginalAppName -eq $segment.name }
        if ($segmentResults.Count -gt 50) {
            Write-Log "Completed segment '$($segment.name)' - generated $($segmentResults.Count) result records" -Level "DEBUG"
        }
    }
    
    Write-Progress -Activity "Processing ZPA Segments" -Completed
    
    # Calculate access policy statistics
    if ($null -ne $appToScimGroupLookup) {
        foreach ($segment in $filteredSegments) {
            $appId = $segment.id.ToString()
            if ($appToScimGroupLookup.ContainsKey($appId) -and $appToScimGroupLookup[$appId].Count -gt 0) {
                $accessPolicyStats.AppsWithGroups++
            } else {
                $accessPolicyStats.AppsWithoutPolicies++
            }
        }
    } else {
        $accessPolicyStats.AppsUsingPlaceholder = $filteredSegments.Count
    }
    #endregion
    
    #region Data Grouping and Deduplication
    Write-Log "Performing data grouping and deduplication" -Level "INFO"
    
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
            ConnectorGroup = $firstItem.ConnectorGroup
            Conflict = $firstItem.Conflict
            ConflictingEnterpriseApp = $firstItem.ConflictingEnterpriseApp
            Provision = $firstItem.Provision
        }
    }
    #endregion
    
    #region Export Results
    Write-Log "Exporting results to CSV file" -Level "INFO"
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $outputFileName = "${timestamp}_GSA_EnterpriseApps_All.csv"
    $outputFilePath = Join-Path $OutputBasePath $outputFileName
    
    $exportSuccess = Export-DataToFile -Data $groupedResults -FilePath $outputFilePath -Format "CSV"
    
    if ($exportSuccess) {
        Write-Log "Results exported successfully to: $outputFilePath" -Level "INFO"
    } else {
        Write-Log "Failed to export results" -Level "ERROR"
    }
    #endregion
    
    #region Statistics and Summary
    Write-Log "" -Level "INFO"
    Write-Log "=== TRANSFORMATION SUMMARY ===" -Level "INFO"
    Write-Log "Total segments loaded: $originalCount" -Level "INFO"
    if (-not [string]::IsNullOrEmpty($SegmentGroupPath)) {
        Write-Log "  Standalone segments file: $($loadingStats.TotalFromStandalone) segments" -Level "INFO"
        Write-Log "  Segment groups file: $($loadingStats.TotalFromSegmentGroups) segments" -Level "INFO"
        Write-Log "  Unique from standalone: $($loadingStats.UniqueFromStandalone)" -Level "INFO"
        Write-Log "  Unique from segment groups: $($loadingStats.UniqueFromSegmentGroups)" -Level "INFO"
        Write-Log "  Duplicates removed: $($loadingStats.DuplicatesRemoved)" -Level "INFO"
    }
    Write-Log "Segments processed: $($filteredSegments.Count)" -Level "INFO"
    Write-Log "Total result records: $($allResults.Count)" -Level "INFO"
    Write-Log "Grouped result records: $($groupedResults.Count)" -Level "INFO"
    Write-Log "Conflicts detected: $conflictCount" -Level "INFO"
    Write-Log "" -Level "INFO"
    
    # Access Policy Integration Summary
    if ($accessPolicyStats.FilesProvided) {
        Write-Log "Access Policy Integration:" -Level "INFO"
        Write-Log "  Access policy files: Provided" -Level "INFO"
        Write-Log "  APPs with assigned groups: $($accessPolicyStats.AppsWithGroups) ($(if ($filteredSegments.Count -gt 0) { [math]::Round(($accessPolicyStats.AppsWithGroups / $filteredSegments.Count) * 100, 1) } else { 0 })%)" -Level "INFO"
        Write-Log "  APPs without access policies: $($accessPolicyStats.AppsWithoutPolicies) ($(if ($filteredSegments.Count -gt 0) { [math]::Round(($accessPolicyStats.AppsWithoutPolicies / $filteredSegments.Count) * 100, 1) } else { 0 })%)" -Level "INFO"
        Write-Log "  APPs using placeholder: 0 (0.0%)" -Level "INFO"
    } else {
        Write-Log "Access Policy Integration:" -Level "INFO"
        Write-Log "  Access policy files: Not provided" -Level "INFO"
        Write-Log "  All APPs using placeholder: $($accessPolicyStats.AppsUsingPlaceholder) (100.0%)" -Level "INFO"
    }
    Write-Log "" -Level "INFO"
    Write-Log "Output file: $outputFilePath" -Level "INFO"
    Write-Log "" -Level "INFO"
    Write-Log "=== NEXT STEPS ===" -Level "INFO"
    Write-Log "1. Review the exported CSV file for accuracy" -Level "INFO"
    Write-Log "2. Replace all 'Placeholder_Replace_Me' values with actual values:" -Level "INFO"
    Write-Log "   - EntraGroups: Set appropriate Entra ID group names (if not auto-populated)" -Level "INFO"
    Write-Log "   - ConnectorGroup: Set appropriate connector group names" -Level "INFO"
    Write-Log "3. Review and resolve any conflicts identified in the 'Conflict' column" -Level "INFO"
    Write-Log "4. Import the completed data into Global Secure Access" -Level "INFO"
    Write-Log "" -Level "INFO"
    
    if ($conflictCount -gt 0) {
        Write-Log "WARNING: $conflictCount conflicts were detected. Please review the 'ConflictingEnterpriseApp' column for details." -Level "WARN"
    }
    
    Write-Log "Script completed successfully!" -Level "INFO"
    #endregion
}
catch {
    Write-Log "Fatal error in main script execution: $_" -Level "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level "ERROR"
    exit 1
}

#endregion
