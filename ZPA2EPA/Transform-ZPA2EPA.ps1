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
    [string]$OutputBasePath = $PSScriptRoot,
    
    [Parameter(HelpMessage = "Specific segment name for exact match processing")]
    [string]$TargetAppSegmentName,
    
    [Parameter(HelpMessage = "Wildcard pattern for segment name matching")]
    [string]$AppSegmentNamePattern,
    
    [Parameter(HelpMessage = "Comma-separated list of specific segment names to skip (exact match)")]
    [string]$SkipAppSegmentName,
    
    [Parameter(HelpMessage = "Comma-separated list of wildcard patterns for segment names to skip")]
    [string]$SkipAppSegmentNamePattern,
    
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
        $logFilePath = Join-Path $OutputBasePath "script.log"
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
        return "IP"
    }
    
    # Check if it's a CIDR notation
    if ($Destination -match '^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$') {
        return "Subnet"
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

#endregion

#region Main Script Logic

try {
    Write-Log "Starting ZPA to GSA transformation script" -Level "INFO"
    Write-Log "Script version: 1.0" -Level "INFO"
    Write-Log "Parameters: AppSegmentPath=$AppSegmentPath, OutputBasePath=$OutputBasePath" -Level "INFO"
    
    if ($EnableDebugLogging) {
        Write-Log "Debug logging is enabled" -Level "INFO"
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
    
    #region Data Loading Phase
    Write-Log "Loading ZPA application segments from: $AppSegmentPath" -Level "INFO"
    
    if (-not (Test-Path $AppSegmentPath)) {
        Write-Log "Application segments file not found: $AppSegmentPath" -Level "ERROR"
        exit 1
    }
    
    try {
        $appSegmentsJson = Get-Content -Path $AppSegmentPath -Raw -Encoding UTF8
        $appSegments = $appSegmentsJson | ConvertFrom-Json
        
        if ($null -eq $appSegments) {
            Write-Log "Failed to parse JSON from file: $AppSegmentPath" -Level "ERROR"
            exit 1
        }
        
        Write-Log "Loaded $($appSegments.Count) application segments" -Level "INFO"
    }
    catch {
        Write-Log "Error loading application segments: $_" -Level "ERROR"
        exit 1
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
    $ipRangeToProtocolToPorts = @{}      # IP ranges (as integer tuples) -> protocols -> port ranges
    $hostToProtocolToPorts = @{}         # FQDNs -> protocols -> port ranges
    $dnsSuffixes = @{}                   # Wildcard domain suffixes
    $allResults = @()
    $conflictCount = 0
    $processedCount = 0
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
                    if ($destinationType -eq "Subnet") {
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
                        
                        # Conflict detection logic
                        if ($destinationType -eq "IP" -or $destinationType -eq "Subnet") {
                            # Convert to IP range for comparison
                            $currentRange = if ($destinationType -eq "IP") {
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
                                                    $existingApp = $protocolData[$combo.Protocol][$existingPort]
                                                    $conflictingApps += $existingApp
                                                    Write-Log "Conflict detected: ${cleanDomain}:$($combo.Port):$($combo.Protocol) conflicts with existing app: $existingApp" -Level "WARN"
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
                                $ipRangeToProtocolToPorts[$currentRange][$combo.Protocol][$combo.Port] = $enterpriseAppName
                            }
                        } else {
                            # FQDN conflict detection
                            if ($hostToProtocolToPorts.ContainsKey($cleanDomain)) {
                                if ($hostToProtocolToPorts[$cleanDomain].ContainsKey($combo.Protocol)) {
                                    foreach ($existingPort in $hostToProtocolToPorts[$cleanDomain][$combo.Protocol].Keys) {
                                        if (Test-PortRangeOverlap -PortRange1 $combo.Port -PortRange2 $existingPort) {
                                            $hasConflict = $true
                                            $existingApp = $hostToProtocolToPorts[$cleanDomain][$combo.Protocol][$existingPort]
                                            $conflictingApps += $existingApp
                                            Write-Log "Conflict detected: ${cleanDomain}:$($combo.Port):$($combo.Protocol) conflicts with existing app: $existingApp" -Level "WARN"
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
                                                $existingApp = $suffixData[$combo.Protocol][$existingPort]
                                                $conflictingApps += $existingApp
                                                Write-Log "Conflict detected: ${cleanDomain}:$($combo.Port):$($combo.Protocol) conflicts with wildcard app: $existingApp (pattern: $suffix)" -Level "WARN"
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
                            $hostToProtocolToPorts[$cleanDomain][$combo.Protocol][$combo.Port] = $enterpriseAppName
                            
                            # Handle wildcard domains
                            if ($cleanDomain.StartsWith('*.')) {
                                if (-not $dnsSuffixes.ContainsKey($cleanDomain)) {
                                    $dnsSuffixes[$cleanDomain] = @{}
                                }
                                if (-not $dnsSuffixes[$cleanDomain].ContainsKey($combo.Protocol)) {
                                    $dnsSuffixes[$cleanDomain][$combo.Protocol] = @{}
                                }
                                $dnsSuffixes[$cleanDomain][$combo.Protocol][$combo.Port] = $enterpriseAppName
                            }
                        }
                        
                        if ($hasConflict) {
                            $conflictCount++
                        }
                        
                        # Create result object
                        $resultObj = [PSCustomObject]@{
                            OriginalAppName = $segment.name
                            EnterpriseAppName = $enterpriseAppName
                            destinationHost = $cleanDomain
                            DestinationType = $destinationType
                            Protocol = $combo.Protocol
                            Ports = $combo.Port
                            SegmentGroup = if ($segment.segmentGroupName) { $segment.segmentGroupName } else { "Unknown" }
                            ServerGroups = $serverGroupsString
                            ConditionalAccessPolicy = "Placeholder_Replace_Me"
                            EntraGroup = "Placeholder_Replace_Me"
                            ConnectorGroup = "Placeholder_Replace_Me"
                            Conflict = if ($hasConflict) { "Yes" } else { "No" }
                            ConflictingEnterpriseApp = if ($conflictingApps.Count -gt 0) { ($conflictingApps | Sort-Object -Unique) -join ", " } else { "" }
                            Provision = if ($hasConflict) { "No" } else { "Yes" }
                        }
                        
                        $allResults += $resultObj
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
    #endregion
    
    #region Data Grouping and Deduplication
    Write-Log "Performing data grouping and deduplication" -Level "INFO"
    
    $groupedResults = $allResults | Group-Object -Property EnterpriseAppName, destinationHost, DestinationType, Protocol, SegmentGroup, ServerGroups, Conflict, ConflictingEnterpriseApp | ForEach-Object {
        $group = $_.Group
        $firstItem = $group[0]
        
        # Consolidate ports within groups
        $uniquePorts = ($group | ForEach-Object { $_.Ports } | Sort-Object -Unique) -join ", "
        
        [PSCustomObject]@{
            OriginalAppName = $firstItem.OriginalAppName
            EnterpriseAppName = $firstItem.EnterpriseAppName
            destinationHost = $firstItem.destinationHost
            DestinationType = $firstItem.DestinationType
            Protocol = $firstItem.Protocol
            Ports = $uniquePorts
            SegmentGroup = $firstItem.SegmentGroup
            ServerGroups = $firstItem.ServerGroups
            ConditionalAccessPolicy = $firstItem.ConditionalAccessPolicy
            EntraGroup = $firstItem.EntraGroup
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
    Write-Log "Original segments loaded: $originalCount" -Level "INFO"
    Write-Log "Segments processed: $($filteredSegments.Count)" -Level "INFO"
    Write-Log "Total result records: $($allResults.Count)" -Level "INFO"
    Write-Log "Grouped result records: $($groupedResults.Count)" -Level "INFO"
    Write-Log "Conflicts detected: $conflictCount" -Level "INFO"
    Write-Log "Output file: $outputFilePath" -Level "INFO"
    Write-Log "" -Level "INFO"
    Write-Log "=== NEXT STEPS ===" -Level "INFO"
    Write-Log "1. Review the exported CSV file for accuracy" -Level "INFO"
    Write-Log "2. Replace all 'Placeholder_Replace_Me' values with actual values:" -Level "INFO"
    Write-Log "   - ConditionalAccessPolicy: Set appropriate CA policy names, if needed" -Level "INFO"
    Write-Log "   - EntraGroup: Set appropriate Entra ID group names" -Level "INFO"
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
