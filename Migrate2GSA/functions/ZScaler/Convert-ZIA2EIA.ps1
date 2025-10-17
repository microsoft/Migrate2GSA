function Convert-ZIA2EIA {
    <#
    .SYNOPSIS
        Converts ZScaler Internet Access (ZIA) URL filtering configuration to Microsoft Entra Internet Access (EIA) format.
    
    .DESCRIPTION
        This function processes ZIA URL filtering policies, custom URL categories, and predefined category mappings
        to generate CSV files ready for import into Microsoft Entra Internet Access (EIA).
        
        The conversion process includes:
        - Transforming ZIA URL filtering rules to EIA security profiles
        - Converting ZIA URL categories (custom and predefined) to EIA web content filtering policies
        - Mapping ZIA predefined categories to GSA (Global Secure Access) web categories
        - Generating import-ready CSV files for EIA configuration
    
    .PARAMETER UrlFilteringPolicyPath
        Path to the ZIA URL Filtering Policy JSON export file.
        Default: url_filtering_policy.json in current directory
    
    .PARAMETER UrlCategoriesPath
        Path to the ZIA URL Categories JSON export file.
        Default: url_categories.json in current directory
    
    .PARAMETER CategoryMappingsPath
        Path to the ZIA to EIA category mappings JSON file.
        Default: ZIA2EIA-CategoryMappings.json in current directory
    
    .PARAMETER OutputBasePath
        Base directory for output CSV files and log file.
        Default: Current directory
    
    .PARAMETER EnableDebugLogging
        Enable verbose debug logging for detailed processing information.
    
    .EXAMPLE
        Convert-ZIA2EIA
        
        Converts ZIA configuration using default file paths in the current directory.
    
    .EXAMPLE
        Convert-ZIA2EIA -UrlFilteringPolicyPath "C:\ZIA\url_filtering_policy.json" -OutputBasePath "C:\Output"
        
        Converts ZIA configuration from specified path and saves output to C:\Output.
    
    .EXAMPLE
        Convert-ZIA2EIA -EnableDebugLogging
        
        Converts ZIA configuration with detailed debug logging enabled.
    
    .NOTES
        Author: Andres Canello
        Version: 1.0
        Date: 2025-10-13
        
        Requirements:
        - ZIA URL filtering policy JSON export
        - ZIA URL categories JSON export
        - ZIA to EIA category mappings JSON file
        
        Known Limitations:
        - 300-character limit per Destinations field (except webCategory type)
        - IPv6 addresses not supported
        - CIDR ranges not supported for IP addresses
        - Port numbers not supported
    #>
    
    [CmdletBinding(SupportsShouldProcess = $false)]
    param(
        [Parameter(HelpMessage = "Path to ZIA URL Filtering Policy JSON export")]
        [ValidateScript({
            if (Test-Path $_) { return $true }
            else { throw "File not found: $_" }
        })]
        [string]$UrlFilteringPolicyPath = (Join-Path $PWD "url_filtering_policy.json"),
        
        [Parameter(HelpMessage = "Path to ZIA URL Categories JSON export")]
        [ValidateScript({
            if (Test-Path $_) { return $true }
            else { throw "File not found: $_" }
        })]
        [string]$UrlCategoriesPath = (Join-Path $PWD "url_categories.json"),
        
        [Parameter(HelpMessage = "Path to ZIA to EIA category mappings JSON file")]
        [ValidateScript({
            if (Test-Path $_) { return $true }
            else { throw "File not found: $_" }
        })]
        [string]$CategoryMappingsPath = (Join-Path $PWD "ZIA2EIA-CategoryMappings.json"),
        
        [Parameter(HelpMessage = "Base directory for output files")]
        [ValidateScript({
            if (Test-Path $_ -PathType Container) { return $true }
            else { throw "Directory not found: $_" }
        })]
        [string]$OutputBasePath = $PWD,
        
        [Parameter(HelpMessage = "Enable verbose debug logging")]
        [switch]$EnableDebugLogging
    )
    
    Set-StrictMode -Version Latest
    
    #region Helper Functions
    
    function Get-DestinationType {
        <#
        .SYNOPSIS
            Classify destination entry as URL, FQDN, IPv4, or IPv6 address.
        #>
        param([string]$Destination)
        
        # Empty check
        if ([string]::IsNullOrWhiteSpace($Destination)) { return $null }
        
        # IPv4 check (basic pattern matching)
        if ($Destination -match '^(\d{1,3}\.){3}\d{1,3}$') { return 'ipv4' }
        
        # Path check - URLs contain forward slash (check before IPv6 to avoid false positives)
        if ($Destination -like '*/*') { return 'URL' }
        
        # IPv6 detection (hex characters with colons, but no forward slashes)
        # Must have multiple colons and contain hex characters (0-9, a-f, A-F)
        if ($Destination -match '^[0-9a-fA-F:]+$' -and $Destination -match ':.*:') { return 'ipv6' }
        
        # Wildcard position check
        if ($Destination -like '*`**') {
            if ($Destination.StartsWith('*.')) { return 'FQDN' }
            else { return 'URL' }  # Wildcard elsewhere makes it URL pattern
        }
        
        # Default to FQDN
        return 'FQDN'
    }
    
    function Get-BaseDomain {
        <#
        .SYNOPSIS
            Extract base domain (last 2 segments) for grouping.
        #>
        param([string]$Domain)
        
        # Remove leading wildcards (both ZScaler .domain and standard *.domain formats)
        $cleanDomain = $Domain -replace '^\*\.', '' -replace '^\.', ''
        
        # Extract path-free domain for URLs
        if ($cleanDomain -like '*/*') {
            $cleanDomain = $cleanDomain.Split('/')[0]
        }
        
        # Get last 2 segments
        $segments = $cleanDomain.Split('.')
        if ($segments.Count -ge 2) {
            return "$($segments[-2]).$($segments[-1])"
        }
        
        return $cleanDomain
    }
    
    function Test-ValidIPv4Address {
        <#
        .SYNOPSIS
            Validate IPv4 address format.
        #>
        param([string]$IpAddress)
        
        # Must match IPv4 pattern
        if ($IpAddress -notmatch '^(\d{1,3}\.){3}\d{1,3}$') { return $false }
        
        # Validate each octet is 0-255
        $octets = $IpAddress.Split('.')
        foreach ($octet in $octets) {
            $num = [int]$octet
            if ($num -lt 0 -or $num -gt 255) { return $false }
        }
        
        return $true
    }
    
    function Split-UserEmail {
        <#
        .SYNOPSIS
            Extract email from "Display Name (email@domain.com)" format.
            Handles multiple parentheses by looking for email pattern or using last parentheses group.
        #>
        param([string]$UserName)
        
        # First, try to find email pattern within parentheses (most reliable)
        # Match email pattern: something@something.something
        if ($UserName -match '\(([^)]*@[^)]+\.[^)]+)\)') {
            return $Matches[1]
        }
        
        # Fallback: Extract content from the last set of parentheses
        # This handles cases where there are multiple parentheses groups
        if ($UserName -match '\(([^)]+)\)[^(]*$') {
            return $Matches[1]
        }
        
        Write-LogMessage "Could not parse email from: $UserName" -Level "WARN" `
            -Component "Convert-ZIA2EIA" -LogPath $script:logPath -EnableDebugLogging $script:EnableDebugLogging
        return $null
    }
    
    function Split-ByCharacterLimit {
        <#
        .SYNOPSIS
            Split destination arrays by character limit without truncating entries.
        #>
        param(
            [array]$Entries,
            [int]$MaxLength = 300
        )
        
        Write-LogMessage "Split-ByCharacterLimit: Received $($Entries.Count) entries, MaxLength=$MaxLength" -Level "DEBUG" `
            -Component "Split-ByCharacterLimit" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
        
        $groups = @()
        $currentGroup = @()
        $currentLength = 0
        
        foreach ($entry in $Entries) {
            $entryLength = $entry.Length
            $separator = if ($currentGroup.Count -gt 0) { 1 } else { 0 }  # semicolon
            
            Write-LogMessage "Entry: '$entry' (length=$entryLength), currentLength=$currentLength, separator=$separator, would be=$($currentLength + $entryLength + $separator)" -Level "DEBUG" `
                -Component "Split-ByCharacterLimit" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
            
            if (($currentLength + $entryLength + $separator) -gt $MaxLength -and $currentGroup.Count -gt 0) {
                # Current group is full, start new group
                Write-LogMessage "Starting new group (current group has $($currentGroup.Count) entries, length=$currentLength)" -Level "DEBUG" `
                    -Component "Split-ByCharacterLimit" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
                $groups += ,@($currentGroup)
                $currentGroup = @($entry)
                $currentLength = $entryLength
            }
            else {
                $currentGroup += $entry
                $currentLength += $entryLength + $separator
            }
        }
        
        # Add remaining group
        if ($currentGroup.Count -gt 0) {
            $groups += ,@($currentGroup)
        }
        
        Write-LogMessage "Split-ByCharacterLimit: Created $($groups.Count) group(s)" -Level "DEBUG" `
            -Component "Split-ByCharacterLimit" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
        
        # Return with comma operator to prevent PowerShell from flattening the array
        return ,$groups
    }
    
    function Get-CustomCategoryPolicyName {
        <#
        .SYNOPSIS
            Look up custom category policy name based on category ID and action.
        #>
        param(
            [string]$CategoryId,
            [string]$Action,
            [hashtable]$CustomCategoryPoliciesHashtable
        )
        
        # Get base policy info from hashtable (created in Phase 2)
        $basePolicyInfo = $CustomCategoryPoliciesHashtable[$CategoryId]
        
        if ($null -eq $basePolicyInfo) {
            Write-LogMessage "Custom category not found: $CategoryId" -Level "WARN" `
                -Component "Convert-ZIA2EIA" -LogPath $script:logPath -EnableDebugLogging $script:EnableDebugLogging
            return $null
        }
        
        # If action is BLOCK or CAUTION, use the base policy (created with -Block suffix in Phase 2)
        if ($Action -eq "BLOCK" -or $Action -eq "CAUTION") {
            return $basePolicyInfo.BlockPolicyName
        }
        
        # If action is ALLOW, check if Allow version exists, if not return null (will be created)
        if ($Action -eq "ALLOW") {
            if ($null -ne $basePolicyInfo.AllowPolicyName) {
                return $basePolicyInfo.AllowPolicyName
            }
            return $null  # Signal that Allow policy needs to be created
        }
        
        # Default to Block policy for unknown actions
        return $basePolicyInfo.BlockPolicyName
    }
    
    function ConvertTo-CleanDestination {
        <#
        .SYNOPSIS
            Clean and normalize destination entries by removing unsupported components.
            Also converts ZScaler wildcard format (.domain) to EIA format (*.domain).
        #>
        param(
            [string]$Destination,
            [string]$LogPath,
            [bool]$EnableDebugLogging
        )
        
        if ([string]::IsNullOrWhiteSpace($Destination)) { return $null }
        
        $cleaned = $Destination.Trim()
        
        # Convert ZScaler leading dot wildcard (.domain) to EIA wildcard format (*.domain)
        if ($cleaned -match '^\.([a-zA-Z0-9][^/]*)'  -and $cleaned -notmatch '^\.\.') {
            Write-LogMessage "Converting ZScaler wildcard from '$cleaned' to '*.$($Matches[1])'" -Level "DEBUG" `
                -Component "ConvertTo-CleanDestination" -LogPath $LogPath -EnableDebugLogging:$EnableDebugLogging
            $cleaned = "*.$($Matches[1])"
        }
        
        # Remove schema (http:// or https://)
        if ($cleaned -match '^https?://') {
            Write-LogMessage "Removing schema from: $Destination" -Level "DEBUG" `
                -Component "ConvertTo-CleanDestination" -LogPath $LogPath -EnableDebugLogging:$EnableDebugLogging
            $cleaned = $cleaned -replace '^https?://', ''
        }
        
        # Check for IPv4 with port/path (should be skipped)
        if ($cleaned -match '^(\d{1,3}\.){3}\d{1,3}[:/]') {
            Write-LogMessage "Skipping IPv4 with port/path: $Destination" -Level "DEBUG" `
                -Component "ConvertTo-CleanDestination" -LogPath $LogPath -EnableDebugLogging:$EnableDebugLogging
            return $null
        }
        
        # Remove port (for non-IP entries)
        # Only match port at the end of the string to avoid matching IPv6 colons
        if ($cleaned -match ':\d+$' -and $cleaned -notmatch '^(\d{1,3}\.){3}\d{1,3}(:\d+)?$') {
            Write-LogMessage "Removing port from: $Destination" -Level "DEBUG" `
                -Component "ConvertTo-CleanDestination" -LogPath $LogPath -EnableDebugLogging:$EnableDebugLogging
            $cleaned = $cleaned -replace ':\d+$', ''
        }
        
        # Remove query string
        if ($cleaned.Contains('?')) {
            Write-LogMessage "Removing query string from: $Destination" -Level "DEBUG" `
                -Component "ConvertTo-CleanDestination" -LogPath $LogPath -EnableDebugLogging:$EnableDebugLogging
            $cleaned = $cleaned.Split('?')[0]
        }
        
        # Remove fragment
        if ($cleaned.Contains('#')) {
            Write-LogMessage "Removing fragment from: $Destination" -Level "DEBUG" `
                -Component "ConvertTo-CleanDestination" -LogPath $LogPath -EnableDebugLogging:$EnableDebugLogging
            $cleaned = $cleaned.Split('#')[0]
        }
        
        # Return null if cleaning resulted in empty string
        if ([string]::IsNullOrWhiteSpace($cleaned)) {
            Write-LogMessage "Destination became empty after cleaning: $Destination" -Level "DEBUG" `
                -Component "ConvertTo-CleanDestination" -LogPath $LogPath -EnableDebugLogging:$EnableDebugLogging
            return $null
        }
        
        return $cleaned
    }
    
    #endregion
    
    #region Initialization
    
    # Initialize logging
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $script:logPath = Join-Path $OutputBasePath "${timestamp}_Convert-ZIA2EIA.log"
    $script:EnableDebugLogging = $EnableDebugLogging
    
    Write-LogMessage "Starting ZIA to EIA conversion" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    
    Write-LogMessage "Input files:" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  URL Filtering Policy: $UrlFilteringPolicyPath" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  URL Categories: $UrlCategoriesPath" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  Category Mappings: $CategoryMappingsPath" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  Output Path: $OutputBasePath" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    
    # Initialize statistics
    $stats = @{
        TotalRulesLoaded = 0
        RulesProcessed = 0
        RulesSkippedDisabled = 0
        CustomCategoriesProcessed = 0
        CustomCategoriesSkipped = 0
        PredefinedCategoriesReferenced = 0
        UnmappedCategories = 0
        URLsClassified = 0
        FQDNsClassified = 0
        IPsClassified = 0
        EntriesSkipped = 0
        UsersProcessed = 0
        UsersSkippedDeleted = 0
        GroupsProcessed = 0
        PoliciesCreated = 0
        SecurityProfilesCreated = 0
        GroupsSplitForCharLimit = 0
        PriorityConflictsResolved = 0
        TotalFQDNsInPolicies = 0
        TotalURLsInPolicies = 0
        TotalRulesInPolicies = 0
    }
    
    # Collections for output
    $policies = [System.Collections.ArrayList]::new()
    $securityProfiles = [System.Collections.ArrayList]::new()
    
    #endregion
    
    #region Phase 1: Data Loading
    
    Write-LogMessage "Phase 1: Loading input files..." -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    
    # Load URL Filtering Policy
    try {
        Write-LogMessage "Loading URL filtering policy from: $UrlFilteringPolicyPath" -Level "INFO" `
            -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        $urlFilteringPolicy = Get-Content -Path $UrlFilteringPolicyPath -Raw | ConvertFrom-Json
        $stats.TotalRulesLoaded = $urlFilteringPolicy.Count
        Write-LogMessage "Loaded $($stats.TotalRulesLoaded) URL filtering rules" -Level "INFO" `
            -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }
    catch {
        Write-LogMessage "Failed to load URL filtering policy: $_" -Level "ERROR" `
            -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        throw "Failed to load URL filtering policy file: $UrlFilteringPolicyPath"
    }
    
    # Load URL Categories
    try {
        Write-LogMessage "Loading URL categories from: $UrlCategoriesPath" -Level "INFO" `
            -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        $urlCategories = Get-Content -Path $UrlCategoriesPath -Raw | ConvertFrom-Json
        Write-LogMessage "Loaded $($urlCategories.Count) URL categories" -Level "INFO" `
            -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }
    catch {
        Write-LogMessage "Failed to load URL categories: $_" -Level "ERROR" `
            -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        throw "Failed to load URL categories file: $UrlCategoriesPath"
    }
    
    # Load Category Mappings
    try {
        Write-LogMessage "Loading category mappings from: $CategoryMappingsPath" -Level "INFO" `
            -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        $categoryMappings = Get-Content -Path $CategoryMappingsPath -Raw | ConvertFrom-Json
        Write-LogMessage "Loaded $($categoryMappings.MappingData.Count) category mappings" -Level "INFO" `
            -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }
    catch {
        Write-LogMessage "Failed to load category mappings: $_" -Level "ERROR" `
            -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        throw "Failed to load category mappings file: $CategoryMappingsPath"
    }
    
    # Build lookup tables
    Write-LogMessage "Building lookup tables..." -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    
    # Category mappings for predefined categories
    $categoryMappingsHashtable = @{}
    foreach ($mapping in $categoryMappings.MappingData) {
        # Skip mappings with null or empty ZIACategory
        if ([string]::IsNullOrWhiteSpace($mapping.ZIACategory)) {
            $gsaCategory = if ($mapping.PSObject.Properties['GSACategory']) { $mapping.GSACategory } else { "N/A" }
            $description = if ($mapping.PSObject.Properties['Description']) { $mapping.Description } else { "N/A" }
            Write-LogMessage "Skipping mapping with null or empty ZIACategory - GSACategory: '$gsaCategory', Description: '$description'" -Level "WARN" `
                -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            continue
        }
        $categoryMappingsHashtable[$mapping.ZIACategory] = $mapping
    }
    
    # Custom categories for quick lookup
    $customCategoriesHashtable = @{}
    foreach ($category in $urlCategories | Where-Object { $_.customCategory -eq $true }) {
        $customCategoriesHashtable[$category.id] = $category
    }
    Write-LogMessage "Found $($customCategoriesHashtable.Count) custom categories" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    
    # Custom category policies tracking (populated in Phase 2)
    $customCategoryPoliciesHashtable = @{}
    
    # Track skipped custom categories with reasons
    $skippedCustomCategories = @{}
    
    #endregion
    
    #region Phase 2: Custom Category Processing
    
    Write-LogMessage "Phase 2: Processing custom categories..." -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    
    foreach ($category in $urlCategories) {
        # Filter non-URL categories
        if ($category.type -ne "URL_CATEGORY") {
            Write-LogMessage "Skipping non-URL category type: $($category.type) for category $($category.id)" -Level "WARN" `
                -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            continue
        }
        
        # Skip predefined categories (handled in Phase 3)
        if ($category.customCategory -ne $true) {
            continue
        }
        
        Write-LogMessage "Processing custom category: $($category.id)" -Level "DEBUG" `
            -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        
        # Combine and deduplicate URLs
        $allUrls = @()
        if ($category.urls) { $allUrls += $category.urls }
        if ($category.dbCategorizedUrls) { $allUrls += $category.dbCategorizedUrls }
        
        # Skip empty categories
        if ($allUrls.Count -eq 0) {
            Write-LogMessage "Skipping empty custom category: $($category.id)" -Level "WARN" `
                -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            $skippedCustomCategories[$category.id] = "Empty category (no URLs)"
            $stats.CustomCategoriesSkipped++
            continue
        }
        
        # Deduplicate (case-insensitive)
        $uniqueUrls = @($allUrls | Group-Object -Property { $_.ToLower() } | ForEach-Object { $_.Group[0] })
        $duplicateCount = $allUrls.Count - $uniqueUrls.Count
        if ($duplicateCount -gt 0) {
            Write-LogMessage "Removed $duplicateCount duplicate entries from category $($category.id)" -Level "DEBUG" `
                -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        }
        
        # Clean destinations
        $cleanedDestinations = @()
        foreach ($url in $uniqueUrls) {
            $cleaned = ConvertTo-CleanDestination -Destination $url -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            if ($null -ne $cleaned) {
                $cleanedDestinations += $cleaned
            }
            else {
                $stats.EntriesSkipped++
            }
        }
        
        # Deduplicate again after cleaning (wildcard conversion may create duplicates)
        $preDedupeCount = $cleanedDestinations.Count
        $cleanedDestinations = @($cleanedDestinations | Group-Object -Property { $_.ToLower() } | ForEach-Object { $_.Group[0] })
        $postCleanDuplicates = $preDedupeCount - $cleanedDestinations.Count
        if ($postCleanDuplicates -gt 0) {
            Write-LogMessage "Removed $postCleanDuplicates duplicate entries after cleaning for category $($category.id)" -Level "DEBUG" `
                -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        }
        
        if ($cleanedDestinations.Count -eq 0) {
            Write-LogMessage "No valid destinations after cleaning for category: $($category.id) (had $($uniqueUrls.Count) entries before cleaning)" -Level "WARN" `
                -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            $skippedCustomCategories[$category.id] = "No valid destinations after cleaning ($($uniqueUrls.Count) entries were invalid)"
            $stats.CustomCategoriesSkipped++
            continue
        }
        
        # Classify destinations
        $classifiedDestinations = @{
            'FQDN' = [System.Collections.ArrayList]::new()
            'URL' = [System.Collections.ArrayList]::new()
            'ipAddress' = [System.Collections.ArrayList]::new()
        }
        
        foreach ($dest in $cleanedDestinations) {
            $type = Get-DestinationType -Destination $dest
            
            switch ($type) {
                'ipv4' {
                    if (Test-ValidIPv4Address -IpAddress $dest) {
                        [void]$classifiedDestinations['ipAddress'].Add($dest)
                        $stats.IPsClassified++
                    }
                    else {
                        Write-LogMessage "Invalid IPv4 address: $dest" -Level "WARN" `
                            -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                        $stats.EntriesSkipped++
                    }
                }
                'ipv6' {
                    Write-LogMessage "Skipping IPv6 address (not supported): $dest" -Level "WARN" `
                        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                    $stats.EntriesSkipped++
                }
                'URL' {
                    [void]$classifiedDestinations['URL'].Add($dest)
                    $stats.URLsClassified++
                }
                'FQDN' {
                    [void]$classifiedDestinations['FQDN'].Add($dest)
                    $stats.FQDNsClassified++
                }
            }
        }
        
        # Determine policy name
        $basePolicyName = if ($category.configuredName) { $category.configuredName } else { $category.id }
        $policyName = "$basePolicyName-Block"
        
        # Process FQDNs grouped by base domain
        if ($classifiedDestinations['FQDN'].Count -gt 0) {
            # Group FQDNs by base domain
            $fqdnsByBaseDomain = @{}
            foreach ($fqdn in $classifiedDestinations['FQDN']) {
                $baseDomain = Get-BaseDomain -Domain $fqdn
                if (-not $fqdnsByBaseDomain.ContainsKey($baseDomain)) {
                    $fqdnsByBaseDomain[$baseDomain] = [System.Collections.ArrayList]::new()
                }
                [void]$fqdnsByBaseDomain[$baseDomain].Add($fqdn)
            }
            
            # Create policy entries for each base domain group
            foreach ($baseDomain in $fqdnsByBaseDomain.Keys) {
                Write-LogMessage "Processing base domain '$baseDomain' with $($fqdnsByBaseDomain[$baseDomain].Count) FQDNs" -Level "DEBUG" `
                    -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                
                $groups = Split-ByCharacterLimit -Entries @($fqdnsByBaseDomain[$baseDomain]) -MaxLength 300
                
                Write-LogMessage "Split into $($groups.Count) group(s) for base domain '$baseDomain'" -Level "DEBUG" `
                    -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                
                if ($groups.Count -gt 1) { $stats.GroupsSplitForCharLimit++ }
                
                for ($i = 0; $i -lt $groups.Count; $i++) {
                    $ruleName = if ($i -eq 0) { $baseDomain } else { "$baseDomain-$($i + 1)" }
                    
                    $policyEntry = [PSCustomObject]@{
                        PolicyName = $policyName
                        PolicyType = "WebContentFiltering"
                        PolicyAction = "Block"
                        Description = if ($category.PSObject.Properties['description']) { $category.description } else { "" }
                        RuleType = "FQDN"
                        RuleDestinations = $groups[$i] -join ";"
                        RuleName = $ruleName
                        ReviewNeeded = "No"
                        ReviewDetails = ""
                        Provision = "Yes"
                    }
                    
                    [void]$policies.Add($policyEntry)
                    $stats.TotalRulesInPolicies++
                    $stats.TotalFQDNsInPolicies += $groups[$i].Count
                }
            }
        }
        
        # Process URLs grouped by base domain
        if ($classifiedDestinations['URL'].Count -gt 0) {
            # Group URLs by base domain
            $urlsByBaseDomain = @{}
            foreach ($url in $classifiedDestinations['URL']) {
                $baseDomain = Get-BaseDomain -Domain $url
                if (-not $urlsByBaseDomain.ContainsKey($baseDomain)) {
                    $urlsByBaseDomain[$baseDomain] = [System.Collections.ArrayList]::new()
                }
                [void]$urlsByBaseDomain[$baseDomain].Add($url)
            }
            
            # Create policy entries for each base domain group
            foreach ($baseDomain in $urlsByBaseDomain.Keys) {
                $groups = Split-ByCharacterLimit -Entries @($urlsByBaseDomain[$baseDomain]) -MaxLength 300
                
                if ($groups.Count -gt 1) { $stats.GroupsSplitForCharLimit++ }
                
                for ($i = 0; $i -lt $groups.Count; $i++) {
                    $ruleName = if ($i -eq 0) { $baseDomain } else { "$baseDomain-$($i + 1)" }
                    
                    $policyEntry = [PSCustomObject]@{
                        PolicyName = $policyName
                        PolicyType = "WebContentFiltering"
                        PolicyAction = "Block"
                        Description = if ($category.PSObject.Properties['description']) { $category.description } else { "" }
                        RuleType = "URL"
                        RuleDestinations = $groups[$i] -join ";"
                        RuleName = $ruleName
                        ReviewNeeded = "No"
                        ReviewDetails = ""
                        Provision = "Yes"
                    }
                    
                    [void]$policies.Add($policyEntry)
                    $stats.TotalRulesInPolicies++
                    $stats.TotalURLsInPolicies += $groups[$i].Count
                }
            }
        }
        
        # Process IP addresses (not grouped by domain)
        if ($classifiedDestinations['ipAddress'].Count -gt 0) {
            $groups = Split-ByCharacterLimit -Entries @($classifiedDestinations['ipAddress']) -MaxLength 300
            
            if ($groups.Count -gt 1) { $stats.GroupsSplitForCharLimit++ }
            
            for ($i = 0; $i -lt $groups.Count; $i++) {
                $ruleName = if ($i -eq 0) { "IPs" } else { "IPs-$($i + 1)" }
                
                $policyEntry = [PSCustomObject]@{
                    PolicyName = $policyName
                    PolicyType = "WebContentFiltering"
                    PolicyAction = "Block"
                    Description = if ($category.PSObject.Properties['description']) { $category.description } else { "" }
                    RuleType = "ipAddress"
                    RuleDestinations = $groups[$i] -join ";"
                    RuleName = $ruleName
                    ReviewNeeded = "No"
                    ReviewDetails = ""
                    Provision = "Yes"
                }
                
                [void]$policies.Add($policyEntry)
                $stats.TotalRulesInPolicies++
            }
        }
        
        # Track this custom category policy for Phase 3 lookup
        $customCategoryPoliciesHashtable[$category.id] = @{
            BlockPolicyName = $policyName
            AllowPolicyName = $null
            CautionPolicyName = $null
            BaseName = $basePolicyName
        }
        
        $stats.CustomCategoriesProcessed++
    }
    
    Write-LogMessage "Custom categories processed: $($stats.CustomCategoriesProcessed), skipped: $($stats.CustomCategoriesSkipped)" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    
    #endregion
    
    #region Phase 3: URL Filtering Rule Processing
    
    Write-LogMessage "Phase 3: Processing URL filtering rules..." -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    
    foreach ($rule in $urlFilteringPolicy) {
        # Skip disabled rules
        if ($rule.state -ne "ENABLED") {
            Write-LogMessage "Skipping disabled rule: $($rule.name)" -Level "DEBUG" `
                -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            $stats.RulesSkippedDisabled++
            continue
        }
        
        Write-LogMessage "Processing rule: $($rule.name)" -Level "DEBUG" `
            -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        
        # Extract users
        $validUsers = [System.Collections.ArrayList]::new()
        if ($rule.PSObject.Properties['users'] -and $rule.users) {
            foreach ($user in $rule.users) {
                $isDeleted = if ($user.PSObject.Properties['deleted']) { $user.deleted } else { $false }
                if ($isDeleted -eq $true) {
                    Write-LogMessage "Skipping deleted user: $($user.name)" -Level "DEBUG" `
                        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                    $stats.UsersSkippedDeleted++
                    continue
                }
                
                $email = Split-UserEmail -UserName $user.name
                if ($null -ne $email) {
                    [void]$validUsers.Add($email)
                    $stats.UsersProcessed++
                }
            }
        }
        
        # Extract groups
        $groups = [System.Collections.ArrayList]::new()
        if ($rule.PSObject.Properties['groups'] -and $rule.groups) {
            foreach ($group in $rule.groups) {
                [void]$groups.Add($group.name)
                $stats.GroupsProcessed++
            }
        }
        
        # Default assignment if no users and no groups
        if ($validUsers.Count -eq 0 -and $groups.Count -eq 0) {
            [void]$groups.Add("Replace_with_All_IA_Users_Group")
        }
        
        # Separate custom from predefined categories
        $customCategoryRefs = [System.Collections.ArrayList]::new()
        $predefinedCategoryRefs = [System.Collections.ArrayList]::new()
        
        if ($rule.urlCategories) {
            foreach ($categoryId in $rule.urlCategories) {
                if ($customCategoriesHashtable.ContainsKey($categoryId)) {
                    [void]$customCategoryRefs.Add($categoryId)
                }
                else {
                    [void]$predefinedCategoryRefs.Add($categoryId)
                }
            }
        }
        
        # Process custom category policy references
        $customCategoryPolicyNames = [System.Collections.ArrayList]::new()
        $needsReview = $false
        $reviewReasons = [System.Collections.ArrayList]::new()
        
        foreach ($customCatId in $customCategoryRefs) {
            $policyInfo = $customCategoryPoliciesHashtable[$customCatId]
            
            if ($null -eq $policyInfo) {
                if ($skippedCustomCategories.ContainsKey($customCatId)) {
                    Write-LogMessage "Custom category policy not found: $customCatId (Reason: $($skippedCustomCategories[$customCatId]))" -Level "WARN" `
                        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                }
                else {
                    Write-LogMessage "Custom category policy not found: $customCatId (Category not found in URL categories file)" -Level "WARN" `
                        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                }
                continue
            }
            
            # Determine which policy to use based on action
            if ($rule.action -eq "BLOCK") {
                [void]$customCategoryPolicyNames.Add($policyInfo.BlockPolicyName)
            }
            elseif ($rule.action -eq "CAUTION") {
                Write-LogMessage "Rule '$($rule.name)': CAUTION action preserved for category $customCatId - review required" -Level "WARN" `
                    -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                
                # Check if Caution version exists
                if ($null -eq $policyInfo.CautionPolicyName) {
                    # Need to create Caution version by duplicating Block policies
                    $cautionPolicyName = "$($policyInfo.BaseName)-Caution"
                    
                    # Find all policy entries with the Block policy name and duplicate them
                    $blockPolicies = $policies | Where-Object { $_.PolicyName -eq $policyInfo.BlockPolicyName }
                    
                    foreach ($blockPolicy in $blockPolicies) {
                        $cautionPolicy = [PSCustomObject]@{
                            PolicyName = $cautionPolicyName
                            PolicyType = $blockPolicy.PolicyType
                            PolicyAction = "Caution"
                            Description = $blockPolicy.Description
                            RuleType = $blockPolicy.RuleType
                            RuleDestinations = $blockPolicy.RuleDestinations
                            RuleName = $blockPolicy.RuleName
                            ReviewNeeded = "Yes"
                            ReviewDetails = "Rule action CAUTION requires review"
                            Provision = "No"
                        }
                        
                        [void]$policies.Add($cautionPolicy)
                        $stats.TotalRulesInPolicies++
                        
                        # Count FQDNs and URLs for caution policies
                        if ($cautionPolicy.RuleType -eq 'FQDN') {
                            $fqdnCount = ($cautionPolicy.RuleDestinations -split ';').Count
                            $stats.TotalFQDNsInPolicies += $fqdnCount
                        }
                        elseif ($cautionPolicy.RuleType -eq 'URL') {
                            $urlCount = ($cautionPolicy.RuleDestinations -split ';').Count
                            $stats.TotalURLsInPolicies += $urlCount
                        }
                    }
                    
                    # Update tracking hashtable
                    $policyInfo.CautionPolicyName = $cautionPolicyName
                    
                    Write-LogMessage "Created Caution version of policy: $cautionPolicyName" -Level "DEBUG" `
                        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                }
                
                [void]$customCategoryPolicyNames.Add($policyInfo.CautionPolicyName)
                
                if ("Rule action CAUTION requires review" -notin $reviewReasons) {
                    [void]$reviewReasons.Add("Rule action CAUTION requires review")
                }
                $needsReview = $true
            }
            elseif ($rule.action -eq "ALLOW") {
                # Check if Allow version exists
                if ($null -eq $policyInfo.AllowPolicyName) {
                    # Need to create Allow version by duplicating Block policies
                    $allowPolicyName = "$($policyInfo.BaseName)-Allow"
                    
                    # Find all policy entries with the Block policy name and duplicate them
                    $blockPolicies = $policies | Where-Object { $_.PolicyName -eq $policyInfo.BlockPolicyName }
                    
                    foreach ($blockPolicy in $blockPolicies) {
                        $allowPolicy = [PSCustomObject]@{
                            PolicyName = $allowPolicyName
                            PolicyType = $blockPolicy.PolicyType
                            PolicyAction = "Allow"
                            Description = $blockPolicy.Description
                            RuleType = $blockPolicy.RuleType
                            RuleDestinations = $blockPolicy.RuleDestinations
                            RuleName = $blockPolicy.RuleName
                            ReviewNeeded = $blockPolicy.ReviewNeeded
                            ReviewDetails = $blockPolicy.ReviewDetails
                            Provision = if ($blockPolicy.ReviewNeeded -eq "Yes") { "No" } else { "Yes" }
                        }
                        
                        [void]$policies.Add($allowPolicy)
                        $stats.TotalRulesInPolicies++
                        
                        # Count FQDNs and URLs for allow policies
                        if ($allowPolicy.RuleType -eq 'FQDN') {
                            $fqdnCount = ($allowPolicy.RuleDestinations -split ';').Count
                            $stats.TotalFQDNsInPolicies += $fqdnCount
                        }
                        elseif ($allowPolicy.RuleType -eq 'URL') {
                            $urlCount = ($allowPolicy.RuleDestinations -split ';').Count
                            $stats.TotalURLsInPolicies += $urlCount
                        }
                    }
                    
                    # Update tracking hashtable
                    $policyInfo.AllowPolicyName = $allowPolicyName
                    
                    Write-LogMessage "Created Allow version of policy: $allowPolicyName" -Level "DEBUG" `
                        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                }
                
                [void]$customCategoryPolicyNames.Add($policyInfo.AllowPolicyName)
            }
        }
        
        # Update custom category policies with review information if needed
        if ($needsReview -and $customCategoryPolicyNames.Count -gt 0 -and $reviewReasons.Count -gt 0) {
            foreach ($policyName in $customCategoryPolicyNames) {
                # Find all policy entries with this policy name and update them
                for ($i = 0; $i -lt $policies.Count; $i++) {
                    if ($policies[$i].PolicyName -eq $policyName) {
                        $policies[$i].ReviewNeeded = "Yes"
                        
                        # Merge review reasons (avoid duplicates)
                        $existingReasons = if ($policies[$i].ReviewDetails) { 
                            $policies[$i].ReviewDetails -split "; " 
                        } else { 
                            @() 
                        }
                        
                        foreach ($reason in $reviewReasons) {
                            if ($reason -notin $existingReasons) {
                                $existingReasons += $reason
                            }
                        }
                        
                        $policies[$i].ReviewDetails = $existingReasons -join "; "
                        $policies[$i].Provision = "No"
                    }
                }
            }
        }
        
        # Process predefined categories
        $predefinedPolicyName = $null
        
        if ($predefinedCategoryRefs.Count -gt 0) {
            $mappedCategories = [System.Collections.ArrayList]::new()
            $hasUnmapped = $false
            
            foreach ($categoryId in $predefinedCategoryRefs) {
                $mapping = $categoryMappingsHashtable[$categoryId]
                
                if ($null -eq $mapping -or 
                    [string]::IsNullOrWhiteSpace($mapping.GSACategory) -or
                    $mapping.GSACategory -eq 'Unmapped') {
                    
                    [void]$mappedCategories.Add("${categoryId}_Unmapped")
                    $hasUnmapped = $true
                    $stats.UnmappedCategories++
                    Write-LogMessage "Unmapped category: $categoryId" -Level "DEBUG" `
                        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                }
                else {
                    [void]$mappedCategories.Add($mapping.GSACategory)
                }
            }
            
            $stats.PredefinedCategoriesReferenced += $predefinedCategoryRefs.Count
            
            # Handle CAUTION action
            $finalAction = $rule.action
            if ($rule.action -eq "CAUTION") {
                Write-LogMessage "Rule '$($rule.name)': CAUTION action preserved for predefined categories - review required" -Level "WARN" `
                    -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                if ("Rule action CAUTION requires review" -notin $reviewReasons) {
                    [void]$reviewReasons.Add("Rule action CAUTION requires review")
                }
                $needsReview = $true
            }
            
            # Build review reasons
            $policyReviewReasons = [System.Collections.ArrayList]::new()
            if ($hasUnmapped) {
                [void]$policyReviewReasons.Add("Unmapped categories found")
                $needsReview = $true
            }
            if ($rule.action -eq "CAUTION") {
                [void]$policyReviewReasons.Add("Rule action CAUTION requires review")
            }
            
            $policyEntry = [PSCustomObject]@{
                PolicyName = "$($rule.name)-WebCategories-$($finalAction.Substring(0,1) + $finalAction.Substring(1).ToLower())"
                PolicyType = "WebContentFiltering"
                PolicyAction = if ($finalAction -eq "ALLOW") { "Allow" } elseif ($finalAction -eq "CAUTION") { "Caution" } else { "Block" }
                Description = "Converted from $($rule.name) categories"
                RuleType = "webCategory"
                RuleDestinations = $mappedCategories -join ";"
                RuleName = "WebCategories"
                ReviewNeeded = if ($needsReview) { "Yes" } else { "No" }
                ReviewDetails = $policyReviewReasons -join "; "
                Provision = if ($needsReview) { "No" } else { "Yes" }
            }
            
            [void]$policies.Add($policyEntry)
            $stats.TotalRulesInPolicies++
            $predefinedPolicyName = $policyEntry.PolicyName
        }
        
        # Create security profile
        $policyLinks = [System.Collections.ArrayList]::new()
        
        if ($customCategoryPolicyNames.Count -gt 0) {
            [void]$policyLinks.AddRange($customCategoryPolicyNames)
        }
        
        if ($null -ne $predefinedPolicyName) {
            [void]$policyLinks.Add($predefinedPolicyName)
        }
        
        $securityProfile = [PSCustomObject]@{
            SecurityProfileName = $rule.name
            SecurityProfilePriority = $rule.order * 10
            EntraGroups = $groups -join ";"
            EntraUsers = $validUsers -join ";"
            PolicyLinks = $policyLinks -join ";"
            Description = if ($rule.PSObject.Properties['description']) { $rule.description } else { "" }
            Provision = "Yes"
        }
        
        [void]$securityProfiles.Add($securityProfile)
        $stats.RulesProcessed++
    }
    
    Write-LogMessage "Rules processed: $($stats.RulesProcessed), skipped (disabled): $($stats.RulesSkippedDisabled)" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    
    # Resolve priority conflicts
    Write-LogMessage "Resolving priority conflicts..." -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    
    $priorityTracker = @{}
    
    foreach ($secProfile in $securityProfiles) {
        while ($priorityTracker.ContainsKey($secProfile.SecurityProfilePriority)) {
            Write-LogMessage "Priority conflict at $($secProfile.SecurityProfilePriority), incrementing" -Level "INFO" `
                -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            $secProfile.SecurityProfilePriority++
            $stats.PriorityConflictsResolved++
        }
        
        $priorityTracker[$secProfile.SecurityProfilePriority] = $secProfile.SecurityProfileName
    }
    
    # Cleanup unreferenced policies
    Write-LogMessage "Cleaning up unreferenced policies..." -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    
    $referencedPolicies = @{}
    foreach ($secProfile in $securityProfiles) {
        $policyNames = $secProfile.PolicyLinks -split ';'
        foreach ($policyName in $policyNames) {
            $referencedPolicies[$policyName] = $true
        }
    }
    
    $originalPolicyCount = $policies.Count
    $policies = [System.Collections.ArrayList]@($policies | Where-Object {
        # Keep predefined category policies (they're created per-rule)
        if ($_.RuleType -eq 'webCategory') {
            return $true
        }
        
        # Keep custom category policies that are referenced
        if ($referencedPolicies.ContainsKey($_.PolicyName)) {
            return $true
        }
        
        # Remove unreferenced custom category policy
        return $false
    })
    
    $removedPolicies = $originalPolicyCount - $policies.Count
    if ($removedPolicies -gt 0) {
        Write-LogMessage "Removed $removedPolicies unreferenced policies" -Level "INFO" `
            -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }
    
    $stats.PoliciesCreated = $policies.Count
    $stats.SecurityProfilesCreated = $securityProfiles.Count
    
    #endregion
    
    #region Phase 4: Export and Summary
    
    Write-LogMessage "Phase 4: Exporting results..." -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    
    # Export Policies CSV
    $policiesCsvPath = Join-Path $OutputBasePath "${timestamp}_EIA_Policies.csv"
    # Use UTF8 with BOM for better compatibility with Excel and other applications
    $policies | Export-Csv -Path $policiesCsvPath -NoTypeInformation -Encoding utf8BOM
    Write-LogMessage "Exported $($policies.Count) policies to: $policiesCsvPath" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    
    # Export Security Profiles CSV
    $spCsvPath = Join-Path $OutputBasePath "${timestamp}_EIA_SecurityProfiles.csv"
    # Use UTF8 with BOM for better compatibility with Excel and other applications
    $securityProfiles | Export-Csv -Path $spCsvPath -NoTypeInformation -Encoding utf8BOM
    Write-LogMessage "Exported $($securityProfiles.Count) security profiles to: $spCsvPath" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    
    # Generate summary
    Write-LogMessage "" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "=== CONVERSION SUMMARY ===" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Total rules loaded: $($stats.TotalRulesLoaded)" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Rules processed (enabled): $($stats.RulesProcessed)" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Rules skipped (disabled): $($stats.RulesSkippedDisabled)" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Custom categories processed: $($stats.CustomCategoriesProcessed)" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Custom categories skipped (empty): $($stats.CustomCategoriesSkipped)" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Predefined categories referenced: $($stats.PredefinedCategoriesReferenced)" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Unmapped predefined categories: $($stats.UnmappedCategories)" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Policies created: $($stats.PoliciesCreated)" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Security profiles created: $($stats.SecurityProfilesCreated)" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "URLs classified: $($stats.URLsClassified)" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "FQDNs classified: $($stats.FQDNsClassified)" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "IP addresses classified: $($stats.IPsClassified)" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Groups created from splitting: $($stats.GroupsSplitForCharLimit)" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Priority conflicts resolved: $($stats.PriorityConflictsResolved)" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Output files:" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Policies: $policiesCsvPath" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Security Profiles: $spCsvPath" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Log File: $logPath" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    
    # Phase 5: Validate against Global Secure Access limits
    Write-LogMessage "" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "=== GLOBAL SECURE ACCESS LIMITS VALIDATION ===" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    
    # Define limits
    $limits = @{
        MaxPolicies = 100
        MaxRules = 1000
        MaxFQDNs = 8000
        MaxSecurityProfiles = 256
    }
    
    # Calculate unique policy count
    $uniquePolicies = ($policies | Select-Object -Property PolicyName -Unique).Count
    $totalFQDNsAndURLs = $stats.TotalFQDNsInPolicies + $stats.TotalURLsInPolicies
    
    # Display counts
    Write-LogMessage "Current configuration:" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Web content filtering policies: $uniquePolicies (Limit: $($limits.MaxPolicies))" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Rules across all policies: $($stats.TotalRulesInPolicies) (Limit: $($limits.MaxRules))" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Total FQDNs and URLs: $totalFQDNsAndURLs (Limit: $($limits.MaxFQDNs))" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "    - FQDNs: $($stats.TotalFQDNsInPolicies)" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "    - URLs: $($stats.TotalURLsInPolicies)" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Security profiles: $($stats.SecurityProfilesCreated) (Limit: $($limits.MaxSecurityProfiles))" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    
    # Check for limit violations and display warnings
    $hasWarnings = $false
    Write-LogMessage "" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    
    if ($uniquePolicies -gt $limits.MaxPolicies) {
        $hasWarnings = $true
        $overage = $uniquePolicies - $limits.MaxPolicies
        Write-LogMessage "WARNING: Web content filtering policies ($uniquePolicies) exceeds the limit of $($limits.MaxPolicies) by $overage policies" -Level "WARN" `
            -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }
    
    if ($stats.TotalRulesInPolicies -gt $limits.MaxRules) {
        $hasWarnings = $true
        $overage = $stats.TotalRulesInPolicies - $limits.MaxRules
        Write-LogMessage "WARNING: Total rules ($($stats.TotalRulesInPolicies)) exceeds the limit of $($limits.MaxRules) by $overage rules" -Level "WARN" `
            -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }
    
    if ($totalFQDNsAndURLs -gt $limits.MaxFQDNs) {
        $hasWarnings = $true
        $overage = $totalFQDNsAndURLs - $limits.MaxFQDNs
        Write-LogMessage "WARNING: Total FQDNs and URLs ($totalFQDNsAndURLs) exceeds the limit of $($limits.MaxFQDNs) by $overage entries" -Level "WARN" `
            -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        Write-LogMessage "  - FQDNs: $($stats.TotalFQDNsInPolicies)" -Level "WARN" `
            -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        Write-LogMessage "  - URLs: $($stats.TotalURLsInPolicies)" -Level "WARN" `
            -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }
    
    if ($stats.SecurityProfilesCreated -gt $limits.MaxSecurityProfiles) {
        $hasWarnings = $true
        $overage = $stats.SecurityProfilesCreated - $limits.MaxSecurityProfiles
        Write-LogMessage "WARNING: Security profiles ($($stats.SecurityProfilesCreated)) exceeds the limit of $($limits.MaxSecurityProfiles) by $overage profiles" -Level "WARN" `
            -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }
    
    if (-not $hasWarnings) {
        Write-LogMessage "All limits are within Global Secure Access boundaries." -Level "INFO" `
            -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }
    else {
        Write-LogMessage "" -Level "INFO" `
            -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        Write-LogMessage "Action required: Please review and reduce the configuration to meet Global Secure Access limits before importing." -Level "WARN" `
            -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }
    
    Write-LogMessage "" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Conversion completed successfully" -Level "INFO" `
        -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    
    #endregion
}
