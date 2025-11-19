function Convert-NSWG2EIA {
    <#
    .SYNOPSIS
        Converts Netskope Secure Web Gateway (NSWG) configuration to Microsoft Entra Internet Access (EIA) format.
    
    .DESCRIPTION
        Transforms Netskope Real-time Protection policies, custom categories, and URL lists
        into EIA-compatible web content filtering policies and security profiles.
        
        The function processes:
        - Real-time Protection policies
        - Custom web categories
        - URL lists
        - Predefined category mappings
        
        And generates:
        - Web content filtering policies CSV
        - Security profiles CSV
        - Detailed log file
    
    .PARAMETER RealTimeProtectionPoliciesPath
        Path to Netskope Real-time Protection Policies JSON export file.
    
    .PARAMETER UrlListsPath
        Path to Netskope URL Lists JSON export file.
    
    .PARAMETER CustomCategoriesPath
        Path to Netskope Custom Categories JSON export file.
    
    .PARAMETER CategoryMappingsPath
        Path to NSWG to EIA category mappings CSV file.
    
    .PARAMETER OutputBasePath
        Base directory for output files. Defaults to current directory.
    
    .PARAMETER EnableDebugLogging
        Enable verbose debug logging.
    
    .EXAMPLE
        Convert-NSWG2EIA -RealTimeProtectionPoliciesPath "real_time_protection_policies.json" `
                         -UrlListsPath "url_lists.json" `
                         -CustomCategoriesPath "custom_categories.json" `
                         -CategoryMappingsPath "NSWG2EIA-CategoryMappings.csv"
        
        Converts Netskope configuration using files in current directory with default output path.
    
    .EXAMPLE
        Convert-NSWG2EIA -RealTimeProtectionPoliciesPath "C:\Netskope\policies.json" `
                         -UrlListsPath "C:\Netskope\url_lists.json" `
                         -CustomCategoriesPath "C:\Netskope\custom_categories.json" `
                         -CategoryMappingsPath "C:\Mappings\NSWG2EIA-CategoryMappings.csv" `
                         -OutputBasePath "C:\Output" `
                         -EnableDebugLogging
        
        Converts using specified paths with debug logging enabled.
    
    .NOTES
        Version: 1.0
        Author: Andres Canello
        Date: 2025-11-12
    #>
    [CmdletBinding(SupportsShouldProcess = $false)]
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Path to Netskope Real-time Protection Policies JSON export")]
        [ValidateScript({
            if (Test-Path $_ -PathType Leaf) { return $true }
            else { throw "File not found: $_" }
        })]
        [string]$RealTimeProtectionPoliciesPath,
        
        [Parameter(Mandatory = $true, HelpMessage = "Path to Netskope URL Lists JSON export")]
        [ValidateScript({
            if (Test-Path $_ -PathType Leaf) { return $true }
            else { throw "File not found: $_" }
        })]
        [string]$UrlListsPath,
        
        [Parameter(Mandatory = $true, HelpMessage = "Path to Netskope Custom Categories JSON export")]
        [ValidateScript({
            if (Test-Path $_ -PathType Leaf) { return $true }
            else { throw "File not found: $_" }
        })]
        [string]$CustomCategoriesPath,
        
        [Parameter(Mandatory = $true, HelpMessage = "Path to NSWG to EIA category mappings CSV file")]
        [ValidateScript({
            if (Test-Path $_ -PathType Leaf) { return $true }
            else { throw "File not found: $_" }
        })]
        [string]$CategoryMappingsPath,
        
        [Parameter(HelpMessage = "Base directory for output files")]
        [ValidateScript({
            if (Test-Path $_ -PathType Container) { return $true }
            else { throw "Directory not found: $_" }
        })]
        [string]$OutputBasePath = $PWD,
        
        [Parameter(HelpMessage = "Enable verbose debug logging")]
        [switch]$EnableDebugLogging
    )
    
    #region Initialize Logging
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $script:logPath = Join-Path $OutputBasePath "${timestamp}_Convert-NSWG2EIA.log"
    $logPath = $script:logPath  # For backwards compatibility
    
    # Set log level and debug flag at script scope for internal functions
    $script:LogLevel = if ($EnableDebugLogging) { "DEBUG" } else { "INFO" }
    $script:EnableDebugLogging = $EnableDebugLogging
    
    Write-LogMessage -Message "===== Convert-NSWG2EIA Started =====" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "Timestamp: $timestamp" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "Log Level: $script:LogLevel" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "Output Base Path: $OutputBasePath" -Level "INFO" -LogPath $logPath
    
    #endregion Initialize Logging
    
    #region Helper Functions
    
    function Resolve-CategoryMapping {
        <#
        .SYNOPSIS
            Resolves a Netskope category name to its GSA category mapping.
        
        .DESCRIPTION
            Checks if a Netskoke category exists in the mapping hashtable and validates
            that it has a valid GSA category value. Returns detailed information about
            the mapping status for logging and statistics.
        
        .PARAMETER CategoryName
            The Netskope category name to resolve.
        
        .PARAMETER CategoryMappingsHashtable
            Hashtable containing the category mappings.
        
        .OUTPUTS
            Returns a hashtable with:
            - GSACategory: The mapped category or UNMAPPED prefix
            - IsMapped: Boolean indicating if mapping was successful
            - MappingType: 'Success', 'NoMappingRow', or 'NoGSAValue'
            - LogMessage: Specific log message for this mapping result
        #>
        param(
            [Parameter(Mandatory = $true)]
            [string]$CategoryName,
            
            [Parameter(Mandatory = $true)]
            [hashtable]$CategoryMappingsHashtable
        )
        
        $mapping = $CategoryMappingsHashtable[$CategoryName]
        
        if ($null -eq $mapping) {
            # Category not found in mapping file
            return @{
                GSACategory = "UNMAPPED:$CategoryName"
                IsMapped = $false
                MappingType = 'NoMappingRow'
                LogMessage = "Netskope category '$CategoryName' not found in mapping file"
            }
        }
        
        if ([string]::IsNullOrWhiteSpace($mapping.GSACategory) -or $mapping.GSACategory -eq "Unmapped") {
            # Mapping row exists but no GSA category value
            return @{
                GSACategory = "UNMAPPED:$CategoryName"
                IsMapped = $false
                MappingType = 'NoGSAValue'
                LogMessage = "Netskope category '$CategoryName' found in mapping file but GSACategory is empty or 'Unmapped'"
            }
        }
        
        # Successfully mapped
        return @{
            GSACategory = $mapping.GSACategory
            IsMapped = $true
            MappingType = 'Success'
            LogMessage = "Netskope category '$CategoryName' successfully mapped to '$($mapping.GSACategory)'"
        }
    }
    
    #endregion Helper Functions
    
    #region Initialize Statistics
    
    $stats = @{
        TotalRTPoliciesLoaded = 0
        WebPoliciesProcessed = 0
        PoliciesSkippedDisabled = 0
        PoliciesSkippedNPA = 0
        PoliciesSkippedAppTags = 0
        CustomCategoriesProcessed = 0
        UrlListsProcessed = 0
        UrlListsExact = 0
        UrlListsRegex = 0
        PredefinedCategoriesReferenced = 0
        UnmappedCategories_MissingInFile = 0
        UnmappedCategories_NoGSAValue = 0
        ApplicationObjectsFound = 0
        URLsClassified = 0
        FQDNsClassified = 0
        IPsClassified = 0
        EntriesSkipped = 0
        PoliciesCreated = 0
        CustomCategoryPolicies = 0
        PredefinedCategoryPolicies = 0
        ApplicationPolicies = 0
        SecurityProfilesCreated = 0
        SecurityProfilesAllUsers = 0
        SecurityProfilesSpecific = 0
        UnreferencedPoliciesRemoved = 0
    }
    
    #endregion Initialize Statistics
    
    #region Phase 1: Data Loading and Validation
    
    Write-LogMessage -Message "===== Phase 1: Data Loading and Validation =====" -Level "INFO" -LogPath $logPath
    
    try {
        # Load Real-time Protection Policies
        Write-LogMessage -Message "Loading Real-time Protection Policies from: $RealTimeProtectionPoliciesPath" -Level "INFO" -LogPath $logPath
        $rtPoliciesJson = Get-Content -Path $RealTimeProtectionPoliciesPath -Raw -ErrorAction Stop
        $rtPoliciesData = $rtPoliciesJson | ConvertFrom-Json -ErrorAction Stop
        
        # Handle nested data structure - check if root is an array (direct format)
        # or if it's a wrapper object with a 'data' property containing the array
        if ($rtPoliciesData -is [array]) {
            # Plain array format: [{ruleName: "...", status: "..."}, ...]
            $realTimePolicies = $rtPoliciesData
        } elseif ($rtPoliciesData.data -and $rtPoliciesData.data -is [array]) {
            # Wrapped format: {data: [{ruleName: "...", status: "..."}, ...]}
            $realTimePolicies = $rtPoliciesData.data
        } else {
            $realTimePolicies = $rtPoliciesData
        }
        
        $stats.TotalRTPoliciesLoaded = $realTimePolicies.Count
        Write-LogMessage -Message "Loaded $($stats.TotalRTPoliciesLoaded) Real-time Protection policies" -Level "INFO" -LogPath $logPath
        
        # Load URL Lists
        Write-LogMessage -Message "Loading URL Lists from: $UrlListsPath" -Level "INFO" -LogPath $logPath
        $urlListsJson = Get-Content -Path $UrlListsPath -Raw -ErrorAction Stop
        $urlListsData = $urlListsJson | ConvertFrom-Json -ErrorAction Stop
        
        # Handle nested data structure - check if root is an array with 'id' property (direct format)
        # or if it's a wrapper object with a 'data' property containing the array
        if ($urlListsData -is [array] -and $null -ne $urlListsData[0].id) {
            # Direct array format: [{id: 1, name: "...", data: {...}}, ...]
            $urlLists = $urlListsData
        } elseif ($urlListsData.data -and $urlListsData.data -is [array]) {
            # Wrapped format: {data: [{id: 1, name: "...", data: {...}}, ...]}
            $urlLists = $urlListsData.data
        } else {
            $urlLists = $urlListsData
        }
        
        # Ensure $urlLists is an array
        if ($null -eq $urlLists) {
            $urlLists = @()
            Write-LogMessage -Message "Warning: URL lists data is null, initialized as empty array" -Level "WARN" -LogPath $logPath
        } elseif ($urlLists -isnot [array]) {
            $urlLists = @($urlLists)
            Write-LogMessage -Message "Warning: URL lists data was not an array, converted to array" -Level "WARN" -LogPath $logPath
        }
        
        $stats.UrlListsProcessed = $urlLists.Count
        Write-LogMessage -Message "Loaded $($stats.UrlListsProcessed) URL lists" -Level "INFO" -LogPath $logPath
        
        # Load Custom Categories
        Write-LogMessage -Message "Loading Custom Categories from: $CustomCategoriesPath" -Level "INFO" -LogPath $logPath
        $customCategoriesJson = Get-Content -Path $CustomCategoriesPath -Raw -ErrorAction Stop
        $customCategoriesData = $customCategoriesJson | ConvertFrom-Json -ErrorAction Stop
        
        # Handle nested data.data structure
        if ($customCategoriesData.data.data) {
            $customCategories = $customCategoriesData.data.data
        } elseif ($customCategoriesData.data) {
            $customCategories = $customCategoriesData.data
        } else {
            $customCategories = $customCategoriesData
        }
        
        $stats.CustomCategoriesProcessed = $customCategories.Count
        Write-LogMessage -Message "Loaded $($stats.CustomCategoriesProcessed) custom categories" -Level "INFO" -LogPath $logPath
        
        # Load Category Mappings
        Write-LogMessage -Message "Loading Category Mappings from: $CategoryMappingsPath" -Level "INFO" -LogPath $logPath
        $categoryMappings = Import-Csv -Path $CategoryMappingsPath -ErrorAction Stop
        Write-LogMessage -Message "Loaded $($categoryMappings.Count) category mappings" -Level "INFO" -LogPath $logPath
        
    }
    catch {
        $errorMsg = "Fatal error loading input files: $_"
        Write-LogMessage -Message $errorMsg -Level "ERROR" -LogPath $logPath
        throw $errorMsg
    }
    
    #endregion Phase 1: Data Loading and Validation
    
    #region Build Lookup Tables
    
    Write-LogMessage -Message "Building lookup tables..." -Level "INFO" -LogPath $logPath
    
    # Category mappings hashtable
    $categoryMappingsHashtable = @{}
    foreach ($mapping in $categoryMappings) {
        $categoryMappingsHashtable[$mapping.NSWGCategory] = $mapping
    }
    Write-LogMessage -Message "Built category mappings hashtable with $($categoryMappingsHashtable.Count) entries" -Level "DEBUG" -LogPath $logPath
    
    # URL Lists hashtable
    $urlListsHashtable = @{}
    foreach ($urlList in $urlLists) {
        if ($null -ne $urlList.id -and $urlList.id -ne "") {
            # Convert ID to string to ensure consistent lookups
            $urlListsHashtable[[string]$urlList.id] = $urlList
            Write-LogMessage -Message "Added URL list ID [string]$($urlList.id) to hashtable: $($urlList.name)" -Level "DEBUG" -LogPath $logPath
        } else {
            Write-LogMessage -Message "Warning: Skipping URL list with null or empty ID. Name: '$($urlList.name)'" -Level "WARN" -LogPath $logPath
        }
    }
    Write-LogMessage -Message "Built URL lists hashtable with $($urlListsHashtable.Count) entries" -Level "DEBUG" -LogPath $logPath
    
    # Custom categories hashtable by name
    $customCategoriesByName = @{}
    foreach ($category in $customCategories) {
        $customCategoriesByName[$category.name] = $category
    }
    Write-LogMessage -Message "Built custom categories hashtable with $($customCategoriesByName.Count) entries" -Level "DEBUG" -LogPath $logPath
    
    # Custom category policies tracking (populated in Phase 2)
    $customCategoryPoliciesHashtable = @{}
    
    # Collections for output
    $policies = [System.Collections.ArrayList]::new()
    $securityProfiles = [System.Collections.ArrayList]::new()
    
    #endregion Build Lookup Tables
    
    #region Phase 2: URL List and Custom Category Processing
    
    Write-LogMessage -Message "===== Phase 2: URL List and Custom Category Processing =====" -Level "INFO" -LogPath $logPath
    
    #region Phase 2.1: Process URL Lists
    
    Write-LogMessage -Message "Processing URL lists..." -Level "INFO" -LogPath $logPath
    
    foreach ($urlList in $urlLists) {
        Write-LogMessage -Message "Processing URL list: $($urlList.name) (ID: $($urlList.id))" -Level "DEBUG" -LogPath $logPath
        
        # Check for regex type
        $hasRegex = $false
        $reviewDetails = ""
        if ($urlList.data.type -eq "regex") {
            $hasRegex = $true
            $reviewDetails = "URL List contains regex patterns"
            $stats.UrlListsRegex++
            Write-LogMessage -Message "URL List '$($urlList.name)' is regex type - will flag for review" -Level "WARN" -LogPath $logPath
        } else {
            $stats.UrlListsExact++
        }
        
        # Collect and deduplicate destinations
        $uniqueDestinations = @()
        if ($urlList.data.urls) {
            $uniqueDestinations = @($urlList.data.urls | Group-Object -Property { $_.ToLower() } | ForEach-Object { $_.Group[0] })
        }
        
        Write-LogMessage -Message "URL List '$($urlList.name)' has $($uniqueDestinations.Count) unique destinations" -Level "DEBUG" -LogPath $logPath
        
        # Clean destinations
        $cleanedDestinations = [System.Collections.ArrayList]::new()
        foreach ($dest in $uniqueDestinations) {
            $cleaned = ConvertTo-CleanDestination -Destination $dest -LogPath $logPath -EnableDebugLogging $EnableDebugLogging
            if ($null -ne $cleaned) {
                [void]$cleanedDestinations.Add($cleaned)
            }
        }
        
        # Classify destinations
        $classified = @{
            'FQDN' = [System.Collections.ArrayList]::new()
            'URL' = [System.Collections.ArrayList]::new()
            'ipAddress' = [System.Collections.ArrayList]::new()
        }
        
        foreach ($dest in $cleanedDestinations) {
            $destType = Get-DestinationType -Destination $dest
            if ($destType -eq 'ipv4') {
                [void]$classified['ipAddress'].Add($dest)
                $stats.IPsClassified++
            } elseif ($destType -eq 'ipv6') {
                Write-LogMessage -Message "IPv6 address not supported: $dest" -Level "WARN" -LogPath $logPath
                $stats.EntriesSkipped++
            } elseif ($destType -eq 'URL') {
                [void]$classified['URL'].Add($dest)
                $stats.URLsClassified++
            } else {
                [void]$classified['FQDN'].Add($dest)
                $stats.FQDNsClassified++
            }
        }
        
        # Check for IP addresses (not yet supported - flag for review) - do this once before creating policies
        $hasIpAddresses = $classified['ipAddress'].Count -gt 0
        if ($hasIpAddresses) {
            Write-LogMessage -Message "URL List '$($urlList.name)' contains IP addresses (not yet supported in EIA) - flagging for review" -Level "WARN" -LogPath $logPath
        }
        
        # Create BOTH Allow and Block policies for this URL list
        foreach ($action in @('Allow', 'Block')) {
            $policyName = "$($urlList.name)-$action"
            
            # For regex lists, use Block action and flag for review
            $actualAction = if ($hasRegex) { 'Block' } else { $action }
            
            # Process each destination type
            foreach ($destType in @('FQDN', 'URL', 'ipAddress')) {
                if ($classified[$destType].Count -eq 0) { continue }
                
                # Determine if this specific destination type needs review
                $needsReview = $false
                $reviewDetailsForType = $reviewDetails
                
                if ($destType -eq 'ipAddress') {
                    # IP addresses are not supported - flag for review
                    $needsReview = $true
                    if ($reviewDetailsForType) {
                        $reviewDetailsForType += "; IP addresses not yet supported in EIA"
                    } else {
                        $reviewDetailsForType = "IP addresses not yet supported in EIA"
                    }
                } elseif ($hasRegex) {
                    # Regex patterns need review
                    $needsReview = $true
                }
                
                # Group by base domain (for FQDN and URL)
                if ($destType -in @('FQDN', 'URL')) {
                    $grouped = $classified[$destType] | Group-Object -Property { Get-BaseDomain -Domain $_ }
                    
                    foreach ($group in $grouped) {
                        $baseDomain = $group.Name
                        $destinations = @($group.Group)
                        
                        # Split by character limit
                        $splitResults = Split-ByCharacterLimit -Entries $destinations -MaxLength 300 -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                        
                        $ruleIndex = 1
                        foreach ($chunk in $splitResults) {
                            $ruleName = if ($splitResults.Count -gt 1) {
                                "$baseDomain-$ruleIndex"
                            } else {
                                $baseDomain
                            }
                            
                            $policyEntry = [PSCustomObject]@{
                                PolicyName = $policyName
                                PolicyType = "WebContentFiltering"
                                PolicyAction = $actualAction
                                Description = "URL List: $($urlList.name)"
                                RuleType = $destType
                                RuleDestinations = $chunk -join ';'
                                RuleName = $ruleName
                                ReviewNeeded = if ($needsReview) { "Yes" } else { "No" }
                                ReviewDetails = $reviewDetailsForType
                                Provision = if ($needsReview) { "No" } else { "Yes" }
                            }
                            [void]$policies.Add($policyEntry)
                            $ruleIndex++
                        }
                    }
                } else {
                    # IP addresses - split by character limit
                    $splitResults = Split-ByCharacterLimit -Entries $classified[$destType] -MaxLength 300 -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                    
                    $ruleIndex = 1
                    foreach ($chunk in $splitResults) {
                        $ruleName = if ($splitResults.Count -gt 1) {
                            "IPs-$ruleIndex"
                        } else {
                            "IPs"
                        }
                        
                        $policyEntry = [PSCustomObject]@{
                            PolicyName = $policyName
                            PolicyType = "WebContentFiltering"
                            PolicyAction = $actualAction
                            Description = "URL List: $($urlList.name)"
                            RuleType = $destType
                            RuleDestinations = $chunk -join ';'
                            RuleName = $ruleName
                            ReviewNeeded = if ($needsReview) { "Yes" } else { "No" }
                            ReviewDetails = $reviewDetailsForType
                            Provision = if ($needsReview) { "No" } else { "Yes" }
                        }
                        [void]$policies.Add($policyEntry)
                        $ruleIndex++
                    }
                }
            }
        }
    }
    
    Write-LogMessage -Message "URL lists processing complete. Created $($policies.Count) policy rules" -Level "INFO" -LogPath $logPath
    
    #endregion Phase 2.1: Process URL Lists
    
    #region Phase 2.2: Process Custom Categories
    
    Write-LogMessage -Message "Processing custom categories..." -Level "INFO" -LogPath $logPath
    
    foreach ($category in $customCategories) {
        Write-LogMessage -Message "Processing custom category: $($category.name) (ID: $($category.id))" -Level "DEBUG" -LogPath $logPath
        
        # Track URL list references for later linking
        $inclusionUrlListIds = [System.Collections.ArrayList]::new()
        $exclusionUrlListIds = [System.Collections.ArrayList]::new()
        $predefinedCategories = [System.Collections.ArrayList]::new()
        $hasUnmappedCategories = $false
        $unmappedCategoryNames = [System.Collections.ArrayList]::new()
        
        # Collect inclusion URL list IDs
        if ($category.data.inclusion) {
            foreach ($urlListRef in $category.data.inclusion) {
                [void]$inclusionUrlListIds.Add($urlListRef.id)
            }
            Write-LogMessage -Message "Custom category '$($category.name)' has $($inclusionUrlListIds.Count) inclusion URL lists" -Level "DEBUG" -LogPath $logPath
        }
        
        # Collect exclusion URL list IDs
        if ($category.data.exclusion) {
            foreach ($urlListRef in $category.data.exclusion) {
                [void]$exclusionUrlListIds.Add($urlListRef.id)
            }
            Write-LogMessage -Message "Custom category '$($category.name)' has $($exclusionUrlListIds.Count) exclusion URL lists" -Level "DEBUG" -LogPath $logPath
        }
        
        # Check for URL lists in both inclusion AND exclusion (warn if found)
        $duplicateUrlLists = $inclusionUrlListIds | Where-Object { $exclusionUrlListIds -contains $_ }
        if ($duplicateUrlLists.Count -gt 0) {
            $duplicateNames = $duplicateUrlLists | ForEach-Object { $urlListsHashtable[$_].name }
            Write-LogMessage -Message "Custom category '$($category.name)' has URL lists in both inclusion and exclusion arrays: $(($duplicateNames) -join ', ')" -Level "WARN" -LogPath $logPath
        }
        
        # Process predefined categories
        if ($category.data.categories) {
            $categoriesMissingInFile = [System.Collections.ArrayList]::new()
            $categoriesWithoutGSAValue = [System.Collections.ArrayList]::new()
            
            foreach ($catRef in $category.data.categories) {
                $mappingResult = Resolve-CategoryMapping -CategoryName $catRef.name -CategoryMappingsHashtable $categoryMappingsHashtable
                
                if ($mappingResult.IsMapped) {
                    [void]$predefinedCategories.Add($mappingResult.GSACategory)
                    $stats.PredefinedCategoriesReferenced++
                } else {
                    [void]$predefinedCategories.Add($mappingResult.GSACategory)
                    $hasUnmappedCategories = $true
                    
                    if ($mappingResult.MappingType -eq 'NoMappingRow') {
                        $stats.UnmappedCategories_MissingInFile++
                        [void]$categoriesMissingInFile.Add($catRef.name)
                    } else {
                        $stats.UnmappedCategories_NoGSAValue++
                        [void]$categoriesWithoutGSAValue.Add($catRef.name)
                    }
                    
                    Write-LogMessage -Message "Custom category '$($category.name)': $($mappingResult.LogMessage)" -Level "WARN" -LogPath $logPath
                }
            }
            
            # Build unmapped category names list for review details
            if ($categoriesMissingInFile.Count -gt 0) {
                foreach ($catName in $categoriesMissingInFile) {
                    [void]$unmappedCategoryNames.Add($catName)
                }
            }
            if ($categoriesWithoutGSAValue.Count -gt 0) {
                foreach ($catName in $categoriesWithoutGSAValue) {
                    [void]$unmappedCategoryNames.Add($catName)
                }
            }
            
            Write-LogMessage -Message "Custom category '$($category.name)' has $($predefinedCategories.Count) predefined categories" -Level "DEBUG" -LogPath $logPath
        }
        
        # Create policies for predefined categories (if any)
        if ($predefinedCategories.Count -gt 0) {
            foreach ($action in @('Allow', 'Block')) {
                $policyName = "$($category.name)-WebCategories-$action"
                
                $reviewDetails = if ($hasUnmappedCategories) {
                    $reviewParts = [System.Collections.ArrayList]::new()
                    if ($categoriesMissingInFile.Count -gt 0) {
                        [void]$reviewParts.Add("Missing in mapping file: $(($categoriesMissingInFile) -join ', ')")
                    }
                    if ($categoriesWithoutGSAValue.Count -gt 0) {
                        [void]$reviewParts.Add("No matching GSA category: $(($categoriesWithoutGSAValue) -join ', ')")
                    }
                    $reviewParts -join '; '
                } else {
                    ""
                }
                
                $policyEntry = [PSCustomObject]@{
                    PolicyName = $policyName
                    PolicyType = "WebContentFiltering"
                    PolicyAction = $action
                    Description = "$($category.name) - Predefined categories"
                    RuleType = "webCategory"
                    RuleDestinations = $predefinedCategories -join ';'
                    RuleName = "WebCategories"
                    ReviewNeeded = if ($hasUnmappedCategories) { "Yes" } else { "No" }
                    ReviewDetails = $reviewDetails
                    Provision = if ($hasUnmappedCategories) { "No" } else { "Yes" }
                }
                [void]$policies.Add($policyEntry)
                $stats.CustomCategoryPolicies++
            }
        }
        
        # Store custom category info for Phase 3 lookup
        $customCategoryPoliciesHashtable[$category.name] = @{
            InclusionUrlListIds = $inclusionUrlListIds
            ExclusionUrlListIds = $exclusionUrlListIds
            HasPredefinedCategories = ($predefinedCategories.Count -gt 0)
            HasDuplicateUrlLists = ($duplicateUrlLists.Count -gt 0)
            DuplicateUrlListIds = $duplicateUrlLists
        }
    }
    
    Write-LogMessage -Message "Custom categories processing complete. Total policy rules: $($policies.Count)" -Level "INFO" -LogPath $logPath
    
    #endregion Phase 2.2: Process Custom Categories
    
    #endregion Phase 2: URL List and Custom Category Processing
    
    #region Phase 3: Real-time Protection Policy Processing
    
    Write-LogMessage -Message "===== Phase 3: Real-time Protection Policy Processing =====" -Level "INFO" -LogPath $logPath
    
    #region Phase 3.1: Filter Policies
    
    Write-LogMessage -Message "Filtering Real-time Protection policies..." -Level "INFO" -LogPath $logPath
    
    # Filter out disabled, NPA policies, and app-tag filtered policies
    $webPolicies = $realTimePolicies | Where-Object {
        $_.status -eq "Enabled" -and 
        $_.accessMethod -ne "Client" -and
        ([string]::IsNullOrWhiteSpace($_.app_tags) -or $_.app_tags -eq "Any")
    }
    
    $disabledPolicies = $realTimePolicies | Where-Object { $_.status -ne "Enabled" }
    $npaPolicies = $realTimePolicies | Where-Object { $_.accessMethod -eq "Client" }
    $skippedAppTagPolicies = $realTimePolicies | Where-Object {
        $_.status -eq "Enabled" -and 
        $_.accessMethod -ne "Client" -and
        -not ([string]::IsNullOrWhiteSpace($_.app_tags)) -and
        $_.app_tags -ne "Any"
    }
    
    $stats.WebPoliciesProcessed = $webPolicies.Count
    $stats.PoliciesSkippedDisabled = $disabledPolicies.Count
    $stats.PoliciesSkippedNPA = $npaPolicies.Count
    $stats.PoliciesSkippedAppTags = $skippedAppTagPolicies.Count
    
    Write-LogMessage -Message "Filtered $($stats.WebPoliciesProcessed) enabled web policies from $($stats.TotalRTPoliciesLoaded) total policies" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "Skipped $($stats.PoliciesSkippedDisabled) disabled policies" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "Skipped $($stats.PoliciesSkippedNPA) NPA policies" -Level "INFO" -LogPath $logPath
    
    if ($stats.PoliciesSkippedAppTags -gt 0) {
        Write-LogMessage -Message "Skipped $($stats.PoliciesSkippedAppTags) policies with app_tags filtering (CASB)" -Level "WARN" -LogPath $logPath
        foreach ($policy in $skippedAppTagPolicies) {
            Write-LogMessage -Message "Skipped policy '$($policy.ruleName)' with app_tags='$($policy.app_tags)'" -Level "DEBUG" -LogPath $logPath
        }
    }
    
    #endregion Phase 3.1: Filter Policies
    
    #region Phase 3.2: Parse and Process Each Policy
    
    Write-LogMessage -Message "Processing individual Real-time Protection policies..." -Level "INFO" -LogPath $logPath
    
    $policiesForAggregation = [System.Collections.ArrayList]::new()
    
    foreach ($policy in $webPolicies) {
        Write-LogMessage -Message "Processing policy: $($policy.ruleName)" -Level "DEBUG" -LogPath $logPath
        
        # Parse user field
        $userEntries = $policy.user -split ',' | ForEach-Object { $_.Trim() }
        $emails = [System.Collections.ArrayList]::new()
        $groups = [System.Collections.ArrayList]::new()
        
        foreach ($entry in $userEntries) {
            if ($entry -eq "All") {
                $groups = [System.Collections.ArrayList]@("Replace_with_All_IA_Users_Group")
                $emails = [System.Collections.ArrayList]::new()
                break
            } elseif ($entry -like "*/*") {
                # X500 group path
                $groupName = Get-GroupNameFromX500 -X500Path $entry
                if ($null -ne $groupName) {
                    [void]$groups.Add($groupName)
                }
            } elseif ($entry -like "*@*") {
                # Email address
                [void]$emails.Add($entry)
            }
        }
        
        Write-LogMessage -Message "Policy '$($policy.ruleName)' assigned to $($emails.Count) users and $($groups.Count) groups" -Level "DEBUG" -LogPath $logPath
        
        # Parse application field
        $appEntries = $policy.application -split ',' | ForEach-Object { $_.Trim() }
        $policyLinks = [System.Collections.ArrayList]::new()
        $needsReview = $false
        $reviewReasons = [System.Collections.ArrayList]::new()
        
        foreach ($appEntry in $appEntries) {
            Write-LogMessage -Message "Processing application entry: $appEntry" -Level "DEBUG" -LogPath $logPath
            
            # Resolve application type
            $appResolution = Resolve-NSWGApplication -ApplicationName $appEntry `
                                                      -CustomCategoriesHashtable $customCategoriesByName `
                                                      -CategoryMappingsHashtable $categoryMappingsHashtable
            
            if ($appResolution.IsCustomCategory) {
                # Custom category
                Write-LogMessage -Message "Application '$appEntry' is a custom category" -Level "DEBUG" -LogPath $logPath
                
                $categoryInfo = $customCategoryPoliciesHashtable[$appEntry]
                
                # Check for duplicate URL lists (in both inclusion and exclusion)
                if ($categoryInfo.HasDuplicateUrlLists) {
                    $needsReview = $true
                    $duplicateNames = $categoryInfo.DuplicateUrlListIds | ForEach-Object { $urlListsHashtable[$_].name }
                    [void]$reviewReasons.Add("Custom category '$appEntry' has URL lists in both inclusion and exclusion: $(($duplicateNames) -join ', ')")
                }
                
                # Determine action based on policy action
                $policyAction = if ($policy.action -like "Alert*" -or $policy.action -like "User Alert*") {
                    "Block"
                } elseif ($policy.action -like "Block*") {
                    "Block"
                } else {
                    "Allow"
                }
                
                # Link to URL list policies based on RT action
                # Inclusions: normal action
                foreach ($urlListId in $categoryInfo.InclusionUrlListIds) {
                    # Convert ID to string for hashtable lookup
                    $urlList = $urlListsHashtable[[string]$urlListId]
                    if ($null -ne $urlList) {
                        $urlListPolicyName = "$($urlList.name)-$policyAction"
                        [void]$policyLinks.Add($urlListPolicyName)
                        Write-LogMessage -Message "Linking to inclusion URL list policy: $urlListPolicyName" -Level "DEBUG" -LogPath $logPath
                    } else {
                        Write-LogMessage -Message "URL list ID [string]$urlListId not found in hashtable. Available keys: $(($urlListsHashtable.Keys | Sort-Object) -join ', ')" -Level "WARN" -LogPath $logPath
                    }
                }
                
                # Exclusions: INVERSE action
                foreach ($urlListId in $categoryInfo.ExclusionUrlListIds) {
                    # Convert ID to string for hashtable lookup
                    $urlList = $urlListsHashtable[[string]$urlListId]
                    if ($null -ne $urlList) {
                        $inverseAction = if ($policyAction -eq "Allow") { "Block" } else { "Allow" }
                        $urlListPolicyName = "$($urlList.name)-$inverseAction"
                        [void]$policyLinks.Add($urlListPolicyName)
                        Write-LogMessage -Message "Linking to exclusion URL list policy (INVERSE): $urlListPolicyName" -Level "DEBUG" -LogPath $logPath
                    } else {
                        Write-LogMessage -Message "URL list ID [string]$urlListId not found in hashtable. Available keys: $(($urlListsHashtable.Keys | Sort-Object) -join ', ')" -Level "WARN" -LogPath $logPath
                    }
                }
                
                # Link to predefined category policy (if exists)
                if ($categoryInfo.HasPredefinedCategories) {
                    $categoryPolicyName = "$appEntry-WebCategories-$policyAction"
                    [void]$policyLinks.Add($categoryPolicyName)
                    Write-LogMessage -Message "Linking to custom category predefined categories policy: $categoryPolicyName" -Level "DEBUG" -LogPath $logPath
                }
                
                continue
            }
            
            if ($appResolution.IsPredefinedCategory) {
                # Predefined category
                Write-LogMessage -Message "Application '$appEntry' is a predefined category" -Level "DEBUG" -LogPath $logPath
                
                $mapping = $categoryMappingsHashtable[$appEntry]
                
                $policyAction = if ($policy.action -like "Alert*" -or $policy.action -like "User Alert*") {
                    "Block"
                } elseif ($policy.action -like "Block*") {
                    "Block"
                } else {
                    "Allow"
                }
                
                # Create policy using RT policy's ruleName
                $policyName = "$($policy.ruleName)-WebCategories-$policyAction"
                
                # Check if policy already exists
                $existingPolicy = $policies | Where-Object { $_.PolicyName -eq $policyName }
                if ($null -eq $existingPolicy) {
                    $mappingResult = Resolve-CategoryMapping -CategoryName $appEntry -CategoryMappingsHashtable $categoryMappingsHashtable
                    
                    $hasUnmappedCategory = -not $mappingResult.IsMapped
                    $gsaCategory = $mappingResult.GSACategory
                    
                    if ($hasUnmappedCategory) {
                        if ($mappingResult.MappingType -eq 'NoMappingRow') {
                            $stats.UnmappedCategories_MissingInFile++
                        } else {
                            $stats.UnmappedCategories_NoGSAValue++
                        }
                        Write-LogMessage -Message "RT Policy '$($policy.ruleName)': $($mappingResult.LogMessage)" -Level "WARN" -LogPath $logPath
                    }
                    
                    $reviewDetails = if ($hasUnmappedCategory) {
                        if ($mappingResult.MappingType -eq 'NoMappingRow') {
                            "Missing in mapping file: $appEntry"
                        } else {
                            "No matching GSA category: $appEntry"
                        }
                    } else {
                        ""
                    }
                    
                    $policyEntry = [PSCustomObject]@{
                        PolicyName = $policyName
                        PolicyType = "WebContentFiltering"
                        PolicyAction = $policyAction
                        Description = "Predefined category: $appEntry"
                        RuleType = "webCategory"
                        RuleDestinations = $gsaCategory
                        RuleName = "WebCategories"
                        ReviewNeeded = if ($hasUnmappedCategory) { "Yes" } else { "No" }
                        ReviewDetails = $reviewDetails
                        Provision = if ($hasUnmappedCategory) { "No" } else { "Yes" }
                    }
                    [void]$policies.Add($policyEntry)
                    $stats.PredefinedCategoryPolicies++
                }
                
                [void]$policyLinks.Add($policyName)
                Write-LogMessage -Message "Linking to predefined category policy: $policyName" -Level "DEBUG" -LogPath $logPath
                
                continue
            }
            
            # Treat as application object (flag for review)
            Write-LogMessage -Message "Application '$appEntry' is an application object - flagging for review" -Level "WARN" -LogPath $logPath
            $stats.ApplicationObjectsFound++
            
            $policyAction = if ($policy.action -like "Alert*" -or $policy.action -like "User Alert*") {
                "Block"
            } elseif ($policy.action -like "Block*") {
                "Block"
            } else {
                "Allow"
            }
            
            $policyName = "$($policy.ruleName)-Application-$policyAction"
            
            # Check if policy already exists
            $existingPolicy = $policies | Where-Object { $_.PolicyName -eq $policyName }
            if ($null -eq $existingPolicy) {
                $policyEntry = [PSCustomObject]@{
                    PolicyName = $policyName
                    PolicyType = "WebContentFiltering"
                    PolicyAction = $policyAction
                    Description = "Application object: $appEntry"
                    RuleType = "FQDN"
                    RuleDestinations = "PLACEHOLDER_APPLICATION_$appEntry"
                    RuleName = "Application"
                    ReviewNeeded = "Yes"
                    ReviewDetails = "Application object '$appEntry' requires manual mapping to destinations"
                    Provision = "No"
                }
                [void]$policies.Add($policyEntry)
                $stats.ApplicationPolicies++
            }
            
            [void]$policyLinks.Add($policyName)
            
            $needsReview = $true
            [void]$reviewReasons.Add("Application object '$appEntry' requires manual mapping")
        }
        
        # Store policy info for aggregation
        $policyInfo = [PSCustomObject]@{
            RuleName = $policy.ruleName
            Emails = $emails
            Groups = $groups
            SecurityProfileLinks = $policyLinks
            Priority = [int]$policy.groupOrder * 10
            NeedsReview = $needsReview
            ReviewReasons = $reviewReasons
        }
        
        [void]$policiesForAggregation.Add($policyInfo)
    }
    
    Write-LogMessage -Message "Individual policy processing complete. $($policiesForAggregation.Count) policies ready for aggregation" -Level "INFO" -LogPath $logPath
    
    #endregion Phase 3.2: Parse and Process Each Policy
    
    #region Phase 3.3: Aggregate Policies by User/Group Assignment
    
    Write-LogMessage -Message "Aggregating policies by user/group assignment..." -Level "INFO" -LogPath $logPath
    
    # Group policies by user/group assignment
    $allUsersPolicies = [System.Collections.ArrayList]::new()
    $userGroupPolicies = @{}
    
    foreach ($policyInfo in $policiesForAggregation) {
        # Check if assigned to "All"
        if ($policyInfo.Groups -contains "Replace_with_All_IA_Users_Group") {
            [void]$allUsersPolicies.Add($policyInfo)
            continue
        }
        
        # Create key from sorted users and groups
        $combinedKey = ConvertTo-UserGroupKey -Emails $policyInfo.Emails -Groups $policyInfo.Groups
        
        if (-not $userGroupPolicies.ContainsKey($combinedKey)) {
            $userGroupPolicies[$combinedKey] = [System.Collections.ArrayList]::new()
        }
        
        [void]$userGroupPolicies[$combinedKey].Add($policyInfo)
    }
    
    Write-LogMessage -Message "Found $($allUsersPolicies.Count) policies for 'All users'" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "Found $($userGroupPolicies.Count) unique user/group assignment sets" -Level "INFO" -LogPath $logPath
    
    # Create security profiles for specific user/group assignments
    $profileIndex = 1
    foreach ($key in $userGroupPolicies.Keys) {
        $policiesGroup = $userGroupPolicies[$key]
        
        $policyLinks = [System.Collections.ArrayList]::new()
        $ruleNames = [System.Collections.ArrayList]::new()
        
        # Get users and groups from first policy (all in group have same assignment)
        $emails = $policiesGroup[0].Emails
        $groups = $policiesGroup[0].Groups
        
        foreach ($policyInfo in $policiesGroup) {
            foreach ($link in $policyInfo.SecurityProfileLinks) {
                [void]$policyLinks.Add($link)
            }
            [void]$ruleNames.Add($policyInfo.RuleName)
        }
        
        # Deduplicate policy links
        $uniquePolicyLinks = $policyLinks | Select-Object -Unique
        
        # Order policy links: Allow policies first (alphabetically), then Block policies (alphabetically)
        $allowPolicies = @($uniquePolicyLinks | Where-Object { $_ -like "*-Allow" } | Sort-Object)
        $blockPolicies = @($uniquePolicyLinks | Where-Object { $_ -like "*-Block" } | Sort-Object)
        $orderedPolicyLinks = $allowPolicies + $blockPolicies
        
        $securityProfile = [PSCustomObject]@{
            SecurityProfileName = "SecurityProfile-{0:D3}" -f $profileIndex
            Priority = 500 + (($profileIndex - 1) * 100)
            CADisplayName = "SecurityProfile-{0:D3}" -f $profileIndex
            EntraGroups = ($groups -join ';')
            EntraUsers = ($emails -join ';')
            SecurityProfileLinks = ($orderedPolicyLinks -join ';')
            Description = "Aggregated from $($policiesGroup.Count) real-time protection policies"
            Provision = "Yes"
            Notes = ($ruleNames -join ', ')
        }
        [void]$securityProfiles.Add($securityProfile)
        $stats.SecurityProfilesSpecific++
        
        $profileIndex++
    }
    
    # Create security profile for "All" users (lowest precedence - highest priority number)
    if ($allUsersPolicies.Count -gt 0) {
        $allPolicyLinks = [System.Collections.ArrayList]::new()
        $allRuleNames = [System.Collections.ArrayList]::new()
        
        foreach ($policyInfo in $allUsersPolicies) {
            foreach ($link in $policyInfo.SecurityProfileLinks) {
                [void]$allPolicyLinks.Add($link)
            }
            [void]$allRuleNames.Add($policyInfo.RuleName)
        }
        
        # Deduplicate policy links
        $uniquePolicyLinks = $allPolicyLinks | Select-Object -Unique
        
        # Order policy links: Allow policies first (alphabetically), then Block policies (alphabetically)
        $allowPolicies = @($uniquePolicyLinks | Where-Object { $_ -like "*-Allow" } | Sort-Object)
        $blockPolicies = @($uniquePolicyLinks | Where-Object { $_ -like "*-Block" } | Sort-Object)
        $orderedPolicyLinks = $allowPolicies + $blockPolicies
        
        $securityProfile = [PSCustomObject]@{
            SecurityProfileName = "SecurityProfile-All-Users"
            Priority = 500 + ($userGroupPolicies.Count * 100)
            CADisplayName = "SecurityProfile-All-Users"
            EntraGroups = "Replace_with_All_IA_Users_Group"
            EntraUsers = ""
            SecurityProfileLinks = ($orderedPolicyLinks -join ';')
            Description = "Aggregated from $($allUsersPolicies.Count) real-time protection policies"
            Provision = "Yes"
            Notes = ($allRuleNames -join ', ')
        }
        [void]$securityProfiles.Add($securityProfile)
        $stats.SecurityProfilesAllUsers++
    }
    
    $stats.SecurityProfilesCreated = $securityProfiles.Count
    Write-LogMessage -Message "Created $($stats.SecurityProfilesCreated) security profiles" -Level "INFO" -LogPath $logPath
    
    #endregion Phase 3.3: Aggregate Policies by User/Group Assignment
    
    #region Phase 3.4: Cleanup Unreferenced Policies
    
    Write-LogMessage -Message "Cleaning up unreferenced policies..." -Level "INFO" -LogPath $logPath
    
    # Collect all policy names referenced in security profiles
    $referencedPolicies = @{}
    foreach ($secProfile in $securityProfiles) {
        $policyNames = $secProfile.SecurityProfileLinks -split ';'
        foreach ($policyName in $policyNames) {
            $referencedPolicies[$policyName] = $true
        }
    }
    
    Write-LogMessage -Message "Found $($referencedPolicies.Count) unique referenced policies" -Level "DEBUG" -LogPath $logPath
    
    # Remove unreferenced policies (URL list policies, custom category policies, etc.)
    $originalPolicyCount = $policies.Count
    
    # Group policies by PolicyName to get unique policy names
    $policyGroups = $policies | Group-Object -Property PolicyName
    
    # Filter to keep only policies that are referenced
    $referencedPolicyNames = @{}
    foreach ($policyGroup in $policyGroups) {
        if ($referencedPolicies.ContainsKey($policyGroup.Name)) {
            $referencedPolicyNames[$policyGroup.Name] = $true
        }
    }
    
    # Keep only policies that are referenced
    $policies = [System.Collections.ArrayList]@($policies | Where-Object {
        $referencedPolicyNames.ContainsKey($_.PolicyName)
    })
    
    $removedPolicies = $originalPolicyCount - $policies.Count
    $stats.UnreferencedPoliciesRemoved = $removedPolicies
    
    if ($removedPolicies -gt 0) {
        $removedPolicyCount = $policyGroups.Count - $referencedPolicyNames.Count
        Write-LogMessage -Message "Removed $removedPolicies unreferenced policy rules (from $removedPolicyCount policies)" -Level "INFO" -LogPath $logPath
        
        # Log which policies were removed
        $removedPolicyNames = $policyGroups | Where-Object { -not $referencedPolicyNames.ContainsKey($_.Name) } | Select-Object -ExpandProperty Name
        foreach ($removedPolicyName in $removedPolicyNames) {
            Write-LogMessage -Message "Removed unreferenced policy: $removedPolicyName" -Level "DEBUG" -LogPath $logPath
        }
    } else {
        Write-LogMessage -Message "No unreferenced policies to remove" -Level "INFO" -LogPath $logPath
    }
    
    $stats.PoliciesCreated = $policies.Count
    
    #endregion Phase 3.4: Cleanup Unreferenced Policies
    
    #endregion Phase 3: Real-time Protection Policy Processing
    
    #region Phase 4: Export and Summary
    
    Write-LogMessage -Message "===== Phase 4: Export and Summary =====" -Level "INFO" -LogPath $logPath
    
    #region Phase 4.1: Export Policies CSV
    
    try {
        $policiesCsvPath = Join-Path $OutputBasePath "${timestamp}_EIA_Policies.csv"
        $policies | Export-Csv -Path $policiesCsvPath -NoTypeInformation -Encoding utf8BOM
        Write-LogMessage -Message "Exported $($policies.Count) policy rules to: $policiesCsvPath" -Level "INFO" -LogPath $logPath
    }
    catch {
        $errorMsg = "Fatal error exporting policies CSV: $_"
        Write-LogMessage -Message $errorMsg -Level "ERROR" -LogPath $logPath
        throw $errorMsg
    }
    
    #endregion Phase 4.1: Export Policies CSV
    
    #region Phase 4.2: Export Security Profiles CSV with Priority Suffixes
    
    try {
        $spCsvPath = Join-Path $OutputBasePath "${timestamp}_EIA_SecurityProfiles.csv"
        
        # Add priority suffixes to policy links during export
        $securityProfilesForExport = $securityProfiles | ForEach-Object {
            $profile = $_ | Select-Object *
            $policyLinks = $_.SecurityProfileLinks -split ';'
            $formattedLinks = [System.Collections.ArrayList]::new()
            $linkPriority = 100
            foreach ($link in $policyLinks) {
                [void]$formattedLinks.Add("${link}:${linkPriority}")
                $linkPriority += 100
            }
            $profile.SecurityProfileLinks = $formattedLinks -join ';'
            $profile
        }
        
        $securityProfilesForExport | Export-Csv -Path $spCsvPath -NoTypeInformation -Encoding utf8BOM
        Write-LogMessage -Message "Exported $($securityProfiles.Count) security profiles to: $spCsvPath" -Level "INFO" -LogPath $logPath
    }
    catch {
        $errorMsg = "Fatal error exporting security profiles CSV: $_"
        Write-LogMessage -Message $errorMsg -Level "ERROR" -LogPath $logPath
        throw $errorMsg
    }
    
    #endregion Phase 4.2: Export Security Profiles CSV with Priority Suffixes
    
    #region Phase 4.3: Generate Summary Statistics
    
    Write-LogMessage -Message "" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "===== CONVERSION SUMMARY =====" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "Total real-time protection policies loaded: $($stats.TotalRTPoliciesLoaded)" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "Web policies processed (enabled, non-NPA): $($stats.WebPoliciesProcessed)" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "Policies skipped (disabled): $($stats.PoliciesSkippedDisabled)" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "Policies skipped (NPA): $($stats.PoliciesSkippedNPA)" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "Policies skipped (app_tags filter): $($stats.PoliciesSkippedAppTags)" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "Custom categories processed: $($stats.CustomCategoriesProcessed)" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "URL lists processed: $($stats.UrlListsProcessed)" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "  - Exact type: $($stats.UrlListsExact)" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "  - Regex type (flagged): $($stats.UrlListsRegex)" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "Predefined categories referenced: $($stats.PredefinedCategoriesReferenced)" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "Unmapped predefined categories:" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "  - Missing in mapping file: $($stats.UnmappedCategories_MissingInFile)" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "  - No matching GSA category: $($stats.UnmappedCategories_NoGSAValue)" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "Application objects found: $($stats.ApplicationObjectsFound)" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "Policies created: $($stats.PoliciesCreated)" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "  - Custom category policies: $($stats.CustomCategoryPolicies)" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "  - Predefined category policies: $($stats.PredefinedCategoryPolicies)" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "  - Application policies: $($stats.ApplicationPolicies)" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "Security profiles created: $($stats.SecurityProfilesCreated)" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "  - All users: $($stats.SecurityProfilesAllUsers)" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "  - Specific assignments: $($stats.SecurityProfilesSpecific)" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "URLs classified: $($stats.URLsClassified)" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "FQDNs classified: $($stats.FQDNsClassified)" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "IP addresses classified: $($stats.IPsClassified)" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "Entries skipped (IPv6, etc.): $($stats.EntriesSkipped)" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "Unreferenced policy rules removed: $($stats.UnreferencedPoliciesRemoved)" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "Output files:" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "  - Policies: $policiesCsvPath" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "  - Security Profiles: $spCsvPath" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "  - Log File: $logPath" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "" -Level "INFO" -LogPath $logPath
    Write-LogMessage -Message "===== Convert-NSWG2EIA Completed Successfully =====" -Level "INFO" -LogPath $logPath
    
    #endregion Phase 4.3: Generate Summary Statistics
    
    #endregion Phase 4: Export and Summary
    
    # Return summary object
    return [PSCustomObject]@{
        PoliciesCreated = $stats.PoliciesCreated
        SecurityProfilesCreated = $stats.SecurityProfilesCreated
        PoliciesCsvPath = $policiesCsvPath
        SecurityProfilesCsvPath = $spCsvPath
        LogFilePath = $logPath
    }
}
