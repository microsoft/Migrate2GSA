function Convert-ForcepointWS2EIA {
    <#
    .SYNOPSIS
        Converts Forcepoint Web Security (FWS) policies to Microsoft Entra Internet Access (EIA) format.
    
    .DESCRIPTION
        This function processes Forcepoint Web Security policy configuration to generate CSV files ready for 
        import into Microsoft Entra Internet Access (EIA). The function processes a matrix-style CSV file where 
        rows represent web categories (predefined or user-defined FQDNs) and columns represent security groups, 
        with cell values indicating the policy action (Block, Allow, Continue, Do not block).
        
        The conversion process includes:
        - Transforming Forcepoint category-based policies to EIA web content filtering policies
        - Converting Forcepoint security group assignments to EIA security profiles
        - Mapping Forcepoint predefined categories to GSA (Global Secure Access) web categories
        - Generating import-ready CSV files for EIA configuration
        - Deduplicating identical policies across security groups
    
    .PARAMETER ForcepointPoliciesPath
        Path to the Forcepoint Policies CSV export file. This should be a matrix-style CSV where rows represent
        web categories or FQDNs and columns represent security groups with their disposition settings.
    
    .PARAMETER CategoryMappingsPath
        Path to the Forcepoint to GSA category mappings CSV file. This file provides mapping between Forcepoint
        predefined web categories and Microsoft GSA (Global Secure Access) web categories.
    
    .PARAMETER OutputBasePath
        Base directory for output CSV files and log file.
        Default: Current directory
    
    .PARAMETER EnableDebugLogging
        Enable verbose debug logging for detailed processing information.
    
    .EXAMPLE
        Convert-ForcepointWS2EIA -ForcepointPoliciesPath "C:\FWS\policies.csv" -CategoryMappingsPath "C:\FWS\mappings.csv"
        
        Converts Forcepoint configuration from specified paths using default output directory.
    
    .EXAMPLE
        Convert-ForcepointWS2EIA -ForcepointPoliciesPath ".\policies.csv" -CategoryMappingsPath ".\mappings.csv" -OutputBasePath "C:\Output"
        
        Converts Forcepoint configuration and saves output to C:\Output.
    
    .EXAMPLE
        Convert-ForcepointWS2EIA -ForcepointPoliciesPath ".\policies.csv" -CategoryMappingsPath ".\mappings.csv" -EnableDebugLogging
        
        Converts Forcepoint configuration with detailed debug logging enabled.
    
    .NOTES
        Author: Andres Canello
        Version: 1.0
        Date: 2026-02-05
        
        Requirements:
        - Forcepoint Web Security policies CSV export (matrix format)
        - Forcepoint to GSA category mappings CSV file
        
        Known Limitations:
        - GSA limits: 100 policies, 1000 rules, 8000 FQDNs, 256 security profiles
        - Column headers must end with " Disposition" suffix
        - User-Defined detection relies on "User-Defined" as parent category name
        - No FQDN validation performed
    #>
    
    [CmdletBinding(SupportsShouldProcess = $false)]
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Path to Forcepoint Policies CSV export")]
        [ValidateScript({
            if (Test-Path $_) { return $true }
            else { throw "File not found: $_" }
        })]
        [string]$ForcepointPoliciesPath,
        
        [Parameter(Mandatory = $true, HelpMessage = "Path to Forcepoint to GSA category mappings CSV file")]
        [ValidateScript({
            if (Test-Path $_) { return $true }
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
    
    Set-StrictMode -Version Latest
    
    #region Helper Functions
    
    function Create-PolicyEntries {
        <#
        .SYNOPSIS
            Create policy CSV entries for a policy definition.
        
        .DESCRIPTION
            For each unique policy definition, creates CSV rows. Each policy has ONE action (Block or Allow),
            so if a security group has both blocked and allowed items, TWO separate policies are created.
            Web categories are combined into a single rule with semicolon-separated destinations.
            FQDNs are created as individual rules (one per FQDN).
        #>
        param(
            [Parameter(Mandatory = $true)]
            $PolicyDefObject,
            
            [Parameter(Mandatory = $true)]
            [AllowEmptyCollection()]
            [System.Collections.ArrayList]$Policies,
            
            [Parameter(Mandatory = $true)]
            [ref]$PolicyCounterRef
        )
        
        $def = $PolicyDefObject.Definition
        
        # Create Block policy with rules (if needed)
        if ($def.BlockedCategories.Count -gt 0 -or $def.BlockedFQDNs.Count -gt 0) {
            $blockPolicyName = "Web Content Filtering $($PolicyCounterRef.Value)-Block"
            $PolicyDefObject.BlockPolicyName = $blockPolicyName
            $PolicyCounterRef.Value++
            
            # Rule 1: Blocked categories
            if ($def.BlockedCategories.Count -gt 0) {
                # Check if THIS RULE needs review
                $ruleReviewNeeded = $false
                $ruleReviewReasons = @()
                
                # Check if any blocked categories are unmapped
                $unmappedInThisRule = $def.BlockedCategories | Where-Object { $_ -like '*_Unmapped' }
                if ($unmappedInThisRule) {
                    $ruleReviewNeeded = $true
                    $ruleReviewReasons += "Unmapped categories: $($unmappedInThisRule -join ', ')"
                }
                
                if ($def.HasContinueAction) {
                    $ruleReviewNeeded = $true
                    $ruleReviewReasons += "Continue action converted to Block (requires review)"
                }
                
                if ($def.HasAuthAction) {
                    $ruleReviewNeeded = $true
                    $ruleReviewReasons += "Auth action converted to Block (requires review)"
                }
                
                $ruleProvision = if ($ruleReviewNeeded) { "No" } else { "Yes" }
                $ruleReviewDetails = $ruleReviewReasons -join "; "
                
                [void]$Policies.Add([PSCustomObject]@{
                    PolicyName = $blockPolicyName
                    PolicyType = "WebContentFiltering"
                    PolicyAction = "Block"
                    Description = "Converted from Forcepoint - Block rules"
                    RuleType = "webCategory"
                    RuleDestinations = $def.BlockedCategories -join ";"
                    RuleName = "Blocked_Categories"
                    ReviewNeeded = if ($ruleReviewNeeded) { "Yes" } else { "No" }
                    ReviewDetails = $ruleReviewDetails
                    Provision = $ruleProvision
                })
                
                # Update statistics
                if ($ruleReviewNeeded) {
                    $script:stats.RulesNeedingReview++
                }
            }
            
            # Rules 2+: Blocked FQDNs (one per FQDN)
            foreach ($fqdn in $def.BlockedFQDNs) {
                $ruleReviewNeeded = $false
                $ruleReviewReasons = @()
                
                if ($def.HasContinueAction) {
                    $ruleReviewNeeded = $true
                    $ruleReviewReasons += "Continue action converted to Block (requires review)"
                }
                
                if ($def.HasAuthAction) {
                    $ruleReviewNeeded = $true
                    $ruleReviewReasons += "Auth action converted to Block (requires review)"
                }
                
                $ruleProvision = if ($ruleReviewNeeded) { "No" } else { "Yes" }
                $ruleReviewDetails = $ruleReviewReasons -join "; "
                
                [void]$Policies.Add([PSCustomObject]@{
                    PolicyName = $blockPolicyName
                    PolicyType = "WebContentFiltering"
                    PolicyAction = "Block"
                    Description = "Converted from Forcepoint - Block rules"
                    RuleType = "FQDN"
                    RuleDestinations = $fqdn
                    RuleName = "$fqdn-Block"
                    ReviewNeeded = if ($ruleReviewNeeded) { "Yes" } else { "No" }
                    ReviewDetails = $ruleReviewDetails
                    Provision = $ruleProvision
                })
                
                # Update statistics
                if ($ruleReviewNeeded) {
                    $script:stats.RulesNeedingReview++
                }
            }
            
            $script:stats.BlockPoliciesCreated++
        }
        
        # Create Allow policy with rules (if needed)
        if ($def.AllowedCategories.Count -gt 0 -or $def.AllowedFQDNs.Count -gt 0) {
            $allowPolicyName = "Web Content Filtering $($PolicyCounterRef.Value)-Allow"
            $PolicyDefObject.AllowPolicyName = $allowPolicyName
            $PolicyCounterRef.Value++
            
            # Rule 1: Allowed categories
            if ($def.AllowedCategories.Count -gt 0) {
                # Check if THIS RULE needs review
                $ruleReviewNeeded = $false
                $ruleReviewReasons = @()
                
                # Check if any allowed categories are unmapped
                $unmappedInThisRule = $def.AllowedCategories | Where-Object { $_ -like '*_Unmapped' }
                if ($unmappedInThisRule) {
                    $ruleReviewNeeded = $true
                    $ruleReviewReasons += "Unmapped categories: $($unmappedInThisRule -join ', ')"
                }
                
                $ruleProvision = if ($ruleReviewNeeded) { "No" } else { "Yes" }
                $ruleReviewDetails = $ruleReviewReasons -join "; "
                
                [void]$Policies.Add([PSCustomObject]@{
                    PolicyName = $allowPolicyName
                    PolicyType = "WebContentFiltering"
                    PolicyAction = "Allow"
                    Description = "Converted from Forcepoint - Allow rules"
                    RuleType = "webCategory"
                    RuleDestinations = $def.AllowedCategories -join ";"
                    RuleName = "Allowed_Categories"
                    ReviewNeeded = if ($ruleReviewNeeded) { "Yes" } else { "No" }
                    ReviewDetails = $ruleReviewDetails
                    Provision = $ruleProvision
                })
                
                # Update statistics
                if ($ruleReviewNeeded) {
                    $script:stats.RulesNeedingReview++
                }
            }
            
            # Rules 2+: Allowed FQDNs (one per FQDN)
            foreach ($fqdn in $def.AllowedFQDNs) {
                [void]$Policies.Add([PSCustomObject]@{
                    PolicyName = $allowPolicyName
                    PolicyType = "WebContentFiltering"
                    PolicyAction = "Allow"
                    Description = "Converted from Forcepoint - Allow rules"
                    RuleType = "FQDN"
                    RuleDestinations = $fqdn
                    RuleName = "$fqdn-Allow"
                    ReviewNeeded = "No"
                    ReviewDetails = ""
                    Provision = "Yes"
                })
            }
            
            $script:stats.AllowPoliciesCreated++
        }
    }
    
    #endregion
    
    #region Initialization
    
    # Initialize logging
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $script:logPath = Join-Path $OutputBasePath "${timestamp}_Convert-ForcepointWS2EIA.log"
    $script:EnableDebugLogging = $EnableDebugLogging
    
    Write-LogMessage "Starting Forcepoint Web Security to EIA conversion" -Level "INFO" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "" -Level "INFO"
    
    Write-LogMessage "Input files:" -Level "INFO" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  Forcepoint Policies: $ForcepointPoliciesPath" -Level "INFO" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  Category Mappings: $CategoryMappingsPath" -Level "INFO" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  Output Path: $OutputBasePath" -Level "INFO" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "" -Level "INFO"
    
    # Initialize statistics
    $script:stats = @{
        # Input (raw counts)
        TotalRowsProcessed = 0
        SecurityGroupsFound = 0
        DefaultGroupIncluded = $false
        
        # Actions (total occurrence counts)
        ContinueActionsConverted = 0
        AuthActionsConverted = 0
        BlockActionsProcessed = 0
        AllowActionsProcessed = 0
        UnknownActionsSkipped = 0
        
        # Categories (occurrence-based counts)
        TotalUnmappedCategories = 0
        TotalMappedCategories = 0
        TotalUserDefinedFQDNs = 0
        
        # Deduplication
        TotalSecurityGroups = 0
        UniquePolicyDefinitions = 0
        GroupsSharingPolicies = 0
        
        # Outputs
        UniquePoliciesCreated = 0
        BlockPoliciesCreated = 0
        AllowPoliciesCreated = 0
        PolicyEntriesCreated = 0
        RulesNeedingReview = 0
        SecurityProfilesCreated = 0
    }
    
    # Initialize collections
    $policyDefinitionsHashtable = @{}  # Hash → PolicyDefinitionObject
    $groupToPolicyDefHashtable = @{}   # GroupName → PolicyDefinitionHash
    
    # Sequential counters
    $policyCounter = 1
    $securityProfileCounter = 1
    
    # Collections for output
    $policies = [System.Collections.ArrayList]::new()
    $securityProfiles = [System.Collections.ArrayList]::new()
    
    #endregion
    
    #region Phase 1: Data Loading
    
    Write-LogMessage "Phase 1: Loading input files" -Level "INFO" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    
    # Load Forcepoint Policies CSV
    try {
        Write-LogMessage "Loading Forcepoint policies from: $ForcepointPoliciesPath" -Level "DEBUG" `
            -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        
        $policiesCsv = Import-Csv -Path $ForcepointPoliciesPath -Encoding UTF8
        
        if ($policiesCsv.Count -eq 0) {
            throw "Forcepoint policies CSV is empty"
        }
        
        Write-LogMessage "Loaded $($policiesCsv.Count) rows from Forcepoint policies" -Level "INFO" `
            -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        
        $stats.TotalRowsProcessed = $policiesCsv.Count
    }
    catch {
        Write-LogMessage "Failed to load Forcepoint policies: $_" -Level "ERROR" `
            -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        throw
    }
    
    # Validate CSV structure
    if ($policiesCsv.Count -eq 0) {
        throw "Forcepoint policies CSV is empty"
    }
    
    $firstRow = $policiesCsv[0]
    $allColumns = $firstRow.PSObject.Properties.Name
    
    if ($allColumns.Count -lt 3) {
        throw "Invalid CSV structure: minimum 3 columns required (Parent Category Name, Child Category Name, DEFAULT Disposition)"
    }
    
    # Load Category Mappings CSV
    try {
        Write-LogMessage "Loading category mappings from: $CategoryMappingsPath" -Level "DEBUG" `
            -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        
        $categoryMappings = Import-Csv -Path $CategoryMappingsPath -Encoding UTF8
        
        if ($categoryMappings.Count -eq 0) {
            throw "Category mappings CSV is empty"
        }
        
        # Validate required columns
        $mappingColumns = $categoryMappings[0].PSObject.Properties.Name
        if ($mappingColumns -notcontains 'ForcepointCategory' -or $mappingColumns -notcontains 'GSACategory') {
            throw "Invalid category mappings CSV: missing required columns (ForcepointCategory, GSACategory)"
        }
        
        Write-LogMessage "Loaded $($categoryMappings.Count) category mappings" -Level "INFO" `
            -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }
    catch {
        Write-LogMessage "Failed to load category mappings: $_" -Level "ERROR" `
            -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        throw
    }
    
    # Identify Security Group Columns
    Write-LogMessage "Identifying security group columns" -Level "DEBUG" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    
    # Filter for disposition columns (exclude first 3 fixed columns)
    $groupColumns = $allColumns | Where-Object {
        $_ -notmatch '^(Parent Category Name|Child Category Name|DEFAULT Disposition)$' -and
        $_ -match 'Disposition$'
    }
    
    if ($groupColumns.Count -eq 0 -and $allColumns -notcontains 'DEFAULT Disposition') {
        throw "No security group columns found. CSV must contain at least 'DEFAULT Disposition' or security group columns ending with 'Disposition'"
    }
    
    # Extract group names
    $securityGroups = $groupColumns | ForEach-Object {
        ($_ -replace ' Disposition$', '').Trim()
    }
    
    # Check for DEFAULT disposition
    if ($allColumns -match '^DEFAULT Disposition$') {
        $stats.DefaultGroupIncluded = $true
        if ($securityGroups -notcontains 'DEFAULT') {
            $securityGroups = @('DEFAULT') + $securityGroups
        }
    }
    
    # Store original column order for priority assignment
    $groupColumnOrder = @{}
    $priority = 0
    foreach ($col in ($allColumns | Where-Object { $_ -match 'Disposition$' })) {
        $groupName = ($col -replace ' Disposition$', '').Trim()
        $groupColumnOrder[$groupName] = $priority
        $priority++
    }
    
    $stats.SecurityGroupsFound = $securityGroups.Count
    $stats.TotalSecurityGroups = $securityGroups.Count
    
    # Log security groups vs DEFAULT policy separately for clarity
    $actualGroups = $securityGroups | Where-Object { $_ -ne 'DEFAULT' }
    $hasDefault = $securityGroups -contains 'DEFAULT'
    
    if ($hasDefault -and $actualGroups.Count -gt 0) {
        Write-LogMessage "Found DEFAULT policy and $($actualGroups.Count) security groups: $($actualGroups -join ', ')" -Level "INFO" `
            -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }
    elseif ($hasDefault) {
        Write-LogMessage "Found DEFAULT policy (no additional security groups)" -Level "INFO" `
            -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }
    else {
        Write-LogMessage "Found $($securityGroups.Count) security groups: $($securityGroups -join ', ')" -Level "INFO" `
            -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }
    
    # Build Category Mapping Hashtable
    Write-LogMessage "Building category mapping lookup table" -Level "DEBUG" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    
    $categoryMappingsHashtable = @{}
    foreach ($mapping in $categoryMappings) {
        $categoryMappingsHashtable[$mapping.ForcepointCategory] = $mapping
    }
    
    Write-LogMessage "Phase 1 complete" -Level "INFO" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "" -Level "INFO"
    
    #endregion
    
    #region Phase 2: Parse Forcepoint Policies
    
    Write-LogMessage "Phase 2: Parsing Forcepoint policies by security group" -Level "INFO" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    
    foreach ($groupName in $securityGroups) {
        Write-LogMessage "Processing security group: $groupName" -Level "DEBUG" `
            -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        
        # Initialize policy definition for this group
        $policyDefinition = @{
            BlockedCategories = @()
            AllowedCategories = @()
            BlockedFQDNs = @()
            AllowedFQDNs = @()
            HasContinueAction = $false
            HasAuthAction = $false
            UnmappedCategories = @()
        }
        
        # Determine disposition column name
        $dispositionColumn = if ($groupName -eq 'DEFAULT') {
            'DEFAULT Disposition'
        } else {
            "$groupName Disposition"
        }
        
        # Check if column exists
        if ($allColumns -notcontains $dispositionColumn) {
            Write-LogMessage "Disposition column not found for group '$groupName', skipping" -Level "WARN" `
                -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            continue
        }
        
        # Process each row
        foreach ($row in $policiesCsv) {
            $parentCategory = $row.'Parent Category Name'
            $childCategory = $row.'Child Category Name'
            $disposition = $row.$dispositionColumn
            
            # Skip if no disposition or empty
            if ([string]::IsNullOrWhiteSpace($disposition)) {
                continue
            }
            
            # Normalize disposition
            $disposition = $disposition.Trim()
            
            # Map action (case-insensitive)
            $action = switch -Regex ($disposition) {
                '^Block$' { 
                    $stats.BlockActionsProcessed++
                    'Block' 
                }
                '^Continue$' { 
                    $policyDefinition.HasContinueAction = $true
                    $stats.ContinueActionsConverted++
                    $stats.BlockActionsProcessed++
                    'Block' 
                }
                '^Auth$' { 
                    $policyDefinition.HasAuthAction = $true
                    $stats.AuthActionsConverted++
                    $stats.BlockActionsProcessed++
                    'Block' 
                }
                '^Allow$' { 
                    $stats.AllowActionsProcessed++
                    'Allow' 
                }
                '^Do not block$' { 
                    $stats.AllowActionsProcessed++
                    'Allow' 
                }
                default { 
                    Write-LogMessage "Unknown disposition '$disposition' for $childCategory in group $groupName" -Level "WARN" `
                        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                    $stats.UnknownActionsSkipped++
                    $null 
                }
            }
            
            if ($null -eq $action) { 
                continue 
            }
            
            # Categorize and add to appropriate collection
            if ($parentCategory -eq 'User-Defined') {
                # FQDN entry
                $stats.TotalUserDefinedFQDNs++
                
                if ($action -eq 'Block') {
                    $policyDefinition.BlockedFQDNs += $childCategory
                }
                else {
                    $policyDefinition.AllowedFQDNs += $childCategory
                }
            }
            else {
                # Predefined category - lookup in mapping
                $mapping = $categoryMappingsHashtable[$childCategory]
                
                if ($null -eq $mapping -or 
                    [string]::IsNullOrWhiteSpace($mapping.GSACategory) -or 
                    $mapping.GSACategory -eq 'Unmapped') {
                    
                    # Unmapped category
                    $gsaCategory = "${childCategory}_Unmapped"
                    $policyDefinition.UnmappedCategories += $childCategory
                    $stats.TotalUnmappedCategories++
                }
                else {
                    $gsaCategory = $mapping.GSACategory
                    $stats.TotalMappedCategories++
                }
                
                # Add to appropriate list
                if ($action -eq 'Block') {
                    $policyDefinition.BlockedCategories += $gsaCategory
                }
                else {
                    $policyDefinition.AllowedCategories += $gsaCategory
                }
            }
        }
        
        # Deduplicate and sort
        $policyDefinition.BlockedCategories = @($policyDefinition.BlockedCategories | 
            Select-Object -Unique | Sort-Object)
        $policyDefinition.AllowedCategories = @($policyDefinition.AllowedCategories | 
            Select-Object -Unique | Sort-Object)
        $policyDefinition.BlockedFQDNs = @($policyDefinition.BlockedFQDNs | 
            Select-Object -Unique | Sort-Object)
        $policyDefinition.AllowedFQDNs = @($policyDefinition.AllowedFQDNs | 
            Select-Object -Unique | Sort-Object)
        $policyDefinition.UnmappedCategories = @($policyDefinition.UnmappedCategories | 
            Select-Object -Unique | Sort-Object)
        
        # Skip empty policy definitions
        $totalItems = $policyDefinition.BlockedCategories.Count + 
                      $policyDefinition.AllowedCategories.Count + 
                      $policyDefinition.BlockedFQDNs.Count + 
                      $policyDefinition.AllowedFQDNs.Count
        
        if ($totalItems -eq 0) {
            Write-LogMessage "Security group '$groupName' has no dispositions defined, skipping" -Level "INFO" `
                -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            continue
        }
        
        Write-LogMessage "Group '$groupName' summary: $($policyDefinition.BlockedCategories.Count) blocked categories, $($policyDefinition.AllowedCategories.Count) allowed categories, $($policyDefinition.BlockedFQDNs.Count) blocked FQDNs, $($policyDefinition.AllowedFQDNs.Count) allowed FQDNs" -Level "DEBUG" `
            -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        
        # Generate policy definition hash
        $hashInput = @(
            "BlockedCategories:$($policyDefinition.BlockedCategories -join ',')"
            "AllowedCategories:$($policyDefinition.AllowedCategories -join ',')"
            "BlockedFQDNs:$($policyDefinition.BlockedFQDNs -join ',')"
            "AllowedFQDNs:$($policyDefinition.AllowedFQDNs -join ',')"
        ) -join '|'
        
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($hashInput))
        $hash = [BitConverter]::ToString($hashBytes) -replace '-', ''
        
        # Check for duplicate policy
        if ($policyDefinitionsHashtable.ContainsKey($hash)) {
            # Policy already exists - reuse it
            $existingPolicyDef = $policyDefinitionsHashtable[$hash]
            
            # Add this group to the existing policy's group list
            $existingPolicyDef.SecurityGroups += $groupName
            
            # Store mapping for security profile creation
            $groupToPolicyDefHashtable[$groupName] = $hash
            
            $stats.GroupsSharingPolicies++
            
            Write-LogMessage "Security group '$groupName' matches existing policy definition (hash: $($hash.Substring(0,8))...)" -Level "DEBUG" `
                -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        }
        else {
            # New unique policy - create policies for Block and/or Allow
            Write-LogMessage "Creating new policy definition for group '$groupName'" -Level "DEBUG" `
                -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            
            # Store policy definition
            $policyDefObject = @{
                Hash = $hash
                Definition = $policyDefinition
                SecurityGroups = @($groupName)
                BlockPolicyName = $null
                AllowPolicyName = $null
            }
            
            $policyDefinitionsHashtable[$hash] = $policyDefObject
            $groupToPolicyDefHashtable[$groupName] = $hash
            
            $stats.UniquePolicyDefinitions++
            
            # Create policy entries (assigns policy names with unique numbers)
            Create-PolicyEntries -PolicyDefObject $policyDefObject -Policies $policies -PolicyCounterRef ([ref]$policyCounter)
        }
    }
    
    $stats.UniquePoliciesCreated = ($policies | Select-Object -Property PolicyName -Unique).Count
    $stats.PolicyEntriesCreated = $policies.Count
    
    Write-LogMessage "Phase 2 complete: Created $($stats.UniquePoliciesCreated) unique policies with $($stats.PolicyEntriesCreated) total rules" -Level "INFO" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "" -Level "INFO"
    
    #endregion
    
    #region Phase 3: Security Profile Creation
    
    Write-LogMessage "Phase 3: Creating security profiles" -Level "INFO" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    
    # Invert the mapping: Hash → List of groups
    $hashToGroupsHashtable = @{}
    
    foreach ($groupName in $groupToPolicyDefHashtable.Keys) {
        $hash = $groupToPolicyDefHashtable[$groupName]
        
        if (-not $hashToGroupsHashtable.ContainsKey($hash)) {
            $hashToGroupsHashtable[$hash] = @()
        }
        
        $hashToGroupsHashtable[$hash] += $groupName
    }
    
    # Assign priorities based on column order
    $groupPriorities = @{}
    $defaultPriority = 60000
    $currentPriority = 500
    
    $groupsToProcess = $securityGroups | Sort-Object { $groupColumnOrder[$_] }
    
    foreach ($groupName in $groupsToProcess) {
        if ($groupName -eq 'DEFAULT') {
            $groupPriorities[$groupName] = $defaultPriority
        }
        else {
            $groupPriorities[$groupName] = $currentPriority
            $currentPriority += 100
        }
    }
    
    # Create security profiles
    foreach ($hash in $hashToGroupsHashtable.Keys) {
        $policyDefObject = $policyDefinitionsHashtable[$hash]
        $groups = $hashToGroupsHashtable[$hash]
        
        # Group names preserve spaces (only trim whitespace at start/end)
        $targetGroups = $groups | ForEach-Object { $_.Trim() }
        
        # Determine priority (use lowest priority of all groups sharing this policy)
        $priority = ($groups | ForEach-Object { $groupPriorities[$_] } | Measure-Object -Minimum).Minimum
        
        # Handle DEFAULT group
        if ($groups -contains 'DEFAULT') {
            $targetGroup = 'Replace_with_All_IA_Users_Group'
        }
        else {
            $targetGroup = $targetGroups -join ";"
        }
        
        # Build policy links
        # IMPORTANT: Allow policies FIRST, then Block policies
        $policyLinks = @()
        $linkPriority = 100
        
        # Add Allow policy first (if exists)
        if ($policyDefObject.AllowPolicyName) {
            $policyLinks += "$($policyDefObject.AllowPolicyName):${linkPriority}"
            $linkPriority += 100
        }
        
        # Add Block policy second (if exists)
        if ($policyDefObject.BlockPolicyName) {
            $policyLinks += "$($policyDefObject.BlockPolicyName):${linkPriority}"
            $linkPriority += 100
        }
        
        # Create security profile
        $profileName = "Security_Profile_$securityProfileCounter"
        $securityProfileCounter++
        
        $securityProfile = [PSCustomObject]@{
            SecurityProfileName = $profileName
            Priority = $priority
            SecurityProfileLinks = $policyLinks -join ";"
            CADisplayName = "CA_$profileName"
            EntraUsers = "_Replace_Me"
            EntraGroups = $targetGroup
            Description = "Converted from Forcepoint - Groups: $($groups -join ', ')"
            Provision = "Yes"
        }
        
        [void]$securityProfiles.Add($securityProfile)
        
        Write-LogMessage "Created $profileName for groups: $($groups -join ', ') (priority: $priority)" -Level "DEBUG" `
            -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }
    
    # Sort security profiles by priority
    $sortedProfiles = $securityProfiles | Sort-Object -Property Priority
    $securityProfiles = [System.Collections.ArrayList]::new($sortedProfiles)
    
    $stats.SecurityProfilesCreated = $securityProfiles.Count
    
    Write-LogMessage "Phase 3 complete: Created $($stats.SecurityProfilesCreated) security profiles" -Level "INFO" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "" -Level "INFO"
    
    #endregion
    
    #region Phase 4: Export and Summary
    
    Write-LogMessage "Phase 4: Exporting output files" -Level "INFO" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    
    # Export Policies CSV
    $policiesCsvPath = Join-Path $OutputBasePath "${timestamp}_EIA_Policies.csv"
    $policies | Export-Csv -Path $policiesCsvPath -NoTypeInformation -Encoding utf8BOM
    Write-LogMessage "Exported $($policies.Count) policy entries to: $policiesCsvPath" -Level "INFO" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    
    # Export Security Profiles CSV
    $spCsvPath = Join-Path $OutputBasePath "${timestamp}_EIA_SecurityProfiles.csv"
    $securityProfiles | Export-Csv -Path $spCsvPath -NoTypeInformation -Encoding utf8BOM
    Write-LogMessage "Exported $($securityProfiles.Count) security profiles to: $spCsvPath" -Level "INFO" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    
    Write-LogMessage "" -Level "INFO"
    
    # Generate Summary Statistics
    Write-LogMessage "=== CONVERSION SUMMARY ===" -Level "SUMMARY" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "" -Level "INFO"
    
    Write-LogMessage "Input Processing:" -Level "SUMMARY" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Total Forcepoint rows processed: $($stats.TotalRowsProcessed)" -Level "SUMMARY" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Security groups found: $($stats.SecurityGroupsFound)" -Level "SUMMARY" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - DEFAULT group included: $(if ($stats.DefaultGroupIncluded) { 'Yes' } else { 'No' })" -Level "SUMMARY" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "" -Level "INFO"
    
    Write-LogMessage "Policy Creation:" -Level "SUMMARY" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Unique policies created: $($stats.UniquePoliciesCreated)" -Level "SUMMARY" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "    - Block policies: $($stats.BlockPoliciesCreated)" -Level "SUMMARY" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "    - Allow policies: $($stats.AllowPoliciesCreated)" -Level "SUMMARY" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Total policy entries (CSV rows): $($stats.PolicyEntriesCreated)" -Level "SUMMARY" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Rules requiring review: $($stats.RulesNeedingReview)" -Level "SUMMARY" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "" -Level "INFO"
    
    Write-LogMessage "Security Profiles:" -Level "SUMMARY" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Security profiles created: $($stats.SecurityProfilesCreated)" -Level "SUMMARY" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "" -Level "INFO"
    
    Write-LogMessage "Actions Processed:" -Level "SUMMARY" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Block actions: $($stats.BlockActionsProcessed)" -Level "SUMMARY" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Allow actions: $($stats.AllowActionsProcessed)" -Level "SUMMARY" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Continue actions converted to Block: $($stats.ContinueActionsConverted)" -Level "SUMMARY" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Auth actions converted to Block: $($stats.AuthActionsConverted)" -Level "SUMMARY" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Unknown actions skipped: $($stats.UnknownActionsSkipped)" -Level "SUMMARY" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "" -Level "INFO"
    
    Write-LogMessage "Category Mapping:" -Level "SUMMARY" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Mapped categories: $($stats.TotalMappedCategories)" -Level "SUMMARY" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Unmapped categories: $($stats.TotalUnmappedCategories)" -Level "SUMMARY" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - User-defined FQDNs: $($stats.TotalUserDefinedFQDNs)" -Level "SUMMARY" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "" -Level "INFO"
    
    Write-LogMessage "Deduplication Results:" -Level "SUMMARY" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Total security groups: $($stats.TotalSecurityGroups)" -Level "SUMMARY" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Unique policy definitions: $($stats.UniquePolicyDefinitions)" -Level "SUMMARY" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Groups sharing policies: $($stats.GroupsSharingPolicies)" -Level "SUMMARY" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "" -Level "INFO"
    
    Write-LogMessage "Output Files:" -Level "SUMMARY" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Policies: $policiesCsvPath" -Level "SUMMARY" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Security Profiles: $spCsvPath" -Level "SUMMARY" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Log File: $logPath" -Level "SUMMARY" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "" -Level "INFO"
    
    # Validate Against GSA Limits
    $limits = @{
        MaxPolicies = 100
        MaxRules = 1000
        MaxFQDNs = 8000
        MaxSecurityProfiles = 256
    }
    
    $uniquePolicies = ($policies | Select-Object -Property PolicyName -Unique).Count
    $totalRules = $policies.Count
    $totalFQDNs = ($policies | Where-Object { $_.RuleType -eq 'FQDN' }).Count
    
    Write-LogMessage "GSA Limits Validation:" -Level "SUMMARY" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    
    if ($uniquePolicies -gt $limits.MaxPolicies) {
        Write-LogMessage "  WARNING: Unique policies ($uniquePolicies) exceeds limit of $($limits.MaxPolicies)" -Level "WARN" `
            -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    } else {
        Write-LogMessage "  - Policies: $uniquePolicies / $($limits.MaxPolicies) (OK)" -Level "SUMMARY" `
            -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }
    
    if ($totalRules -gt $limits.MaxRules) {
        Write-LogMessage "  WARNING: Total rules ($totalRules) exceeds limit of $($limits.MaxRules)" -Level "WARN" `
            -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    } else {
        Write-LogMessage "  - Rules: $totalRules / $($limits.MaxRules) (OK)" -Level "SUMMARY" `
            -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }
    
    if ($totalFQDNs -gt $limits.MaxFQDNs) {
        Write-LogMessage "  WARNING: Total FQDNs ($totalFQDNs) exceeds limit of $($limits.MaxFQDNs)" -Level "WARN" `
            -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    } else {
        Write-LogMessage "  - FQDNs: $totalFQDNs / $($limits.MaxFQDNs) (OK)" -Level "SUMMARY" `
            -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }
    
    if ($securityProfiles.Count -gt $limits.MaxSecurityProfiles) {
        Write-LogMessage "  WARNING: Security profiles ($($securityProfiles.Count)) exceeds limit of $($limits.MaxSecurityProfiles)" -Level "WARN" `
            -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    } else {
        Write-LogMessage "  - Security Profiles: $($securityProfiles.Count) / $($limits.MaxSecurityProfiles) (OK)" -Level "SUMMARY" `
            -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }
    
    Write-LogMessage "" -Level "INFO"
    Write-LogMessage "Conversion completed successfully" -Level "SUCCESS" `
        -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    
    #endregion
}
