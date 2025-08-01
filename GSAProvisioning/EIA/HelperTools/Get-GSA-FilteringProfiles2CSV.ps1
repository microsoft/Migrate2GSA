[CmdletBinding()]
param(
    [Parameter(HelpMessage = "Base directory for output files and logs")]
    [ValidateScript({
        if (Test-Path $_ -PathType Container) { return $true }
        else { throw "Directory not found: $_" }
    })]
    [string]$OutputBasePath = $PWD,
    
    [Parameter(HelpMessage = "Enable verbose debug logging")]
    [switch]$EnableDebugLogging,
    
    [Parameter(HelpMessage = "Tenant ID for Microsoft Graph authentication")]
    [string]$TenantId,
    
    [Parameter(HelpMessage = "Filter by specific filtering profile name")]
    [string]$ProfileNameFilter,
    
    [Parameter(HelpMessage = "Include additional metadata and timestamps")]
    [switch]$IncludeMetadata
)

# Set strict mode for better error handling
Set-StrictMode -Version Latest

# Initialize logging
$script:LogFolder = Join-Path $OutputBasePath "logs"
$script:LogFile = $null
$script:CSVFolder = Join-Path $OutputBasePath "CSVs"

#region Helper Functions

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "DEBUG")]
        [string]$Level = "INFO",
        
        [Parameter(Mandatory = $false)]
        [string]$Component = "Main"
    )
    
    try {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logLevel = "[$Level]"
        $logComponent = "[$Component]"
        $logMessage = "[$timestamp] $logLevel $logComponent $Message"
        
        # Color coding for console output
        switch ($Level) {
            "ERROR" { Write-Host $logMessage -ForegroundColor Red }
            "WARN" { Write-Host $logMessage -ForegroundColor Yellow }
            "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
            "DEBUG" { 
                if ($EnableDebugLogging) {
                    Write-Host $logMessage -ForegroundColor Cyan 
                }
            }
            default { Write-Host $logMessage -ForegroundColor White }
        }
        
        # Write to log file if specified
        if ($script:LogFile -and (Test-Path $script:LogFile -IsValid)) {
            try {
                Add-Content -Path $script:LogFile -Value $logMessage -ErrorAction SilentlyContinue
            }
            catch {
                # Silently ignore log file write errors to prevent infinite loops
            }
        }
    }
    catch {
        Write-Warning "Failed to write log: $_"
    }
}

function Test-Prerequisites {
    Write-Log "Checking required PowerShell modules..." -Component "Prerequisites"
    
    $requiredModules = @(
        'Microsoft.Graph.Authentication',
        'Microsoft.Graph.Identity.DirectoryManagement'
    )
    
    $missingModules = @()
    
    foreach ($module in $requiredModules) {
        if (Get-Module -ListAvailable -Name $module) {
            Write-Log "Found module: $module" -Level "DEBUG" -Component "Prerequisites"
        } else {
            $missingModules += $module
        }
    }
    
    if ($missingModules.Count -gt 0) {
        Write-Log "Missing required modules: $($missingModules -join ', ')" -Level "ERROR" -Component "Prerequisites"
        return $false
    }
    
    Write-Log "All required modules are available" -Level "SUCCESS" -Component "Prerequisites"
    return $true
}

function Connect-ToMSGraph {
    param(
        [string]$TenantId
    )
    
    Write-Log "Connecting to Microsoft Graph..." -Component "Authentication"
    
    try {
        # Required scopes for Global Secure Access
        $scopes = @(
            'NetworkAccess.Read.All',
            'Policy.Read.All',
            'Directory.Read.All'
        )
        
        $connectParams = @{
            Scopes = $scopes
        }
        
        if ($TenantId) {
            $connectParams.TenantId = $TenantId
        }
        
        Connect-MgGraph @connectParams
        
        $context = Get-MgContext
        Write-Log "Connected to Microsoft Graph successfully" -Level "SUCCESS" -Component "Authentication"
        Write-Log "Tenant: $($context.TenantId)" -Level "DEBUG" -Component "Authentication"
        Write-Log "Account: $($context.Account)" -Level "DEBUG" -Component "Authentication"
        
        return $true
    }
    catch {
        Write-Log "Failed to connect to Microsoft Graph: $_" -Level "ERROR" -Component "Authentication"
        return $false
    }
}

function Get-GSAFilteringProfiles {
    Write-Log "Retrieving Global Secure Access filtering profiles..." -Component "DataRetrieval"
    
    try {
        Write-Log "Calling Microsoft Graph Network Access API for filtering profiles..." -Level "DEBUG" -Component "DataRetrieval"
        
        # Use actual Microsoft Graph Network Access API with conditionalAccessPolicies expanded
        $uri = "https://graph.microsoft.com/beta/networkAccess/filteringProfiles?`$expand=conditionalAccessPolicies"
        $response = Invoke-MgGraphRequest -Uri $uri -Method GET
        
        # Handle both direct arrays and paginated responses
        $profiles = if ($response.value) { $response.value } else { $response }
        
        if (-not $profiles) {
            Write-Log "No filtering profiles found in tenant" -Level "WARN" -Component "DataRetrieval"
            return @()
        }
        
        Write-Log "Retrieved $($profiles.Count) filtering profiles with CA policy associations" -Level "SUCCESS" -Component "DataRetrieval"
        return $profiles
    }
    catch {
        Write-Log "Failed to retrieve filtering profiles: $_" -Level "ERROR" -Component "DataRetrieval"
        throw
    }
}

function Get-GSAFilteringPolicies {
    param(
        [string]$ProfileId
    )
    
    Write-Log "Retrieving filtering policies for profile: $ProfileId" -Level "DEBUG" -Component "DataRetrieval"
    
    try {
        # Use actual Microsoft Graph Network Access API
        $uri = "https://graph.microsoft.com/beta/networkAccess/filteringProfiles('$ProfileId')/policies"
        $response = Invoke-MgGraphRequest -Uri $uri -Method GET
        
        # Handle both direct arrays and paginated responses
        $policies = if ($response.value) { $response.value } else { $response }
        
        if (-not $policies) {
            Write-Log "No filtering policies found for profile $ProfileId" -Level "WARN" -Component "DataRetrieval"
            return @()
        }
        
        Write-Log "Retrieved $($policies.Count) filtering policies for profile $ProfileId" -Level "DEBUG" -Component "DataRetrieval"
        return $policies
    }
    catch {
        Write-Log "Failed to retrieve filtering policies for profile $ProfileId : $_" -Level "ERROR" -Component "DataRetrieval"
        throw
    }
}

function Get-GSAFilteringRules {
    param(
        [string]$PolicyId
    )
    
    Write-Log "Retrieving filtering rules for policy: $PolicyId" -Level "DEBUG" -Component "DataRetrieval"
    
    try {
        # Use actual Microsoft Graph Network Access API
        $uri = "https://graph.microsoft.com/beta/networkAccess/filteringPolicies('$PolicyId')/policyRules"
        $response = Invoke-MgGraphRequest -Uri $uri -Method GET
        
        # Handle both direct arrays and paginated responses
        $rules = if ($response.value) { $response.value } else { $response }
        
        if (-not $rules) {
            Write-Log "No filtering rules found for policy $PolicyId" -Level "WARN" -Component "DataRetrieval"
            return @()
        }
        
        Write-Log "Retrieved $($rules.Count) filtering rules for policy $PolicyId" -Level "DEBUG" -Component "DataRetrieval"
        return $rules
    }
    catch {
        Write-Log "Failed to retrieve filtering rules for policy $PolicyId : $_" -Level "ERROR" -Component "DataRetrieval"
        throw
    }
}

function Get-ConditionalAccessPolicies {
    Write-Log "Retrieving Conditional Access policies..." -Level "DEBUG" -Component "DataRetrieval"
    
    try {
        # Use actual Microsoft Graph API for Conditional Access policies
        $uri = "https://graph.microsoft.com/beta/identity/conditionalAccess/policies"
        $response = Invoke-MgGraphRequest -Uri $uri -Method GET
        
        # Handle both direct arrays and paginated responses
        $policies = if ($response.value) { $response.value } else { $response }
        
        if (-not $policies) {
            Write-Log "No Conditional Access policies found" -Level "WARN" -Component "DataRetrieval"
            return @()
        }
        
        Write-Log "Retrieved $($policies.Count) Conditional Access policies" -Level "DEBUG" -Component "DataRetrieval"
        return $policies
    }
    catch {
        Write-Log "Failed to retrieve Conditional Access policies: $_" -Level "ERROR" -Component "DataRetrieval"
        return @()
    }
}

function Get-CATargetInfo {
    param(
        [string]$ConditionalAccessPolicyId
    )
    
    if (-not $ConditionalAccessPolicyId) {
        return @{
            Groups = "No-CA-Policy-Assigned"
            Users = "No-CA-Policy-Assigned"
        }
    }
    
    try {
        Write-Log "Retrieving target groups and users for CA policy: $ConditionalAccessPolicyId" -Level "DEBUG" -Component "DataProcessing"
        $fullCAPolicy = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies/$ConditionalAccessPolicyId" -Method GET -ErrorAction SilentlyContinue
        
        # Process target groups
        $targetGroupNames = @()
        if ($fullCAPolicy.conditions.users.includeGroups) {
            foreach ($groupId in $fullCAPolicy.conditions.users.includeGroups) {
                try {
                    $group = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/groups/$groupId" -Method GET -ErrorAction SilentlyContinue
                    if ($group.displayName) {
                        $targetGroupNames += $group.displayName
                    }
                }
                catch {
                    $targetGroupNames += "Group-$groupId"
                }
            }
        }
        
        # Process target users
        $targetUserNames = @()
        if ($fullCAPolicy.conditions.users.includeUsers) {
            foreach ($userId in $fullCAPolicy.conditions.users.includeUsers) {
                try {
                    $user = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/users/$userId" -Method GET -ErrorAction SilentlyContinue
                    if ($user.displayName) {
                        $userInfo = "$($user.displayName) ($($user.userPrincipalName))"
                        $targetUserNames += $userInfo
                    }
                }
                catch {
                    $targetUserNames += "User-$userId"
                }
            }
        }
        
        $groups = if ($targetGroupNames.Count -gt 0) { $targetGroupNames -join "; " } else { "All-Users" }
        $users = if ($targetUserNames.Count -gt 0) { $targetUserNames -join "; " } else { "" }
        
        return @{
            Groups = $groups
            Users = $users
        }
    }
    catch {
        Write-Log "Could not retrieve CA policy targeting details for $ConditionalAccessPolicyId" -Level "WARN" -Component "DataProcessing"
        return @{
            Groups = "Unknown-Target"
            Users = "Unknown-Target"
        }
    }
}

function Convert-ToCSVFormat {
    param(
        [object[]]$Profiles,
        [object[]]$ConditionalAccessPolicies
    )
    
    Write-Log "Converting GSA configuration to CSV format..." -Component "DataProcessing"
    
    $csvData = @()
    $currentDateTime = Get-Date
    
    # Create lookup hashtable for CA policies
    $caLookup = @{}
    foreach ($cap in $ConditionalAccessPolicies) {
        $caLookup[$cap.displayName] = $cap.id
    }
    
    foreach ($profile in $Profiles) {
        Write-Log "Processing profile: $($profile.name)" -Level "DEBUG" -Component "DataProcessing"
        
        # Apply profile filter if specified
        if ($ProfileNameFilter -and $profile.name -ne $ProfileNameFilter) {
            Write-Log "Skipping profile $($profile.name) due to filter" -Level "DEBUG" -Component "DataProcessing"
            continue
        }
        
        $policies = Get-GSAFilteringPolicies -ProfileId $profile.id
        $profileProcessed = $false
        
        foreach ($policyLink in $policies) {
            # Extract the actual policy from the policy link
            $policy = if ($policyLink.policy) { $policyLink.policy } else { $policyLink }
            
            Write-Log "Processing policy: $($policy.name)" -Level "DEBUG" -Component "DataProcessing"
            
            $rules = Get-GSAFilteringRules -PolicyId $policy.id
            $policyProcessed = $false
            
            foreach ($rule in $rules) {
                Write-Log "Processing rule: $($rule.name)" -Level "DEBUG" -Component "DataProcessing"
                
                # Extract destination information based on rule type
                $destinationFQDN = ""
                $destinationURL = ""
                $destinationIPAddress = ""
                $destinationIPRange = ""
                $destinationIPSubnet = ""
                $webCategoryName = ""
                $webCategoryId = ""
                
                # Process destinations array
                if ($rule.destinations) {
                    foreach ($destination in $rule.destinations) {
                        Write-Log "Processing destination with type: $($destination.'@odata.type')" -Level "DEBUG" -Component "DataProcessing"
                        
                        switch ($destination.'@odata.type') {
                            '#microsoft.graph.networkaccess.webCategory' {
                                Write-Log "Processing web category destination: $($destination.name)" -Level "DEBUG" -Component "DataProcessing"
                                $webCategoryName = $destination.name
                                $webCategoryId = if ($destination.PSObject.Properties['id']) { $destination.id } else { "" }
                            }
                            '#microsoft.graph.networkaccess.fqdn' {
                                $destinationFQDN = $destination.value
                            }
                            '#microsoft.graph.networkaccess.url' {
                                $destinationURL = $destination.value
                            }
                        }
                    }
                }
                
                # Collect Conditional Access policy information for this profile
                $caPolicy = if ($profile.conditionalAccessPolicies -and $profile.conditionalAccessPolicies.Count -gt 0) { $profile.conditionalAccessPolicies[0] } else { $null }
                $caPolicyId = if ($caPolicy) { $caPolicy.id } else { "" }
                $caPolicyName = if ($caPolicy) { $caPolicy.displayName } else { "No-CA-Policy-Assigned" }
                $caTargetInfo = Get-CATargetInfo -ConditionalAccessPolicyId $caPolicyId
                
                # Create CSV row for this rule
                $csvRow = [PSCustomObject]@{
                    ProfileName = $profile.name
                    ProfileDescription = $profile.description
                    ProfilePriority = $profile.priority
                    PolicyName = $policy.name
                    PolicyDescription = $policy.description
                    RuleName = $rule.name
                    RuleDescription = "Imported from GSA configuration"
                    RuleType = if ($webCategoryName) { "webCategory" } elseif ($destinationFQDN) { "fqdn" } elseif ($destinationURL) { "url" } else { "unknown" }
                    Action = if ($policy.action) { $policy.action } else { "block" }
                    DestinationFQDN = $destinationFQDN
                    DestinationURL = $destinationURL
                    DestinationIPAddress = $destinationIPAddress
                    DestinationIPRange = $destinationIPRange
                    DestinationIPSubnet = $destinationIPSubnet
                    WebCategoryName = $webCategoryName
                    WebCategoryId = $webCategoryId
                    ConditionalAccessPolicyName = $caPolicyName
                    ConditionalAccessPolicyId = $caPolicyId
                    TargetGroups = $caTargetInfo.Groups
                    TargetUsers = $caTargetInfo.Users
                    ExcludeGroups = "IT-Admins"
                    ExcludeUsers = ""
                    TimeRestriction = ""
                    LocationRestriction = ""
                    DeviceRestriction = ""
                    Enabled = $true
                    Priority = 10
                    SourceSystem = "GSA-Import"
                    SourceRuleId = $rule.id
                    SourcePolicyName = $policy.name
                    CreateProfile = if (-not $profileProcessed) { $true } else { $false }
                    CreatePolicy = if (-not $policyProcessed) { $true } else { $false }
                    CreateRule = $true
                    ValidationStatus = "Valid"
                    ValidationMessage = ""
                    ConflictDetected = $false
                    ConflictingRules = ""
                    ProvisioningStatus = "Pending"
                    ProvisioningMessage = ""
                    CreatedProfileId = $profile.id
                    CreatedPolicyId = $policy.id
                    CreatedRuleId = $rule.id
                    CreatedDate = $currentDateTime.ToString("dd/MM/yyyy HH:mm:ss")
                    ProcessedDate = ""
                    LastModifiedDate = $currentDateTime.ToString("dd/MM/yyyy HH:mm:ss")
                    Notes = "Imported from existing GSA filtering configuration"
                    Tags = "gsa-import,web-category"
                }
                
                $csvData += $csvRow
                $policyProcessed = $true
            }
            $profileProcessed = $true
        }
    }
    
    Write-Log "Converted $($csvData.Count) rules to CSV format" -Level "SUCCESS" -Component "DataProcessing"
    return $csvData
}

#endregion

#region Main Script

try {
    Write-Log "Starting GSA Filtering Profiles import script" -Component "Main"
    Write-Log "Script version: 1.0" -Component "Main"
    Write-Log "Output Base Path: $OutputBasePath" -Component "Main"
    
    # Initialize logging
    if (-not (Test-Path $script:LogFolder)) {
        New-Item -ItemType Directory -Path $script:LogFolder -Force | Out-Null
        Write-Log "Created log folder: $script:LogFolder" -Component "Main"
    }
    
    # Initialize CSV output folder
    if (-not (Test-Path $script:CSVFolder)) {
        New-Item -ItemType Directory -Path $script:CSVFolder -Force | Out-Null
        Write-Log "Created CSV folder: $script:CSVFolder" -Component "Main"
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $script:LogFile = Join-Path $script:LogFolder "${timestamp}_GSA_Import.log"
    Write-Log "Log file initialized: $script:LogFile" -Component "Main"
    
    # Test prerequisites
    if (-not (Test-Prerequisites)) {
        Write-Log "Prerequisites check failed. Exiting." -Level "ERROR" -Component "Main"
        exit 1
    }
    
    # Connect to Microsoft Graph
    if (-not (Connect-ToMSGraph -TenantId $TenantId)) {
        Write-Log "Failed to connect to Microsoft Graph. Exiting." -Level "ERROR" -Component "Main"
        exit 1
    }
    
    Write-Log "Retrieving Global Secure Access filtering configuration..." -Component "Main"
    
    # Get GSA filtering configuration
    $profiles = Get-GSAFilteringProfiles
    $conditionalAccessPolicies = Get-ConditionalAccessPolicies
    
    if ($profiles.Count -eq 0) {
        Write-Log "No filtering profiles found. Nothing to export." -Level "WARN" -Component "Main"
        exit 0
    }
    
    # Convert to CSV format
    $csvData = Convert-ToCSVFormat -Profiles $profiles -ConditionalAccessPolicies $conditionalAccessPolicies
    
    if ($csvData.Count -eq 0) {
        Write-Log "No data to export after processing. Check filters and configuration." -Level "WARN" -Component "Main"
        exit 0
    }
    
    # Generate output filename with timestamp
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $outputFileName = "${timestamp}_GSA_Filtering_Import.csv"
    $outputPath = Join-Path $script:CSVFolder $outputFileName
    
    # Export to CSV
    Write-Log "Exporting GSA filtering configuration to CSV: $outputPath" -Component "Export"
    $csvData | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8
    
    Write-Log "Successfully exported $($csvData.Count) rows to CSV file" -Level "SUCCESS" -Component "Export"
    
    # Summary
    Write-Log "=== EXPORT SUMMARY ===" -Component "Main"
    Write-Log "Total filtering profiles: $($profiles.Count)" -Component "Main"
    $uniquePolicies = ($csvData | Select-Object -Unique PolicyName).Count
    Write-Log "Total filtering policies: $uniquePolicies" -Component "Main"
    Write-Log "Total filtering rules: $($csvData.Count)" -Component "Main"
    Write-Log "CSV file location: $outputPath" -Component "Main"
    
    # Per-profile breakdown
    $profileStats = $csvData | Group-Object ProfileName
    foreach ($stat in $profileStats) {
        Write-Log "Profile '$($stat.Name)': $($stat.Count) rules" -Level "DEBUG" -Component "Main"
    }
    
    Write-Log "GSA Filtering Profiles import completed successfully!" -Level "SUCCESS" -Component "Main"
    Write-Log "CSV file saved to: $outputPath" -Level "SUCCESS" -Component "Main"
}
catch {
    Write-Log "Fatal error in main script execution: $_" -Level "ERROR" -Component "Main"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level "ERROR" -Component "Main"
    exit 1
}
finally {
    # Cleanup
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        Write-Log "Disconnected from Microsoft Graph" -Level "DEBUG" -Component "Cleanup"
    }
    catch {
        # Ignore cleanup errors
    }
}

#endregion
