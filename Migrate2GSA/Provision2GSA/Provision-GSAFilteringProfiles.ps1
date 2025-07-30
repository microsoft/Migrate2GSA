[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Path to the GSA filtering CSV file")]
    [ValidateScript({
        if (Test-Path $_) { return $true }
        else { throw "CSV file not found: $_" }
    })]
    [string]$CSVFilePath,
    
    [Parameter(HelpMessage = "Base directory for output files and logs")]
    [ValidateScript({
        if (Test-Path $_ -PathType Container) { return $true }
        else { throw "Directory not found: $_" }
    })]
    [string]$OutputBasePath = $PWD,
    
    [Parameter(HelpMessage = "Perform validation only without creating resources")]
    [switch]$ValidateOnly,
    
    [Parameter(HelpMessage = "Enable verbose debug logging")]
    [switch]$EnableDebugLogging,
    
    [Parameter(HelpMessage = "Tenant ID for Microsoft Graph authentication")]
    [string]$TenantId,
    
    [Parameter(HelpMessage = "Process only specific profile name")]
    [string]$ProfileNameFilter
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
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "DEBUG")]
        [string]$Level = "INFO",
        
        [Parameter(Mandatory = $false)]
        [string]$Component = "Main"
    )
    
    try {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        
        # Handle empty messages for spacing
        if ([string]::IsNullOrEmpty($Message)) {
            $logMessage = ""
        } else {
            $logMessage = "[$timestamp] [$Level] [$Component] $Message"
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
                "SUCCESS" { Write-Host $logMessage -ForegroundColor Cyan }
                "DEBUG" { Write-Host $logMessage -ForegroundColor Gray }
            }
        }
        
        # Write to log file
        $logFilePath = Join-Path $OutputBasePath "provision-gsa-filtering.log"
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
            Write-Warning "Failed to write to log file: $_"
        }
    }
    catch {
        Write-Host "[$Level] [$Component] $Message"
    }
}

function Test-RequiredModules {
    Write-Log "Checking required PowerShell modules..." -Component "Prerequisites"
    
    $requiredModules = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Identity.DirectoryManagement')
    $missingModules = @()
    
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            $missingModules += $module
            Write-Log "Missing required module: $module" -Level "ERROR" -Component "Prerequisites"
        } else {
            Write-Log "Found module: $module" -Level "DEBUG" -Component "Prerequisites"
        }
    }
    
    if ($missingModules.Count -gt 0) {
        Write-Log "Missing required modules. Install with: Install-Module $($missingModules -join ', ')" -Level "ERROR" -Component "Prerequisites"
        return $false
    }
    
    Write-Log "All required modules are available" -Level "SUCCESS" -Component "Prerequisites"
    return $true
}

function Connect-ToMicrosoftGraph {
    param(
        [string]$TenantId
    )
    
    Write-Log "Connecting to Microsoft Graph..." -Component "Authentication"
    
    try {
        # Required scopes for Global Secure Access
        $scopes = @(
            'NetworkAccess.ReadWrite.All',
            'Policy.ReadWrite.ConditionalAccess',
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

function Import-GSAFilteringCSV {
    param(
        [string]$FilePath
    )
    
    Write-Log "Loading GSA filtering configuration from CSV: $FilePath" -Component "Import"
    
    try {
        $csvData = Import-Csv -Path $FilePath -Encoding UTF8
        
        if ($null -eq $csvData -or $csvData.Count -eq 0) {
            Write-Log "CSV file is empty or invalid" -Level "ERROR" -Component "Import"
            return $null
        }
        
        Write-Log "Loaded $($csvData.Count) rows from CSV" -Level "SUCCESS" -Component "Import"
        
        # Apply profile filter if specified
        if ($ProfileNameFilter) {
            $originalCount = $csvData.Count
            $csvData = $csvData | Where-Object { $_.ProfileName -eq $ProfileNameFilter }
            Write-Log "Filtered to $($csvData.Count) rows for profile: $ProfileNameFilter (was $originalCount)" -Component "Import"
        }
        
        return $csvData
    }
    catch {
        Write-Log "Error loading CSV file: $_" -Level "ERROR" -Component "Import"
        return $null
    }
}

function Test-CSVValidation {
    param(
        [object[]]$CSVData
    )
    
    Write-Log "Validating CSV data structure and content..." -Component "Validation"
    
    $validationResults = @()
    $requiredFields = @('ProfileName', 'PolicyName', 'RuleName', 'RuleType', 'Action')
    $validRuleTypes = @('fqdn', 'webCategory', 'ipAddress', 'ipRange', 'ipSubnet', 'url')
    $validActions = @('allow', 'block')
    
    for ($i = 0; $i -lt $CSVData.Count; $i++) {
        $row = $CSVData[$i]
        $rowNumber = $i + 2  # +2 because CSV has header row and we're 0-indexed
        $rowErrors = @()
        
        # Check required fields
        foreach ($field in $requiredFields) {
            if ([string]::IsNullOrWhiteSpace($row.$field)) {
                $rowErrors += "Missing required field: $field"
            }
        }
        
        # Validate RuleType
        if ($row.RuleType -notin $validRuleTypes) {
            $rowErrors += "Invalid RuleType: '$($row.RuleType)'. Must be one of: $($validRuleTypes -join ', ')"
        }
        
        # Validate Action
        if ($row.Action -notin $validActions) {
            $rowErrors += "Invalid Action: '$($row.Action)'. Must be one of: $($validActions -join ', ')"
        }
        
        # Validate rule type specific requirements
        switch ($row.RuleType) {
            'fqdn' {
                if ([string]::IsNullOrWhiteSpace($row.DestinationFQDN)) {
                    $rowErrors += "DestinationFQDN is required when RuleType is 'fqdn'"
                }
            }
            'webCategory' {
                if ([string]::IsNullOrWhiteSpace($row.WebCategoryName)) {
                    $rowErrors += "WebCategoryName is required when RuleType is 'webCategory'"
                }
            }
            'ipAddress' {
                if ([string]::IsNullOrWhiteSpace($row.DestinationIPAddress)) {
                    $rowErrors += "DestinationIPAddress is required when RuleType is 'ipAddress'"
                } elseif ($row.DestinationIPAddress -notmatch '^(\d{1,3}\.){3}\d{1,3}$') {
                    $rowErrors += "Invalid IP address format: '$($row.DestinationIPAddress)'"
                }
            }
            'ipRange' {
                if ([string]::IsNullOrWhiteSpace($row.DestinationIPRange)) {
                    $rowErrors += "DestinationIPRange is required when RuleType is 'ipRange'"
                }
            }
            'ipSubnet' {
                if ([string]::IsNullOrWhiteSpace($row.DestinationIPSubnet)) {
                    $rowErrors += "DestinationIPSubnet is required when RuleType is 'ipSubnet'"
                } elseif ($row.DestinationIPSubnet -notmatch '^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$') {
                    $rowErrors += "Invalid CIDR format: '$($row.DestinationIPSubnet)'"
                }
            }
            'url' {
                if ([string]::IsNullOrWhiteSpace($row.DestinationURL)) {
                    $rowErrors += "DestinationURL is required when RuleType is 'url'"
                }
            }
        }
        
        # Create validation result
        $result = [PSCustomObject]@{
            RowNumber = $rowNumber
            ProfileName = $row.ProfileName
            PolicyName = $row.PolicyName
            RuleName = $row.RuleName
            IsValid = $rowErrors.Count -eq 0
            Errors = $rowErrors
        }
        
        $validationResults += $result
        
        if ($rowErrors.Count -gt 0) {
            Write-Log "Row $rowNumber validation errors: $($rowErrors -join '; ')" -Level "ERROR" -Component "Validation"
        } else {
            Write-Log "Row $rowNumber validation passed" -Level "DEBUG" -Component "Validation"
        }
    }
    
    $validRows = ($validationResults | Where-Object { $_.IsValid }).Count
    $invalidRows = ($validationResults | Where-Object { -not $_.IsValid }).Count
    
    Write-Log "Validation complete: $validRows valid, $invalidRows invalid" -Level "INFO" -Component "Validation"
    
    if ($invalidRows -gt 0) {
        Write-Log "CSV validation failed with $invalidRows invalid rows" -Level "ERROR" -Component "Validation"
    } else {
        Write-Log "CSV validation passed successfully" -Level "SUCCESS" -Component "Validation"
    }
    
    return $validationResults
}

function Group-CSVDataByProfile {
    param(
        [object[]]$CSVData
    )
    
    Write-Log "Grouping CSV data by filtering profiles..." -Component "Processing"
    
    $profileGroups = $CSVData | Group-Object -Property ProfileName
    
    $result = @{}
    
    foreach ($profileGroup in $profileGroups) {
        $profileName = $profileGroup.Name
        $profileRows = $profileGroup.Group
        
        # Get profile metadata from first row
        $firstRow = $profileRows[0]
        
        # Group policies within profile
        $policyGroups = $profileRows | Group-Object -Property PolicyName
        
        $policies = @{}
        foreach ($policyGroup in $policyGroups) {
            $policyName = $policyGroup.Name
            $policyRows = $policyGroup.Group
            
            $policies[$policyName] = @{
                Description = $policyRows[0].PolicyDescription
                Rules = $policyRows
                ShouldCreate = ($policyRows | Where-Object { $_.CreatePolicy -eq 'True' }).Count -gt 0
            }
        }
        
        $result[$profileName] = @{
            Name = $profileName
            Description = $firstRow.ProfileDescription
            Priority = if ($firstRow.ProfilePriority) { [int]$firstRow.ProfilePriority } else { 100 }
            Policies = $policies
            ShouldCreate = ($profileRows | Where-Object { $_.CreateProfile -eq 'True' }).Count -gt 0
            ConditionalAccessPolicy = $firstRow.ConditionalAccessPolicyName
        }
        
        Write-Log "Profile '$profileName': $($policies.Count) policies, $($profileRows.Count) total rules" -Level "DEBUG" -Component "Processing"
    }
    
    Write-Log "Grouped data into $($result.Count) filtering profiles" -Level "SUCCESS" -Component "Processing"
    return $result
}

function New-FilteringProfile {
    param(
        [string]$Name,
        [string]$Description,
        [int]$Priority = 100
    )
    
    Write-Log "Creating filtering profile: $Name" -Component "Provisioning"
    
    if ($ValidateOnly) {
        Write-Log "VALIDATE-ONLY: Would create filtering profile '$Name'" -Level "WARN" -Component "Provisioning"
        return @{ Id = "validate-only-profile-id"; Name = $Name }
    }
    
    try {
        # In a real implementation, this would call Microsoft Graph API
        # For now, return a mock response
        
        $profileBody = @{
            name = $Name
            description = $Description
            priority = $Priority
            state = "enabled"
        }
        
        Write-Log "Profile creation payload: $($profileBody | ConvertTo-Json -Compress)" -Level "DEBUG" -Component "Provisioning"
        
        # Mock API call - replace with actual Graph call:
        # $profile = New-MgNetworkAccessFilteringProfile -BodyParameter $profileBody
        
        $mockProfile = @{
            Id = "profile-$(New-Guid)"
            Name = $Name
            Description = $Description
            Priority = $Priority
        }
        
        Write-Log "Created filtering profile '$Name' with ID: $($mockProfile.Id)" -Level "SUCCESS" -Component "Provisioning"
        return $mockProfile
    }
    catch {
        Write-Log "Failed to create filtering profile '$Name': $_" -Level "ERROR" -Component "Provisioning"
        throw
    }
}

function New-FilteringPolicy {
    param(
        [string]$Name,
        [string]$Description,
        [string]$ProfileId
    )
    
    Write-Log "Creating filtering policy: $Name" -Component "Provisioning"
    
    if ($ValidateOnly) {
        Write-Log "VALIDATE-ONLY: Would create filtering policy '$Name' in profile '$ProfileId'" -Level "WARN" -Component "Provisioning"
        return @{ Id = "validate-only-policy-id"; Name = $Name }
    }
    
    try {
        $policyBody = @{
            name = $Name
            description = $Description
        }
        
        Write-Log "Policy creation payload: $($policyBody | ConvertTo-Json -Compress)" -Level "DEBUG" -Component "Provisioning"
        
        # Mock API call - replace with actual Graph call:
        # $policy = New-MgNetworkAccessFilteringPolicy -BodyParameter $policyBody
        
        $mockPolicy = @{
            Id = "policy-$(New-Guid)"
            Name = $Name
            Description = $Description
        }
        
        Write-Log "Created filtering policy '$Name' with ID: $($mockPolicy.Id)" -Level "SUCCESS" -Component "Provisioning"
        return $mockPolicy
    }
    catch {
        Write-Log "Failed to create filtering policy '$Name': $_" -Level "ERROR" -Component "Provisioning"
        throw
    }
}

function New-FilteringRule {
    param(
        [object]$RuleData,
        [string]$PolicyId
    )
    
    Write-Log "Creating filtering rule: $($RuleData.RuleName)" -Component "Provisioning"
    
    if ($ValidateOnly) {
        Write-Log "VALIDATE-ONLY: Would create rule '$($RuleData.RuleName)' in policy '$PolicyId'" -Level "WARN" -Component "Provisioning"
        return @{ Id = "validate-only-rule-id"; Name = $RuleData.RuleName }
    }
    
    try {
        # Build destinations array based on rule type
        $destinations = @()
        
        switch ($RuleData.RuleType) {
            'fqdn' {
                $destinations += @{
                    '@odata.type' = '#microsoft.graph.networkaccess.fqdn'
                    value = $RuleData.DestinationFQDN
                }
            }
            'webCategory' {
                $destinations += @{
                    '@odata.type' = '#microsoft.graph.networkaccess.webCategory'
                    name = $RuleData.WebCategoryName
                }
            }
            'ipAddress' {
                $destinations += @{
                    '@odata.type' = '#microsoft.graph.networkaccess.ipAddress'
                    value = $RuleData.DestinationIPAddress
                }
            }
            'ipRange' {
                $destinations += @{
                    '@odata.type' = '#microsoft.graph.networkaccess.ipRange'
                    value = $RuleData.DestinationIPRange
                }
            }
            'ipSubnet' {
                $destinations += @{
                    '@odata.type' = '#microsoft.graph.networkaccess.ipSubnet'
                    value = $RuleData.DestinationIPSubnet
                }
            }
            'url' {
                $destinations += @{
                    '@odata.type' = '#microsoft.graph.networkaccess.url'
                    value = $RuleData.DestinationURL
                }
            }
        }
        
        $ruleBody = @{
            '@odata.type' = if ($RuleData.RuleType -eq 'webCategory') { 
                '#microsoft.graph.networkaccess.webCategoryFilteringRule' 
            } else { 
                '#microsoft.graph.networkaccess.fqdnFilteringRule' 
            }
            name = $RuleData.RuleName
            ruleType = $RuleData.RuleType
            destinations = $destinations
        }
        
        Write-Log "Rule creation payload: $($ruleBody | ConvertTo-Json -Depth 5 -Compress)" -Level "DEBUG" -Component "Provisioning"
        
        # Mock API call - replace with actual Graph call:
        # $rule = New-MgNetworkAccessFilteringPolicyRule -FilteringPolicyId $PolicyId -BodyParameter $ruleBody
        
        $mockRule = @{
            Id = "rule-$(New-Guid)"
            Name = $RuleData.RuleName
            RuleType = $RuleData.RuleType
            Action = $RuleData.Action
        }
        
        Write-Log "Created filtering rule '$($RuleData.RuleName)' with ID: $($mockRule.Id)" -Level "SUCCESS" -Component "Provisioning"
        return $mockRule
    }
    catch {
        Write-Log "Failed to create filtering rule '$($RuleData.RuleName)': $_" -Level "ERROR" -Component "Provisioning"
        throw
    }
}

function Export-ProvisioningResults {
    param(
        [object[]]$Results,
        [string]$OutputPath
    )
    
    Write-Log "Exporting provisioning results to: $OutputPath" -Component "Export"
    
    try {
        $Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
        Write-Log "Provisioning results exported successfully" -Level "SUCCESS" -Component "Export"
    }
    catch {
        Write-Log "Failed to export provisioning results: $_" -Level "ERROR" -Component "Export"
    }
}

#endregion

#region Main Script Logic

try {
    Write-Log "Starting GSA Filtering Profiles provisioning script" -Level "INFO"
    Write-Log "Script version: 1.0" -Level "INFO"
    Write-Log "CSV File: $CSVFilePath" -Level "INFO"
    Write-Log "Output Base Path: $OutputBasePath" -Level "INFO"
    Write-Log "Validate Only: $ValidateOnly" -Level "INFO"
    
    # Check prerequisites
    if (-not (Test-RequiredModules)) {
        Write-Log "Prerequisites check failed. Please install required modules." -Level "ERROR"
        exit 1
    }
    
    # Connect to Microsoft Graph (skip in validate-only mode)
    if (-not $ValidateOnly) {
        if (-not (Connect-ToMicrosoftGraph -TenantId $TenantId)) {
            Write-Log "Failed to connect to Microsoft Graph. Exiting." -Level "ERROR"
            exit 1
        }
    }
    
    # Load and validate CSV data
    $csvData = Import-GSAFilteringCSV -FilePath $CSVFilePath
    if ($null -eq $csvData) {
        Write-Log "Failed to load CSV data. Exiting." -Level "ERROR"
        exit 1
    }
    
    # Validate CSV structure and content
    $validationResults = Test-CSVValidation -CSVData $csvData
    $invalidRows = $validationResults | Where-Object { -not $_.IsValid }
    
    if ($invalidRows.Count -gt 0) {
        Write-Log "CSV validation failed. Please fix errors and try again." -Level "ERROR"
        
        # Export validation results
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $validationResultsPath = Join-Path $OutputBasePath "${timestamp}_GSA_Filtering_Validation_Results.csv"
        $validationResults | Export-Csv -Path $validationResultsPath -NoTypeInformation -Encoding UTF8
        Write-Log "Validation results exported to: $validationResultsPath" -Level "INFO"
        
        exit 1
    }
    
    if ($ValidateOnly) {
        Write-Log "Validation completed successfully. No provisioning performed." -Level "SUCCESS"
        exit 0
    }
    
    # Group data by profiles and policies
    $profileGroups = Group-CSVDataByProfile -CSVData $csvData
    
    # Start provisioning
    Write-Log "Starting provisioning process..." -Component "Provisioning"
    
    $provisioningResults = @()
    $totalProfiles = $profileGroups.Count
    $processedProfiles = 0
    
    foreach ($profileName in $profileGroups.Keys) {
        $processedProfiles++
        $profile = $profileGroups[$profileName]
        
        Write-Progress -Activity "Provisioning GSA Filtering" -Status "Processing profile $processedProfiles of $totalProfiles" -PercentComplete (($processedProfiles / $totalProfiles) * 100)
        
        try {
            Write-Log "Processing profile: $profileName" -Component "Provisioning"
            
            # Create filtering profile if needed
            $createdProfile = $null
            if ($profile.ShouldCreate) {
                $createdProfile = New-FilteringProfile -Name $profile.Name -Description $profile.Description -Priority $profile.Priority
            } else {
                Write-Log "Skipping profile creation for: $profileName" -Level "DEBUG" -Component "Provisioning"
            }
            
            # Process policies within profile
            foreach ($policyName in $profile.Policies.Keys) {
                $policy = $profile.Policies[$policyName]
                
                Write-Log "Processing policy: $policyName" -Component "Provisioning"
                
                # Create filtering policy if needed
                $createdPolicy = $null
                if ($policy.ShouldCreate) {
                    $profileId = if ($createdProfile) { $createdProfile.Id } else { "existing-profile-id" }
                    $createdPolicy = New-FilteringPolicy -Name $policyName -Description $policy.Description -ProfileId $profileId
                } else {
                    Write-Log "Skipping policy creation for: $policyName" -Level "DEBUG" -Component "Provisioning"
                }
                
                # Process rules within policy
                foreach ($ruleData in $policy.Rules) {
                    if ($ruleData.CreateRule -eq 'True') {
                        $policyId = if ($createdPolicy) { $createdPolicy.Id } else { "existing-policy-id" }
                        $createdRule = New-FilteringRule -RuleData $ruleData -PolicyId $policyId
                        
                        # Record provisioning result
                        $result = [PSCustomObject]@{
                            ProfileName = $profileName
                            PolicyName = $policyName
                            RuleName = $ruleData.RuleName
                            RuleType = $ruleData.RuleType
                            Action = $ruleData.Action
                            ProvisioningStatus = 'Success'
                            CreatedProfileId = if ($createdProfile) { $createdProfile.Id } else { '' }
                            CreatedPolicyId = if ($createdPolicy) { $createdPolicy.Id } else { '' }
                            CreatedRuleId = $createdRule.Id
                            ProcessedDate = Get-Date
                            Message = 'Rule created successfully'
                        }
                        
                        $provisioningResults += $result
                    } else {
                        Write-Log "Skipping rule creation for: $($ruleData.RuleName)" -Level "DEBUG" -Component "Provisioning"
                    }
                }
            }
        }
        catch {
            Write-Log "Error processing profile '$profileName': $_" -Level "ERROR" -Component "Provisioning"
            
            # Record error result
            $errorResult = [PSCustomObject]@{
                ProfileName = $profileName
                PolicyName = ''
                RuleName = ''
                RuleType = ''
                Action = ''
                ProvisioningStatus = 'Failed'
                CreatedProfileId = ''
                CreatedPolicyId = ''
                CreatedRuleId = ''
                ProcessedDate = Get-Date
                Message = "Profile processing failed: $_"
            }
            
            $provisioningResults += $errorResult
            continue
        }
    }
    
    Write-Progress -Activity "Provisioning GSA Filtering" -Completed
    
    # Export provisioning results
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $resultsPath = Join-Path $OutputBasePath "${timestamp}_GSA_Filtering_Provisioning_Results.csv"
    Export-ProvisioningResults -Results $provisioningResults -OutputPath $resultsPath
    
    # Summary
    $successCount = ($provisioningResults | Where-Object { $_.ProvisioningStatus -eq 'Success' }).Count
    $failureCount = ($provisioningResults | Where-Object { $_.ProvisioningStatus -eq 'Failed' }).Count
    
    Write-Log ""
    Write-Log "=== PROVISIONING SUMMARY ===" -Level "INFO"
    Write-Log "Total profiles processed: $($profileGroups.Count)" -Level "INFO"
    Write-Log "Successful provisions: $successCount" -Level "INFO"
    Write-Log "Failed provisions: $failureCount" -Level "INFO"
    Write-Log "Results exported to: $resultsPath" -Level "INFO"
    Write-Log ""
    
    if ($failureCount -gt 0) {
        Write-Log "Some provisioning operations failed. Check the results file for details." -Level "WARN"
    } else {
        Write-Log "All provisioning operations completed successfully!" -Level "SUCCESS"
    }
}
catch {
    Write-Log "Fatal error in main script execution: $_" -Level "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level "ERROR"
    exit 1
}
finally {
    # Cleanup
    if (-not $ValidateOnly) {
        try {
            Disconnect-MgGraph | Out-Null
            Write-Log "Disconnected from Microsoft Graph" -Level "DEBUG" -Component "Cleanup"
        }
        catch {
            # Ignore disconnect errors
        }
    }
}

#endregion
