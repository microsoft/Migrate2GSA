function New-WebContentFilteringRules {
    <#
    .SYNOPSIS
        Creates web content filtering rules for a policy, skipping existing rules.
    
    .DESCRIPTION
        Creates filtering rules (FQDN, URL, webCategory) for a web content filtering policy.
        Checks for existing rules by name and only creates missing rules (idempotent behavior).
    
    .PARAMETER PolicyId
        The unique identifier of the filtering policy.
    
    .PARAMETER Rules
        Array of rule objects from the policies CSV (all rows for this policy).
    
    .PARAMETER PolicyName
        Name of the policy (for logging and tracking).
    
    .OUTPUTS
        Returns hashtable with:
        - TotalRules (int): Total number of rules attempted
        - CreatedRules (int): Number of rules created
        - ReusedRules (int): Number of rules that already existed
        - FailedRules (int): Number of rules that failed
        - HasSuccessfulRules (bool): True if at least one rule was created or reused
    
    .EXAMPLE
        $result = New-WebContentFilteringRules -PolicyId "policy-id" -Rules $rulesArray -PolicyName "Finance_WebFilter"
    
    .NOTES
        Author: Andres Canello
        Idempotent: Skips existing rules, creates only missing rules.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PolicyId,
        
        [Parameter(Mandatory = $true)]
        [array]$Rules,
        
        [Parameter(Mandatory = $true)]
        [string]$PolicyName
    )
    
    try {
        Write-LogMessage "Processing $($Rules.Count) rules for policy: $PolicyName" -Level INFO -Component "PolicyProvisioning"
        
        # Get existing rules for this policy
        $existingRules = Get-IntFilteringRule -PolicyId $PolicyId
        $existingRuleNames = @()
        
        if ($null -ne $existingRules) {
            # Handle both single object and array responses
            if ($existingRules -isnot [array]) {
                $existingRules = @($existingRules)
            }
            
            # Check value property for collection response
            if ($existingRules[0].PSObject.Properties.Name -contains 'value') {
                $existingRules = $existingRules[0].value
            }
            
            $existingRuleNames = $existingRules | ForEach-Object { $_.name }
            Write-LogMessage "Found $($existingRuleNames.Count) existing rules in policy" -Level INFO -Component "PolicyProvisioning"
        }
        
        $createdCount = 0
        $reusedCount = 0
        $failedCount = 0
        
        foreach ($row in $Rules) {
            # Validate required fields
            if ([string]::IsNullOrWhiteSpace($row.PolicyName) -or 
                [string]::IsNullOrWhiteSpace($row.RuleType) -or 
                [string]::IsNullOrWhiteSpace($row.RuleDestinations) -or 
                [string]::IsNullOrWhiteSpace($row.RuleName)) {
                
                Write-LogMessage "Skipping rule: missing required fields (RuleType, RuleDestinations, or RuleName)" -Level ERROR -Component "PolicyProvisioning"
                $Global:RecordLookup[$row.UniqueRecordId].ProvisioningResult = "Failed: Missing required fields"
                $failedCount++
                continue
            }
            
            $ruleName = $row.RuleName
            $ruleType = $row.RuleType
            $destinations = $row.ParsedDestinations
            
            # Check if rule already exists
            if ($existingRuleNames -contains $ruleName) {
                Write-LogMessage "Rule already exists: $ruleName. Skipping." -Level INFO -Component "PolicyProvisioning"
                $Global:RecordLookup[$row.UniqueRecordId].ProvisioningResult = "Reused: Rule already exists"
                $Global:ProvisioningStats.ReusedRules++
                $reusedCount++
                continue
            }
            
            # Create rule based on type
            try {
                Write-LogMessage "Creating rule: $ruleName (Type: $ruleType)" -Level INFO -Component "PolicyProvisioning"
                
                $newRule = $null
                
                switch ($ruleType.ToLower()) {
                    'fqdn' {
                        $newRule = New-IntFqdnFilteringRule -PolicyId $PolicyId -Name $ruleName -Fqdns $destinations
                    }
                    'url' {
                        $newRule = New-IntUrlFilteringRule -PolicyId $PolicyId -Name $ruleName -Urls $destinations
                    }
                    'webcategory' {
                        $newRule = New-IntWebCategoryFilteringRule -PolicyId $PolicyId -Name $ruleName -Categories $destinations
                    }
                    default {
                        Write-LogMessage "Unknown rule type: $ruleType for rule $ruleName. Skipping." -Level WARN -Component "PolicyProvisioning"
                        $Global:RecordLookup[$row.UniqueRecordId].ProvisioningResult = "Failed: Unknown rule type '$ruleType'"
                        $failedCount++
                        continue
                    }
                }
                
                if ($null -ne $newRule -and $newRule.id) {
                    Write-LogMessage "Successfully created rule: $ruleName (ID: $($newRule.id))" -Level SUCCESS -Component "PolicyProvisioning"
                    $Global:RecordLookup[$row.UniqueRecordId].ProvisioningResult = "Provisioned: Rule created successfully"
                    $Global:RecordLookup[$row.UniqueRecordId].RuleId = $newRule.id
                    $Global:ProvisioningStats.CreatedRules++
                    $createdCount++
                }
                else {
                    Write-LogMessage "Failed to create rule: $ruleName (no ID returned)" -Level ERROR -Component "PolicyProvisioning"
                    $Global:RecordLookup[$row.UniqueRecordId].ProvisioningResult = "Failed: Rule creation returned no ID"
                    $Global:ProvisioningStats.FailedRules++
                    $failedCount++
                }
            }
            catch {
                Write-LogMessage "Error creating rule '$ruleName': $_" -Level ERROR -Component "PolicyProvisioning"
                $Global:RecordLookup[$row.UniqueRecordId].ProvisioningResult = "Failed: $($_.Exception.Message)"
                $Global:ProvisioningStats.FailedRules++
                $failedCount++
            }
        }
        
        Write-LogMessage "Rule provisioning for policy '$PolicyName': $createdCount created, $reusedCount reused, $failedCount failed" -Level SUMMARY -Component "PolicyProvisioning"
        
        return @{
            TotalRules         = $Rules.Count
            CreatedRules       = $createdCount
            ReusedRules        = $reusedCount
            FailedRules        = $failedCount
            HasSuccessfulRules = ($createdCount + $reusedCount) -gt 0
        }
    }
    catch {
        Write-LogMessage "Error processing rules for policy '$PolicyName': $_" -Level ERROR -Component "PolicyProvisioning"
        throw
    }
}
