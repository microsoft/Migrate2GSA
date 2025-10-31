function New-TLSInspectionRules {
    <#
    .SYNOPSIS
        Creates TLS inspection rules for a policy, skipping existing rules.
    
    .DESCRIPTION
        Creates TLS inspection rules (bypass/inspect) for a TLS inspection policy.
        Checks for existing rules by name and only creates missing rules (idempotent behavior).
    
    .PARAMETER PolicyId
        The unique identifier of the TLS inspection policy.
    
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
        $result = New-TLSInspectionRules -PolicyId "policy-id" -Rules $rulesArray -PolicyName "Finance_TLSInspect"
    
    .NOTES
        Author: Andres Canello
        Idempotent: Skips existing rules, creates only missing rules.
        Automatically assigns sequential priorities to rules.
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
        Write-LogMessage "Processing $($Rules.Count) TLS rules for policy: $PolicyName" -Level INFO -Component "PolicyProvisioning"
        
        # Get existing rules for this policy
        $existingRules = Get-IntTlsInspectionRule -PolicyId $PolicyId
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
            Write-LogMessage "Found $($existingRuleNames.Count) existing TLS rules in policy" -Level INFO -Component "PolicyProvisioning"
        }
        
        $createdCount = 0
        $reusedCount = 0
        $failedCount = 0
        $rulePriority = 100  # Start priority at 100, increment by 10 for each rule
        
        foreach ($row in $Rules) {
            # Validate required fields
            if ([string]::IsNullOrWhiteSpace($row.PolicyName) -or 
                [string]::IsNullOrWhiteSpace($row.RuleType) -or 
                [string]::IsNullOrWhiteSpace($row.RuleDestinations) -or 
                [string]::IsNullOrWhiteSpace($row.RuleName)) {
                
                Write-LogMessage "Skipping TLS rule: missing required fields (RuleType, RuleDestinations, or RuleName)" -Level ERROR -Component "PolicyProvisioning"
                $Global:RecordLookup[$row.UniqueRecordId].ProvisioningResult = "Failed: Missing required fields"
                $failedCount++
                continue
            }
            
            $ruleName = $row.RuleName
            $ruleAction = $row.RuleType.ToLower()  # bypass or inspect
            $destinations = $row.ParsedDestinations
            
            # Check if rule already exists
            if ($existingRuleNames -contains $ruleName) {
                Write-LogMessage "TLS rule already exists: $ruleName. Skipping." -Level INFO -Component "PolicyProvisioning"
                $Global:RecordLookup[$row.UniqueRecordId].ProvisioningResult = "Reused: Rule already exists"
                $Global:ProvisioningStats.ReusedRules++
                $reusedCount++
                continue
            }
            
            # Create TLS inspection rule
            try {
                Write-LogMessage "Creating TLS rule: $ruleName (Action: $ruleAction, Priority: $rulePriority)" -Level INFO -Component "PolicyProvisioning"
                
                $newRule = New-IntTlsInspectionRule `
                    -PolicyId $PolicyId `
                    -Name $ruleName `
                    -Priority $rulePriority `
                    -Action $ruleAction `
                    -Status 'enabled' `
                    -Fqdns $destinations
                
                if ($null -ne $newRule -and $newRule.id) {
                    Write-LogMessage "Successfully created TLS rule: $ruleName (ID: $($newRule.id))" -Level SUCCESS -Component "PolicyProvisioning"
                    $Global:RecordLookup[$row.UniqueRecordId].ProvisioningResult = "Provisioned: Rule created successfully"
                    $Global:RecordLookup[$row.UniqueRecordId].RuleId = $newRule.id
                    $Global:ProvisioningStats.CreatedRules++
                    $createdCount++
                }
                else {
                    Write-LogMessage "Failed to create TLS rule: $ruleName (no ID returned)" -Level ERROR -Component "PolicyProvisioning"
                    $Global:RecordLookup[$row.UniqueRecordId].ProvisioningResult = "Failed: Rule creation returned no ID"
                    $Global:ProvisioningStats.FailedRules++
                    $failedCount++
                }
                
                # Increment priority for next rule
                $rulePriority += 10
            }
            catch {
                Write-LogMessage "Error creating TLS rule '$ruleName': $_" -Level ERROR -Component "PolicyProvisioning"
                $Global:RecordLookup[$row.UniqueRecordId].ProvisioningResult = "Failed: $($_.Exception.Message)"
                $Global:ProvisioningStats.FailedRules++
                $failedCount++
            }
        }
        
        Write-LogMessage "TLS rule provisioning for policy '$PolicyName': $createdCount created, $reusedCount reused, $failedCount failed" -Level SUMMARY -Component "PolicyProvisioning"
        
        return @{
            TotalRules         = $Rules.Count
            CreatedRules       = $createdCount
            ReusedRules        = $reusedCount
            FailedRules        = $failedCount
            HasSuccessfulRules = ($createdCount + $reusedCount) -gt 0
        }
    }
    catch {
        Write-LogMessage "Error processing TLS rules for policy '$PolicyName': $_" -Level ERROR -Component "PolicyProvisioning"
        throw
    }
}
