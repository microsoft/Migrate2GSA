function New-TLSInspectionPolicy {
    <#
    .SYNOPSIS
        Creates or reuses a TLS inspection policy.
    
    .DESCRIPTION
        Creates a new TLS inspection policy or reuses an existing one if it already exists in the tenant.
        The policy name is automatically suffixed with [Migrate2GSA] for identification.
    
    .PARAMETER PolicyGroup
        Grouped policy rule rows from the policies CSV (all rows for the same PolicyName).
    
    .OUTPUTS
        Returns hashtable with Success (bool), Action (string), PolicyId (string), and Error (string).
    
    .EXAMPLE
        New-TLSInspectionPolicy -PolicyGroup $policyGroup
    
    .NOTES
        Author: Andres Canello
        Idempotent: Reuses existing policies, adds only missing rules.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $PolicyGroup
    )
    
    try {
        # Extract policy metadata from first row (validated to be consistent)
        $policyMetadata = $PolicyGroup.Group[0]
        
        # Validate required fields
        if ([string]::IsNullOrWhiteSpace($policyMetadata.PolicyName) -or 
            [string]::IsNullOrWhiteSpace($policyMetadata.PolicyType)) {
            
            Write-LogMessage "Skipping TLS policy: missing required fields (PolicyName or PolicyType)" -Level ERROR -Component "PolicyProvisioning"
            
            return @{
                Success  = $false
                Action   = "Failed"
                PolicyId = $null
                Error    = "Missing required fields"
            }
        }
        
        $policyName = $policyMetadata.PolicyName
        $policyNameWithSuffix = "${policyName}[Migrate2GSA]"
        $defaultAction = $policyMetadata.PolicyAction.ToLower()  # bypass or inspect
        $description = $policyMetadata.Description
        
        Write-LogMessage "Creating/checking TLS inspection policy: $policyName (Default Action: $defaultAction)" -Level INFO -Component "PolicyProvisioning"
        
        # Check if policy already exists
        $existingPolicies = Get-IntTlsInspectionPolicy
        $existingPolicy = $null
        
        if ($null -ne $existingPolicies) {
            # Handle both single object and array responses
            if ($existingPolicies -isnot [array]) {
                $existingPolicies = @($existingPolicies)
            }
            
            # Check value property for collection response
            if ($existingPolicies[0].PSObject.Properties.Name -contains 'value') {
                $existingPolicies = $existingPolicies[0].value
            }
            
            $existingPolicy = $existingPolicies | Where-Object { $_.name -eq $policyNameWithSuffix } | Select-Object -First 1
        }
        
        if ($null -ne $existingPolicy) {
            Write-LogMessage "TLS policy already exists: $policyNameWithSuffix (ID: $($existingPolicy.id)). Will add missing rules." -Level INFO -Component "PolicyProvisioning"
            
            return @{
                Success  = $true
                Action   = "Reused"
                PolicyId = $existingPolicy.id
                Error    = $null
            }
        }
        else {
            # Create new policy
            Write-LogMessage "Creating new TLS policy: $policyNameWithSuffix (Default Action: $defaultAction)" -Level INFO -Component "PolicyProvisioning"
            
            $newPolicy = New-IntTlsInspectionPolicy -Name $policyNameWithSuffix -DefaultAction $defaultAction -Description $description
            
            if ($null -ne $newPolicy -and $newPolicy.id) {
                Write-LogMessage "Successfully created TLS policy: $policyNameWithSuffix (ID: $($newPolicy.id))" -Level SUCCESS -Component "PolicyProvisioning"
                
                return @{
                    Success  = $true
                    Action   = "Created"
                    PolicyId = $newPolicy.id
                    Error    = $null
                }
            }
            else {
                Write-LogMessage "Failed to create TLS policy: $policyNameWithSuffix" -Level ERROR -Component "PolicyProvisioning"
                
                return @{
                    Success  = $false
                    Action   = "Failed"
                    PolicyId = $null
                    Error    = "Policy creation returned no ID"
                }
            }
        }
    }
    catch {
        Write-LogMessage "Error creating/reusing TLS inspection policy: $_" -Level ERROR -Component "PolicyProvisioning"
        
        return @{
            Success  = $false
            Action   = "Failed"
            PolicyId = $null
            Error    = $_.Exception.Message
        }
    }
}
