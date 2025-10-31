function New-ConditionalAccessPolicy {
    <#
    .SYNOPSIS
        Creates a Conditional Access policy linked to a security profile.
    
    .DESCRIPTION
        Creates a new Conditional Access policy that enforces the specified security profile
        for assigned users and groups. The policy is created in DISABLED state for safety.
        Skips creation if a policy with the same name already exists (name conflict).
    
    .PARAMETER ProfileRow
        Single row from security profiles CSV containing CA policy metadata and assignments.
    
    .PARAMETER SecurityProfileId
        The unique identifier of the security profile to link to.
    
    .OUTPUTS
        Returns hashtable with:
        - Success (bool)
        - Action (string: "Created", "Skipped", "Failed")
        - CAPolicyId (string)
        - Error (string)
    
    .EXAMPLE
        New-ConditionalAccessPolicy -ProfileRow $profileRow -SecurityProfileId "profile-id"
    
    .NOTES
        Author: Andres Canello
        CA policies are always created in DISABLED state for admin validation.
        CA policy names are automatically suffixed with [Migrate2GSA].
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ProfileRow,
        
        [Parameter(Mandatory = $true)]
        [string]$SecurityProfileId
    )
    
    try {
        $caDisplayName = $ProfileRow.CADisplayName
        $caDisplayNameWithSuffix = "${caDisplayName}[Migrate2GSA]"
        $users = $ProfileRow.ParsedUsers
        $groups = $ProfileRow.ParsedGroups
        
        Write-LogMessage "Creating Conditional Access policy: $caDisplayName" -Level INFO -Component "ConditionalAccessProvisioning"
        
        # Check if CA policy already exists (name conflict)
        Write-LogMessage "Checking for existing CA policy with name: $caDisplayNameWithSuffix" -Level INFO -Component "ConditionalAccessProvisioning"
        
        $filter = "displayName eq '$caDisplayNameWithSuffix'"
        $uri = "https://graph.microsoft.com/beta/identity/conditionalAccess/policies?`$filter=$([System.Web.HttpUtility]::UrlEncode($filter))"
        $existingPolicies = Invoke-InternalGraphRequest -Method GET -Uri $uri
        
        if ($null -ne $existingPolicies -and 
            $existingPolicies.PSObject.Properties.Name -contains 'value' -and 
            $existingPolicies.value.Count -gt 0) {
            
            Write-LogMessage "CA policy already exists: $caDisplayNameWithSuffix. Skipping creation (not modified)." -Level WARN -Component "ConditionalAccessProvisioning"
            
            $Global:RecordLookup[$ProfileRow.UniqueRecordId].ProvisioningResult += " | CA Policy: Skipped - already exists"
            
            return @{
                Success    = $true
                Action     = "Skipped"
                CAPolicyId = $existingPolicies.value[0].id
                Error      = "CA policy already exists"
            }
        }
        
        # Resolve user and group IDs from caches
        $includeUserIds = @()
        $includeGroupIds = @()
        
        foreach ($upn in $users) {
            if ($Global:EntraUserCache.ContainsKey($upn)) {
                $userId = $Global:EntraUserCache[$upn]
                if ($null -ne $userId) {
                    $includeUserIds += $userId
                }
            }
        }
        
        foreach ($groupName in $groups) {
            if ($Global:EntraGroupCache.ContainsKey($groupName)) {
                $groupId = $Global:EntraGroupCache[$groupName]
                if ($null -ne $groupId) {
                    $includeGroupIds += $groupId
                }
            }
        }
        
        Write-LogMessage "CA policy will include $($includeUserIds.Count) users and $($includeGroupIds.Count) groups" -Level INFO -Component "ConditionalAccessProvisioning"
        
        # Build CA policy body
        # Reference: https://learn.microsoft.com/en-us/graph/tutorial-entra-internet-access#step-3-link-a-conditional-access-policy
        $body = @{
            displayName = $caDisplayNameWithSuffix
            state       = 'disabled'  # Always create in disabled state for safety
            conditions  = @{
                users = @{
                    includeUsers  = $includeUserIds
                    includeGroups = $includeGroupIds
                    excludeUsers  = @()
                    excludeGroups = @()
                    excludeRoles  = @()
                }
                applications = @{
                    # Target "All internet resources with Global Secure Access" app
                    includeApplications = @('5dc48733-b5df-475c-a49b-fa307ef00853')
                    excludeApplications = @()
                }
            }
            sessionControls = @{
                globalSecureAccessFilteringProfile = @{
                    profileId = $SecurityProfileId
                    isEnabled = $true
                }
            }
        }
        
        $bodyJson = $body | ConvertTo-Json -Depth 10
        $uri = "https://graph.microsoft.com/beta/identity/conditionalAccess/policies"
        
        Write-LogMessage "Creating CA policy with $($includeUserIds.Count) users and $($includeGroupIds.Count) groups" -Level INFO -Component "ConditionalAccessProvisioning"
        
        $newPolicy = Invoke-InternalGraphRequest -Method POST -Uri $uri -Body $bodyJson
        
        if ($null -ne $newPolicy -and $newPolicy.id) {
            Write-LogMessage "Successfully created CA policy: $caDisplayNameWithSuffix (ID: $($newPolicy.id), State: disabled)" -Level SUCCESS -Component "ConditionalAccessProvisioning"
            
            $Global:RecordLookup[$ProfileRow.UniqueRecordId].ProvisioningResult += " | CA Policy: Created successfully (disabled state)"
            $Global:RecordLookup[$ProfileRow.UniqueRecordId].CAPolicyId = $newPolicy.id
            
            return @{
                Success    = $true
                Action     = "Created"
                CAPolicyId = $newPolicy.id
                Error      = $null
            }
        }
        else {
            Write-LogMessage "Failed to create CA policy: $caDisplayNameWithSuffix (no ID returned)" -Level ERROR -Component "ConditionalAccessProvisioning"
            
            $Global:RecordLookup[$ProfileRow.UniqueRecordId].ProvisioningResult += " | CA Policy: Failed - no ID returned"
            
            return @{
                Success    = $false
                Action     = "Failed"
                CAPolicyId = $null
                Error      = "CA policy creation returned no ID"
            }
        }
    }
    catch {
        Write-LogMessage "Error creating Conditional Access policy: $_" -Level ERROR -Component "ConditionalAccessProvisioning"
        
        $Global:RecordLookup[$ProfileRow.UniqueRecordId].ProvisioningResult += " | CA Policy: Failed - $($_.Exception.Message)"
        
        return @{
            Success    = $false
            Action     = "Failed"
            CAPolicyId = $null
            Error      = $_.Exception.Message
        }
    }
}
