function New-SecurityProfile {
    <#
    .SYNOPSIS
        Creates or reuses a security profile with policy links.
    
    .DESCRIPTION
        Creates a new security profile or reuses an existing one if it already exists in the tenant.
        Links policies (Web Content Filtering and TLS Inspection) to the profile.
        Determines if CA policy should be created based on policy link success.
        The profile name is automatically suffixed with [Migrate2GSA] for identification.
    
    .PARAMETER ProfileRow
        Single row from security profiles CSV containing profile metadata and policy links.
    
    .OUTPUTS
        Returns hashtable with:
        - Success (bool)
        - Action (string: "Created", "Reused", "Failed")
        - ProfileId (string)
        - ShouldCreateCAPolicy (bool) - whether users/groups are specified
        - AllPolicyLinksSucceeded (bool) - whether all policy links were created successfully
        - Error (string)
    
    .EXAMPLE
        New-SecurityProfile -ProfileRow $profileRow
    
    .NOTES
        Author: Andres Canello
        Idempotent: Reuses existing profiles, adds only missing policy links.
        CA policy is only created if ALL policy links succeed.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ProfileRow
    )
    
    try {
        $profileName = $ProfileRow.SecurityProfileName
        $profileNameWithSuffix = "${profileName}[Migrate2GSA]"
        $priority = [int]$ProfileRow.Priority
        $policyLinks = $ProfileRow.ParsedPolicyLinks
        
        Write-LogMessage "Processing security profile: $profileName (Priority: $priority)" -Level INFO -Component "SecurityProfileProvisioning"
        
        # Determine if CA policy should be created
        $hasUsers = $ProfileRow.ParsedUsers.Count -gt 0
        $hasGroups = $ProfileRow.ParsedGroups.Count -gt 0
        $shouldCreateCAPolicy = $hasUsers -or $hasGroups
        
        if (-not $shouldCreateCAPolicy) {
            Write-LogMessage "Security Profile will be created without CA policy (no users/groups specified)" -Level INFO -Component "SecurityProfileProvisioning"
        }
        
        # Check if profile already exists
        $existingProfiles = Get-IntSecurityProfile
        $existingProfile = $null
        $profilesList = $null
        
        if ($null -ne $existingProfiles) {
            # Handle Graph API collection response structure
            $profilesList = $existingProfiles
            
            # Check if response has a 'value' property (collection response)
            if ($existingProfiles.PSObject.Properties.Name -contains 'value') {
                $profilesList = $existingProfiles.value
            }
            
            # Ensure we have an array
            if ($profilesList -isnot [array]) {
                $profilesList = @($profilesList)
            }
            
            # Find profile by exact name match
            $existingProfile = $profilesList | Where-Object { $_.name -eq $profileNameWithSuffix } | Select-Object -First 1
        }
        
        $profileId = $null
        $isReused = $false
        
        if ($null -ne $existingProfile) {
            Write-LogMessage "Security Profile already exists: $profileNameWithSuffix (ID: $($existingProfile.id))" -Level INFO -Component "SecurityProfileProvisioning"
            $profileId = $existingProfile.id
            $isReused = $true
            
            # Check if profile is linked to any CA policy
            Write-LogMessage "Checking if profile is linked to CA policy..." -Level INFO -Component "SecurityProfileProvisioning"
            $profileWithLinks = Get-IntSecurityProfile -Id $profileId -ExpandLinks
            
            $isLinkedToCAPolicy = $false
            if ($null -ne $profileWithLinks -and 
                $profileWithLinks.PSObject.Properties.Name -contains 'conditionalAccessPolicies' -and 
                $null -ne $profileWithLinks.conditionalAccessPolicies -and 
                $profileWithLinks.conditionalAccessPolicies.Count -gt 0) {
                
                $isLinkedToCAPolicy = $true
                Write-LogMessage "Profile is linked to CA policy. Cannot add new policy links." -Level WARN -Component "SecurityProfileProvisioning"
                
                $Global:RecordLookup[$ProfileRow.UniqueRecordId].ProvisioningResult = "Skipped: Cannot modify profile linked to CA policy"
                
                return @{
                    Success                  = $true
                    Action                   = "Skipped"
                    ProfileId                = $profileId
                    ShouldCreateCAPolicy     = $false
                    AllPolicyLinksSucceeded  = $false
                    Error                    = "Profile is linked to CA policy"
                }
            }
        }
        else {
            # Create new profile - first check if priority is available
            Write-LogMessage "Creating new security profile: $profileNameWithSuffix with priority $priority" -Level INFO -Component "SecurityProfileProvisioning"
            
            # Verify priority is not already taken by a different profile
            $conflictingProfile = $null
            if ($null -ne $profilesList -and $profilesList.Count -gt 0) {
                $conflictingProfile = $profilesList | Where-Object { 
                    $_.priority -eq $priority -and $_.name -ne $profileNameWithSuffix 
                } | Select-Object -First 1
            }
            
            if ($null -ne $conflictingProfile) {
                $errorMsg = "Priority $priority is already used by profile '$($conflictingProfile.name)'. Please choose a different priority or remove the conflicting profile."
                Write-LogMessage $errorMsg -Level ERROR -Component "SecurityProfileProvisioning"
                
                $Global:RecordLookup[$ProfileRow.UniqueRecordId].ProvisioningResult = "Failed: $errorMsg"
                
                return @{
                    Success                  = $false
                    Action                   = "Failed"
                    ProfileId                = $null
                    ShouldCreateCAPolicy     = $false
                    AllPolicyLinksSucceeded  = $false
                    Error                    = $errorMsg
                }
            }
            
            $newProfile = New-IntSecurityProfile -Name $profileNameWithSuffix -State 'enabled' -Priority $priority
            
            if ($null -ne $newProfile -and $newProfile.id) {
                Write-LogMessage "Successfully created security profile: $profileNameWithSuffix (ID: $($newProfile.id))" -Level SUCCESS -Component "SecurityProfileProvisioning"
                $profileId = $newProfile.id
            }
            else {
                Write-LogMessage "Failed to create security profile: $profileNameWithSuffix" -Level ERROR -Component "SecurityProfileProvisioning"
                
                $Global:RecordLookup[$ProfileRow.UniqueRecordId].ProvisioningResult = "Failed: Profile creation returned no ID"
                
                return @{
                    Success                  = $false
                    Action                   = "Failed"
                    ProfileId                = $null
                    ShouldCreateCAPolicy     = $false
                    AllPolicyLinksSucceeded  = $false
                    Error                    = "Profile creation returned no ID"
                }
            }
        }
        
        # Get existing policy links if profile was reused
        $existingPolicyLinks = @()
        if ($isReused) {
            Write-LogMessage "Retrieving existing policy links..." -Level INFO -Component "SecurityProfileProvisioning"
            $existingLinks = Get-IntFilteringPolicyLink -ProfileId $profileId
            
            if ($null -ne $existingLinks) {
                # Handle both single object and array responses
                if ($existingLinks -isnot [array]) {
                    $existingLinks = @($existingLinks)
                }
                
                # Check value property for collection response
                if ($existingLinks[0].PSObject.Properties.Name -contains 'value') {
                    $existingLinks = $existingLinks[0].value
                }
                
                # Extract policy IDs from existing links
                foreach ($link in $existingLinks) {
                    if ($null -ne $link.policy -and $null -ne $link.policy.id) {
                        $existingPolicyLinks += $link.policy.id
                    }
                }
                
                Write-LogMessage "Found $($existingPolicyLinks.Count) existing policy links" -Level INFO -Component "SecurityProfileProvisioning"
            }
        }
        
        # Create policy links
        Write-LogMessage "Processing $($policyLinks.Count) policy links for profile" -Level INFO -Component "SecurityProfileProvisioning"
        
        $createdLinksCount = 0
        $reusedLinksCount = 0
        $failedLinksCount = 0
        
        foreach ($link in $policyLinks) {
            $linkedPolicyName = $link.PolicyName
            $linkedPolicyNameWithSuffix = "${linkedPolicyName}[Migrate2GSA]"
            $linkPriority = $link.Priority
            
            # Check if policy exists in cache
            if (-not $Global:PolicyIdCache.ContainsKey($linkedPolicyName)) {
                Write-LogMessage "Policy '$linkedPolicyName' not found in cache. May have failed to provision or all rules failed." -Level WARN -Component "SecurityProfileProvisioning"
                $failedLinksCount++
                continue
            }
            
            $linkedPolicyId = $Global:PolicyIdCache[$linkedPolicyName]
            $linkedPolicyType = $Global:PolicyTypeCache[$linkedPolicyName]
            
            if ([string]::IsNullOrEmpty($linkedPolicyType)) {
                Write-LogMessage "Policy type unknown for '$linkedPolicyName'. Defaulting to WebContentFiltering." -Level WARN -Component "SecurityProfileProvisioning"
                $linkedPolicyType = 'WebContentFiltering'
            }
            
            # Verify policy still exists in tenant before attempting to link
            try {
                $policyExists = $false
                
                # Check if it's a web content filtering policy or TLS inspection policy
                if ($linkedPolicyType -eq 'WebContentFiltering') {
                    $wcfPolicy = Get-IntFilteringPolicy -Id $linkedPolicyId -ErrorAction SilentlyContinue
                    if ($null -ne $wcfPolicy) {
                        $policyExists = $true
                    }
                }
                else {
                    $tlsPolicy = Get-IntTlsInspectionPolicy -Id $linkedPolicyId -ErrorAction SilentlyContinue
                    if ($null -ne $tlsPolicy) {
                        $policyExists = $true
                    }
                }
                
                if (-not $policyExists) {
                    Write-LogMessage "Policy '$linkedPolicyName' (ID: $linkedPolicyId, Type: $linkedPolicyType) not found in tenant. Policy may have been deleted." -Level ERROR -Component "SecurityProfileProvisioning"
                    $failedLinksCount++
                    continue
                }
            }
            catch {
                Write-LogMessage "Error verifying policy existence for '$linkedPolicyName': $_" -Level ERROR -Component "SecurityProfileProvisioning"
                $failedLinksCount++
                continue
            }
            
            # Check if link already exists
            if ($existingPolicyLinks -contains $linkedPolicyId) {
                Write-LogMessage "Policy link already exists for policy: $linkedPolicyName. Skipping." -Level INFO -Component "SecurityProfileProvisioning"
                $reusedLinksCount++
                continue
            }
            
            # Create policy link
            try {
                Write-LogMessage "Creating policy link: $linkedPolicyName (Type: $linkedPolicyType, Priority: $linkPriority)" -Level INFO -Component "SecurityProfileProvisioning"
                
                # Note: The action parameter should match the policy's action, but since we're linking existing policies,
                # we'll use the policy's inherent action. For filtering policies, action is part of the policy definition.
                $newLink = New-IntFilteringPolicyLink -ProfileId $profileId -PolicyId $linkedPolicyId -Priority $linkPriority -PolicyType $linkedPolicyType
                
                if ($null -ne $newLink -and $newLink.id) {
                    Write-LogMessage "Successfully created policy link for: $linkedPolicyName" -Level SUCCESS -Component "SecurityProfileProvisioning"
                    $createdLinksCount++
                }
                else {
                    Write-LogMessage "Failed to create policy link for: $linkedPolicyName (no ID returned)" -Level ERROR -Component "SecurityProfileProvisioning"
                    $failedLinksCount++
                }
            }
            catch {
                Write-LogMessage "Error creating policy link for '$linkedPolicyName': $_" -Level ERROR -Component "SecurityProfileProvisioning"
                $failedLinksCount++
            }
        }
        
        $totalExpectedLinks = $policyLinks.Count
        $totalSuccessfulLinks = $createdLinksCount + $reusedLinksCount
        $allLinksSucceeded = ($totalSuccessfulLinks -eq $totalExpectedLinks) -and ($failedLinksCount -eq 0)
        
        Write-LogMessage "Policy link provisioning: $createdLinksCount created, $reusedLinksCount reused, $failedLinksCount failed" -Level SUMMARY -Component "SecurityProfileProvisioning"
        
        # Update provisioning result
        if ($allLinksSucceeded) {
            if ($isReused) {
                $Global:RecordLookup[$ProfileRow.UniqueRecordId].ProvisioningResult = "Reused: Profile exists - added $createdLinksCount new policy links, $reusedLinksCount links already existed"
            }
            else {
                $Global:RecordLookup[$ProfileRow.UniqueRecordId].ProvisioningResult = "Provisioned: Profile and all policy links created successfully"
            }
            $Global:RecordLookup[$ProfileRow.UniqueRecordId].SecurityProfileId = $profileId
        }
        else {
            $Global:RecordLookup[$ProfileRow.UniqueRecordId].ProvisioningResult = "Partial: Profile created but some policy links failed ($failedLinksCount failed)"
            $Global:RecordLookup[$ProfileRow.UniqueRecordId].SecurityProfileId = $profileId
        }
        
        return @{
            Success                  = $true
            Action                   = if ($isReused) { "Reused" } else { "Created" }
            ProfileId                = $profileId
            ShouldCreateCAPolicy     = $shouldCreateCAPolicy
            AllPolicyLinksSucceeded  = $allLinksSucceeded
            Error                    = $null
        }
    }
    catch {
        Write-LogMessage "Error creating/reusing security profile: $_" -Level ERROR -Component "SecurityProfileProvisioning"
        
        $Global:RecordLookup[$ProfileRow.UniqueRecordId].ProvisioningResult = "Failed: $($_.Exception.Message)"
        
        return @{
            Success                  = $false
            Action                   = "Failed"
            ProfileId                = $null
            ShouldCreateCAPolicy     = $false
            AllPolicyLinksSucceeded  = $false
            Error                    = $_.Exception.Message
        }
    }
}
