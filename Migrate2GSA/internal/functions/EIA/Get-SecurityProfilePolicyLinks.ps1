function Get-SecurityProfilePolicyLinks {
    <#
    .SYNOPSIS
        Retrieves and formats policy links for a security profile.
    
    .DESCRIPTION
        Retrieves a security profile with expanded policy details and builds the SecurityProfileLinks
        string in the format required for CSV export: "PolicyName:Priority;PolicyName2:Priority2"
        
        This function uses the Graph API expansion feature to retrieve policy details and
        linked Conditional Access policy names in a single call:
        GET /beta/networkAccess/filteringProfiles/{id}?$expand=policies($expand=policy),ConditionalAccessPolicies
        
        Without expansion, policy links only contain the link ID and priority, but not the policy name.
        The expansion retrieves the full policy object including the name.
        
        The ConditionalAccessPolicies expansion returns CA policy id and displayName without
        requiring Policy.Read.All scope.
    
    .PARAMETER ProfileId
        The unique identifier (GUID) of the security profile (filtering profile).
    
    .OUTPUTS
        PSCustomObject with properties:
        - LinksString: Semicolon-separated string of "PolicyName:Priority" pairs (or just "PolicyName" for non-filtering links)
        - CADisplayName: Display name of the linked Conditional Access policy (empty string if none)
    
    .EXAMPLE
        $profileId = "9b942d05-184b-4065-8b54-dd470010c456"
        $result = Get-SecurityProfilePolicyLinks -ProfileId $profileId
        $result.LinksString   # "Block FR *.gouv.fr:100;Allow Social Media:200"
        $result.CADisplayName # "CA_Finance_Access"
    
    .EXAMPLE
        $profiles = Get-IntSecurityProfile
        foreach ($profile in $profiles) {
            $result = Get-SecurityProfilePolicyLinks -ProfileId $profile.id
            Write-Host "Profile '$($profile.name)' links: $($result.LinksString), CA: $($result.CADisplayName)"
        }
    
    .NOTES
        Author: Franck Heilmann and Andres Canello
        Used by: Export-EntraInternetAccessConfig
        
        This function makes a Graph API call. Ensure proper authentication and scopes
        (NetworkAccessPolicy.Read.All) are in place before calling.
        
        Policy links may reference deleted policies. These are logged as warnings and excluded
        from the output string.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ProfileId
    )

    try {
        # Build URI with expansion to get policy details and linked CA policies
        $uri = "/beta/networkAccess/filteringProfiles/$ProfileId`?`$expand=policies(`$expand=policy),ConditionalAccessPolicies"
        
        Write-LogMessage "Retrieving security profile policy links for profile ID: $ProfileId" -Level DEBUG -Component "SecurityProfileLinks"
        
        # Retrieve expanded profile data
        $profileExpanded = Invoke-InternalGraphRequest -Method GET -Uri $uri
        
        if (-not $profileExpanded) {
            Write-LogMessage "Failed to retrieve security profile with ID: $ProfileId" -Level ERROR -Component "SecurityProfileLinks"
            return [PSCustomObject]@{ LinksString = ""; CADisplayName = "" }
        }

        # Extract linked CA policy display name from expansion
        $caDisplayName = ""
        if ($profileExpanded.PSObject.Properties['conditionalAccessPolicies'] -and $profileExpanded.conditionalAccessPolicies) {
            $caPolicies = @($profileExpanded.conditionalAccessPolicies)
            if ($caPolicies.Count -gt 0) {
                $caDisplayName = $caPolicies[0].displayName
                Write-LogMessage "  Found linked CA policy: $caDisplayName" -Level DEBUG -Component "SecurityProfileLinks"
                if ($caPolicies.Count -gt 1) {
                    Write-LogMessage "  Security profile '$($profileExpanded.name)' has $($caPolicies.Count) linked CA policies. Using first: $caDisplayName" -Level WARN -Component "SecurityProfileLinks"
                }
            }
        }

        # Check if profile has policy links
        if (-not $profileExpanded.PSObject.Properties['policies'] -or -not $profileExpanded.policies) {
            Write-LogMessage "Security profile '$($profileExpanded.name)' (ID: $ProfileId) has no policy links" -Level WARN -Component "SecurityProfileLinks"
            return [PSCustomObject]@{ LinksString = ""; CADisplayName = $caDisplayName }
        }

        $policyLinksArray = @($profileExpanded.policies)
        
        if ($policyLinksArray.Count -eq 0) {
            Write-LogMessage "Security profile '$($profileExpanded.name)' (ID: $ProfileId) has empty policies array" -Level WARN -Component "SecurityProfileLinks"
            return [PSCustomObject]@{ LinksString = ""; CADisplayName = $caDisplayName }
        }

        # Build policy links strings
        $policyLinkStrings = @()
        $validLinksCount = 0
        $deletedLinksCount = 0

        foreach ($policyLink in $policyLinksArray) {
            # Check if policy object exists (policy may be deleted)
            if (-not $policyLink.PSObject.Properties['policy'] -or -not $policyLink.policy) {
                Write-LogMessage "Policy link in profile '$($profileExpanded.name)' has no policy object (policy may be deleted). Link ID: $($policyLink.id)" -Level WARN -Component "SecurityProfileLinks"
                $deletedLinksCount++
                continue
            }

            # Validate policy has name
            if (-not $policyLink.policy.PSObject.Properties['name'] -or [string]::IsNullOrWhiteSpace($policyLink.policy.name)) {
                Write-LogMessage "Policy in link has no name. Link ID: $($policyLink.id), Policy ID: $($policyLink.policy.id)" -Level WARN -Component "SecurityProfileLinks"
                $deletedLinksCount++
                continue
            }

            $policyName = $policyLink.policy.name
            $odataType = if ($policyLink.PSObject.Properties['@odata.type']) { $policyLink.'@odata.type' } else { '' }

            # Only filteringPolicyLink has a priority property.
            # TLS inspection, threat intelligence, and cloud firewall links have state only.
            if ($policyLink.PSObject.Properties['priority']) {
                $linkString = "$($policyName):$($policyLink.priority)"
            }
            else {
                $linkString = $policyName
                Write-LogMessage "  Policy link '$policyName' ($odataType) has no priority (expected for non-filtering links)" -Level DEBUG -Component "SecurityProfileLinks"
            }
            
            $policyLinkStrings += $linkString
            $validLinksCount++
            
            Write-LogMessage "  Added policy link: $linkString (State: $($policyLink.state), Type: $odataType)" -Level DEBUG -Component "SecurityProfileLinks"
        }

        # Log summary
        if ($deletedLinksCount -gt 0) {
            Write-LogMessage "Security profile '$($profileExpanded.name)' has $deletedLinksCount deleted/invalid policy link(s)" -Level WARN -Component "SecurityProfileLinks"
        }

        if ($validLinksCount -eq 0) {
            Write-LogMessage "Security profile '$($profileExpanded.name)' has no valid policy links after filtering" -Level WARN -Component "SecurityProfileLinks"
            return [PSCustomObject]@{ LinksString = ""; CADisplayName = $caDisplayName }
        }

        # Join policy links with semicolons
        $linksResult = $policyLinkStrings -join ';'
        
        Write-LogMessage "Security profile '$($profileExpanded.name)' has $validLinksCount valid policy link(s)" -Level DEBUG -Component "SecurityProfileLinks"
        
        return [PSCustomObject]@{ LinksString = $linksResult; CADisplayName = $caDisplayName }
    }
    catch {
        Write-LogMessage "Error retrieving policy links for security profile '$ProfileId': $_" -Level ERROR -Component "SecurityProfileLinks"
        return [PSCustomObject]@{ LinksString = ""; CADisplayName = "" }
    }
}
