function Get-SecurityProfilePolicyLinks {
    <#
    .SYNOPSIS
        Retrieves and formats policy links for a security profile.
    
    .DESCRIPTION
        Retrieves a security profile with expanded policy details and builds the SecurityProfileLinks
        string in the format required for CSV export: "PolicyName:Priority;PolicyName2:Priority2"
        
        This function uses the Graph API expansion feature to retrieve policy details:
        GET /beta/networkAccess/filteringProfiles/{id}?$expand=policies($expand=policy)
        
        Without expansion, policy links only contain the link ID and priority, but not the policy name.
        The expansion retrieves the full policy object including the name.
    
    .PARAMETER ProfileId
        The unique identifier (GUID) of the security profile (filtering profile).
    
    .OUTPUTS
        System.String
        Semicolon-separated string of "PolicyName:Priority" pairs.
        Returns empty string if no valid policy links found.
    
    .EXAMPLE
        $profileId = "9b942d05-184b-4065-8b54-dd470010c456"
        $linksString = Get-SecurityProfilePolicyLinks -ProfileId $profileId
        # Output: "Block FR *.gouv.fr:100;Allow Social Media:200"
    
    .EXAMPLE
        $profiles = Get-IntSecurityProfile
        foreach ($profile in $profiles) {
            $links = Get-SecurityProfilePolicyLinks -ProfileId $profile.id
            Write-Host "Profile '$($profile.name)' links: $links"
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
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ProfileId
    )

    try {
        # Build URI with expansion to get policy details
        $uri = "/beta/networkAccess/filteringProfiles/$ProfileId`?`$expand=policies(`$expand=policy)"
        
        Write-LogMessage "Retrieving security profile policy links for profile ID: $ProfileId" -Level DEBUG -Component "SecurityProfileLinks"
        
        # Retrieve expanded profile data
        $profileExpanded = Invoke-InternalGraphRequest -Method GET -Uri $uri
        
        if (-not $profileExpanded) {
            Write-LogMessage "Failed to retrieve security profile with ID: $ProfileId" -Level ERROR -Component "SecurityProfileLinks"
            return ""
        }

        # Check if profile has policy links
        if (-not $profileExpanded.PSObject.Properties['policies'] -or -not $profileExpanded.policies) {
            Write-LogMessage "Security profile '$($profileExpanded.name)' (ID: $ProfileId) has no policy links" -Level WARN -Component "SecurityProfileLinks"
            return ""
        }

        $policyLinksArray = @($profileExpanded.policies)
        
        if ($policyLinksArray.Count -eq 0) {
            Write-LogMessage "Security profile '$($profileExpanded.name)' (ID: $ProfileId) has empty policies array" -Level WARN -Component "SecurityProfileLinks"
            return ""
        }

        # Build policy links strings
        $policyLinkStrings = @()
        $validLinksCount = 0
        $deletedLinksCount = 0

        foreach ($policyLink in $policyLinksArray) {
            # Validate policy link has required properties
            if (-not $policyLink.PSObject.Properties['priority']) {
                Write-LogMessage "Policy link in profile '$($profileExpanded.name)' missing 'priority' property. Skipping." -Level WARN -Component "SecurityProfileLinks"
                continue
            }

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

            # Build PolicyName:Priority string
            $policyName = $policyLink.policy.name
            $priority = $policyLink.priority
            $linkString = "$($policyName):$($priority)"
            
            $policyLinkStrings += $linkString
            $validLinksCount++
            
            Write-LogMessage "  Added policy link: $linkString (State: $($policyLink.state))" -Level DEBUG -Component "SecurityProfileLinks"
        }

        # Log summary
        if ($deletedLinksCount -gt 0) {
            Write-LogMessage "Security profile '$($profileExpanded.name)' has $deletedLinksCount deleted/invalid policy link(s)" -Level WARN -Component "SecurityProfileLinks"
        }

        if ($validLinksCount -eq 0) {
            Write-LogMessage "Security profile '$($profileExpanded.name)' has no valid policy links after filtering" -Level WARN -Component "SecurityProfileLinks"
            return ""
        }

        # Join policy links with semicolons
        $result = $policyLinkStrings -join ';'
        
        Write-LogMessage "Security profile '$($profileExpanded.name)' has $validLinksCount valid policy link(s)" -Level DEBUG -Component "SecurityProfileLinks"
        
        return $result
    }
    catch {
        Write-LogMessage "Error retrieving policy links for security profile '$ProfileId': $_" -Level ERROR -Component "SecurityProfileLinks"
        return ""
    }
}
