function Resolve-EntraUsers {
    <#
    .SYNOPSIS
        Resolves and caches Entra ID users for Conditional Access policy assignments.
    
    .DESCRIPTION
        Parses EntraUsers column from security profiles CSV, aggregates and deduplicates user principal names,
        resolves each user via Microsoft Graph, and caches the results for efficient lookup during provisioning.
    
    .PARAMETER ConfigData
        Security profiles configuration data (one row per profile with CA policy information).
    
    .OUTPUTS
        None. Results are stored in $Global:EntraUserCache hashtable.
    
    .EXAMPLE
        Resolve-EntraUsers -ConfigData $securityProfilesConfig
    
    .NOTES
        Author: Andres Canello
        Requires: User.Read.All Graph API permission
        Missing users are cached as $null for later validation.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$ConfigData
    )
    
    try {
        Write-LogMessage "Starting user resolution..." -Level INFO -Component "Validation"
        
        # Aggregate all unique user principal names from all security profiles
        $allUsers = @()
        foreach ($row in $ConfigData) {
            if ($row.PSObject.Properties.Name -contains 'ParsedUsers' -and $row.ParsedUsers.Count -gt 0) {
                $allUsers += $row.ParsedUsers
            }
        }
        
        # Deduplicate users
        $uniqueUsers = $allUsers | Select-Object -Unique | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        
        if ($uniqueUsers.Count -eq 0) {
            Write-LogMessage "No users to resolve" -Level INFO -Component "Validation"
            return
        }
        
        Write-LogMessage "Found $($uniqueUsers.Count) unique users to resolve" -Level INFO -Component "Validation"
        
        # Resolve each user
        $resolvedCount = 0
        $missingCount = 0
        
        foreach ($upn in $uniqueUsers) {
            try {
                Write-LogMessage "Resolving user: $upn" -Level DEBUG -Component "Validation"
                
                $filter = "userPrincipalName eq '$upn'"
                $user = Get-IntUser -Filter $filter
                
                if ($null -ne $user) {
                    # Handle array response (take first match)
                    if ($user -is [array]) {
                        $user = $user[0]
                    }
                    
                    $Global:EntraUserCache[$upn] = $user.id
                    $resolvedCount++
                    Write-LogMessage "Resolved user: $upn (ID: $($user.id))" -Level DEBUG -Component "Validation"
                }
                else {
                    $Global:EntraUserCache[$upn] = $null
                    $missingCount++
                    Write-LogMessage "User not found in tenant: $upn" -Level WARN -Component "Validation"
                }
            }
            catch {
                $Global:EntraUserCache[$upn] = $null
                $missingCount++
                Write-LogMessage "Failed to resolve user '$upn': $_" -Level WARN -Component "Validation"
            }
        }
        
        Write-LogMessage "User resolution completed: $resolvedCount resolved, $missingCount missing" -Level INFO -Component "Validation"
    }
    catch {
        Write-LogMessage "Failed to resolve users: $_" -Level ERROR -Component "Validation"
        throw
    }
}
