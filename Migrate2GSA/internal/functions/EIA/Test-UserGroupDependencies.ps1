function Test-UserGroupDependencies {
    <#
    .SYNOPSIS
        Validates that all referenced users and groups exist in the target tenant.
    
    .DESCRIPTION
        Checks the global user and group caches for any missing (null) values.
        If any users or groups are missing, throws an error with a complete list,
        stopping script execution before any provisioning begins.
    
    .PARAMETER ConfigData
        Security profiles configuration data (used for context, actual validation uses caches).
    
    .OUTPUTS
        None. Throws error if any dependencies are missing.
    
    .EXAMPLE
        Test-UserGroupDependencies -ConfigData $securityProfilesConfig
    
    .NOTES
        Author: Andres Canello
        This function ensures all CA policy assignments are valid before provisioning.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$ConfigData
    )
    
    try {
        Write-LogMessage "Validating user and group dependencies..." -Level INFO -Component "Validation"
        
        $missingUsers = @()
        $missingGroups = @()
        
        # Check for missing users
        foreach ($upn in $Global:EntraUserCache.Keys) {
            if ($null -eq $Global:EntraUserCache[$upn]) {
                $missingUsers += $upn
            }
        }
        
        # Check for missing groups
        foreach ($groupName in $Global:EntraGroupCache.Keys) {
            if ($null -eq $Global:EntraGroupCache[$groupName]) {
                $missingGroups += $groupName
            }
        }
        
        # If any dependencies are missing, throw error
        if ($missingUsers.Count -gt 0 -or $missingGroups.Count -gt 0) {
            $errorMessage = "Cannot proceed with provisioning. The following users/groups were not found in the target tenant:`n"
            
            if ($missingUsers.Count -gt 0) {
                $errorMessage += "Missing Users: $($missingUsers -join ', ')`n"
            }
            
            if ($missingGroups.Count -gt 0) {
                $errorMessage += "Missing Groups: $($missingGroups -join ', ')`n"
            }
            
            $errorMessage += "Please verify these users/groups exist in the target tenant and update the CSV accordingly."
            
            Write-LogMessage $errorMessage -Level ERROR -Component "Validation"
            throw $errorMessage
        }
        
        Write-LogMessage "All user and group dependencies validated successfully" -Level SUCCESS -Component "Validation"
    }
    catch {
        # Re-throw to stop execution
        throw
    }
}
