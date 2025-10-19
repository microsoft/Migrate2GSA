function Get-IntFilteringPolicyLink {
    <#
    .SYNOPSIS
        Retrieves filtering policy links for a security profile.
    
    .DESCRIPTION
        Gets filtering policy links from Microsoft Graph API for a specific security profile.
        Can retrieve all policy links or a specific link by ID.
    
    .PARAMETER ProfileId
        The unique identifier of the security profile.
    
    .PARAMETER Id
        The unique identifier of the policy link to retrieve.
    
    .EXAMPLE
        Get-IntFilteringPolicyLink -ProfileId "12345678-1234-1234-1234-123456789012"
        Retrieves all policy links for the specified profile.
    
    .EXAMPLE
        Get-IntFilteringPolicyLink -ProfileId "12345678-1234-1234-1234-123456789012" -Id "87654321-4321-4321-4321-210987654321"
        Retrieves a specific policy link by ID.
    #>
    [CmdletBinding(DefaultParameterSetName = 'All')]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ProfileId,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'ById')]
        [ValidateNotNullOrEmpty()]
        [string]$Id
    )

    try {
        $uri = if ($PSCmdlet.ParameterSetName -eq 'ById') {
            "https://graph.microsoft.com/beta/networkAccess/filteringProfiles/$ProfileId/policies/$Id"
        }
        else {
            "https://graph.microsoft.com/beta/networkAccess/filteringProfiles/$ProfileId/policies"
        }

        $response = Invoke-InternalGraphRequest -Method GET -Uri $uri
        return $response
    }
    catch {
        Write-Error "Failed to retrieve filtering policy link: $_"
        throw
    }
}
