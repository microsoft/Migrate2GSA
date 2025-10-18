function Get-IntServicePrincipalAppRoleAssignedTo {
    <#
    .SYNOPSIS
        Retrieves app role assignments for a service principal.
    
    .DESCRIPTION
        Gets all app role assignments (appRoleAssignedTo) for a specified service principal.
        This shows which users, groups, or service principals have been assigned to the application.
        Automatically handles pagination to retrieve all assignments.
    
    .PARAMETER ServicePrincipalId
        The object ID of the service principal to query for app role assignments.
    
    .OUTPUTS
        Returns an array of app role assignment objects with properties including:
        - Id: Assignment identifier
        - AppRoleId: The app role identifier
        - PrincipalId: The assigned principal's ID
        - PrincipalType: Type of principal (User, Group, ServicePrincipal)
        - PrincipalDisplayName: Display name of the assigned principal
        - ResourceId: The service principal resource ID
        - ResourceDisplayName: Display name of the resource
        - CreationTimestamp: When the assignment was created
    
    .EXAMPLE
        $assignments = Get-ServicePrincipalAppRoleAssignedTo -ServicePrincipalId "3c04d402-505f-408d-98ed-ea5e0b925c8c"
        Retrieves all app role assignments for the specified service principal.
    
    .EXAMPLE
        $servicePrincipal = Get-ServicePrincipal -Filter "displayName eq 'My App'"
        $assignments = Get-ServicePrincipalAppRoleAssignedTo -ServicePrincipalId $servicePrincipal.Id
        Gets assignments for a service principal by first looking it up by name.
    
    .NOTES
        This is an internal function and should not be exported from the module.
        Uses Invoke-InternalGraphRequest for consistent error handling and automatic pagination.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ServicePrincipalId
    )
    
    begin {
        Write-Verbose "Retrieving app role assignments for service principal: $ServicePrincipalId"
    }
    
    process {
        try {
            # Construct the Graph API endpoint
            $uri = "/beta/servicePrincipals/$ServicePrincipalId/appRoleAssignedTo"
            
            # Make the API request with automatic pagination
            $graphParams = @{
                Uri = $uri
                Method = 'GET'
            }
            
            if ($DebugPreference -eq 'Continue') {
                Write-Debug "Get-ServicePrincipalAppRoleAssignedTo: Calling Graph API endpoint: $uri"
            }
            
            $result = Invoke-InternalGraphRequest @graphParams
            
            if ($DebugPreference -eq 'Continue') {
                $count = if ($result) { $result.Count } else { 0 }
                Write-Debug "Get-ServicePrincipalAppRoleAssignedTo: Retrieved $count app role assignment(s)"
            }
            
            return $result
        }
        catch {
            Write-Error "Failed to retrieve app role assignments for service principal '$ServicePrincipalId': $_"
            throw
        }
    }
}
