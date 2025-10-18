function New-IntGroupAppRoleAssignment {
    <#
    .SYNOPSIS
        Creates a new app role assignment for a group.
    
    .DESCRIPTION
        Assigns an app role to a group by creating an appRoleAssignment for the specified group.
        This grants the group access to the application with the specified app role.
    
    .PARAMETER GroupId
        The object ID of the group to which the app role will be assigned.
    
    .PARAMETER AppRoleId
        The ID of the app role to assign. Use '00000000-0000-0000-0000-000000000000' for default access.
    
    .PARAMETER PrincipalId
        The ID of the principal (typically the same as GroupId for group assignments).
    
    .PARAMETER ResourceId
        The object ID of the service principal (resource) that defines the app role.
    
    .OUTPUTS
        Returns the created app role assignment object with properties including:
        - Id: Assignment identifier
        - AppRoleId: The assigned app role identifier
        - PrincipalId: The group's ID
        - ResourceId: The service principal's ID
        - CreationTimestamp: When the assignment was created
    
    .EXAMPLE
        $assignment = New-IntGroupAppRoleAssignment -GroupId "f0cf3091-3cb9-4ceb-b897-fd521a81e714" `
                                                     -AppRoleId "00000000-0000-0000-0000-000000000000" `
                                                     -PrincipalId "f0cf3091-3cb9-4ceb-b897-fd521a81e714" `
                                                     -ResourceId "a1b2c3d4-e5f6-4a5b-8c7d-9e8f7a6b5c4d"
        Creates a new app role assignment for the specified group.
    
    .EXAMPLE
        $params = @{
            GroupId = $group.Id
            AppRoleId = $appRole.Id
            PrincipalId = $group.Id
            ResourceId = $servicePrincipal.Id
        }
        $assignment = New-IntGroupAppRoleAssignment @params
        Creates an app role assignment using splatting.
    
    .NOTES
        This is an internal function and should not be exported from the module.
        Uses Invoke-InternalGraphRequest for consistent error handling and retry logic.
        
        API Endpoint: POST /groups/{group-id}/appRoleAssignments
        Graph Permission Required: AppRoleAssignment.ReadWrite.All
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$GroupId,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AppRoleId,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PrincipalId,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ResourceId
    )
    
    begin {
        Write-Verbose "Creating app role assignment for group: $GroupId"
    }
    
    process {
        try {
            # Construct the Graph API endpoint
            $uri = "/beta/groups/$GroupId/appRoleAssignments"
            
            # Build request body
            $body = @{
                appRoleId = $AppRoleId
                principalId = $PrincipalId
                resourceId = $ResourceId
            }
            
            if ($DebugPreference -eq 'Continue') {
                Write-Debug "New-IntGroupAppRoleAssignment: Calling Graph API endpoint: $uri"
                Write-Debug "New-IntGroupAppRoleAssignment: Request body: $(ConvertTo-Json $body -Depth 5)"
            }
            
            # Make the API request
            $graphParams = @{
                Uri = $uri
                Method = 'POST'
                Body = $body
            }
            
            $result = Invoke-InternalGraphRequest @graphParams
            
            if ($DebugPreference -eq 'Continue') {
                Write-Debug "New-IntGroupAppRoleAssignment: Successfully created app role assignment"
            }
            
            return $result
        }
        catch {
            Write-Error "Failed to create app role assignment for group '$GroupId': $_"
            throw
        }
    }
}
