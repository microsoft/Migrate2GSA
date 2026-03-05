function Get-IntConditionalAccessPolicy {
    <#
    .SYNOPSIS
        Retrieves Conditional Access policies from Microsoft Entra ID.

    .DESCRIPTION
        Queries Microsoft Entra ID to retrieve Conditional Access policies using
        the Microsoft Graph API. Returns all policies in the tenant.

    .OUTPUTS
        Returns Conditional Access policy objects from Microsoft Graph.
        Returns $null if no policies are found.

    .EXAMPLE
        Get-IntConditionalAccessPolicy
        Retrieves all Conditional Access policies in the tenant.

    .NOTES
        Author: Andres Canello
        Requires: Microsoft Graph API permissions (Policy.Read.All minimum)
    #>

    [CmdletBinding()]
    param ()

    process {
        try {
            $params = @{
                Method     = 'GET'
                Uri        = "https://graph.microsoft.com/beta/identity/conditionalAccess/policies"
                OutputType = 'PSObject'
            }

            $response = Invoke-InternalGraphRequest @params

            if ($response) {
                if ($response.PSObject.Properties.Name -contains 'value') {
                    $policies = $response.value

                    if ($policies -and $policies.Count -gt 0) {
                        return $policies
                    }
                    else {
                        return $null
                    }
                }
                else {
                    return $response
                }
            }
            else {
                return $null
            }
        }
        catch {
            Write-Error "Failed to retrieve Conditional Access policies: $_"
            throw
        }
    }
}
