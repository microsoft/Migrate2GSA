function Get-IntTlsInspectionRule {
    <#
    .SYNOPSIS
        Retrieves TLS inspection rules for a TLS inspection policy.
    
    .DESCRIPTION
        Gets TLS inspection rules from Microsoft Graph API for a specific TLS inspection
        policy. Can retrieve all rules or a specific rule by ID.
    
    .PARAMETER PolicyId
        The unique identifier of the TLS inspection policy.
    
    .PARAMETER Id
        The unique identifier of the TLS inspection rule to retrieve.
    
    .EXAMPLE
        Get-IntTlsInspectionRule -PolicyId "12345678-1234-1234-1234-123456789012"
        Retrieves all TLS inspection rules for the specified policy.
    
    .EXAMPLE
        Get-IntTlsInspectionRule -PolicyId "12345678-1234-1234-1234-123456789012" -Id "87654321-4321-4321-4321-210987654321"
        Retrieves a specific TLS inspection rule by ID.
    #>
    [CmdletBinding(DefaultParameterSetName = 'All')]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PolicyId,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'ById')]
        [ValidateNotNullOrEmpty()]
        [string]$Id
    )

    try {
        $uri = if ($PSCmdlet.ParameterSetName -eq 'ById') {
            "https://graph.microsoft.com/beta/networkAccess/tlsInspectionPolicies/$PolicyId/policyRules/$Id"
        }
        else {
            "https://graph.microsoft.com/beta/networkAccess/tlsInspectionPolicies/$PolicyId/policyRules"
        }

        $response = Invoke-InternalGraphRequest -Method GET -Uri $uri
        return $response
    }
    catch {
        Write-Error "Failed to retrieve TLS inspection rule: $_"
        throw
    }
}
