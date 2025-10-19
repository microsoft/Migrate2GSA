function Get-IntThreatIntelligenceRule {
    <#
    .SYNOPSIS
        Retrieves threat intelligence rules for a threat intelligence policy.
    
    .DESCRIPTION
        Gets threat intelligence rules from Microsoft Graph API for a specific
        threat intelligence policy. Can retrieve all rules or a specific rule by ID.
    
    .PARAMETER PolicyId
        The unique identifier of the threat intelligence policy.
    
    .PARAMETER Id
        The unique identifier of the threat intelligence rule to retrieve.
    
    .EXAMPLE
        Get-IntThreatIntelligenceRule -PolicyId "975d3ea5-a5df-43f4-b725-c1f952e59d6a"
        Retrieves all threat intelligence rules for the specified policy.
    
    .EXAMPLE
        Get-IntThreatIntelligenceRule -PolicyId "975d3ea5-a5df-43f4-b725-c1f952e59d6a" -Id "0c375ae2-22d3-474f-ae63-af5f99b0811f"
        Retrieves a specific threat intelligence rule by ID.
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
            "https://graph.microsoft.com/beta/networkAccess/threatIntelligencePolicies/$PolicyId/policyRules/$Id"
        }
        else {
            "https://graph.microsoft.com/beta/networkAccess/threatIntelligencePolicies/$PolicyId/policyRules"
        }

        $response = Invoke-InternalGraphRequest -Method GET -Uri $uri
        return $response
    }
    catch {
        Write-Error "Failed to retrieve threat intelligence rule: $_"
        throw
    }
}
