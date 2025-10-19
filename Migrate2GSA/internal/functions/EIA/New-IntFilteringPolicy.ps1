function New-IntFilteringPolicy {
    <#
    .SYNOPSIS
        Creates a new Entra Internet Access filtering policy.
    
    .DESCRIPTION
        Creates a new filtering policy in Microsoft Graph API with the specified
        name, description, and action.
    
    .PARAMETER Name
        The name of the filtering policy.
    
    .PARAMETER Description
        Optional description of the filtering policy.
    
    .PARAMETER Action
        The action to take. Valid values: block, allow. Default: block.
    
    .EXAMPLE
        New-IntFilteringPolicy -Name "Block Malicious Sites" -Action block
        Creates a new filtering policy with block action.
    
    .EXAMPLE
        New-IntFilteringPolicy -Name "Allow Internal Resources" -Description "Allow access to internal sites" -Action allow
        Creates a new filtering policy with allow action and description.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$Description,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('block', 'allow')]
        [string]$Action = 'block'
    )

    try {
        $body = @{
            name        = $Name
            action      = $Action
            policyRules = @()
        }

        if ($Description) {
            $body['description'] = $Description
        }

        $bodyJson = $body | ConvertTo-Json -Depth 10
        $uri = "https://graph.microsoft.com/beta/networkAccess/filteringPolicies"

        $response = Invoke-InternalGraphRequest -Method POST -Uri $uri -Body $bodyJson
        return $response
    }
    catch {
        Write-Error "Failed to create filtering policy: $_"
        throw
    }
}
