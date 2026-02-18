function Get-IntNetworkAccessForwardingProfile {
    <#
    .SYNOPSIS
        Retrieves network access forwarding profiles from Global Secure Access.

    .DESCRIPTION
        Gets forwarding profiles from the Microsoft Entra Global Secure Access service.
        Can retrieve all profiles or filter by profile type.

    .PARAMETER ProfileType
        Optional filter for the traffic forwarding type.
        Valid values: 'private', 'internet', 'm365'
        Maps to the trafficForwardingType property in the API response.

    .OUTPUTS
        Returns the forwarding profile object(s) matching the specified criteria.

    .EXAMPLE
        Get-IntNetworkAccessForwardingProfile
        Retrieves all forwarding profiles.

    .EXAMPLE
        Get-IntNetworkAccessForwardingProfile -ProfileType 'private'
        Retrieves the Private Access forwarding profile.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateSet('private', 'internet', 'm365')]
        [System.String]
        $ProfileType
    )

    process {
        try {
            $response = Invoke-InternalGraphRequest -Method GET -OutputType PSObject `
                -Uri "https://graph.microsoft.com/beta/networkAccess/forwardingProfiles"

            if (-not $response) {
                return $null
            }

            # Handle collection response
            $profiles = $response
            if ($response.PSObject.Properties.Name -contains 'value') {
                $profiles = $response.value
            }

            # Filter by profile type if specified
            if ($ProfileType -and $profiles) {
                $profiles = $profiles | Where-Object { $_.trafficForwardingType -eq $ProfileType }
                if ($profiles -is [array] -and $profiles.Count -eq 1) {
                    return $profiles[0]
                }
            }

            return $profiles
        }
        catch {
            Write-Error "Failed to retrieve network access forwarding profiles: $_"
            return $null
        }
    }
}
