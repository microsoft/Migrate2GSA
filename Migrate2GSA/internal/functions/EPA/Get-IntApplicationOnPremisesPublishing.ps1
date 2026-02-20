function Get-IntApplicationOnPremisesPublishing {
    <#
    .SYNOPSIS
        Retrieves onPremisesPublishing configuration for an application.

    .DESCRIPTION
        Gets the application proxy (onPremisesPublishing) configuration for a specified
        Private Access application. Also retrieves the assigned connector group via the
        connectorGroup navigation property.

    .PARAMETER ApplicationId
        The object ID of the application.

    .OUTPUTS
        Returns a PSCustomObject with:
        - onPremisesPublishing: The full onPremisesPublishing configuration object
        - connectorGroup: The assigned connector group object (id, name, etc.) or $null

    .EXAMPLE
        $publishing = Get-IntApplicationOnPremisesPublishing -ApplicationId "a1b2c3d4..."
        $connectorGroupId = $publishing.connectorGroup.id
        $connectorGroupName = $publishing.connectorGroup.name
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ApplicationId
    )

    process {
        $result = [PSCustomObject]@{
            onPremisesPublishing = $null
            connectorGroup      = $null
        }

        # Get onPremisesPublishing configuration
        try {
            $publishingResponse = Invoke-InternalGraphRequest -Method GET -OutputType PSObject `
                -Uri "https://graph.microsoft.com/beta/applications/$ApplicationId/onPremisesPublishing"

            if ($publishingResponse) {
                $result.onPremisesPublishing = $publishingResponse
            }
        }
        catch {
            Write-Warning "Failed to retrieve onPremisesPublishing for application '$ApplicationId': $_"
        }

        # Get assigned connector group via navigation property
        try {
            $connectorGroupResponse = Invoke-InternalGraphRequest -Method GET -OutputType PSObject `
                -Uri "https://graph.microsoft.com/beta/applications/$ApplicationId/connectorGroup"

            if ($connectorGroupResponse) {
                $result.connectorGroup = $connectorGroupResponse
            }
        }
        catch {
            Write-Verbose "No connector group assigned or failed to retrieve for application '$ApplicationId': $_"
        }

        return $result
    }
}
