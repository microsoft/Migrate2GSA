function Get-IntDiscoveredApplicationSegmentUserReport {
    <#
    .SYNOPSIS
        Retrieves the list of users who accessed a specific discovered application segment.

    .DESCRIPTION
        Calls the Microsoft Graph beta userReport endpoint to retrieve users who accessed
        a specific discovered application segment during the specified time window.

    .PARAMETER StartDateTime
        Start of the discovery window (UTC).

    .PARAMETER EndDateTime
        End of the discovery window (UTC).

    .PARAMETER DiscoveredApplicationSegmentId
        The segment ID from Get-IntDiscoveredApplicationSegmentReport.

    .PARAMETER Top
        Maximum number of user records to return. Default: 50.

    .OUTPUTS
        Array of user PSObjects, or $null if empty.

    .EXAMPLE
        $users = Get-IntDiscoveredApplicationSegmentUserReport -StartDateTime $start -EndDateTime $end -DiscoveredApplicationSegmentId $segmentId
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [datetime]$StartDateTime,

        [Parameter(Mandatory = $true)]
        [datetime]$EndDateTime,

        [Parameter(Mandatory = $true)]
        [string]$DiscoveredApplicationSegmentId,

        [Parameter(Mandatory = $false)]
        [int]$Top = 50
    )

    process {
        try {
            $startStr = $StartDateTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            $endStr = $EndDateTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

            $uri = "/beta/networkaccess/reports/userReport(startDateTime=$startStr,endDateTime=$endStr,discoveredApplicationSegmentId='$DiscoveredApplicationSegmentId')?`$orderby=lastAccessDateTime desc&`$top=$Top"

            $response = Invoke-InternalGraphRequest -Method GET -OutputType PSObject -Uri $uri

            if (-not $response) {
                return $null
            }

            # Unwrap collection
            if ($response.PSObject.Properties.Name -contains 'value') {
                $users = $response.value
                if ($users -and $users.Count -gt 0) {
                    return $users
                }
                return $null
            }

            return $response
        }
        catch {
            Write-Error "Failed to retrieve user report for segment '$DiscoveredApplicationSegmentId': $_"
            throw
        }
    }
}
