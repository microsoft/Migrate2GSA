function Get-IntDiscoveredApplicationSegmentReport {
    <#
    .SYNOPSIS
        Retrieves discovered application segments from the App Discovery report.

    .DESCRIPTION
        Calls the Microsoft Graph beta endpoint to retrieve discovered application segments
        from the Entra Private Access App Discovery report. Supports filtering by access type
        and limiting the number of results.

    .PARAMETER StartDateTime
        Start of the discovery window (UTC).

    .PARAMETER EndDateTime
        End of the discovery window (UTC).

    .PARAMETER AccessTypeFilter
        Filter by access type: 'quickAccess' or 'appAccess'. Omit for all access types.

    .PARAMETER Top
        Maximum number of records to return. Default: 500.

    .OUTPUTS
        Array of PSObjects representing discovered application segments, or $null if empty.

    .EXAMPLE
        $segments = Get-IntDiscoveredApplicationSegmentReport -StartDateTime $start -EndDateTime $end -AccessTypeFilter 'quickAccess'
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [datetime]$StartDateTime,

        [Parameter(Mandatory = $true)]
        [datetime]$EndDateTime,

        [Parameter(Mandatory = $false)]
        [ValidateSet('quickAccess', 'appAccess')]
        [string]$AccessTypeFilter,

        [Parameter(Mandatory = $false)]
        [int]$Top = 500
    )

    process {
        try {
            $startStr = $StartDateTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            $endStr = $EndDateTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

            $baseUri = "/beta/networkaccess/reports/getDiscoveredApplicationSegmentReport(startDateTime=$startStr,endDateTime=$endStr)"

            # Build OData filter
            $filter = "lastAccessDateTime ge $startStr and lastAccessDateTime lt $endStr"
            if ($AccessTypeFilter) {
                $filter += " and accessType eq '$AccessTypeFilter'"
            }

            $uri = "$baseUri`?`$filter=$filter&`$orderby=userCount desc&`$top=$Top"

            $response = Invoke-InternalGraphRequest -Method GET -OutputType PSObject -Uri $uri

            if (-not $response) {
                return $null
            }

            # Unwrap collection
            if ($response.PSObject.Properties.Name -contains 'value') {
                $segments = $response.value
                if ($segments -and $segments.Count -gt 0) {
                    return $segments
                }
                return $null
            }

            return $response
        }
        catch {
            Write-Error "Failed to retrieve discovered application segment report: $_"
            throw
        }
    }
}
