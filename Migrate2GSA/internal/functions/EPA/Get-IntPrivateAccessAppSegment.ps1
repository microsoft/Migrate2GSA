function Get-IntPrivateAccessAppSegment {

    [CmdletBinding(DefaultParameterSetName = 'AllApplicationSegments')]
    param (
        [Alias('ObjectId')]
        [Parameter(Mandatory = $True, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [System.String]
        $ApplicationId,

        [Parameter(Mandatory = $False, ParameterSetName = 'SingleApplicationSegment')]
        [System.String]
        $ApplicationSegmentId
    )

    PROCESS {
        try {
            switch ($PSCmdlet.ParameterSetName) {
                "AllApplicationSegments" {
                    # Retrieve all application segments
                    $response = Invoke-InternalGraphRequest -Method GET -Headers $customHeaders -OutputType PSObject -Uri "https://graph.microsoft.com/beta/applications/$ApplicationId/onPremisesPublishing/segmentsConfiguration/microsoft.graph.ipSegmentConfiguration/applicationSegments"
                    $response
                    break
                }
                "SingleApplicationSegment" {
                    # Retrieve a single application segment
                    $response = Invoke-InternalGraphRequest -Method GET -Headers $customHeaders -OutputType PSObject -Uri "https://graph.microsoft.com/beta/applications/$ApplicationId/onPremisesPublishing/segmentsConfiguration/microsoft.graph.ipSegmentConfiguration/applicationSegments/$ApplicationSegmentId"
                    $response
                    break
                }
            }
        } catch {
            Write-Error "Failed to retrieve the application segment(s): $_"
        }
    }
}