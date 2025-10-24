function Get-IntGSATenantStatus {
        
    PROCESS {
        try {

            # Invoke the API request to get the tenant status
            $response = Invoke-InternalGraphRequest -Method GET -OutputType PSObject -Uri "/beta/networkAccess/tenantStatus"

            # Check the response and provide feedback
            if ($response) {
                Write-Output $response
            }
            else {
                Write-Error "Failed to retrieve the Global Secure Access Tenant status."
            }
        }
        catch {
            Write-Error "An error occurred while retrieving the Global Secure Access Tenant status: $_"
        }
    }
}