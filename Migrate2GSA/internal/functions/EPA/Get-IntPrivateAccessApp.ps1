function Get-IntPrivateAccessApp {
    
    [CmdletBinding(DefaultParameterSetName = 'AllPrivateAccessApps')]
    param (
        [Alias("ObjectId")]
        [Parameter(Mandatory = $True, ParameterSetName = 'SingleAppID')]
        [System.String]
        $ApplicationId,
        
        [Parameter(Mandatory = $False, ParameterSetName = 'SingleAppName')]
        [System.String]
        $ApplicationName,

        [Parameter(Mandatory = $False, ParameterSetName = 'QuickAccessApp')]
        [switch]
        $QuickAccessOnly
    )

    PROCESS {
        try {

            switch ($PSCmdlet.ParameterSetName) {
                "AllPrivateAccessApps" {
                    # Retrieve all private access applications
                    $response = Invoke-InternalGraphRequest -Method GET -OutputType PSObject -Uri 'https://graph.microsoft.com/beta/applications?$count=true&$select=displayName,appId,id,tags,createdDateTime,servicePrincipalType,createdDateTime,servicePrincipalNames&$filter=tags/Any(x: x eq ''PrivateAccessNonWebApplication'') or tags/Any(x: x eq ''NetworkAccessManagedApplication'') or tags/Any(x: x eq ''NetworkAccessQuickAccessApplication'')'
                    $response
                    break
                }
                "SingleAppID" {
                    # Retrieve a single application by ID
                    $response = Invoke-InternalGraphRequest -Method GET -OutputType PSObject -Uri "https://graph.microsoft.com/beta/applications/$ApplicationId/?`$select=displayName,appId,id,tags,createdDateTime,servicePrincipalType,createdDateTime,servicePrincipalNames"
                    $response
                    break
                }
                "SingleAppName" {
                    # Retrieve a single application by name
                    $response = Invoke-InternalGraphRequest -Method GET -OutputType PSObject -Uri "https://graph.microsoft.com/beta/applications?`$count=true&`$select=displayName,appId,id,tags,createdDateTime,servicePrincipalType,createdDateTime,servicePrincipalNames&`$filter=DisplayName eq '$ApplicationName'"
                    $response
                    break
                }
                "QuickAccessApp" {
                    # Retrieve only Quick Access applications using server-side filter
                    $response = Invoke-InternalGraphRequest -Method GET -OutputType PSObject -Uri "https://graph.microsoft.com/beta/applications?`$count=true&`$select=displayName,appId,id,tags,createdDateTime&`$filter=tags/Any(x: x eq 'NetworkAccessQuickAccessApplication')"
                    $response
                    break
                }
            }
        }
        catch {
            Write-Error "Failed to retrieve the application(s): $_"
        }
    }
}