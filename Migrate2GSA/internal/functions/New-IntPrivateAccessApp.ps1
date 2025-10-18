function New-IntPrivateAccessApp {
    <#
    .SYNOPSIS
        Creates a new Entra Private Access application.
    
    .DESCRIPTION
        Creates and configures a new Entra Private Access application using the Microsoft Graph API.
        Optionally assigns a connector group to the application.
    
    .PARAMETER ApplicationName
        The display name for the new Private Access application.
    
    .PARAMETER ConnectorGroupId
        Optional. The ID of the connector group to assign to the application.
    
    .EXAMPLE
        $result = New-IntPrivateAccessApp -ApplicationName "MyApp"
        Creates a new Private Access app named "MyApp".
    
    .EXAMPLE
        $result = New-IntPrivateAccessApp -ApplicationName "MyApp" -ConnectorGroupId "12345-abcde" -Verbose
        Creates a new Private Access app and assigns it to a connector group.
    
    .OUTPUTS
        PSCustomObject with Success, ApplicationName, ApplicationObjectId, AppId, ServicePrincipalId, and Message properties.
    
    .NOTES
        Requires Microsoft.Graph.Authentication module and an active Graph session with appropriate permissions.
        Required scopes: Application.ReadWrite.All, Directory.ReadWrite.All
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ApplicationName,
        
        [Parameter(Mandatory = $false)]
        [string]$ConnectorGroupId
    )

    begin {
        # Write-Verbose "Starting Private Access application creation process"
        
        # Verify Graph connection
        try {
            $context = Get-MgContext
            if (-not $context) {
                throw "Not connected to Microsoft Graph. Please run 'Connect-MgGraph -Scopes Application.ReadWrite.All,Directory.ReadWrite.All'"
            }
            # Write-Verbose "Graph connection verified. Connected as: $($context.Account)"
        }
        catch {
            throw "Microsoft Graph connection check failed: $_"
        }
    }

    process {
        try {
            # Prepare the request body for instantiating the Private Access app
            $bodyJson = @{ displayName = $ApplicationName } | ConvertTo-Json -Depth 99 -Compress
            # Write-Verbose "Request body: $bodyJson"

            # Instantiate the Private Access app
            # Write-Verbose "Instantiating Private Access application template for '$ApplicationName'"
            $params = @{
                Method = 'POST'
                Uri    = 'https://graph.microsoft.com/beta/applicationTemplates/8adf8e6e-67b2-4cf2-a259-e3dc5476c621/instantiate'
                Body   = $bodyJson
            }
            
            # Write-Verbose "Calling Invoke-InternalGraphRequest with params: Method=$($params.Method), Uri=$($params.Uri)"
            $newApp = Invoke-InternalGraphRequest @params

            # Write-Verbose "Response received. Type: $($newApp.GetType().FullName)"
            # Write-Verbose "Response object: $($newApp | ConvertTo-Json -Depth 3 -Compress)"

            # Validate response
            if (-not $newApp) {
                throw "Application instantiation returned null. Ensure you are connected to Microsoft Graph with 'Connect-MgGraph -Scopes Application.ReadWrite.All,Directory.ReadWrite.All'"
            }

            # Check response structure
            # Write-Verbose "Checking response properties..."
            if ($newApp.PSObject.Properties['application']) {
                # Write-Verbose "Found 'application' property"
                if ($newApp.application.PSObject.Properties['objectId']) {
                    # Write-Verbose "Found 'objectId' property: $($newApp.application.objectId)"
                } elseif ($newApp.application.PSObject.Properties['id']) {
                    # Write-Verbose "Found 'id' property instead of 'objectId': $($newApp.application.id)"
                    # Use 'id' if 'objectId' doesn't exist
                    $newApp.application | Add-Member -NotePropertyName 'objectId' -NotePropertyValue $newApp.application.id -Force
                } else {
                    throw "Application object missing both 'objectId' and 'id' properties. Available properties: $($newApp.application.PSObject.Properties.Name -join ', ')"
                }
            } else {
                throw "Response missing 'application' property. Available properties: $($newApp.PSObject.Properties.Name -join ', ')"
            }

            $newAppId = $newApp.application.objectId
            if (-not $newAppId) {
                $newAppId = $newApp.application.id
            }
            
            if (-not $newAppId) {
                throw "Could not determine application ID from response"
            }
            
            # Write-Verbose "Application instantiated with Object ID: $newAppId"

            # Prepare the request body for setting the app to be accessible via the ZTNA client
            $bodyJson = @{
                "onPremisesPublishing" = @{
                    "applicationType"           = "nonwebapp"
                    "isAccessibleViaZTNAClient" = $true
                }
            } | ConvertTo-Json -Depth 99 -Compress

            # Set the Private Access app to be accessible via the ZTNA client
            # Write-Verbose "Configuring application as Private Access (ZTNA) app"
            $params = @{
                Method = 'PATCH'
                Uri    = "https://graph.microsoft.com/beta/applications/$newAppId/"
                Body   = $bodyJson
            }

            Invoke-InternalGraphRequest @params

            # If ConnectorGroupId has been specified, assign the connector group to the app
            if ($ConnectorGroupId) {
                # Write-Verbose "Assigning connector group '$ConnectorGroupId' to application"
                $bodyJson = @{
                    "@odata.id" = "https://graph.microsoft.com/beta/onPremisesPublishingProfiles/applicationproxy/connectorGroups/$ConnectorGroupId"
                } | ConvertTo-Json -Depth 99 -Compress
                
                $params = @{
                    Method = 'PUT'
                    Uri    = "https://graph.microsoft.com/beta/applications/$newAppId/connectorGroup/`$ref"
                    Body   = $bodyJson
                }

                Invoke-InternalGraphRequest @params
            }

            # Write-Verbose "Private Access application '$ApplicationName' has been successfully created and configured."
            
            # Determine the correct property names for the response
            $appId = if ($newApp.application.PSObject.Properties['appId']) { 
                $newApp.application.appId 
            } else { 
                $null 
            }
            
            $servicePrincipalId = if ($newApp.PSObject.Properties['servicePrincipal']) {
                if ($newApp.servicePrincipal.PSObject.Properties['objectId']) {
                    $newApp.servicePrincipal.objectId
                } elseif ($newApp.servicePrincipal.PSObject.Properties['id']) {
                    $newApp.servicePrincipal.id
                } else {
                    $null
                }
            } else {
                $null
            }
            
            # Return application details
            return [PSCustomObject]@{
                Success              = $true
                ApplicationName      = $ApplicationName
                ApplicationObjectId  = $newAppId
                AppId                = $appId
                ServicePrincipalId   = $servicePrincipalId
                Message              = "Private Access application '$ApplicationName' has been successfully created and configured."
            }
        }
        catch {
            $errorMessage = $_.Exception.Message
            $errorDetails = if ($_.ErrorDetails) { $_.ErrorDetails.Message } else { "No additional details" }
            $stackTrace = $_.ScriptStackTrace
            
            Write-Error "Failed to create the Private Access app '$ApplicationName'. Error: $errorMessage`nDetails: $errorDetails`nStack: $stackTrace"
            
            # Return failure object
            return [PSCustomObject]@{
                Success         = $false
                ApplicationName = $ApplicationName
                Error           = $errorMessage
                ErrorDetails    = $errorDetails
                StackTrace      = $stackTrace
                Message         = "Failed to create the Private Access app."
            }
        }
    }

    end {
        #Write-Verbose "Completed Private Access application creation process"
    }
}