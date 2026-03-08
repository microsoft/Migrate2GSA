function Export-IntApplicationTemplates {
    <#
    .SYNOPSIS
        Exports all application templates from Microsoft Graph to a CSV file.

    .DESCRIPTION
        Queries the Microsoft Graph API for application templates (displayName, description, and endpoints),
        handles pagination via Invoke-InternalGraphRequest, and saves the results to a CSV file
        in the current directory. Prompts for confirmation before overwriting an existing file.

    .PARAMETER OutputFileName
        The name of the CSV output file. Default: EntraInternetAccessApplicationTemplates.csv

    .PARAMETER Force
        Overwrite the output file without prompting if it already exists.

    .EXAMPLE
        Export-IntApplicationTemplates
        Exports all application templates to EntraInternetAccessApplicationTemplates.csv.

    .EXAMPLE
        Export-IntApplicationTemplates -Force
        Exports all application templates and overwrites the file without prompting.

    .OUTPUTS
        System.Object[]
        Returns the array of application template objects.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$OutputFileName = 'EntraInternetAccessApplicationTemplates.csv',

        [Parameter()]
        [switch]$Force
    )

    begin {
        Write-Verbose "Starting application templates export"
        $outputPath = Join-Path -Path (Get-Location) -ChildPath $OutputFileName
    }

    process {
        try {
            # Check if file already exists
            if ((Test-Path -Path $outputPath) -and -not $Force) {
                if (-not $PSCmdlet.ShouldContinue(
                    "The file '$outputPath' already exists. Do you want to overwrite it?",
                    "Confirm Overwrite")) {
                    Write-Warning "Operation cancelled. File '$outputPath' was not overwritten."
                    return
                }
            }

            $uri = 'https://graph.microsoft.com/beta/applicationTemplates?$select=displayName,description,endpoints'

            Write-Verbose "Querying Graph API for application templates"
            $results = Invoke-InternalGraphRequest -Method GET -Uri $uri

            if (-not $results) {
                Write-Warning "No application templates returned from Graph API."
                return
            }

            $resultCount = if ($results -is [System.Array]) { $results.Count } else { 1 }
            Write-Verbose "Retrieved $resultCount application template(s)"

            if ($PSCmdlet.ShouldProcess($outputPath, "Export application templates to CSV file")) {
                $csvRows = foreach ($template in $results) {
                    $endpointsString = if ($template.endpoints) {
                        ($template.endpoints -join '; ')
                    } else { '' }

                    [PSCustomObject]@{
                        DisplayName = $template.displayName
                        Description = $template.description
                        Endpoints   = $endpointsString
                    }
                }

                $csvRows | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8
                Write-Host "Successfully exported $resultCount application template(s) to '$outputPath'"
            }
        }
        catch {
            Write-Error "Failed to export application templates: $_"
            throw
        }
    }

    end {
        Write-Verbose "Application templates export completed"
    }
}
