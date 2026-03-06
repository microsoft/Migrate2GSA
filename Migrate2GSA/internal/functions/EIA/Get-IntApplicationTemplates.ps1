function Get-IntApplicationTemplates {
    <#
    .SYNOPSIS
        Retrieves all application templates from Microsoft Graph and saves them to a JSON file.

    .DESCRIPTION
        Queries the Microsoft Graph API for application templates (displayName and endpoints),
        handles pagination via Invoke-InternalGraphRequest, and saves the results to a JSON file
        in the current directory. Prompts for confirmation before overwriting an existing file.

    .PARAMETER OutputFileName
        The name of the JSON output file. Default: EntraInternetAccessApplicationTemplates.json

    .PARAMETER Force
        Overwrite the output file without prompting if it already exists.

    .EXAMPLE
        Get-IntApplicationTemplates
        Retrieves all application templates and saves to EntraInternetAccessApplicationTemplates.json.

    .EXAMPLE
        Get-IntApplicationTemplates -Force
        Retrieves all application templates and overwrites the file without prompting.

    .OUTPUTS
        System.Object[]
        Returns the array of application template objects.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$OutputFileName = 'EntraInternetAccessApplicationTemplates.json',

        [Parameter()]
        [switch]$Force
    )

    begin {
        Write-Verbose "Starting application templates retrieval"
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

            $uri = 'https://graph.microsoft.com/beta/applicationTemplates?$select=displayName,endpoints'

            Write-Verbose "Querying Graph API for application templates"
            $results = Invoke-InternalGraphRequest -Method GET -Uri $uri

            if (-not $results) {
                Write-Warning "No application templates returned from Graph API."
                return
            }

            $resultCount = if ($results -is [System.Array]) { $results.Count } else { 1 }
            Write-Verbose "Retrieved $resultCount application template(s)"

            if ($PSCmdlet.ShouldProcess($outputPath, "Save application templates to JSON file")) {
                $results | ConvertTo-Json -Depth 10 | Set-Content -Path $outputPath -Encoding UTF8
                Write-Host "Successfully saved $resultCount application template(s) to '$outputPath'"
            }
        }
        catch {
            Write-Error "Failed to retrieve application templates: $_"
            throw
        }
    }

    end {
        Write-Verbose "Application templates retrieval completed"
    }
}
