function Export-UmbrellaAppMappingTemplate {
    <#
    .SYNOPSIS
        Extracts all unique Cisco Umbrella application names from web policies and generates an app mapping template.

    .DESCRIPTION
        Reads application names and IDs from web_policies.json (via proxyRuleset.extradata.applications),
        deduplicates by application ID, and outputs a CSV mapping template for use with Convert-CiscoUmbrella2EIA.

        The output CSV contains columns:
        - UmbrellaAppId:   The numeric application ID from Umbrella
        - UmbrellaAppName: The application display name from Umbrella
        - GSAAppName:      (blank) Fill in the matching Entra Internet Access application name
        - MatchType:       (blank) Fill in: exact, approximate, or leave empty for no match
        - Note:            (blank) Optional notes about the mapping decision

        The user (or an AI assistant) fills in GSAAppName and MatchType by comparing against the
        Entra Internet Access application templates JSON file.

    .PARAMETER WebPoliciesPath
        Path to the Cisco Umbrella web_policies.json export file.

    .PARAMETER OutputPath
        Path for the output CSV mapping template file.
        Defaults to CiscoUmbrella2EIA-AppMappings-Template.csv in the current directory.

    .EXAMPLE
        Export-UmbrellaAppMappingTemplate -WebPoliciesPath ".\web_policies.json"

        Extracts all application names and writes CiscoUmbrella2EIA-AppMappings-Template.csv to the current directory.

    .EXAMPLE
        Export-UmbrellaAppMappingTemplate -WebPoliciesPath "C:\backup\web_policies.json" -OutputPath "C:\output\AppMappings.csv"

        Extracts all application names and writes the mapping template to the specified output path.

    .NOTES
        This is a helper utility for building the application mapping file used by Convert-CiscoUmbrella2EIA.
        After generating the template, fill in GSAAppName and MatchType for each entry by comparing against
        the Entra Internet Access application templates (EntraInternetAccessApplicationTemplates.json).
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory, HelpMessage = "Path to Cisco Umbrella web_policies.json export")]
        [ValidateScript({
            if (Test-Path $_) { return $true }
            else { throw "File not found: $_" }
        })]
        [string]$WebPoliciesPath,

        [Parameter(HelpMessage = "Output path for the app mapping template CSV file")]
        [string]$OutputPath = (Join-Path $PWD "CiscoUmbrella2EIA-AppMappings-Template.csv")
    )

    Set-StrictMode -Version Latest

    # ── Load web_policies.json ───────────────────────────────────────────
    Write-Host "Loading web policies from: $WebPoliciesPath"
    try {
        $webPolicies = Get-Content -Path $WebPoliciesPath -Raw | ConvertFrom-Json
    }
    catch {
        throw "Failed to parse web_policies.json: $_"
    }

    # ── Extract unique applications ──────────────────────────────────────
    $appMap = [System.Collections.Generic.Dictionary[int, hashtable]]::new()

    foreach ($policy in @($webPolicies)) {
        $ruleset = $policy.PSObject.Properties['proxyRuleset']
        if ($null -eq $ruleset) { continue }

        $extradata = $ruleset.Value.PSObject.Properties['extradata']
        if ($null -eq $extradata) { continue }

        $applications = $extradata.Value.PSObject.Properties['applications']
        if ($null -eq $applications) { continue }

        foreach ($app in $applications.Value) {
            $appId = [int]$app.id
            if (-not $appMap.ContainsKey($appId) -and -not [string]::IsNullOrWhiteSpace($app.label)) {
                $description = ''
                if ($app.PSObject.Properties.Name -contains 'description' -and -not [string]::IsNullOrWhiteSpace($app.description)) {
                    $description = $app.description.Trim()
                }
                $appMap[$appId] = @{ Label = $app.label.Trim(); Description = $description }
            }
        }
    }

    Write-Host "  Unique applications found: $($appMap.Count)"

    # ── Build mapping template (sorted by app name) ──────────────────────
    $mappingTemplate = @(
        foreach ($kvp in $appMap.GetEnumerator() | Sort-Object -Property { $_.Value.Label }) {
            [PSCustomObject]@{
                UmbrellaAppId          = $kvp.Key
                UmbrellaAppName        = $kvp.Value.Label
                UmbrellaAppDescription = $kvp.Value.Description
                GSAAppName             = ""
                MatchType              = ""
                Note                   = ""
            }
        }
    )

    # ── Export ────────────────────────────────────────────────────────────
    $mappingTemplate | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding utf8

    Write-Host "App mapping template written to: $OutputPath"
    Write-Host "Entries: $($mappingTemplate.Count)"
    Write-Host ""
    Write-Host "Next steps:"
    Write-Host "  1. Open the CSV and the Entra Internet Access application templates JSON"
    Write-Host "  2. For each UmbrellaAppName, find the matching Entra app and fill in GSAAppName"
    Write-Host "  3. Set MatchType to 'exact' or 'approximate' for each mapped entry"
    Write-Host "  4. Leave GSAAppName and MatchType empty for apps with no Entra equivalent"

    return $mappingTemplate
}
