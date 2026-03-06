function Export-UmbrellaCategoryMappingTemplate {
    <#
    .SYNOPSIS
        Extracts all unique Cisco Umbrella web categories from exported config files and generates a category mapping template.

    .DESCRIPTION
        Reads category names from both category_settings.json (DNS policy categories) and
        web_policies.json (web policy rule categories via proxyRuleset.extradata), deduplicates them,
        and outputs a CSV mapping template file for use with Convert-CiscoUmbrella2EIA.

        The output file contains entries with UmbrellaCategory populated and GSACategory/Note blank,
        ready for the user to fill in the corresponding Microsoft Entra Internet Access category names.

    .PARAMETER CategorySettingsPath
        Path to the Cisco Umbrella category_settings.json export file.

    .PARAMETER WebPoliciesPath
        Path to the Cisco Umbrella web_policies.json export file.

    .PARAMETER OutputPath
        Path for the output CSV mapping template file.
        Defaults to CiscoUmbrella2EIA-CategoryMappings.csv in the current directory.

    .EXAMPLE
        Export-UmbrellaCategoryMappingTemplate -CategorySettingsPath ".\category_settings.json" -WebPoliciesPath ".\web_policies.json"

        Extracts all categories and writes CiscoUmbrella2EIA-CategoryMappings.csv to the current directory.

    .EXAMPLE
        Export-UmbrellaCategoryMappingTemplate -CategorySettingsPath "C:\backup\category_settings.json" -WebPoliciesPath "C:\backup\web_policies.json" -OutputPath "C:\output\CategoryMappings.csv"

        Extracts all categories and writes the mapping template to the specified output path.

    .NOTES
        This is a helper utility for building the category mapping file required by Convert-CiscoUmbrella2EIA.
        After running this script, manually fill in the GSACategory values for each entry.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory, HelpMessage = "Path to Cisco Umbrella category_settings.json export")]
        [ValidateScript({
            if (Test-Path $_) { return $true }
            else { throw "File not found: $_" }
        })]
        [string]$CategorySettingsPath,

        [Parameter(Mandatory, HelpMessage = "Path to Cisco Umbrella web_policies.json export")]
        [ValidateScript({
            if (Test-Path $_) { return $true }
            else { throw "File not found: $_" }
        })]
        [string]$WebPoliciesPath,

        [Parameter(HelpMessage = "Output path for the category mapping template CSV file")]
        [string]$OutputPath = (Join-Path $PWD "CiscoUmbrella2EIA-CategoryMappings.csv")
    )

    Set-StrictMode -Version Latest

    # ── Load category_settings.json ──────────────────────────────────────
    Write-Host "Loading category settings from: $CategorySettingsPath"
    try {
        $categorySettings = Get-Content -Path $CategorySettingsPath -Raw | ConvertFrom-Json
    }
    catch {
        throw "Failed to parse category_settings.json: $_"
    }

    # ── Load web_policies.json ───────────────────────────────────────────
    Write-Host "Loading web policies from: $WebPoliciesPath"
    try {
        $webPolicies = Get-Content -Path $WebPoliciesPath -Raw | ConvertFrom-Json
    }
    catch {
        throw "Failed to parse web_policies.json: $_"
    }

    # ── Extract categories ───────────────────────────────────────────────
    $allCategories = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    # Source 1: category_settings.json → categories[].name
    $csCount = 0
    foreach ($setting in $categorySettings) {
        if ($null -ne $setting.categories) {
            foreach ($cat in $setting.categories) {
                if (-not [string]::IsNullOrWhiteSpace($cat.name)) {
                    [void]$allCategories.Add($cat.name.Trim())
                    $csCount++
                }
            }
        }
    }
    Write-Host "  category_settings.json: found $csCount category entries"

    # Source 2: web_policies.json → proxyRuleset.extradata.categories[].label
    # Nested checks required — StrictMode prevents chained property access on missing members
    $wpCount = 0
    foreach ($policy in $webPolicies) {
        $ruleset = $policy.PSObject.Properties['proxyRuleset']
        if ($null -eq $ruleset) { continue }

        $extradata = $ruleset.Value.PSObject.Properties['extradata']
        if ($null -eq $extradata) { continue }

        $categories = $extradata.Value.PSObject.Properties['categories']
        if ($null -eq $categories) { continue }

        foreach ($cat in $categories.Value) {
            if (-not [string]::IsNullOrWhiteSpace($cat.label)) {
                [void]$allCategories.Add($cat.label.Trim())
                $wpCount++
            }
        }
    }
    Write-Host "  web_policies.json:      found $wpCount category entries"

    # ── Build mapping template ───────────────────────────────────────────
    $sorted = $allCategories | Sort-Object

    $mappingTemplate = @(
        foreach ($categoryName in $sorted) {
            [PSCustomObject]@{
                UmbrellaCategory = $categoryName
                GSACategory      = ""
                Note             = ""
            }
        }
    )

    Write-Host ""
    Write-Host "Unique categories found: $($mappingTemplate.Count)"

    # ── Export ────────────────────────────────────────────────────────────
    $mappingTemplate | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding utf8

    Write-Host "Category mapping template written to: $OutputPath"
    Write-Host ""
    Write-Host "Next step: Open the file and fill in the GSACategory values for each entry."

    return $mappingTemplate
}
