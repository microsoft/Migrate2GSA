foreach ($file in Get-ChildItem -Path "$PSScriptRoot/internal/functions" -Filter *.ps1 -Recurse) {
    . $file.FullName
}

foreach ($file in Get-ChildItem -Path "$PSScriptRoot/functions" -Filter *.ps1 -Recurse) {
    . $file.FullName
}

foreach ($file in Get-ChildItem -Path "$PSScriptRoot/internal/scripts" -Filter *.ps1 -Recurse) {
    . $file.FullName
}

# Export only public functions
Export-ModuleMember -Function @(
    'Export-ZPAConfig',
    'Export-ZPAConfigOneAPI',
    'Convert-ZPA2EPA',
    'Export-ZIAConfig',
    'Convert-ZIA2EIA',
    'Export-NetskopeConfig',
    'Convert-NPA2EPA',
    'Convert-NSWG2EIA',
    'Convert-ForcepointWS2EIA',
    'Convert-CitrixNS2EPA',
    'Start-EntraPrivateAccessProvisioning',
    'Start-EntraInternetAccessProvisioning',
    'Export-EntraPrivateAccessConfig',
    'Export-EntraInternetAccessConfig',
    'Export-CiscoUmbrellaConfig',
    'Export-MDEWebFilteringConfig'
)