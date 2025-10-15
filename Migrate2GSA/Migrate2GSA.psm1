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
    'Convert-ZPA2EPA',
    'Export-ZIAConfig',
    'Convert-ZIA2EIA',
    'Export-NetskopeConfig',
    'Start-EntraPrivateAccessProvisioning'
)