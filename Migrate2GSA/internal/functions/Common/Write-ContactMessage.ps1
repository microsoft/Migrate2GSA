function Write-ContactMessage {
    <#
    .SYNOPSIS
        Writes a contact/feedback message to the console.

    .DESCRIPTION
        Displays a friendly message encouraging users to share feedback, report
        issues, or ask for help via the Migrate2GSA team email address.
    #>

    [CmdletBinding()]
    param()

    Write-Host ''
    Write-Host '  Migrate2GSA module loaded successfully.' -ForegroundColor Green
    Write-Host '─────────────────────────────────────────────────────────────────' -ForegroundColor DarkGray
    Write-Host '  We''d love to hear how Migrate2GSA is working for you!' -ForegroundColor Cyan
    Write-Host '  Whether it helped speed up your GSA deployment, you ran into an issue,' -ForegroundColor Cyan
    Write-Host '  or you just have a question — we''re here and happy to help.' -ForegroundColor Cyan
    Write-Host '  Reach out to us anytime at migrate2gsateam@microsoft.com' -ForegroundColor Cyan
    Write-Host '─────────────────────────────────────────────────────────────────' -ForegroundColor DarkGray
    Write-Host ''
}
