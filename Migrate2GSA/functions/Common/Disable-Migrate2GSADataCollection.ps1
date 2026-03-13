function Disable-Migrate2GSADataCollection {
    <#
    .SYNOPSIS
        Disables anonymous usage telemetry for the Migrate2GSA module.

    .DESCRIPTION
        Prevents the module from sending anonymous usage telemetry to
        Application Insights for the remainder of the current PowerShell
        session.

        Alternatively, set the environment variable
        MIGRATE2GSA_TELEMETRY_OPTOUT=1 to disable telemetry permanently
        across all sessions.

    .EXAMPLE
        Disable-Migrate2GSADataCollection

        Disables telemetry for the current session.

    .EXAMPLE
        $env:MIGRATE2GSA_TELEMETRY_OPTOUT = '1'

        Disables telemetry via environment variable (persists if set at
        the system/user level).
    #>

    [CmdletBinding()]
    param()

    $script:_TelemetryDisabled = $true
    Write-Verbose "Migrate2GSA telemetry has been disabled for this session."
}
