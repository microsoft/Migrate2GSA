function Send-UsageTelemetry {
    <#
    .SYNOPSIS
        Sends a custom event to Azure Application Insights.

    .DESCRIPTION
        Fire-and-forget telemetry helper. Errors are silently swallowed so
        telemetry never interrupts the caller. Automatically attaches session,
        environment, and module version context to every event.

    .PARAMETER EventName
        Name of the event to record. Recommended convention: use the function
        name that is being tracked, e.g. "Get-MyData".

    .PARAMETER Properties
        Optional hashtable of string key/value metadata to attach to the event.
        Example: @{ InputType = "CSV"; Mode = "Verbose" }

    .PARAMETER Metrics
        Optional hashtable of numeric measurements to attach to the event.
        Example: @{ Duration = 1234; ItemCount = 50 }

    .EXAMPLE
        Send-UsageTelemetry -EventName "Get-MyData"

    .EXAMPLE
        Send-UsageTelemetry -EventName "Get-MyData" `
            -Properties @{ InputType = "CSV" } `
            -Metrics @{ Duration = 523; ItemCount = 10 }
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $EventName,

        [Parameter()]
        [hashtable] $Properties = @{},

        [Parameter()]
        [hashtable] $Metrics = @{}
    )

    # --- Opt-out check -----------------------------------------------------------
    if ($script:_TelemetryDisabled -or $env:MIGRATE2GSA_TELEMETRY_OPTOUT -eq '1') { return }

    # --- Cached configuration (parsed once per session) --------------------------
    if (-not $script:_TelemetryConfig) {
        $connectionString = "InstrumentationKey=5b221879-9781-4928-93f3-34023a215e7f;IngestionEndpoint=https://westeurope-5.in.applicationinsights.azure.com/;LiveEndpoint=https://westeurope.livediagnostics.monitor.azure.com/;ApplicationId=ad78454b-2d06-45fb-b0b4-856016374bd2"
        $parsedIKey        = ($connectionString -split ';' | Where-Object { $_ -match '^InstrumentationKey=' }) -replace 'InstrumentationKey=', ''
        $ingestionBase     = ($connectionString -split ';' | Where-Object { $_ -match '^IngestionEndpoint=' }) -replace 'IngestionEndpoint=', ''

        $script:_TelemetryConfig = @{
            iKey          = $parsedIKey
            IngestionUri  = "$($ingestionBase.TrimEnd('/'))/v2/track"
            MachineId     = [System.Convert]::ToBase64String(
                                [System.Security.Cryptography.SHA256]::HashData(
                                    [System.Text.Encoding]::UTF8.GetBytes($env:COMPUTERNAME ?? $env:HOSTNAME ?? "unknown")
                                )
                            ).Substring(0, 16)
            SessionId     = [System.Guid]::NewGuid().ToString()
        }
    }

    $iKey          = $script:_TelemetryConfig.iKey
    $ingestionUri  = $script:_TelemetryConfig.IngestionUri
    $moduleVersion = (Get-Module -Name 'Migrate2GSA' -ErrorAction SilentlyContinue).Version.ToString() ?? "unknown"
    # -----------------------------------------------------------------------------

    # --- Auto-properties attached to every event ---------------------------------
    $autoProperties = @{
        PSVersion     = $PSVersionTable.PSVersion.ToString()
        OS            = if ($IsWindows) { "Windows" } elseif ($IsLinux) { "Linux" } elseif ($IsMacOS) { "macOS" } else { "Unknown" }
        ModuleVersion = $moduleVersion
        MachineId     = $script:_TelemetryConfig.MachineId
        SessionId     = $script:_TelemetryConfig.SessionId
    }

    # Merge: caller-supplied properties win on conflict
    foreach ($key in $Properties.Keys) {
        $autoProperties[$key] = $Properties[$key]
    }

    # --- Build the payload -------------------------------------------------------
    $payload = @(
        @{
            name = "Microsoft.ApplicationInsights.$iKey.Event"
            time = (Get-Date).ToUniversalTime().ToString("o")
            iKey = $iKey
            data = @{
                baseType = "EventData"
                baseData = @{
                    ver          = 2
                    name         = $EventName
                    properties   = $autoProperties
                    measurements = $Metrics
                }
            }
        }
    ) | ConvertTo-Json -Depth 10 -Compress

    # --- Fire and forget (thread-pool job, never blocks the caller) --------------
    $null = Start-ThreadJob -ScriptBlock {
        param($Uri, $Body)
        try {
            Invoke-RestMethod -Uri $Uri -Method POST -Body $Body `
                              -ContentType "application/json" -TimeoutSec 5
        }
        catch {
            # Silently swallow — telemetry must never break the caller
        }
    } -ArgumentList $ingestionUri, $payload
}
