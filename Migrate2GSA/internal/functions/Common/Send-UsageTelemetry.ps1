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

    # --- Configuration -----------------------------------------------------------
    $ConnectionString = "InstrumentationKey=5b221879-9781-4928-93f3-34023a215e7f;IngestionEndpoint=https://westeurope-5.in.applicationinsights.azure.com/;LiveEndpoint=https://westeurope.livediagnostics.monitor.azure.com/;ApplicationId=ad78454b-2d06-45fb-b0b4-856016374bd2"
    $ModuleVersion    = (Get-Module -Name 'Migrate2GSA' -ErrorAction SilentlyContinue).Version.ToString() ?? "unknown"
    # -----------------------------------------------------------------------------

    # Parse instrumentation key and ingestion endpoint from the connection string
    $iKey            = ($ConnectionString -split ';' | Where-Object { $_ -match '^InstrumentationKey=' }) -replace 'InstrumentationKey=', ''
    $ingestionBase   = ($ConnectionString -split ';' | Where-Object { $_ -match '^IngestionEndpoint=' }) -replace 'IngestionEndpoint=', ''
    $ingestionUri    = "$($ingestionBase.TrimEnd('/'))//v2/track"

    # --- Auto-properties attached to every event ---------------------------------
    $autoProperties = @{
        PSVersion     = $PSVersionTable.PSVersion.ToString()
        OS            = if ($IsWindows) { "Windows" } elseif ($IsLinux) { "Linux" } elseif ($IsMacOS) { "macOS" } else { "Unknown" }
        ModuleVersion = $ModuleVersion
        # Machine name is hashed to avoid capturing PII
        MachineId     = [System.Convert]::ToBase64String(
                            [System.Security.Cryptography.SHA256]::Create().ComputeHash(
                                [System.Text.Encoding]::UTF8.GetBytes($env:COMPUTERNAME ?? $env:HOSTNAME ?? "unknown")
                            )
                        ).Substring(0, 16)
    }

    # Per-session ID — created once per PS session, correlates calls within a run
    if (-not $script:_TelemetrySessionId) {
        $script:_TelemetrySessionId = [System.Guid]::NewGuid().ToString()
    }
    $autoProperties["SessionId"] = $script:_TelemetrySessionId

    # Merge auto-properties with caller-supplied properties (caller wins on conflict)
    $mergedProperties = $autoProperties + $Properties

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
                    properties   = $mergedProperties
                    measurements = $Metrics
                }
            }
        }
    ) | ConvertTo-Json -Depth 10 -Compress

    # --- Fire and forget (background thread, never blocks the caller) ------------
    $null = [System.Threading.Tasks.Task]::Run({
        try {
            $response = Invoke-RestMethod -Uri $using:ingestionUri `
                                          -Method POST `
                                          -Body $using:payload `
                                          -ContentType "application/json" `
                                          -TimeoutSec 5
            # Uncomment the line below to debug telemetry responses:
            # Write-Verbose "Telemetry accepted: $($response.itemsAccepted)/$($response.itemsReceived)"
        }
        catch {
            # Silently swallow — telemetry must never break the caller
        }
    })
}
