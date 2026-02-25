function Convert-CitrixNS2EPA {
    <#
    .SYNOPSIS
        Converts Citrix NetScaler Gateway configuration to Microsoft Entra Private Access (EPA) format.

    .DESCRIPTION
        This function converts Citrix NetScaler Gateway configuration to Microsoft Global Secure Access
        (GSA) Enterprise Application format compatible with Start-EntraPrivateAccessProvisioning.

        The function processes:
        - AAA groups mapped to Enterprise Applications
        - Authorization policies with rule expression parsing (IP/subnet/port)
        - VPN intranet applications with protocol and destination mapping
        - Group bindings with TCP/UDP protocol consolidation
        - Conflict detection for overlapping IP ranges, FQDNs, protocols, and ports

    .PARAMETER ConfigFilePath
        Path to NetScaler configuration file (plain-text).

    .PARAMETER OutputBasePath
        Base directory for output files. Defaults to current working directory.

    .PARAMETER GroupFilter
        Wildcard pattern to include only matching AAA groups.

    .PARAMETER ExcludeGroupFilter
        Wildcard pattern to exclude matching AAA groups.

    .PARAMETER EnableDebugLogging
        Enable verbose debug logging for detailed troubleshooting.

    .PARAMETER PassThru
        Return results to pipeline instead of just saving to file. When specified,
        the function returns the processed data objects for further processing.

    .EXAMPLE
        Convert-CitrixNS2EPA -ConfigFilePath "C:\Export\netscaler.conf"

        Converts all AAA groups from the specified NetScaler configuration file.

    .EXAMPLE
        Convert-CitrixNS2EPA -ConfigFilePath ".\netscaler.conf" -OutputBasePath "C:\Output"

        Converts configuration and writes output to the specified directory.

    .EXAMPLE
        Convert-CitrixNS2EPA -ConfigFilePath ".\netscaler.conf" -GroupFilter "vpn-warehouse-*"

        Processes only AAA groups matching the specified wildcard pattern.

    .EXAMPLE
        Convert-CitrixNS2EPA -ConfigFilePath ".\netscaler.conf" -ExcludeGroupFilter "*-test-*"

        Processes all AAA groups except those matching the specified wildcard pattern.

    .EXAMPLE
        $results = Convert-CitrixNS2EPA -ConfigFilePath ".\netscaler.conf" -PassThru
        $results | Where-Object { $_.Conflict -eq "Yes" } | Export-Csv ".\conflicts.csv" -NoTypeInformation

        Processes configuration and returns results for further pipeline processing.

    .OUTPUTS
        System.Management.Automation.PSCustomObject[]
        Returns an array of transformed GSA Enterprise Application configuration objects.

    .NOTES
        - Requires PowerShell 5.1 or later
        - Input file is plain-text NetScaler configuration
        - Output includes conflict detection and resolution recommendations
        - Reuses core logic from Convert-ZPA2EPA for consistency
    #>

    [CmdletBinding(SupportsShouldProcess = $false)]
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Path to NetScaler configuration file")]
        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [string]$ConfigFilePath,

        [Parameter(Mandatory = $false, HelpMessage = "Base directory for output files")]
        [ValidateScript({Test-Path $_ -PathType Container})]
        [string]$OutputBasePath = $PWD,

        [Parameter(HelpMessage = "Wildcard pattern to include only matching AAA groups")]
        [string]$GroupFilter,

        [Parameter(HelpMessage = "Wildcard pattern to exclude matching AAA groups")]
        [string]$ExcludeGroupFilter,

        [Parameter(HelpMessage = "Enable verbose debug logging")]
        [switch]$EnableDebugLogging,

        [Parameter(HelpMessage = "Return results to pipeline (suppresses automatic console output)")]
        [switch]$PassThru
    )

    # Set strict mode for better error handling
    Set-StrictMode -Version Latest

    # Establish shared timestamp and log destination
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $LogPath = Join-Path -Path $OutputBasePath -ChildPath "${timestamp}_Convert-CitrixNS2EPA.log"

#region Helper Functions (Reused from Convert-ZPA2EPA)

function Convert-CIDRToRange {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CIDR
    )

    try {
        if ($CIDR -notmatch '^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$') {
            Write-LogMessage "Invalid CIDR format: $CIDR" -Level "ERROR" -Component 'ConvertCIDR'
            return $null
        }

        $parts = $CIDR.Split('/')
        $ipAddress = $parts[0]
        $prefixLength = [int]$parts[1]

        if ($prefixLength -lt 0 -or $prefixLength -gt 32) {
            Write-LogMessage "Invalid prefix length in CIDR: $CIDR" -Level "ERROR" -Component 'ConvertCIDR'
            return $null
        }

        $ipInteger = Convert-IPToInteger -IPAddress $ipAddress
        if ($null -eq $ipInteger) {
            return $null
        }

        $subnetMask = [uint32]([math]::Pow(2, 32) - [math]::Pow(2, 32 - $prefixLength))
        $networkAddress = $ipInteger -band $subnetMask
        $broadcastAddress = $networkAddress -bor (-bnot $subnetMask -band 0xFFFFFFFF)

        return @{
            Start = $networkAddress
            End = $broadcastAddress
        }
    }
    catch {
        Write-LogMessage "Error converting CIDR $CIDR to range: $_" -Level "ERROR" -Component 'ConvertCIDR'
        return $null
    }
}

function Convert-IPToInteger {
    param(
        [Parameter(Mandatory = $true)]
        [string]$IPAddress
    )

    try {
        if ($IPAddress -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
            Write-LogMessage "Invalid IP address format: $IPAddress" -Level "ERROR" -Component 'ConvertIP'
            return $null
        }

        $octets = $IPAddress.Split('.')

        foreach ($octet in $octets) {
            $octetInt = [int]$octet
            if ($octetInt -lt 0 -or $octetInt -gt 255) {
                Write-LogMessage "Invalid octet value in IP address: $IPAddress" -Level "ERROR" -Component 'ConvertIP'
                return $null
            }
        }

        $result = [uint32]([int]$octets[0] * 16777216 + [int]$octets[1] * 65536 + [int]$octets[2] * 256 + [int]$octets[3])
        return $result
    }
    catch {
        Write-LogMessage "Error converting IP $IPAddress to integer: $_" -Level "ERROR" -Component 'ConvertIP'
        return $null
    }
}

function Test-IntervalOverlap {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Range1,

        [Parameter(Mandatory = $true)]
        [hashtable]$Range2
    )

    try {
        $maxStart = [Math]::Max($Range1.Start, $Range2.Start)
        $minEnd = [Math]::Min($Range1.End, $Range2.End)
        return $maxStart -le $minEnd
    }
    catch {
        Write-LogMessage "Error checking interval overlap: $_" -Level "ERROR" -Component 'Conflicts'
        return $false
    }
}

function Test-PortRangeOverlap {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PortRange1,

        [Parameter(Mandatory = $true)]
        [string]$PortRange2
    )

    try {
        $ports1List = $PortRange1 -split ',' | ForEach-Object { $_.Trim() }
        $ports2List = $PortRange2 -split ',' | ForEach-Object { $_.Trim() }

        foreach ($port1 in $ports1List) {
            $range1 = if ($port1.Contains('-')) {
                $parts = $port1.Split('-')
                @{ Start = [int]$parts[0]; End = [int]$parts[1] }
            } else {
                @{ Start = [int]$port1; End = [int]$port1 }
            }

            foreach ($port2 in $ports2List) {
                $range2 = if ($port2.Contains('-')) {
                    $parts = $port2.Split('-')
                    @{ Start = [int]$parts[0]; End = [int]$parts[1] }
                } else {
                    @{ Start = [int]$port2; End = [int]$port2 }
                }

                if (Test-IntervalOverlap -Range1 $range1 -Range2 $range2) {
                    return $true
                }
            }
        }

        return $false
    }
    catch {
        Write-LogMessage "Error checking port range overlap: $_" -Level "ERROR" -Component 'Conflicts'
        return $false
    }
}

function Get-DestinationType {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Destination
    )

    if ($Destination -match '^\d{1,3}(\.\d{1,3}){3}$') {
        return "ipAddress"
    }

    if ($Destination -match '^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$') {
        return "ipRangeCidr"
    }

    return "fqdn"
}

function Clear-Domain {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain
    )

    try {
        $cleanDomain = $Domain -replace '[\u200B-\u200D\uFEFF]', ''
        $cleanDomain = $cleanDomain.Trim()
        return $cleanDomain
    }
    catch {
        Write-LogMessage "Error cleaning domain $Domain : $_" -Level "ERROR" -Component 'Parse'
        return $Domain
    }
}

#endregion

#region NetScaler-Specific Parsing Functions

function Read-NetScalerConfig {
    <#
    .SYNOPSIS
        Reads and pre-processes the NetScaler config file.
    .DESCRIPTION
        Strips comments, trims whitespace, skips blank lines.
        Returns array of clean lines.
    #>
    param([string]$FilePath)

    $rawLines = Get-Content -Path $FilePath -Encoding UTF8
    $cleanLines = @()

    foreach ($line in $rawLines) {
        # Strip inline comments
        $commentIndex = $line.IndexOf('#')
        if ($commentIndex -ge 0) {
            $line = $line.Substring(0, $commentIndex)
        }
        $line = $line.Trim()
        if (-not [string]::IsNullOrWhiteSpace($line)) {
            $cleanLines += $line
        }
    }

    return $cleanLines
}

function Parse-AAAGroup {
    <#
    .SYNOPSIS
        Parses an "add aaa group" line.
    .OUTPUTS
        Hashtable with Name.
    #>
    param([string]$Line)

    # add aaa group <groupName> [-weight <num>] [-devno <num>]
    if ($Line -notmatch '(?i)^add\s+aaa\s+group\s+(\S+)') {
        return $null
    }

    return @{
        Name = $Matches[1]
    }
}

function Parse-AuthorizationPolicy {
    <#
    .SYNOPSIS
        Parses an "add authorization policy" line.
    .OUTPUTS
        Hashtable with Name, Action, RawExpression, Destinations, TcpPorts, UdpPorts, HasPortClause.
    #>
    param([string]$Line)

    # add authorization policy <name> "<expression>" <action>
    if ($Line -notmatch '(?i)^add\s+authorization\s+policy\s+(\S+)\s+"([^"]+)"\s+(\S+)') {
        return $null
    }

    $policyName = $Matches[1]
    $ruleExpression = $Matches[2]
    $action = $Matches[3].ToUpper()

    $parsed = Parse-RuleExpression -Expression $ruleExpression

    return @{
        Name          = $policyName
        Action        = $action
        RawExpression = $ruleExpression
        Destinations  = $parsed.Destinations
        TcpPorts      = $parsed.TcpPorts
        UdpPorts      = $parsed.UdpPorts
        HasPortClause = $parsed.HasPortClause
    }
}

function Parse-RuleExpression {
    <#
    .SYNOPSIS
        Parses a Citrix NetScaler policy rule expression string.
    .DESCRIPTION
        Extracts CLIENT.IP.DST.EQ/IN_SUBNET destinations and
        CLIENT.TCP.DSTPORT.EQ/CLIENT.UDP.DSTPORT.EQ port clauses.
    .OUTPUTS
        Hashtable with Destinations (array), TcpPorts (array),
        UdpPorts (array), HasPortClause (bool).
    #>
    param([string]$Expression)

    $destinations = @()
    $tcpPorts = @()
    $udpPorts = @()

    # Extract IP destinations: CLIENT.IP.DST.EQ(<ip>)
    $ipMatches = [regex]::Matches($Expression, 'CLIENT\.IP\.DST\.EQ\(([^)]+)\)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    foreach ($m in $ipMatches) {
        $destinations += $m.Groups[1].Value.Trim()
    }

    # Extract subnet destinations: CLIENT.IP.DST.IN_SUBNET(<cidr>)
    $subnetMatches = [regex]::Matches($Expression, 'CLIENT\.IP\.DST\.IN_SUBNET\(([^)]+)\)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    foreach ($m in $subnetMatches) {
        $destinations += $m.Groups[1].Value.Trim()
    }

    # Extract TCP ports: CLIENT.TCP.DSTPORT.EQ(<port>)
    $tcpPortMatches = [regex]::Matches($Expression, 'CLIENT\.TCP\.DSTPORT\.EQ\((\d+)\)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    foreach ($m in $tcpPortMatches) {
        $tcpPorts += $m.Groups[1].Value
    }

    # Extract UDP ports: CLIENT.UDP.DSTPORT.EQ(<port>)
    $udpPortMatches = [regex]::Matches($Expression, 'CLIENT\.UDP\.DSTPORT\.EQ\((\d+)\)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    foreach ($m in $udpPortMatches) {
        $udpPorts += $m.Groups[1].Value
    }

    $hasPortClause = ($tcpPorts.Count -gt 0) -or ($udpPorts.Count -gt 0)

    return @{
        Destinations  = $destinations
        TcpPorts      = $tcpPorts
        UdpPorts      = $udpPorts
        HasPortClause = $hasPortClause
    }
}

function Parse-IntranetApplication {
    <#
    .SYNOPSIS
        Parses an "add vpn intranetApplication" line.
    .OUTPUTS
        Hashtable with Name, Protocol, Destinations (array), PortRange.
    #>
    param([string]$Line)

    # add vpn intranetApplication <appName> <protocol> "<destination>" -destPort <portRange> [...]
    # Also handle unquoted destinations
    if ($Line -notmatch '(?i)^add\s+vpn\s+intranetApplication\s+(\S+)\s+(TCP|UDP|ANY|ICMP)\s+"?([^"]+?)"?\s+-destPort\s+(\S+)') {
        return $null
    }

    $appName = $Matches[1]
    $protocol = $Matches[2].ToUpper()
    $destinationStr = $Matches[3].Trim()
    $portRange = $Matches[4]

    # Split comma-separated destinations and clean each
    $destinations = @($destinationStr -split ',' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

    return @{
        Name         = $appName
        Protocol     = $protocol
        Destinations = $destinations
        PortRange    = $portRange
    }
}

function Parse-GroupBinding {
    <#
    .SYNOPSIS
        Parses a "bind aaa group" line.
    .OUTPUTS
        Hashtable with GroupName, Type ('policy' or 'intranetApp'),
        TargetName, BindingProtocol ('TCP', 'UDP', or 'ICMP').
    #>
    param([string]$Line)

    if ($Line -notmatch '(?i)^bind\s+aaa\s+group\s+(\S+)\s+(.+)$') {
        return $null
    }

    $groupName = $Matches[1]
    $remainder = $Matches[2]

    # Check if it's a policy binding
    if ($remainder -match '(?i)-policy\s+(\S+)') {
        $policyName = $Matches[1]

        # Determine binding protocol from -type parameter
        $bindingProtocol = 'TCP'  # default
        if ($remainder -match '(?i)-type\s+(\S+)') {
            $typeValue = $Matches[1].ToUpper()
            switch ($typeValue) {
                'UDP_REQUEST'  { $bindingProtocol = 'UDP' }
                'ICMP_REQUEST' { $bindingProtocol = 'ICMP' }
                default        { $bindingProtocol = 'TCP' }
            }
        }

        return @{
            GroupName       = $groupName
            Type            = 'policy'
            TargetName      = $policyName
            BindingProtocol = $bindingProtocol
        }
    }

    # Check if it's an intranet application binding
    if ($remainder -match '(?i)-intranetApplication\s+(\S+)') {
        $appName = $Matches[1]

        return @{
            GroupName       = $groupName
            Type            = 'intranetApp'
            TargetName      = $appName
            BindingProtocol = $null
        }
    }

    return $null
}

function Resolve-GroupBindings {
    <#
    .SYNOPSIS
        Consolidates bindings per group, merging TCP/UDP for same policy.
    .DESCRIPTION
        For each group, builds a map of bound policies with their
        consolidated protocols and list of bound intranet apps.
        Also identifies unbound policies.
    .OUTPUTS
        Hashtable with GroupBindings and UnboundPolicies.
    #>
    param(
        [hashtable]$AAAGroups,
        [hashtable]$AuthPolicies,
        [hashtable]$IntranetApps,
        [array]$Bindings
    )

    $groupBindings = @{}
    $boundPolicyNames = @{}
    $boundIntranetAppNames = @{}
    $icmpBindingsSkipped = 0
    $missingReferences = 0
    $tcpPolicyBindings = 0
    $udpPolicyBindings = 0
    $intranetAppBindings = 0

    foreach ($binding in $Bindings) {
        $groupName = $binding.GroupName

        # Initialize group binding if needed
        if (-not $groupBindings.ContainsKey($groupName)) {
            $groupBindings[$groupName] = @{
                Policies     = @{}
                IntranetApps = @()
            }
        }

        if ($binding.Type -eq 'policy') {
            $policyName = $binding.TargetName

            # Skip ICMP bindings
            if ($binding.BindingProtocol -eq 'ICMP') {
                Write-LogMessage "Skipping ICMP binding for policy '$policyName' in group '$groupName'" -Level "WARN" -Component 'Resolve'
                $icmpBindingsSkipped++
                continue
            }

            # Check if policy exists
            if (-not $AuthPolicies.ContainsKey($policyName)) {
                Write-LogMessage "Binding references undefined policy '$policyName' in group '$groupName'. Skipping." -Level "WARN" -Component 'Resolve'
                $missingReferences++
                continue
            }

            # Track protocol for this policy in this group
            if (-not $groupBindings[$groupName].Policies.ContainsKey($policyName)) {
                $groupBindings[$groupName].Policies[$policyName] = @{ Protocols = @() }
            }

            if ($groupBindings[$groupName].Policies[$policyName].Protocols -notcontains $binding.BindingProtocol) {
                $groupBindings[$groupName].Policies[$policyName].Protocols += $binding.BindingProtocol
            }

            $boundPolicyNames[$policyName] = $true

            if ($binding.BindingProtocol -eq 'TCP') { $tcpPolicyBindings++ }
            if ($binding.BindingProtocol -eq 'UDP') { $udpPolicyBindings++ }
        }
        elseif ($binding.Type -eq 'intranetApp') {
            $appName = $binding.TargetName

            # Check if intranet app exists
            if (-not $IntranetApps.ContainsKey($appName)) {
                Write-LogMessage "Binding references undefined intranet application '$appName' in group '$groupName'. Skipping." -Level "WARN" -Component 'Resolve'
                $missingReferences++
                continue
            }

            if ($groupBindings[$groupName].IntranetApps -notcontains $appName) {
                $groupBindings[$groupName].IntranetApps += $appName
            }

            $boundIntranetAppNames[$appName] = $true
            $intranetAppBindings++
        }
    }

    # Find unbound ALLOW policies
    $unboundPolicies = @()
    foreach ($policyName in $AuthPolicies.Keys) {
        if ($AuthPolicies[$policyName].Action -eq 'ALLOW' -and -not $boundPolicyNames.ContainsKey($policyName)) {
            $unboundPolicies += $policyName
        }
    }

    return @{
        GroupBindings        = $groupBindings
        UnboundPolicies      = $unboundPolicies
        IcmpBindingsSkipped  = $icmpBindingsSkipped
        MissingReferences    = $missingReferences
        TcpPolicyBindings    = $tcpPolicyBindings
        UdpPolicyBindings    = $udpPolicyBindings
        IntranetAppBindings  = $intranetAppBindings
    }
}

function Convert-PolicyToSegments {
    <#
    .SYNOPSIS
        Converts a parsed authorization policy + consolidated protocols
        into one or more output segment objects.
    #>
    param(
        [hashtable]$Policy,
        [array]$ConsolidatedProtocols,
        [string]$EnterpriseAppName,
        [string]$GroupName,
        [ref]$SegmentCounter
    )

    $segments = @()

    foreach ($dest in $Policy.Destinations) {
        $cleanDest = Clear-Domain -Domain $dest
        $destType = Get-DestinationType -Destination $cleanDest

        if ($Policy.HasPortClause) {
            # Ports are defined in the rule expression
            # Separate by protocol based on what the expression declares
            if ($Policy.TcpPorts.Count -gt 0) {
                $tcpPortStr = ($Policy.TcpPorts | Sort-Object -Unique) -join ','
                $segments += [PSCustomObject]@{
                    SegmentId              = "SEG-{0:D6}" -f $SegmentCounter.Value
                    OriginalAppName        = $GroupName
                    EnterpriseAppName      = $EnterpriseAppName
                    destinationHost        = $cleanDest
                    DestinationType        = $destType
                    Protocol               = 'TCP'
                    Ports                  = $tcpPortStr
                    EntraGroups            = $GroupName
                    EntraUsers             = ''
                    ConnectorGroup         = 'Placeholder_Replace_Me'
                    Conflict               = 'No'
                    ConflictingEnterpriseApp = ''
                    Provision              = 'Yes'
                    isQuickAccess          = 'no'
                }
                $SegmentCounter.Value++
            }

            if ($Policy.UdpPorts.Count -gt 0) {
                $udpPortStr = ($Policy.UdpPorts | Sort-Object -Unique) -join ','
                $segments += [PSCustomObject]@{
                    SegmentId              = "SEG-{0:D6}" -f $SegmentCounter.Value
                    OriginalAppName        = $GroupName
                    EnterpriseAppName      = $EnterpriseAppName
                    destinationHost        = $cleanDest
                    DestinationType        = $destType
                    Protocol               = 'UDP'
                    Ports                  = $udpPortStr
                    EntraGroups            = $GroupName
                    EntraUsers             = ''
                    ConnectorGroup         = 'Placeholder_Replace_Me'
                    Conflict               = 'No'
                    ConflictingEnterpriseApp = ''
                    Provision              = 'Yes'
                    isQuickAccess          = 'no'
                }
                $SegmentCounter.Value++
            }
        }
        else {
            # No port clause in expression - protocol comes from bindings
            $protocolStr = ($ConsolidatedProtocols | Sort-Object -Unique) -join ','

            $segments += [PSCustomObject]@{
                SegmentId              = "SEG-{0:D6}" -f $SegmentCounter.Value
                OriginalAppName        = $GroupName
                EnterpriseAppName      = $EnterpriseAppName
                destinationHost        = $cleanDest
                DestinationType        = $destType
                Protocol               = $protocolStr
                Ports                  = '1-65535'
                EntraGroups            = $GroupName
                EntraUsers             = ''
                ConnectorGroup         = 'Placeholder_Replace_Me'
                Conflict               = 'No'
                ConflictingEnterpriseApp = ''
                Provision              = 'Yes'
                isQuickAccess          = 'no'
            }
            $SegmentCounter.Value++
        }
    }

    return $segments
}

function Convert-IntranetAppToSegments {
    <#
    .SYNOPSIS
        Converts a parsed VPN intranet application into one or more
        output segment objects.
    #>
    param(
        [hashtable]$IntranetApp,
        [string]$EnterpriseAppName,
        [string]$GroupName,
        [ref]$SegmentCounter
    )

    $segments = @()

    # Map protocol
    $protocolStr = switch ($IntranetApp.Protocol) {
        'TCP'  { 'TCP' }
        'UDP'  { 'UDP' }
        'ANY'  { 'TCP,UDP' }
        'ICMP' { $null }
        default { $null }
    }

    if ($null -eq $protocolStr) {
        Write-LogMessage "Skipping intranet application '$($IntranetApp.Name)' with unsupported protocol '$($IntranetApp.Protocol)'" -Level "WARN" -Component 'Transform'
        return $segments
    }

    foreach ($dest in $IntranetApp.Destinations) {
        $cleanDest = Clear-Domain -Domain $dest
        $destType = Get-DestinationType -Destination $cleanDest

        $segments += [PSCustomObject]@{
            SegmentId              = "SEG-{0:D6}" -f $SegmentCounter.Value
            OriginalAppName        = $GroupName
            EnterpriseAppName      = $EnterpriseAppName
            destinationHost        = $cleanDest
            DestinationType        = $destType
            Protocol               = $protocolStr
            Ports                  = $IntranetApp.PortRange
            EntraGroups            = $GroupName
            EntraUsers             = ''
            ConnectorGroup         = 'Placeholder_Replace_Me'
            Conflict               = 'No'
            ConflictingEnterpriseApp = ''
            Provision              = 'Yes'
            isQuickAccess          = 'no'
        }
        $SegmentCounter.Value++
    }

    return $segments
}

#endregion

#region Main Script Logic

try {
    Write-LogMessage "Starting Citrix NetScaler to EPA conversion function" -Level "INFO" -Component 'Main'
    Write-LogMessage "Function version: 1.0" -Level "INFO" -Component 'Main'
    Write-LogMessage "Parameters:" -Level "INFO" -Component 'Main'
    Write-LogMessage "  ConfigFilePath: $ConfigFilePath" -Level "INFO" -Component 'Main'
    Write-LogMessage "  OutputBasePath: $OutputBasePath" -Level "INFO" -Component 'Main'

    if ($EnableDebugLogging) {
        Write-LogMessage "  EnableDebugLogging: True" -Level "INFO" -Component 'Main'
    }

    if ($GroupFilter) {
        Write-LogMessage "  GroupFilter: $GroupFilter" -Level "INFO" -Component 'Main'
    }

    if ($ExcludeGroupFilter) {
        Write-LogMessage "  ExcludeGroupFilter: $ExcludeGroupFilter" -Level "INFO" -Component 'Main'
    }

    $startTime = Get-Date

    #region Parse Phase
    Write-LogMessage "" -Level "INFO"
    Write-LogMessage "=== PARSING NETSCALER CONFIGURATION ===" -Level "INFO" -Component 'Parse'

    # Read and pre-process config file
    Write-LogMessage "Loading config from: $ConfigFilePath" -Level "INFO" -Component 'Parse'
    $configLines = Read-NetScalerConfig -FilePath $ConfigFilePath

    if ($null -eq $configLines -or $configLines.Count -eq 0) {
        throw "Configuration file is empty or has no parseable commands: $ConfigFilePath"
    }

    Write-LogMessage "Loaded $($configLines.Count) non-empty lines" -Level "INFO" -Component 'Parse'

    # Initialize parsed collections
    $aaaGroups = @{}
    $authPolicies = @{}
    $intranetApps = @{}
    $bindings = @()
    $denyPoliciesSkipped = 0
    $unrecognizedLines = 0

    # Parse line by line
    $lineNumber = 0
    foreach ($line in $configLines) {
        $lineNumber++

        # Try each parser in order
        # 1. add aaa group
        if ($line -match '(?i)^add\s+aaa\s+group\s+') {
            $parsed = Parse-AAAGroup -Line $line
            if ($null -ne $parsed) {
                if ($aaaGroups.ContainsKey($parsed.Name)) {
                    Write-LogMessage "Duplicate AAA group definition: '$($parsed.Name)'. Using last definition." -Level "WARN" -Component 'Parse'
                }
                $aaaGroups[$parsed.Name] = $parsed
                Write-LogMessage "Parsed AAA group: $($parsed.Name)" -Level "DEBUG" -Component 'Parse'
            }
            continue
        }

        # 2. add authorization policy
        if ($line -match '(?i)^add\s+authorization\s+policy\s+') {
            $parsed = Parse-AuthorizationPolicy -Line $line
            if ($null -ne $parsed) {
                if ($parsed.Action -eq 'DENY') {
                    Write-LogMessage "Skipping DENY policy: '$($parsed.Name)'" -Level "INFO" -Component 'Parse'
                    $denyPoliciesSkipped++
                    continue
                }

                if ($authPolicies.ContainsKey($parsed.Name)) {
                    Write-LogMessage "Duplicate authorization policy definition: '$($parsed.Name)'. Using last definition." -Level "WARN" -Component 'Parse'
                }
                $authPolicies[$parsed.Name] = $parsed
                Write-LogMessage "Parsed authorization policy: $($parsed.Name) (destinations: $($parsed.Destinations.Count), tcpPorts: $($parsed.TcpPorts.Count), udpPorts: $($parsed.UdpPorts.Count))" -Level "DEBUG" -Component 'Parse'
            }
            else {
                Write-LogMessage "Failed to parse authorization policy at line $lineNumber : $line" -Level "ERROR" -Component 'Parse'
            }
            continue
        }

        # 3. add vpn intranetApplication
        if ($line -match '(?i)^add\s+vpn\s+intranetApplication\s+') {
            $parsed = Parse-IntranetApplication -Line $line
            if ($null -ne $parsed) {
                if ($intranetApps.ContainsKey($parsed.Name)) {
                    Write-LogMessage "Duplicate intranet application definition: '$($parsed.Name)'. Using last definition." -Level "WARN" -Component 'Parse'
                }
                $intranetApps[$parsed.Name] = $parsed
                Write-LogMessage "Parsed intranet application: $($parsed.Name) (protocol: $($parsed.Protocol), destinations: $($parsed.Destinations.Count))" -Level "DEBUG" -Component 'Parse'
            }
            else {
                Write-LogMessage "Failed to parse intranet application at line $lineNumber : $line" -Level "ERROR" -Component 'Parse'
            }
            continue
        }

        # 4. bind aaa group
        if ($line -match '(?i)^bind\s+aaa\s+group\s+') {
            $parsed = Parse-GroupBinding -Line $line
            if ($null -ne $parsed) {
                $bindings += $parsed
                Write-LogMessage "Parsed binding: group '$($parsed.GroupName)' -> $($parsed.Type) '$($parsed.TargetName)' (protocol: $($parsed.BindingProtocol))" -Level "DEBUG" -Component 'Parse'
            }
            else {
                Write-LogMessage "Failed to parse group binding at line $lineNumber : $line" -Level "DEBUG" -Component 'Parse'
            }
            continue
        }

        # Unrecognized line
        $unrecognizedLines++
        Write-LogMessage "Unrecognized line $lineNumber : $line" -Level "DEBUG" -Component 'Parse'
    }

    Write-LogMessage "" -Level "INFO"
    Write-LogMessage "Parse results:" -Level "INFO" -Component 'Parse'
    Write-LogMessage "  AAA groups: $($aaaGroups.Count)" -Level "INFO" -Component 'Parse'
    Write-LogMessage "  Authorization policies (ALLOW): $($authPolicies.Count)" -Level "INFO" -Component 'Parse'
    Write-LogMessage "  DENY policies skipped: $denyPoliciesSkipped" -Level "INFO" -Component 'Parse'
    Write-LogMessage "  VPN intranet applications: $($intranetApps.Count)" -Level "INFO" -Component 'Parse'
    Write-LogMessage "  Bindings: $($bindings.Count)" -Level "INFO" -Component 'Parse'
    Write-LogMessage "  Unrecognized lines: $unrecognizedLines" -Level "INFO" -Component 'Parse'

    if ($aaaGroups.Count -eq 0 -and $bindings.Count -eq 0) {
        Write-LogMessage "No AAA groups or bindings found. The file may not contain NetScaler Gateway configuration." -Level "WARN" -Component 'Parse'
    }

    #endregion

    #region Resolve Phase
    Write-LogMessage "" -Level "INFO"
    Write-LogMessage "=== RESOLVING BINDINGS ===" -Level "INFO" -Component 'Resolve'

    $resolveResult = Resolve-GroupBindings `
        -AAAGroups $aaaGroups `
        -AuthPolicies $authPolicies `
        -IntranetApps $intranetApps `
        -Bindings $bindings

    $groupBindings = $resolveResult.GroupBindings
    $unboundPolicies = $resolveResult.UnboundPolicies

    Write-LogMessage "Resolved bindings for $($groupBindings.Count) groups" -Level "INFO" -Component 'Resolve'
    Write-LogMessage "  Policy bindings (TCP): $($resolveResult.TcpPolicyBindings)" -Level "INFO" -Component 'Resolve'
    Write-LogMessage "  Policy bindings (UDP): $($resolveResult.UdpPolicyBindings)" -Level "INFO" -Component 'Resolve'
    Write-LogMessage "  Intranet app bindings: $($resolveResult.IntranetAppBindings)" -Level "INFO" -Component 'Resolve'
    Write-LogMessage "  ICMP bindings (skipped): $($resolveResult.IcmpBindingsSkipped)" -Level "INFO" -Component 'Resolve'
    Write-LogMessage "  Missing references: $($resolveResult.MissingReferences)" -Level "INFO" -Component 'Resolve'

    if ($unboundPolicies.Count -gt 0) {
        Write-LogMessage "Unbound policies: $($unboundPolicies.Count)" -Level "WARN" -Component 'Resolve'
        foreach ($up in $unboundPolicies) {
            Write-LogMessage "  Policy '$up' is defined but not bound to any group" -Level "WARN" -Component 'Resolve'
        }
    }

    # Apply group filters
    $groupsToProcess = @($groupBindings.Keys)

    if ($GroupFilter) {
        Write-LogMessage "Applying group filter: $GroupFilter" -Level "INFO" -Component 'Resolve'
        $groupsToProcess = @($groupsToProcess | Where-Object { $_ -like $GroupFilter })
        Write-LogMessage "Groups after include filter: $($groupsToProcess.Count)" -Level "INFO" -Component 'Resolve'
    }

    if ($ExcludeGroupFilter) {
        Write-LogMessage "Applying exclude group filter: $ExcludeGroupFilter" -Level "INFO" -Component 'Resolve'
        $groupsToProcess = @($groupsToProcess | Where-Object { $_ -notlike $ExcludeGroupFilter })
        Write-LogMessage "Groups after exclude filter: $($groupsToProcess.Count)" -Level "INFO" -Component 'Resolve'
    }

    # Skip groups with no bindings
    $emptyGroups = @()
    $activeGroups = @()
    foreach ($grp in $groupsToProcess) {
        $gb = $groupBindings[$grp]
        if ($gb.Policies.Count -eq 0 -and $gb.IntranetApps.Count -eq 0) {
            $emptyGroups += $grp
            Write-LogMessage "AAA group '$grp' has no bindings. Skipping." -Level "WARN" -Component 'Resolve'
        }
        else {
            $activeGroups += $grp
        }
    }
    $groupsToProcess = $activeGroups

    Write-LogMessage "Groups to process: $($groupsToProcess.Count)" -Level "INFO" -Component 'Resolve'

    if ($groupsToProcess.Count -eq 0 -and $unboundPolicies.Count -eq 0) {
        Write-LogMessage "No groups or unbound policies to process. Returning empty result." -Level "WARN" -Component 'Resolve'
        return @()
    }

    #endregion

    #region Transform Phase
    Write-LogMessage "" -Level "INFO"
    Write-LogMessage "=== TRANSFORMING TO SEGMENTS ===" -Level "INFO" -Component 'Transform'

    $allResults = @()
    $segmentIdCounter = 1
    $processedGroupCount = 0
    $segmentsFromPolicies = 0
    $segmentsFromIntranetApps = 0

    foreach ($groupName in ($groupsToProcess | Sort-Object)) {
        $processedGroupCount++
        $enterpriseAppName = "GSA-$groupName"
        $gb = $groupBindings[$groupName]

        Write-ProgressUpdate -Current $processedGroupCount -Total $groupsToProcess.Count `
            -Activity "Converting NetScaler groups to EPA" `
            -Status "Processing group: $groupName" `
            -StartTime $startTime

        Write-LogMessage "Processing group: $groupName -> $enterpriseAppName" -Level "DEBUG" -Component 'Transform'

        # Process bound authorization policies
        foreach ($policyName in $gb.Policies.Keys) {
            $policy = $authPolicies[$policyName]
            $consolidatedProtocols = @($gb.Policies[$policyName].Protocols)

            # Warn if binding protocol contradicts expression protocol
            if ($policy.HasPortClause) {
                foreach ($bp in $consolidatedProtocols) {
                    if ($bp -eq 'TCP' -and $policy.TcpPorts.Count -eq 0 -and $policy.UdpPorts.Count -gt 0) {
                        Write-LogMessage "Binding protocol TCP contradicts rule expression (only UDP ports) for policy '$policyName' in group '$groupName'. Using expression's protocol." -Level "WARN" -Component 'Transform'
                    }
                    elseif ($bp -eq 'UDP' -and $policy.UdpPorts.Count -eq 0 -and $policy.TcpPorts.Count -gt 0) {
                        Write-LogMessage "Binding protocol UDP contradicts rule expression (only TCP ports) for policy '$policyName' in group '$groupName'. Using expression's protocol." -Level "WARN" -Component 'Transform'
                    }
                }
            }

            $segments = Convert-PolicyToSegments `
                -Policy $policy `
                -ConsolidatedProtocols $consolidatedProtocols `
                -EnterpriseAppName $enterpriseAppName `
                -GroupName $groupName `
                -SegmentCounter ([ref]$segmentIdCounter)

            $allResults += $segments
            $segmentsFromPolicies += $segments.Count
        }

        # Process bound intranet applications
        foreach ($appName in $gb.IntranetApps) {
            $intranetApp = $intranetApps[$appName]

            $segments = Convert-IntranetAppToSegments `
                -IntranetApp $intranetApp `
                -EnterpriseAppName $enterpriseAppName `
                -GroupName $groupName `
                -SegmentCounter ([ref]$segmentIdCounter)

            $allResults += $segments
            $segmentsFromIntranetApps += $segments.Count
        }
    }

    # Process unbound policies
    if ($unboundPolicies.Count -gt 0) {
        Write-LogMessage "Processing $($unboundPolicies.Count) unbound policies under GSA-UnboundPolicies" -Level "INFO" -Component 'Transform'

        foreach ($policyName in $unboundPolicies) {
            $policy = $authPolicies[$policyName]

            # Unbound policies default to TCP with all ports
            $segments = Convert-PolicyToSegments `
                -Policy $policy `
                -ConsolidatedProtocols @('TCP') `
                -EnterpriseAppName 'GSA-UnboundPolicies' `
                -GroupName $policyName `
                -SegmentCounter ([ref]$segmentIdCounter)

            # Mark unbound segments
            foreach ($seg in $segments) {
                $seg.EntraGroups = ''
                $seg.Provision = 'No'
                $seg.OriginalAppName = $policyName
            }

            $allResults += $segments
        }
    }

    Write-Progress -Activity "Converting NetScaler groups to EPA" -Completed

    Write-LogMessage "Generated $($allResults.Count) total segments" -Level "INFO" -Component 'Transform'
    Write-LogMessage "  From authorization policies: $segmentsFromPolicies" -Level "INFO" -Component 'Transform'
    Write-LogMessage "  From intranet applications: $segmentsFromIntranetApps" -Level "INFO" -Component 'Transform'
    Write-LogMessage "  From unbound policies: $($allResults.Count - $segmentsFromPolicies - $segmentsFromIntranetApps)" -Level "INFO" -Component 'Transform'

    #endregion

    #region Conflict Detection
    Write-LogMessage "" -Level "INFO"
    Write-LogMessage "=== CONFLICT DETECTION ===" -Level "INFO" -Component 'Conflicts'

    $ipRangeToProtocolToPorts = @{}
    $hostToProtocolToPorts = @{}
    $dnsSuffixes = @{}
    $conflictCount = 0

    foreach ($result in $allResults) {
        $cleanDomain = $result.destinationHost
        $destType = $result.DestinationType

        # For multi-protocol entries (TCP,UDP), check each protocol separately
        $protocols = @($result.Protocol -split ',' | ForEach-Object { $_.Trim() })

        foreach ($protocol in $protocols) {
            $currentAppInfo = @{
                Name      = $result.EnterpriseAppName
                SegmentId = $result.SegmentId
            }

            $hasConflict = $false
            $conflictingApps = @()

            if ($destType -eq 'ipAddress' -or $destType -eq 'ipRangeCidr') {
                # Convert to IP range for comparison
                $currentRange = if ($destType -eq 'ipAddress') {
                    $ipInt = Convert-IPToInteger -IPAddress $cleanDomain
                    if ($null -ne $ipInt) {
                        @{ Start = $ipInt; End = $ipInt }
                    }
                    else { $null }
                }
                else {
                    Convert-CIDRToRange -CIDR $cleanDomain
                }

                if ($null -ne $currentRange) {
                    foreach ($existingRangeKey in $ipRangeToProtocolToPorts.Keys) {
                        if (Test-IntervalOverlap -Range1 $currentRange -Range2 $existingRangeKey) {
                            $protocolData = $ipRangeToProtocolToPorts[$existingRangeKey]
                            if ($protocolData.ContainsKey($protocol)) {
                                foreach ($existingPort in $protocolData[$protocol].Keys) {
                                    if (Test-PortRangeOverlap -PortRange1 $result.Ports -PortRange2 $existingPort) {
                                        $hasConflict = $true
                                        $existingAppInfo = $protocolData[$protocol][$existingPort]
                                        $conflictReference = "$($existingAppInfo.Name):$($existingAppInfo.SegmentId)"
                                        if ($conflictingApps -notcontains $conflictReference) {
                                            $conflictingApps += $conflictReference
                                        }
                                        Write-LogMessage "CONFLICT DETECTED:" -Level "WARN" -Component 'Conflicts'
                                        Write-LogMessage "  Application: $($result.EnterpriseAppName)" -Level "WARN" -Component 'Conflicts'
                                        Write-LogMessage "  Segment: ${cleanDomain}:${protocol}/$($result.Ports)" -Level "WARN" -Component 'Conflicts'
                                        Write-LogMessage "  Conflicts with: $($existingAppInfo.Name) ($($existingPort):${protocol}) [$($existingAppInfo.SegmentId)]" -Level "WARN" -Component 'Conflicts'
                                        Write-LogMessage "  Recommendation: Consolidate applications or restrict port ranges to avoid overlap" -Level "WARN" -Component 'Conflicts'
                                    }
                                }
                            }
                        }
                    }

                    # Add to tracking
                    if (-not $ipRangeToProtocolToPorts.ContainsKey($currentRange)) {
                        $ipRangeToProtocolToPorts[$currentRange] = @{}
                    }
                    if (-not $ipRangeToProtocolToPorts[$currentRange].ContainsKey($protocol)) {
                        $ipRangeToProtocolToPorts[$currentRange][$protocol] = @{}
                    }
                    $ipRangeToProtocolToPorts[$currentRange][$protocol][$result.Ports] = $currentAppInfo
                }
            }
            else {
                # FQDN conflict detection
                $hostKey = $cleanDomain.ToLowerInvariant()

                if ($hostToProtocolToPorts.ContainsKey($hostKey)) {
                    if ($hostToProtocolToPorts[$hostKey].ContainsKey($protocol)) {
                        foreach ($existingPort in $hostToProtocolToPorts[$hostKey][$protocol].Keys) {
                            if (Test-PortRangeOverlap -PortRange1 $result.Ports -PortRange2 $existingPort) {
                                $hasConflict = $true
                                $existingAppInfo = $hostToProtocolToPorts[$hostKey][$protocol][$existingPort]
                                $conflictReference = "$($existingAppInfo.Name):$($existingAppInfo.SegmentId)"
                                if ($conflictingApps -notcontains $conflictReference) {
                                    $conflictingApps += $conflictReference
                                }
                                Write-LogMessage "CONFLICT DETECTED:" -Level "WARN" -Component 'Conflicts'
                                Write-LogMessage "  Application: $($result.EnterpriseAppName)" -Level "WARN" -Component 'Conflicts'
                                Write-LogMessage "  Segment: ${cleanDomain}:${protocol}/$($result.Ports)" -Level "WARN" -Component 'Conflicts'
                                Write-LogMessage "  Conflicts with: $($existingAppInfo.Name) [$($existingAppInfo.SegmentId)]" -Level "WARN" -Component 'Conflicts'
                                Write-LogMessage "  Recommendation: Consolidate applications or restrict port ranges to avoid overlap" -Level "WARN" -Component 'Conflicts'
                            }
                        }
                    }
                }

                # Check wildcard DNS suffixes
                if ($cleanDomain.StartsWith('*.')) {
                    $suffix = $cleanDomain.Substring(1)  # Remove leading *
                    foreach ($existingSuffix in $dnsSuffixes.Keys) {
                        if ($suffix.EndsWith($existingSuffix) -or $existingSuffix.EndsWith($suffix)) {
                            $suffixData = $dnsSuffixes[$existingSuffix]
                            if ($suffixData.ContainsKey($protocol)) {
                                foreach ($existingPort in $suffixData[$protocol].Keys) {
                                    if (Test-PortRangeOverlap -PortRange1 $result.Ports -PortRange2 $existingPort) {
                                        $hasConflict = $true
                                        $existingAppInfo = $suffixData[$protocol][$existingPort]
                                        $conflictReference = "$($existingAppInfo.Name):$($existingAppInfo.SegmentId)"
                                        if ($conflictingApps -notcontains $conflictReference) {
                                            $conflictingApps += $conflictReference
                                        }
                                        Write-LogMessage "CONFLICT DETECTED: ${cleanDomain}:${protocol}/$($result.Ports) conflicts with wildcard $($existingAppInfo.SegmentId)" -Level "WARN" -Component 'Conflicts'
                                    }
                                }
                            }
                        }
                    }
                }
                else {
                    # Check if current host matches any existing wildcard
                    foreach ($existingSuffix in $dnsSuffixes.Keys) {
                        if ($hostKey.EndsWith($existingSuffix)) {
                            $suffixData = $dnsSuffixes[$existingSuffix]
                            if ($suffixData.ContainsKey($protocol)) {
                                foreach ($existingPort in $suffixData[$protocol].Keys) {
                                    if (Test-PortRangeOverlap -PortRange1 $result.Ports -PortRange2 $existingPort) {
                                        $hasConflict = $true
                                        $existingAppInfo = $suffixData[$protocol][$existingPort]
                                        $conflictReference = "$($existingAppInfo.Name):$($existingAppInfo.SegmentId)"
                                        if ($conflictingApps -notcontains $conflictReference) {
                                            $conflictingApps += $conflictReference
                                        }
                                        Write-LogMessage "CONFLICT DETECTED: ${cleanDomain}:${protocol}/$($result.Ports) matches wildcard $($existingAppInfo.SegmentId)" -Level "WARN" -Component 'Conflicts'
                                    }
                                }
                            }
                        }
                    }
                }

                # Add to tracking structures
                if (-not $hostToProtocolToPorts.ContainsKey($hostKey)) {
                    $hostToProtocolToPorts[$hostKey] = @{}
                }
                if (-not $hostToProtocolToPorts[$hostKey].ContainsKey($protocol)) {
                    $hostToProtocolToPorts[$hostKey][$protocol] = @{}
                }
                $hostToProtocolToPorts[$hostKey][$protocol][$result.Ports] = $currentAppInfo

                # Track wildcard domains
                if ($cleanDomain.StartsWith('*.')) {
                    $suffix = $cleanDomain.Substring(1)
                    if (-not $dnsSuffixes.ContainsKey($suffix)) {
                        $dnsSuffixes[$suffix] = @{}
                    }
                    if (-not $dnsSuffixes[$suffix].ContainsKey($protocol)) {
                        $dnsSuffixes[$suffix][$protocol] = @{}
                    }
                    $dnsSuffixes[$suffix][$protocol][$result.Ports] = $currentAppInfo
                }
            }

            if ($hasConflict) {
                $result.Conflict = 'Yes'
                $result.ConflictingEnterpriseApp = ($conflictingApps | Sort-Object -Unique) -join ', '
                $result.Provision = 'No'
                $conflictCount++
            }
        }
    }

    Write-LogMessage "Conflict detection complete. Conflicts found: $conflictCount" -Level "INFO" -Component 'Conflicts'

    #endregion

    #region Export Results
    Write-LogMessage "" -Level "INFO"
    Write-LogMessage "=== EXPORTING RESULTS ===" -Level "INFO" -Component 'Export'

    $outputFileName = "${timestamp}_GSA_EnterpriseApps_CitrixNS.csv"
    $outputFilePath = Join-Path $OutputBasePath $outputFileName

    # Export with UTF-8 BOM for better compatibility with Excel
    $allResults | Export-Csv -Path $outputFilePath -NoTypeInformation -Encoding utf8BOM

    $exportSuccess = Test-Path $outputFilePath

    if ($exportSuccess) {
        Write-LogMessage "Results exported successfully to: $outputFilePath" -Level "SUCCESS" -Component 'Export'
    }
    else {
        Write-LogMessage "Failed to export results" -Level "ERROR" -Component 'Export'
        throw "Failed to write CSV output file: $outputFilePath"
    }

    #endregion

    #region Statistics and Summary
    Write-LogMessage "" -Level "INFO"
    Write-LogMessage "=== PARSE SUMMARY ===" -Level "SUMMARY" -Component 'Summary'
    Write-LogMessage "Total lines processed: $($configLines.Count)" -Level "SUMMARY" -Component 'Summary'
    Write-LogMessage "AAA groups found: $($aaaGroups.Count)" -Level "SUMMARY" -Component 'Summary'
    Write-LogMessage "Authorization policies found: $($authPolicies.Count)" -Level "SUMMARY" -Component 'Summary'
    Write-LogMessage "VPN intranet applications found: $($intranetApps.Count)" -Level "SUMMARY" -Component 'Summary'
    Write-LogMessage "Bindings found: $($bindings.Count)" -Level "SUMMARY" -Component 'Summary'
    Write-LogMessage "  Policy bindings (TCP): $($resolveResult.TcpPolicyBindings)" -Level "SUMMARY" -Component 'Summary'
    Write-LogMessage "  Policy bindings (UDP): $($resolveResult.UdpPolicyBindings)" -Level "SUMMARY" -Component 'Summary'
    Write-LogMessage "  Intranet app bindings: $($resolveResult.IntranetAppBindings)" -Level "SUMMARY" -Component 'Summary'
    Write-LogMessage "  ICMP bindings (skipped): $($resolveResult.IcmpBindingsSkipped)" -Level "SUMMARY" -Component 'Summary'
    Write-LogMessage "DENY policies skipped: $denyPoliciesSkipped" -Level "SUMMARY" -Component 'Summary'
    Write-LogMessage "Unbound policies: $($unboundPolicies.Count)" -Level "SUMMARY" -Component 'Summary'
    Write-LogMessage "" -Level "INFO"
    Write-LogMessage "=== CONVERSION SUMMARY ===" -Level "SUMMARY" -Component 'Summary'
    Write-LogMessage "Enterprise Applications generated: $($groupsToProcess.Count)" -Level "SUMMARY" -Component 'Summary'
    Write-LogMessage "Total segments generated: $($allResults.Count)" -Level "SUMMARY" -Component 'Summary'
    Write-LogMessage "  From authorization policies: $segmentsFromPolicies" -Level "SUMMARY" -Component 'Summary'
    Write-LogMessage "  From intranet applications: $segmentsFromIntranetApps" -Level "SUMMARY" -Component 'Summary'
    Write-LogMessage "Conflicts detected: $conflictCount" -Level "SUMMARY" -Component 'Summary'

    $provisionNoCount = @($allResults | Where-Object { $_.Provision -eq 'No' }).Count
    Write-LogMessage "Segments with Provision=No: $provisionNoCount" -Level "SUMMARY" -Component 'Summary'
    Write-LogMessage "" -Level "INFO"

    Write-LogMessage "Output file: $outputFilePath" -Level "SUMMARY" -Component 'Summary'
    Write-LogMessage "Log file: $LogPath" -Level "SUMMARY" -Component 'Summary'
    Write-LogMessage "" -Level "INFO"

    Write-LogMessage "=== NEXT STEPS ===" -Level "INFO" -Component 'Summary'
    Write-LogMessage "1. Review the exported CSV file for accuracy" -Level "INFO" -Component 'Summary'
    Write-LogMessage "2. Remap EntraGroups: Replace NetScaler AAA group names with corresponding Entra ID security group names" -Level "INFO" -Component 'Summary'
    Write-LogMessage "3. Replace ConnectorGroup placeholders: Set 'Placeholder_Replace_Me' to actual Private Access connector group names" -Level "INFO" -Component 'Summary'
    Write-LogMessage "4. Review conflicts: Resolve flagged overlapping segments" -Level "INFO" -Component 'Summary'
    Write-LogMessage "5. Review unbound policies: Decide whether to provision or discard" -Level "INFO" -Component 'Summary'
    Write-LogMessage "6. Validate port ranges: Ensure '1-65535' (all ports) segments are intentional" -Level "INFO" -Component 'Summary'
    Write-LogMessage "7. Import the completed data using Start-EntraPrivateAccessProvisioning" -Level "INFO" -Component 'Summary'
    Write-LogMessage "" -Level "INFO"

    if ($conflictCount -gt 0) {
        Write-LogMessage "WARNING: $conflictCount conflicts were detected. Please review the 'ConflictingEnterpriseApp' column for details." -Level "WARN" -Component 'Summary'
    }

    Write-LogMessage "Function completed successfully!" -Level "SUCCESS" -Component 'Main'

    #endregion

    # Return results if PassThru is specified
    if ($PassThru) {
        return $allResults
    }
}
catch {
    Write-LogMessage "Fatal error in function execution: $_" -Level "ERROR" -Component 'Main'
    Write-LogMessage "Stack trace: $($_.ScriptStackTrace)" -Level "ERROR" -Component 'Main'
    throw
}

#endregion
}
