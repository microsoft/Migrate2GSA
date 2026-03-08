function Find-AppMapping {
    <#
    .SYNOPSIS
        Looks up an application name in a mappings hashtable using a three-pass strategy.

    .DESCRIPTION
        Pass 1: Exact match (case-insensitive) against hashtable keys.
        Pass 2: Word-token matching — tokenizes both names into significant words (>= 4 chars),
                requires ALL tokens of the shorter name to appear in the longer name.
                Rejects matches where all overlapping tokens are generic stopwords (cloud, data, etc.).
                Picks the best match by overlap count, then closest name length.
        Pass 3: Prefix matching fallback — compares concatenated lowercase alphanumeric forms,
                requires the shorter string to be >= 5 chars and >= 70% the length of the longer.
        Returns endpoints, match type, and matched display name.

    .PARAMETER AppName
        The application name to look up.

    .PARAMETER AppMappingsHashtable
        Hashtable keyed by displayName.ToLower() containing objects with displayName and endpoints properties.

    .OUTPUTS
        Hashtable with Endpoints (array), MatchType ("exact", "approximate", "none"), and MappedName (string or $null).
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$AppName,

        [Parameter(Mandatory = $true)]
        [hashtable]$AppMappingsHashtable
    )

    # Pass 1: Exact match (case-insensitive)
    $exactMatch = $AppMappingsHashtable[$AppName.ToLower()]
    if ($null -ne $exactMatch) {
        return @{
            Endpoints = $exactMatch.endpoints
            MatchType = "exact"
            MappedName = $exactMatch.displayName
        }
    }

    # Tokenize source name: split on non-alphanumeric, keep tokens >= 4 chars
    $splitPattern = '[\s\-._/,;:()+''\"&]+'
    $sourceTokens = @([regex]::Split($AppName.ToLower(), $splitPattern) | Where-Object { $_.Length -ge 4 })

    # Generic tech/cloud stopwords — matches based solely on these are rejected
    $stopWords = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($w in @(
        'cloud', 'data', 'drive', 'storage', 'migration', 'management', 'enterprise',
        'platform', 'service', 'services', 'system', 'systems', 'online', 'digital',
        'media', 'video', 'network', 'smart', 'mobile', 'global', 'secure', 'security',
        'live', 'chat', 'mail', 'sync', 'backup', 'transfer', 'connect', 'hosting',
        'server', 'block', 'integration', 'analytics', 'monitor', 'studio', 'vision',
        'solutions', 'group', 'notes', 'files', 'stream', 'search', 'news', 'cycle',
        'social', 'marketing', 'advertising', 'audio', 'software', 'content', 'tools',
        'business', 'office', 'hybrid', 'private', 'public', 'personal', 'virtual',
        'remote', 'document', 'documents', 'email', 'messaging', 'meeting', 'meetings',
        'conference', 'call', 'calling', 'object', 'file', 'share', 'sharing',
        'exchange', 'workspace', 'workspaces'
    )) { [void]$stopWords.Add($w) }

    # Pass 2: Word-token matching — all tokens of the shorter name must appear in the longer name
    # Reject if ALL overlapping tokens are generic stopwords
    $bestMatch = $null
    $bestOverlap = 0
    $bestLengthDiff = [int]::MaxValue

    foreach ($key in $AppMappingsHashtable.Keys) {
        $mapping = $AppMappingsHashtable[$key]
        $mappingTokens = @([regex]::Split($mapping.displayName.ToLower(), $splitPattern) | Where-Object { $_.Length -ge 4 })

        if ($sourceTokens.Count -eq 0 -or $mappingTokens.Count -eq 0) { continue }

        # Determine shorter and longer token sets
        if ($sourceTokens.Count -le $mappingTokens.Count) {
            $shorterTokens = $sourceTokens
            $longerTokens = $mappingTokens
        }
        else {
            $shorterTokens = $mappingTokens
            $longerTokens = $sourceTokens
        }

        # Check ALL shorter tokens appear in longer tokens (exact token match)
        $allMatch = $true
        $overlapCount = 0
        foreach ($token in $shorterTokens) {
            if ($longerTokens -contains $token) {
                $overlapCount++
            }
            else {
                $allMatch = $false
                break
            }
        }

        if ($allMatch -and $overlapCount -gt 0) {
            # Reject if ALL overlapping tokens are generic stopwords
            $hasDistinctiveToken = $false
            foreach ($token in $shorterTokens) {
                if (-not $stopWords.Contains($token)) {
                    $hasDistinctiveToken = $true
                    break
                }
            }
            if (-not $hasDistinctiveToken) { continue }

            $lengthDiff = [Math]::Abs($AppName.Length - $mapping.displayName.Length)
            if ($overlapCount -gt $bestOverlap -or ($overlapCount -eq $bestOverlap -and $lengthDiff -lt $bestLengthDiff)) {
                $bestOverlap = $overlapCount
                $bestLengthDiff = $lengthDiff
                $bestMatch = $mapping
            }
        }
    }

    if ($null -ne $bestMatch) {
        return @{
            Endpoints = $bestMatch.endpoints
            MatchType = "approximate"
            MappedName = $bestMatch.displayName
        }
    }

    # Pass 3: Prefix matching fallback — concatenated alphanumeric, shorter >= 5 chars, ratio >= 0.7
    $appNameClean = ($AppName.ToLower() -replace '[^a-z0-9]', '')
    $bestRatio = 0

    foreach ($key in $AppMappingsHashtable.Keys) {
        $mapping = $AppMappingsHashtable[$key]
        $mappingClean = ($mapping.displayName.ToLower() -replace '[^a-z0-9]', '')

        if ($appNameClean.Length -le $mappingClean.Length) {
            $shorter = $appNameClean
            $longer = $mappingClean
        }
        else {
            $shorter = $mappingClean
            $longer = $appNameClean
        }

        if ($shorter.Length -ge 5 -and $longer.StartsWith($shorter)) {
            $ratio = $shorter.Length / $longer.Length
            if ($ratio -ge 0.7 -and $ratio -gt $bestRatio) {
                $bestRatio = $ratio
                $bestMatch = $mapping
            }
        }
    }

    if ($null -ne $bestMatch) {
        return @{
            Endpoints = $bestMatch.endpoints
            MatchType = "approximate"
            MappedName = $bestMatch.displayName
        }
    }

    # No match
    return @{
        Endpoints = @()
        MatchType = "none"
        MappedName = $null
    }
}
