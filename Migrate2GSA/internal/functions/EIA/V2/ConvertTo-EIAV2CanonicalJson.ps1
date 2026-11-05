function ConvertTo-EIAV2CanonicalJson {
    [CmdletBinding()]
    param([AllowNull()][object]$Value)

    function ConvertTo-CanonicalValue {
        param([AllowNull()][object]$InputValue)

        if ($null -eq $InputValue -or ($InputValue -is [string] -and $InputValue.Length -eq 0)) { return $null }
        if ($InputValue -is [System.Collections.IDictionary]) {
            $result = [ordered]@{}
            foreach ($key in ($InputValue.Keys | Sort-Object -CaseSensitive)) {
                $child = ConvertTo-CanonicalValue $InputValue[$key]
                if ($null -ne $child) { $result[$key] = $child }
            }
            if ($result.Count -gt 0) { return $result }
            return $null
        }
        if ($InputValue -is [System.Collections.IEnumerable] -and $InputValue -isnot [string]) {
            $values = @(
                foreach ($item in $InputValue) {
                    $child = ConvertTo-CanonicalValue $item
                    if ($null -ne $child) { $child }
                }
            )
            if ($values.Count -eq 0) { return $null }
            # These collections are sets of destinations or CA assignments, not ordered rules.
            return ,@($values | Sort-Object { ConvertTo-Json -InputObject $_ -Depth 50 -Compress } -CaseSensitive -Unique)
        }
        return $InputValue
    }

    $plainValue = ConvertTo-Json -InputObject $Value -Depth 50 -Compress |
        ConvertFrom-Json -AsHashtable
    ConvertTo-Json -InputObject (ConvertTo-CanonicalValue $plainValue) -Depth 50 -Compress
}
