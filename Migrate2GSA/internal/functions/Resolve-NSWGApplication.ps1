function Resolve-NSWGApplication {
    <#
    .SYNOPSIS
        Determines if an application string is a custom category, predefined category, or application object.
    
    .DESCRIPTION
        Analyzes an application name from Netskope and classifies it by looking it up
        in custom categories and category mappings hashtables.
    
    .PARAMETER ApplicationName
        The name from the application field to resolve.
    
    .PARAMETER CustomCategoriesHashtable
        Hashtable for custom category lookups (key = category name).
    
    .PARAMETER CategoryMappingsHashtable
        Hashtable for predefined category lookups (key = NSWG category name).
    
    .OUTPUTS
        PSCustomObject with properties:
        - Type: "CustomCategory", "PredefinedCategory", or "Application"
        - IsCustomCategory: Boolean
        - IsPredefinedCategory: Boolean
        - IsApplication: Boolean
    
    .EXAMPLE
        Resolve-NSWGApplication -ApplicationName "Whitelist URLs" -CustomCategoriesHashtable $customCats -CategoryMappingsHashtable $catMappings
        Returns: Type = "CustomCategory", IsCustomCategory = $true
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApplicationName,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$CustomCategoriesHashtable,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$CategoryMappingsHashtable
    )
    
    $result = [PSCustomObject]@{
        Type                  = ""
        IsCustomCategory      = $false
        IsPredefinedCategory  = $false
        IsApplication         = $false
    }
    
    # Check if it's a custom category
    if ($CustomCategoriesHashtable.ContainsKey($ApplicationName)) {
        $result.Type = "CustomCategory"
        $result.IsCustomCategory = $true
        return $result
    }
    
    # Check if it's a predefined category
    if ($CategoryMappingsHashtable.ContainsKey($ApplicationName)) {
        $result.Type = "PredefinedCategory"
        $result.IsPredefinedCategory = $true
        return $result
    }
    
    # Otherwise, it's an application object
    $result.Type = "Application"
    $result.IsApplication = $true
    return $result
}
