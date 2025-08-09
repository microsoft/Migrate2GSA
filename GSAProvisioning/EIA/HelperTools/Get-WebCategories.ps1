#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Beta.NetworkAccess

<#
.SYNOPSIS
    Fetches web categories from Microsoft Graph API
    
.DESCRIPTION
    This script authenticates to Microsoft Graph and retrieves web categories from the 
    networkaccess/connectivity/webCategories endpoint. It handles authentication 
    automatically and can use existing sessions or prompt for new login.
    
.PARAMETER TenantId
    The Azure AD tenant ID (optional - will use default if not specified)
    
.PARAMETER Scopes
    The required scopes for the API call (default: NetworkAccessPolicy.Read.All)
    
.EXAMPLE
    .\Get-WebCategories.ps1
    
.EXAMPLE
    .\Get-WebCategories.ps1 -TenantId "your-tenant-id"
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false)]
    [string[]]$Scopes = @("NetworkAccessPolicy.Read.All")
)

# Function to check if required modules are installed
function Test-RequiredModules {
    $requiredModules = @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Beta.NetworkAccess"
    )
    
    $missingModules = @()
    
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            $missingModules += $module
        }
    }
    
    if ($missingModules.Count -gt 0) {
        Write-Host "The following required modules are missing:" -ForegroundColor Red
        $missingModules | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
        Write-Host ""
        Write-Host "To install these modules, run:" -ForegroundColor Green
        Write-Host "Install-Module -Name Microsoft.Graph -Scope CurrentUser" -ForegroundColor Cyan
        return $false
    }
    
    return $true
}

# Function to connect to Microsoft Graph
function Connect-ToGraph {
    param(
        [string]$TenantId,
        [string[]]$Scopes
    )
    
    try {
        # Check if already connected with the required scopes
        $context = Get-MgContext
        if ($context -and $context.Scopes -contains $Scopes[0]) {
            Write-Host "Already connected to Microsoft Graph with required permissions." -ForegroundColor Green
            return $true
        }
        
        # Prepare connection parameters
        $connectParams = @{
            Scopes = $Scopes
        }
        
        if ($TenantId) {
            $connectParams.TenantId = $TenantId
        }
        
        Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
        Write-Host "Required scopes: $($Scopes -join ', ')" -ForegroundColor Gray
        Write-Host "Note: This will open a browser window for authentication." -ForegroundColor Gray
        
        # Connect to Microsoft Graph using interactive browser authentication only
        Connect-MgGraph @connectParams -UseDeviceAuthentication:$false
        
        $newContext = Get-MgContext
        if ($newContext) {
            Write-Host "Successfully connected to Microsoft Graph!" -ForegroundColor Green
            Write-Host "Tenant: $($newContext.TenantId)" -ForegroundColor Gray
            Write-Host "Account: $($newContext.Account)" -ForegroundColor Gray
            return $true
        }
        else {
            throw "Failed to establish connection context"
        }
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
        return $false
    }
}

# Function to fetch web categories
function Get-WebCategories {
    try {
        Write-Host "Fetching web categories from Microsoft Graph..." -ForegroundColor Yellow
        
        # Make the API call
        $webCategories = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/networkaccess/connectivity/webCategories" -Method GET
        
        if ($webCategories -and $webCategories.value) {
            Write-Host "Successfully retrieved $($webCategories.value.Count) web categories!" -ForegroundColor Green
            return $webCategories.value
        }
        else {
            Write-Warning "No web categories found or empty response received."
            return $null
        }
    }
    catch {
        Write-Error "Failed to fetch web categories: $($_.Exception.Message)"
        
        # Check if it's an authentication/permission error
        if ($_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*Unauthorized*") {
            Write-Host ""
            Write-Host "This might be a permissions issue. Please ensure you have the required permissions:" -ForegroundColor Yellow
            Write-Host "  - NetworkAccessPolicy.Read.All" -ForegroundColor Cyan
            Write-Host "  - Or ask your administrator to grant these permissions" -ForegroundColor Cyan
        }
        
        return $null
    }
}

# Function to display web categories in a formatted way
function Show-WebCategories {
    param(
        [Parameter(Mandatory = $true)]
        [array]$Categories
    )
    
    Write-Host ""
    Write-Host "==================== WEB CATEGORIES ====================" -ForegroundColor Cyan
    Write-Host ""
    
    foreach ($category in $Categories) {
        Write-Host "Category: " -NoNewline -ForegroundColor White
        Write-Host "$($category.displayName)" -ForegroundColor Green
        
        if ($category.id) {
            Write-Host "  ID: " -NoNewline -ForegroundColor Gray
            Write-Host "$($category.id)" -ForegroundColor Yellow
        }
        
        if ($category.description) {
            Write-Host "  Description: " -NoNewline -ForegroundColor Gray
            Write-Host "$($category.description)" -ForegroundColor White
        }
        
        if ($category.group) {
            Write-Host "  Group: " -NoNewline -ForegroundColor Gray
            Write-Host "$($category.group)" -ForegroundColor Magenta
        }
        
        Write-Host ""
    }
    
    Write-Host "=======================================================" -ForegroundColor Cyan
    Write-Host "Total categories: $($Categories.Count)" -ForegroundColor Green
}

# Function to export categories to JSON file
function Export-WebCategories {
    param(
        [Parameter(Mandatory = $true)]
        [array]$Categories,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = "WebCategories_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    )
    
    try {
        $Categories | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Host ""
        Write-Host "Web categories exported to: $OutputPath" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to export categories: $($_.Exception.Message)"
    }
}

# Main script execution
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Microsoft Graph Web Categories Fetcher" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if required modules are installed
if (-not (Test-RequiredModules)) {
    Write-Host "Please install the required modules and run the script again." -ForegroundColor Red
    exit 1
}

# Import required modules
try {
    Import-Module Microsoft.Graph.Authentication -Force
    Import-Module Microsoft.Graph.Beta.NetworkAccess -Force
    Write-Host "Required modules loaded successfully." -ForegroundColor Green
}
catch {
    Write-Error "Failed to import required modules: $($_.Exception.Message)"
    exit 1
}

# Connect to Microsoft Graph
if (-not (Connect-ToGraph -TenantId $TenantId -Scopes $Scopes)) {
    Write-Host "Failed to connect to Microsoft Graph. Exiting." -ForegroundColor Red
    exit 1
}

# Fetch web categories
$categories = Get-WebCategories

if ($categories) {
    # Display categories
    Show-WebCategories -Categories $categories
    
    # Ask user if they want to export to JSON
    Write-Host ""
    $export = Read-Host "Do you want to export the categories to a JSON file? (y/N)"
    if ($export -eq 'y' -or $export -eq 'Y') {
        Export-WebCategories -Categories $categories
    }
}
else {
    Write-Host "No categories retrieved. Please check your permissions and try again." -ForegroundColor Red
}

Write-Host ""
Write-Host "Script completed." -ForegroundColor Green
