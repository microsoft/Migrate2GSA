# GSA Filtering Profiles CSV Definition
# This script defines the CSV column structure for creating Global Secure Access
# filtering profiles, policies, and rules via Microsoft Graph PowerShell
## This file is part of the Migration2GSA project, which aims to facilitate the migration

<#
.SYNOPSIS
    Defines CSV column structure for Global Secure Access filtering profiles, policies, and rules.

.DESCRIPTION
    This script provides the CSV column definitions needed to create filtering profiles,
    filtering policies, and policy rules in Microsoft Global Secure Access using Microsoft Graph.
    
    The CSV structure is designed to support the creation of:
    - Filtering Profiles (groups filtering policies and links to Conditional Access)
    - Filtering Policies (defines specific traffic rules)
    - Policy Rules (FQDN and web category filtering rules)

.NOTES
    Author: Provision2GSA Project
    Version: 1.0
    Based on Microsoft Graph Network Access APIs (Beta)
    Documentation: https://learn.microsoft.com/en-us/graph/api/resources/networkaccess-global-secure-access-api-overview?view=graph-rest-beta

.EXAMPLE
    # Example CSV structure for Global Secure Access filtering
    $csvStructure = Get-GSAFilteringCSVDefinition
    $csvStructure | Export-Csv -Path "GSA-Filtering-Template.csv" -NoTypeInformation
#>

function Get-GSAFilteringCSVDefinition {
    <#
    .SYNOPSIS
        Returns the CSV column definition for GSA filtering profiles, policies, and rules.
    
    .DESCRIPTION
        This function defines the complete CSV structure needed to create filtering profiles,
        policies, and rules in Global Secure Access. Each row represents a policy rule
        that will be grouped into policies and profiles.
    
    .OUTPUTS
        PSCustomObject[] - Array of objects defining the CSV column structure
    #>
    
    return [PSCustomObject]@{
        # === GROUPING AND IDENTIFICATION ===
        ProfileName = "String - Name of the filtering profile (groups multiple policies)"
        ProfileDescription = "String - Description of the filtering profile purpose"
        ProfilePriority = "Int64 - Priority for profile processing (lower = higher priority)"
        
        PolicyName = "String - Name of the filtering policy within the profile"
        PolicyDescription = "String - Description of the filtering policy purpose"
        
        RuleName = "String - Name of the individual filtering rule"
        RuleDescription = "String - Description of what this rule does"
        
        # === RULE CONFIGURATION ===
        RuleType = "String - Type of rule: 'fqdn', 'webCategory', 'ipAddress', 'ipRange', 'ipSubnet', 'url'"
        Action = "String - Rule action: 'allow' or 'block'"
        
        # === DESTINATION CONFIGURATION ===
        # For FQDN rules
        DestinationFQDN = "String - Fully qualified domain name (e.g., 'example.com', '*.microsoft.com')"
        
        # For URL rules  
        DestinationURL = "String - Specific URL pattern"
        
        # For IP-based rules
        DestinationIPAddress = "String - Single IP address (e.g., '192.168.1.1')"
        DestinationIPRange = "String - IP range (e.g., '192.168.1.1-192.168.1.100')"
        DestinationIPSubnet = "String - IP subnet in CIDR notation (e.g., '192.168.1.0/24')"
        
        # For web category rules
        WebCategoryName = "String - Web category name (e.g., 'Social Media', 'Gaming', 'Adult Content')"
        WebCategoryId = "String - Web category identifier if known"
        
        # === CONDITIONAL ACCESS INTEGRATION ===
        ConditionalAccessPolicyName = "String - Name of associated Conditional Access policy"
        ConditionalAccessPolicyId = "String - ID of associated Conditional Access policy (if known)"
        
        # === USER/GROUP TARGETING ===
        TargetGroups = "String - Comma-separated list of Entra groups (e.g., 'IT-Users,Finance-Team')"
        TargetUsers = "String - Comma-separated list of specific users (UPNs)"
        ExcludeGroups = "String - Comma-separated list of groups to exclude"
        ExcludeUsers = "String - Comma-separated list of users to exclude (UPNs)"
        
        # === SCHEDULING AND CONDITIONS ===
        TimeRestriction = "String - Time-based restrictions (future use)"
        LocationRestriction = "String - Location-based restrictions (future use)"
        DeviceRestriction = "String - Device-based restrictions (future use)"
        
        # === PROCESSING CONTROL ===
        Enabled = "Boolean - Whether this rule should be enabled (True/False)"
        Priority = "Int32 - Rule priority within the policy (lower = higher priority)"
        
        # === MIGRATION TRACKING ===
        SourceSystem = "String - Source system this rule came from (e.g., 'Zscaler', 'Manual')"
        SourceRuleId = "String - Original rule ID from source system"
        SourcePolicyName = "String - Original policy name from source system"
        
        # === PROVISIONING CONTROL ===
        CreateProfile = "Boolean - Whether to create the filtering profile (True/False)"
        CreatePolicy = "Boolean - Whether to create the filtering policy (True/False)"
        CreateRule = "Boolean - Whether to create this rule (True/False)"
        
        # === VALIDATION AND CONFLICT DETECTION ===
        ValidationStatus = "String - Validation result: 'Valid', 'Warning', 'Error'"
        ValidationMessage = "String - Detailed validation or error message"
        ConflictDetected = "Boolean - Whether conflicts were detected with existing rules"
        ConflictingRules = "String - Names/IDs of conflicting rules"
        
        # === PROVISIONING RESULTS ===
        ProvisioningStatus = "String - Status: 'Pending', 'Success', 'Failed', 'Skipped'"
        ProvisioningMessage = "String - Detailed provisioning result message"
        CreatedProfileId = "String - ID of created filtering profile"
        CreatedPolicyId = "String - ID of created filtering policy"
        CreatedRuleId = "String - ID of created filtering rule"
        
        # === TIMESTAMPS ===
        CreatedDate = "DateTime - When this CSV entry was created"
        ProcessedDate = "DateTime - When this entry was processed"
        LastModifiedDate = "DateTime - When this entry was last modified"
        
        # === NOTES AND COMMENTS ===
        Notes = "String - Additional notes or comments about this rule"
        Tags = "String - Comma-separated tags for categorization"
    }
}

function New-GSAFilteringCSVTemplate {
    <#
    .SYNOPSIS
        Creates a template CSV file with sample data for GSA filtering configuration.
    
    .PARAMETER OutputPath
        Path where the template CSV file should be created.
    
    .EXAMPLE
        New-GSAFilteringCSVTemplate -OutputPath "C:\Temp\GSA-Filtering-Template.csv"
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )
    
    $templateData = @(
        # Example 1: Block social media FQDN
        [PSCustomObject]@{
            ProfileName = "Corporate-Web-Filtering"
            ProfileDescription = "Corporate web filtering policies for security and productivity"
            ProfilePriority = 100
            PolicyName = "Social-Media-Blocking"
            PolicyDescription = "Block access to social media platforms during work hours"
            RuleName = "Block-Facebook"
            RuleDescription = "Block access to Facebook and related domains"
            RuleType = "fqdn"
            Action = "block"
            DestinationFQDN = "*.facebook.com"
            DestinationURL = ""
            DestinationIPAddress = ""
            DestinationIPRange = ""
            DestinationIPSubnet = ""
            WebCategoryName = ""
            WebCategoryId = ""
            ConditionalAccessPolicyName = "Corporate-Device-Policy"
            ConditionalAccessPolicyId = ""
            TargetGroups = "All-Users"
            TargetUsers = ""
            ExcludeGroups = "IT-Admins"
            ExcludeUsers = ""
            TimeRestriction = ""
            LocationRestriction = ""
            DeviceRestriction = ""
            Enabled = $true
            Priority = 10
            SourceSystem = "Manual"
            SourceRuleId = ""
            SourcePolicyName = ""
            CreateProfile = $true
            CreatePolicy = $true
            CreateRule = $true
            ValidationStatus = "Valid"
            ValidationMessage = ""
            ConflictDetected = $false
            ConflictingRules = ""
            ProvisioningStatus = "Pending"
            ProvisioningMessage = ""
            CreatedProfileId = ""
            CreatedPolicyId = ""
            CreatedRuleId = ""
            CreatedDate = (Get-Date)
            ProcessedDate = ""
            LastModifiedDate = (Get-Date)
            Notes = "Example rule for blocking Facebook access"
            Tags = "social-media,productivity,security"
        },
        
        # Example 2: Allow specific business application
        [PSCustomObject]@{
            ProfileName = "Corporate-Web-Filtering"
            ProfileDescription = "Corporate web filtering policies for security and productivity"
            ProfilePriority = 100
            PolicyName = "Business-Applications"
            PolicyDescription = "Allow access to approved business applications"
            RuleName = "Allow-Salesforce"
            RuleDescription = "Allow access to Salesforce CRM platform"
            RuleType = "fqdn"
            Action = "allow"
            DestinationFQDN = "*.salesforce.com"
            DestinationURL = ""
            DestinationIPAddress = ""
            DestinationIPRange = ""
            DestinationIPSubnet = ""
            WebCategoryName = ""
            WebCategoryId = ""
            ConditionalAccessPolicyName = "Corporate-Device-Policy"
            ConditionalAccessPolicyId = ""
            TargetGroups = "Sales-Team,Management"
            TargetUsers = ""
            ExcludeGroups = ""
            ExcludeUsers = ""
            TimeRestriction = ""
            LocationRestriction = ""
            DeviceRestriction = ""
            Enabled = $true
            Priority = 5
            SourceSystem = "Manual"
            SourceRuleId = ""
            SourcePolicyName = ""
            CreateProfile = $false  # Profile already created in first rule
            CreatePolicy = $true
            CreateRule = $true
            ValidationStatus = "Valid"
            ValidationMessage = ""
            ConflictDetected = $false
            ConflictingRules = ""
            ProvisioningStatus = "Pending"
            ProvisioningMessage = ""
            CreatedProfileId = ""
            CreatedPolicyId = ""
            CreatedRuleId = ""
            CreatedDate = (Get-Date)
            ProcessedDate = ""
            LastModifiedDate = (Get-Date)
            Notes = "Allow Salesforce for sales team access"
            Tags = "business-app,crm,sales"
        },
        
        # Example 3: Block web category
        [PSCustomObject]@{
            ProfileName = "Corporate-Web-Filtering"
            ProfileDescription = "Corporate web filtering policies for security and productivity"
            ProfilePriority = 100
            PolicyName = "Category-Blocking"
            PolicyDescription = "Block access to inappropriate web categories"
            RuleName = "Block-Gaming-Category"
            RuleDescription = "Block access to gaming and entertainment websites"
            RuleType = "webCategory"
            Action = "block"
            DestinationFQDN = ""
            DestinationURL = ""
            DestinationIPAddress = ""
            DestinationIPRange = ""
            DestinationIPSubnet = ""
            WebCategoryName = "Gaming"
            WebCategoryId = ""
            ConditionalAccessPolicyName = "Corporate-Device-Policy"
            ConditionalAccessPolicyId = ""
            TargetGroups = "All-Users"
            TargetUsers = ""
            ExcludeGroups = "IT-Admins"
            ExcludeUsers = ""
            TimeRestriction = ""
            LocationRestriction = ""
            DeviceRestriction = ""
            Enabled = $true
            Priority = 20
            SourceSystem = "Manual"
            SourceRuleId = ""
            SourcePolicyName = ""
            CreateProfile = $false  # Profile already created
            CreatePolicy = $true
            CreateRule = $true
            ValidationStatus = "Valid"
            ValidationMessage = ""
            ConflictDetected = $false
            ConflictingRules = ""
            ProvisioningStatus = "Pending"
            ProvisioningMessage = ""
            CreatedProfileId = ""
            CreatedPolicyId = ""
            CreatedRuleId = ""
            CreatedDate = (Get-Date)
            ProcessedDate = ""
            LastModifiedDate = (Get-Date)
            Notes = "Block gaming category to improve productivity"
            Tags = "web-category,productivity,gaming"
        }
    )
    
    # Export template data to CSV
    $templateData | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "GSA Filtering CSV template created at: $OutputPath" -ForegroundColor Green
}

function Get-GSAFilteringCSVValidationRules {
    <#
    .SYNOPSIS
        Returns validation rules for the GSA filtering CSV structure.
    
    .DESCRIPTION
        Defines the validation rules that should be applied when processing
        the GSA filtering CSV file to ensure data quality and compatibility.
    #>
    
    return @{
        RequiredFields = @(
            'ProfileName',
            'PolicyName', 
            'RuleName',
            'RuleType',
            'Action'
        )
        
        RuleTypes = @(
            'fqdn',
            'webCategory', 
            'ipAddress',
            'ipRange',
            'ipSubnet',
            'url'
        )
        
        Actions = @(
            'allow',
            'block'
        )
        
        ValidationRules = @{
            'ProfileName' = 'Must not be empty and should be unique per profile'
            'PolicyName' = 'Must not be empty within a profile'
            'RuleName' = 'Must not be empty within a policy'
            'RuleType' = 'Must be one of: fqdn, webCategory, ipAddress, ipRange, ipSubnet, url'
            'Action' = 'Must be either allow or block'
            'DestinationFQDN' = 'Required when RuleType is fqdn'
            'WebCategoryName' = 'Required when RuleType is webCategory'
            'DestinationIPAddress' = 'Required when RuleType is ipAddress'
            'DestinationIPRange' = 'Required when RuleType is ipRange'
            'DestinationIPSubnet' = 'Required when RuleType is ipSubnet'
            'DestinationURL' = 'Required when RuleType is url'
            'Priority' = 'Must be a positive integer'
            'Enabled' = 'Must be True or False'
        }
        
        ConditionalRequirements = @{
            'fqdn' = @('DestinationFQDN')
            'webCategory' = @('WebCategoryName')
            'ipAddress' = @('DestinationIPAddress')
            'ipRange' = @('DestinationIPRange')
            'ipSubnet' = @('DestinationIPSubnet')
            'url' = @('DestinationURL')
        }
    }
}

# Export functions for use in other scripts
Export-ModuleMember -Function @(
    'Get-GSAFilteringCSVDefinition',
    'New-GSAFilteringCSVTemplate',
    'Get-GSAFilteringCSVValidationRules'
)

# Main execution if script is run directly
if ($MyInvocation.InvocationName -ne '.') {
    Write-Host "=== Global Secure Access Filtering CSV Definition ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "This script defines the CSV structure for creating GSA filtering profiles, policies, and rules." -ForegroundColor Green
    Write-Host ""
    
    # Display the CSV definition
    Write-Host "CSV Column Definitions:" -ForegroundColor Yellow
    $csvDef = Get-GSAFilteringCSVDefinition
    $csvDef.PSObject.Properties | ForEach-Object {
        Write-Host "  $($_.Name): $($_.Value)" -ForegroundColor White
    }
    
    Write-Host ""
    Write-Host "To create a template CSV file, run:" -ForegroundColor Yellow
    Write-Host "  New-GSAFilteringCSVTemplate -OutputPath 'C:\Path\To\Template.csv'" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "To get validation rules, run:" -ForegroundColor Yellow
    Write-Host "  Get-GSAFilteringCSVValidationRules" -ForegroundColor Cyan
}
